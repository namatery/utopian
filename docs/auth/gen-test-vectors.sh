#!/usr/bin/env bash
# Generates docs/auth/test-vectors.json for the UTOPIAN-HMAC-SHA256 scheme
# using only openssl, sha256sum and jq, independently of the Go code.
#
# Usage: docs/auth/gen-test-vectors.sh > docs/auth/test-vectors.json
set -euo pipefail

vector() {
  local name=$1 secret_hex=$2 key_id=$3 ts=$4 nonce=$5 method=$6 path=$7 body=$8
  local body_hash sts sig
  body_hash=$(printf '%s' "$body" | sha256sum | cut -d' ' -f1)
  sts=$(printf 'UTOPIAN-HMAC-SHA256\n%s\n%s\n%s\n%s\n%s\n%s' "$key_id" "$ts" "$nonce" "$method" "$path" "$body_hash")
  sig=$(printf '%s' "$sts" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$secret_hex" | awk '{print $NF}')
  jq -n --arg name "$name" --arg secret_hex "$secret_hex" --arg key_id "$key_id" \
    --argjson timestamp "$ts" --arg nonce "$nonce" --arg method "$method" --arg path "$path" \
    --arg body "$body" --arg body_sha256 "$body_hash" --arg string_to_sign "$sts" --arg signature "$sig" \
    --arg header "UTOPIAN-HMAC-SHA256 KeyId=$key_id, Timestamp=$ts, Nonce=$nonce, Signature=$sig" \
    '{name: $name, secret_hex: $secret_hex, key_id: $key_id, timestamp: $timestamp, nonce: $nonce,
      method: $method, path: $path, body: $body, body_sha256: $body_sha256,
      string_to_sign: $string_to_sign, signature: $signature, header: $header}'
}

SECRET=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

{
  vector "send payment" "$SECRET" "uk_shop_checkout" 1760440000 "Q2FuYXJ5Tm9uY2UtMDAwMQ" POST /v1/rpc \
    '{"method":"sendPayment","params":{"to":"9F0A36BC95EA653E05E39C6B6566AAC5B9B31FB41F15C9F4A0B8CCA6927B814F","amount":"10","currency":"CRP","comment":"order-1001"}}'
  vector "empty body" "$SECRET" "uk_reader" 1760440001 "AAAAAAAAAAAAAAAAAAAAAA" GET /v1/rpc ''
  vector "utf-8 comment" "$SECRET" "uk_shop_checkout" 1760440002 "dGVzdC1ub25jZS0wMDAzLXV0Zjg" POST /v1/rpc \
    '{"method":"sendPayment","params":{"to":"70AE0077C023EF30","amount":"0.000000001","comment":"پرداخت سفارش ۱۰۰۲ ✓"}}'
  vector "different secret" "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" "A-Z_09" 9999999999 \
    "-_-_-_-_-_-_-_-_-_-_-_-_-_" POST /v1/rpc '{"method":"getBalance","params":{}}'
} | jq -s '{scheme: "UTOPIAN-HMAC-SHA256", vectors: .}'
