// Package sign implements the UTOPIAN-HMAC-SHA256 request signing scheme
// (ADR-0002). It is used by both the Utopian server and the Go SDK, so the two
// can never disagree on how a signature is computed.
//
// String to sign (fields separated by "\n", no trailing newline):
//
//	UTOPIAN-HMAC-SHA256
//	<key id>
//	<unix timestamp, seconds>
//	<nonce>
//	<HTTP method>
//	<path>
//	<lowercase hex SHA-256 of the raw body>
//
// Signature = lowercase hex(HMAC-SHA256(secret, string to sign)).
package sign

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// Scheme is the Authorization scheme name and the first line of the
	// string to sign.
	Scheme = "UTOPIAN-HMAC-SHA256"
	// HeaderName is the HTTP header that carries the signature.
	HeaderName = "Authorization"

	maxHeaderLen = 512
	maxKeyIDLen  = 64
	minNonceLen  = 22 // 22 base64url characters carry at least 128 bits
	maxNonceLen  = 64
	maxPathLen   = 1024
	maxMethodLen = 16
	maxTSDigits  = 12
	sigHexLen    = sha256.Size * 2
	nonceBytes   = 16
)

var (
	// ErrInvalid means a header or request field is malformed.
	ErrInvalid = errors.New("sign: invalid")
	// ErrSignatureMismatch means the signature does not match.
	ErrSignatureMismatch = errors.New("sign: signature mismatch")
)

// Request holds the signed fields of an HTTP request.
type Request struct {
	KeyID      string
	Timestamp  int64 // Unix seconds
	Nonce      string
	Method     string // HTTP method, upper case
	Path       string // escaped path, no query
	BodySHA256 [sha256.Size]byte
}

// Header is a parsed Authorization header.
type Header struct {
	KeyID     string
	Timestamp int64
	Nonce     string
	Signature string // lowercase hex
}

// BodyHash returns the SHA-256 of the raw request body.
func BodyHash(body []byte) [sha256.Size]byte {
	return sha256.Sum256(body)
}

// Validate checks every field against its allowed character set and length,
// so no field can contain a newline or otherwise alter the string to sign.
func (r Request) Validate() error {
	if !validKeyID(r.KeyID) {
		return fmt.Errorf("%w: key id", ErrInvalid)
	}
	if r.Timestamp <= 0 {
		return fmt.Errorf("%w: timestamp", ErrInvalid)
	}
	if !validNonce(r.Nonce) {
		return fmt.Errorf("%w: nonce", ErrInvalid)
	}
	if !validMethod(r.Method) {
		return fmt.Errorf("%w: method", ErrInvalid)
	}
	if !validPath(r.Path) {
		return fmt.Errorf("%w: path", ErrInvalid)
	}
	return nil
}

// StringToSign returns the canonical string for r.
func StringToSign(r Request) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	return strings.Join([]string{
		Scheme,
		r.KeyID,
		strconv.FormatInt(r.Timestamp, 10),
		r.Nonce,
		r.Method,
		r.Path,
		hex.EncodeToString(r.BodySHA256[:]),
	}, "\n"), nil
}

// Compute returns the lowercase hex signature of r under secret.
func Compute(secret []byte, r Request) (string, error) {
	mac, err := computeMAC(secret, r)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(mac), nil
}

// Verify checks signature against r in constant time.
func Verify(secret []byte, r Request, signature string) error {
	if !validSignature(signature) {
		return fmt.Errorf("%w: signature", ErrInvalid)
	}
	got, err := hex.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("%w: signature", ErrInvalid)
	}
	want, err := computeMAC(secret, r)
	if err != nil {
		return err
	}
	if !hmac.Equal(got, want) {
		return ErrSignatureMismatch
	}
	return nil
}

func computeMAC(secret []byte, r Request) ([]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("%w: empty secret", ErrInvalid)
	}
	sts, err := StringToSign(r)
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(sts))
	return h.Sum(nil), nil
}

// FormatHeader returns the Authorization header value for h.
func FormatHeader(h Header) string {
	return fmt.Sprintf("%s KeyId=%s, Timestamp=%d, Nonce=%s, Signature=%s",
		Scheme, h.KeyID, h.Timestamp, h.Nonce, h.Signature)
}

// ParseHeader parses an Authorization header value. It is strict: the scheme
// must match, and KeyId, Timestamp, Nonce and Signature must each appear
// exactly once, in any order, with no other parameters.
func ParseHeader(v string) (Header, error) {
	var h Header
	if len(v) > maxHeaderLen {
		return h, fmt.Errorf("%w: header too long", ErrInvalid)
	}
	rest, ok := strings.CutPrefix(v, Scheme+" ")
	if !ok {
		return h, fmt.Errorf("%w: scheme", ErrInvalid)
	}

	seen := map[string]bool{}
	for _, part := range strings.Split(rest, ",") {
		key, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || seen[key] {
			return Header{}, fmt.Errorf("%w: parameter", ErrInvalid)
		}
		seen[key] = true
		switch key {
		case "KeyId":
			if !validKeyID(val) {
				return Header{}, fmt.Errorf("%w: key id", ErrInvalid)
			}
			h.KeyID = val
		case "Timestamp":
			ts, err := parseTimestamp(val)
			if err != nil {
				return Header{}, err
			}
			h.Timestamp = ts
		case "Nonce":
			if !validNonce(val) {
				return Header{}, fmt.Errorf("%w: nonce", ErrInvalid)
			}
			h.Nonce = val
		case "Signature":
			if !validSignature(val) {
				return Header{}, fmt.Errorf("%w: signature", ErrInvalid)
			}
			h.Signature = val
		default:
			return Header{}, fmt.Errorf("%w: unknown parameter", ErrInvalid)
		}
	}
	if len(seen) != 4 {
		return Header{}, fmt.Errorf("%w: missing parameter", ErrInvalid)
	}
	return h, nil
}

// NewNonce returns a random nonce with 128 bits of entropy.
func NewNonce() (string, error) {
	b := make([]byte, nonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SignRequest signs req in place: it reads and restores the body, and sets
// the Authorization header. Requests with a query string are rejected,
// because the query is not covered by the signature.
func SignRequest(req *http.Request, keyID string, secret []byte, now time.Time) error {
	if req.URL.RawQuery != "" || req.URL.ForceQuery {
		return fmt.Errorf("%w: query strings are not signed", ErrInvalid)
	}
	var body []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return err
		}
		if err := req.Body.Close(); err != nil {
			return err
		}
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	req.ContentLength = int64(len(body))

	nonce, err := NewNonce()
	if err != nil {
		return err
	}
	r := Request{
		KeyID:      keyID,
		Timestamp:  now.Unix(),
		Nonce:      nonce,
		Method:     req.Method,
		Path:       req.URL.EscapedPath(),
		BodySHA256: BodyHash(body),
	}
	sig, err := Compute(secret, r)
	if err != nil {
		return err
	}
	req.Header.Set(HeaderName, FormatHeader(Header{KeyID: keyID, Timestamp: r.Timestamp, Nonce: nonce, Signature: sig}))
	return nil
}

func parseTimestamp(s string) (int64, error) {
	if len(s) == 0 || len(s) > maxTSDigits || s[0] == '0' {
		return 0, fmt.Errorf("%w: timestamp", ErrInvalid)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("%w: timestamp", ErrInvalid)
		}
	}
	ts, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: timestamp", ErrInvalid)
	}
	return ts, nil
}

func validKeyID(s string) bool {
	return len(s) >= 1 && len(s) <= maxKeyIDLen && allBytes(s, isIDByte)
}

func validNonce(s string) bool {
	return len(s) >= minNonceLen && len(s) <= maxNonceLen && allBytes(s, isIDByte)
}

func validMethod(s string) bool {
	return len(s) >= 1 && len(s) <= maxMethodLen && allBytes(s, func(c byte) bool { return c >= 'A' && c <= 'Z' })
}

func validPath(s string) bool {
	return len(s) >= 1 && len(s) <= maxPathLen && s[0] == '/' &&
		allBytes(s, func(c byte) bool { return c > ' ' && c < 0x7f && c != '?' && c != '#' })
}

func validSignature(s string) bool {
	return len(s) == sigHexLen && allBytes(s, func(c byte) bool { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') })
}

// isIDByte accepts the base64url alphabet, which also covers key IDs.
func isIDByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
}

func allBytes(s string, ok func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if !ok(s[i]) {
			return false
		}
	}
	return true
}
