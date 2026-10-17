package sign

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type vector struct {
	Name         string `json:"name"`
	SecretHex    string `json:"secret_hex"`
	KeyID        string `json:"key_id"`
	Timestamp    int64  `json:"timestamp"`
	Nonce        string `json:"nonce"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	Body         string `json:"body"`
	BodySHA256   string `json:"body_sha256"`
	StringToSign string `json:"string_to_sign"`
	Signature    string `json:"signature"`
	Header       string `json:"header"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile("../../docs/auth/test-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Scheme  string   `json:"scheme"`
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Scheme != Scheme || len(f.Vectors) == 0 {
		t.Fatalf("unexpected vectors file: scheme %q, %d vectors", f.Scheme, len(f.Vectors))
	}
	return f.Vectors
}

func (v vector) request() Request {
	return Request{
		KeyID: v.KeyID, Timestamp: v.Timestamp, Nonce: v.Nonce,
		Method: v.Method, Path: v.Path, BodySHA256: BodyHash([]byte(v.Body)),
	}
}

func (v vector) secret(t *testing.T) []byte {
	b, err := hex.DecodeString(v.SecretHex)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The vectors were generated with openssl (docs/auth/gen-test-vectors.sh),
// so this checks the Go code against an independent implementation.
func TestVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			r := v.request()
			if got := hex.EncodeToString(r.BodySHA256[:]); got != v.BodySHA256 {
				t.Errorf("body hash = %s, want %s", got, v.BodySHA256)
			}
			sts, err := StringToSign(r)
			if err != nil {
				t.Fatal(err)
			}
			if sts != v.StringToSign {
				t.Errorf("string to sign =\n%q\nwant\n%q", sts, v.StringToSign)
			}
			sig, err := Compute(v.secret(t), r)
			if err != nil {
				t.Fatal(err)
			}
			if sig != v.Signature {
				t.Errorf("signature = %s, want %s", sig, v.Signature)
			}
			if err := Verify(v.secret(t), r, v.Signature); err != nil {
				t.Errorf("Verify: %v", err)
			}

			h, err := ParseHeader(v.Header)
			if err != nil {
				t.Fatalf("ParseHeader: %v", err)
			}
			want := Header{KeyID: v.KeyID, Timestamp: v.Timestamp, Nonce: v.Nonce, Signature: v.Signature}
			if h != want {
				t.Errorf("ParseHeader = %+v, want %+v", h, want)
			}
			if got := FormatHeader(h); got != v.Header {
				t.Errorf("FormatHeader = %q, want %q", got, v.Header)
			}
		})
	}
}

// Changing any signed field, or the secret, must invalidate the signature.
func TestVerifyRejectsAnyChange(t *testing.T) {
	v := loadVectors(t)[0]
	secret := v.secret(t)
	base := v.request()

	mutations := map[string]func(r *Request){
		"key id":    func(r *Request) { r.KeyID += "x" },
		"timestamp": func(r *Request) { r.Timestamp++ },
		"nonce":     func(r *Request) { r.Nonce = "B" + r.Nonce[1:] },
		"method":    func(r *Request) { r.Method = "PUT" },
		"path":      func(r *Request) { r.Path = "/v1/rpc2" },
		"body":      func(r *Request) { r.BodySHA256 = BodyHash([]byte(strings.Replace(v.Body, `"10"`, `"1000"`, 1))) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			r := base
			mutate(&r)
			if err := Verify(secret, r, v.Signature); !errors.Is(err, ErrSignatureMismatch) {
				t.Errorf("err = %v, want ErrSignatureMismatch", err)
			}
		})
	}
	t.Run("secret", func(t *testing.T) {
		other := append([]byte(nil), secret...)
		other[0] ^= 1
		if err := Verify(other, base, v.Signature); !errors.Is(err, ErrSignatureMismatch) {
			t.Errorf("err = %v, want ErrSignatureMismatch", err)
		}
	})
	t.Run("uppercase signature", func(t *testing.T) {
		if err := Verify(secret, base, strings.ToUpper(v.Signature)); !errors.Is(err, ErrInvalid) {
			t.Errorf("err = %v, want ErrInvalid", err)
		}
	})
	t.Run("empty secret", func(t *testing.T) {
		if err := Verify(nil, base, v.Signature); !errors.Is(err, ErrInvalid) {
			t.Errorf("err = %v, want ErrInvalid", err)
		}
	})
}

func TestValidateRejectsInjection(t *testing.T) {
	good := loadVectors(t)[0].request()
	bad := map[string]func(r *Request){
		"newline in key id":   func(r *Request) { r.KeyID = "a\nb" },
		"empty key id":        func(r *Request) { r.KeyID = "" },
		"long key id":         func(r *Request) { r.KeyID = strings.Repeat("a", 65) },
		"zero timestamp":      func(r *Request) { r.Timestamp = 0 },
		"negative timestamp":  func(r *Request) { r.Timestamp = -1 },
		"short nonce":         func(r *Request) { r.Nonce = "abc" },
		"newline in nonce":    func(r *Request) { r.Nonce = strings.Repeat("a", 22) + "\n" },
		"lowercase method":    func(r *Request) { r.Method = "post" },
		"newline in method":   func(r *Request) { r.Method = "POST\n" },
		"relative path":       func(r *Request) { r.Path = "v1/rpc" },
		"query in path":       func(r *Request) { r.Path = "/v1/rpc?x=1" },
		"fragment in path":    func(r *Request) { r.Path = "/v1/rpc#x" },
		"newline in path":     func(r *Request) { r.Path = "/v1/rpc\nPOST" },
		"space in path":       func(r *Request) { r.Path = "/v1/ rpc" },
		"non-ascii path":      func(r *Request) { r.Path = "/v1/rpcé" },
		"long path":           func(r *Request) { r.Path = "/" + strings.Repeat("a", 1024) },
		"non-base64url nonce": func(r *Request) { r.Nonce = strings.Repeat("a", 21) + "+" },
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			r := good
			mutate(&r)
			if _, err := StringToSign(r); !errors.Is(err, ErrInvalid) {
				t.Errorf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestParseHeader(t *testing.T) {
	v := loadVectors(t)[0]
	sig := v.Signature
	ok := []string{
		v.Header,
		"UTOPIAN-HMAC-SHA256 Signature=" + sig + ", Nonce=" + v.Nonce + ", Timestamp=1760440000, KeyId=uk_shop_checkout",
		"UTOPIAN-HMAC-SHA256 KeyId=uk_shop_checkout,Timestamp=1760440000,Nonce=" + v.Nonce + ",Signature=" + sig,
	}
	for _, h := range ok {
		if _, err := ParseHeader(h); err != nil {
			t.Errorf("ParseHeader(%q): %v", h, err)
		}
	}

	params := "KeyId=uk_a, Timestamp=1760440000, Nonce=" + v.Nonce + ", Signature=" + sig
	bad := map[string]string{
		"empty":             "",
		"wrong scheme":      "Bearer " + params,
		"lowercase scheme":  "utopian-hmac-sha256 " + params,
		"no space":          Scheme + params,
		"missing param":     Scheme + " KeyId=uk_a, Timestamp=1760440000, Nonce=" + v.Nonce,
		"duplicate param":   Scheme + " " + params + ", KeyId=uk_b",
		"unknown param":     Scheme + " " + params + ", Extra=1",
		"lowercase key":     Scheme + " keyid=uk_a, Timestamp=1760440000, Nonce=" + v.Nonce + ", Signature=" + sig,
		"quoted value":      Scheme + ` KeyId="uk_a", Timestamp=1760440000, Nonce=` + v.Nonce + ", Signature=" + sig,
		"leading zero ts":   Scheme + " KeyId=uk_a, Timestamp=01760440000, Nonce=" + v.Nonce + ", Signature=" + sig,
		"signed ts":         Scheme + " KeyId=uk_a, Timestamp=+1760440000, Nonce=" + v.Nonce + ", Signature=" + sig,
		"huge ts":           Scheme + " KeyId=uk_a, Timestamp=9999999999999, Nonce=" + v.Nonce + ", Signature=" + sig,
		"short signature":   Scheme + " KeyId=uk_a, Timestamp=1760440000, Nonce=" + v.Nonce + ", Signature=abc",
		"uppercase sig":     Scheme + " KeyId=uk_a, Timestamp=1760440000, Nonce=" + v.Nonce + ", Signature=" + strings.ToUpper(sig),
		"empty param":       Scheme + " " + params + ",",
		"no equals":         Scheme + " KeyId",
		"too long":          Scheme + " " + params + strings.Repeat(" ", 512),
		"newline in key id": Scheme + " KeyId=uk\na, Timestamp=1760440000, Nonce=" + v.Nonce + ", Signature=" + sig,
	}
	for name, h := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseHeader(h); !errors.Is(err, ErrInvalid) {
				t.Errorf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestNewNonce(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		n, err := NewNonce()
		if err != nil {
			t.Fatal(err)
		}
		if !validNonce(n) {
			t.Fatalf("invalid nonce %q", n)
		}
		if seen[n] {
			t.Fatalf("duplicate nonce %q", n)
		}
		seen[n] = true
	}
}

// End to end over HTTP: a signed request verifies on the server side with the
// exact bytes received.
func TestSignRequestRoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	body := `{"method":"getBalance","params":{"currency":"CRP"}}`
	now := time.Unix(1760440000, 0)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		h, err := ParseHeader(r.Header.Get(HeaderName))
		if err != nil {
			t.Errorf("ParseHeader: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		req := Request{KeyID: h.KeyID, Timestamp: h.Timestamp, Nonce: h.Nonce, Method: r.Method, Path: r.URL.EscapedPath(), BodySHA256: BodyHash(raw)}
		if err := Verify(secret, req, h.Signature); err != nil {
			t.Errorf("Verify: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if h.KeyID != "uk_test" || h.Timestamp != now.Unix() || string(raw) != body {
			t.Errorf("unexpected request: %+v body %q", h, raw)
		}
	}))
	defer srv.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/v1/rpc", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if err := SignRequest(req, "uk_test", secret, now); err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	// The body must still be readable for retries by the HTTP client.
	rb, err := req.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := io.ReadAll(rb); !bytes.Equal(got, []byte(body)) {
		t.Fatalf("GetBody = %q", got)
	}
}

func TestSignRequestRejectsQuery(t *testing.T) {
	for _, url := range []string{"http://x/v1/rpc?a=1", "http://x/v1/rpc?"} {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, url, nil)
		if err := SignRequest(req, "uk_test", []byte("secret"), time.Now()); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", url, err)
		}
	}
}

func FuzzParseHeader(f *testing.F) {
	f.Add("UTOPIAN-HMAC-SHA256 KeyId=uk_a, Timestamp=1760440000, Nonce=Q2FuYXJ5Tm9uY2UtMDAwMQ, Signature=" + strings.Repeat("a", 64))
	f.Add("UTOPIAN-HMAC-SHA256 ")
	f.Add("UTOPIAN-HMAC-SHA256 KeyId=,,,,=")
	f.Add("Bearer x")
	f.Fuzz(func(t *testing.T, in string) {
		h, err := ParseHeader(in)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		// Anything accepted must round-trip and be usable in a string to sign.
		h2, err := ParseHeader(FormatHeader(h))
		if err != nil || h2 != h {
			t.Fatalf("round trip failed: %+v -> %+v (%v)", h, h2, err)
		}
		r := Request{KeyID: h.KeyID, Timestamp: h.Timestamp, Nonce: h.Nonce, Method: "POST", Path: "/v1/rpc"}
		sts, err := StringToSign(r)
		if err != nil {
			t.Fatalf("accepted header produced invalid request: %v", err)
		}
		if n := strings.Count(sts, "\n"); n != 6 {
			t.Fatalf("string to sign has %d newlines, want 6", n)
		}
	})
}
