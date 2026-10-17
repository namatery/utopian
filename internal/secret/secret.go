// Package secret provides a container for secret values that cannot be
// printed, marshaled, or logged by accident (ADR-0005).
//
// The only way to read a secret is Value.Reveal. Calls to Reveal are allowed
// only in the packages listed in revealAllowed (enforced by a test).
package secret

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
)

// Redacted is what a Value prints as, in every format.
const Redacted = "[REDACTED]"

// Value holds a secret byte string. The zero Value is empty.
//
// The bytes live behind a pointer so that printing a struct which holds a
// Value in an unexported field shows only an address, never the contents.
type Value struct {
	b *box
}

type box struct {
	data []byte
}

// New returns a Value holding a copy of b.
func New(b []byte) Value {
	if len(b) == 0 {
		return Value{}
	}
	return Value{b: &box{data: append([]byte(nil), b...)}}
}

// FromString returns a Value holding s.
func FromString(s string) Value {
	return New([]byte(s))
}

// Reveal returns a copy of the secret bytes.
//
// Only call Reveal at the point of use (signing, encrypting, sending
// upstream), and never pass the result to logging or error formatting.
func (v Value) Reveal() []byte {
	if v.b == nil {
		return nil
	}
	return append([]byte(nil), v.b.data...)
}

// IsZero reports whether v holds no secret.
func (v Value) IsZero() bool {
	return v.b == nil || len(v.b.data) == 0
}

// Equal reports whether v and other hold the same secret, in constant time
// with respect to the contents.
func (v Value) Equal(other Value) bool {
	var a, b []byte
	if v.b != nil {
		a = v.b.data
	}
	if other.b != nil {
		b = other.b.data
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// String implements fmt.Stringer.
func (Value) String() string { return Redacted }

// GoString implements fmt.GoStringer.
func (Value) GoString() string { return Redacted }

// Format implements fmt.Formatter, so every verb (%v, %+v, %#v, %s, %q, %x, ...)
// prints Redacted.
func (Value) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(Redacted))
}

// LogValue implements slog.LogValuer.
func (Value) LogValue() slog.Value { return slog.StringValue(Redacted) }

// MarshalJSON implements json.Marshaler.
func (Value) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// MarshalText implements encoding.TextMarshaler (used by YAML, TOML, and others).
func (Value) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// ErrNotEncodable is returned by encoders that must not carry secrets.
var ErrNotEncodable = errors.New("secret: value cannot be encoded")

// GobEncode implements gob.GobEncoder and always fails.
func (Value) GobEncode() ([]byte, error) { return nil, ErrNotEncodable }

// MarshalBinary implements encoding.BinaryMarshaler and always fails.
func (Value) MarshalBinary() ([]byte, error) { return nil, ErrNotEncodable }
