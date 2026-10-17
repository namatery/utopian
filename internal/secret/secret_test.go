package secret

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const canary = "CANARY-7f3a9c1e5b"

func TestRevealRoundTrip(t *testing.T) {
	v := FromString(canary)
	if got := string(v.Reveal()); got != canary {
		t.Fatalf("Reveal() = %q, want %q", got, canary)
	}
}

func TestRevealReturnsCopy(t *testing.T) {
	v := FromString(canary)
	b := v.Reveal()
	b[0] = 'X'
	if got := string(v.Reveal()); got != canary {
		t.Fatalf("mutating Reveal() result changed the secret: %q", got)
	}
}

func TestNewCopiesInput(t *testing.T) {
	in := []byte(canary)
	v := New(in)
	in[0] = 'X'
	if got := string(v.Reveal()); got != canary {
		t.Fatalf("mutating New() input changed the secret: %q", got)
	}
}

func TestZero(t *testing.T) {
	var v Value
	if !v.IsZero() || !New(nil).IsZero() || !FromString("").IsZero() {
		t.Fatal("empty values must be zero")
	}
	if FromString(canary).IsZero() {
		t.Fatal("non-empty value reported as zero")
	}
	if v.Reveal() != nil {
		t.Fatal("zero value must reveal nil")
	}
}

func TestEqual(t *testing.T) {
	a, b, c := FromString(canary), FromString(canary), FromString("other")
	if !a.Equal(b) {
		t.Error("equal secrets compare unequal")
	}
	if a.Equal(c) {
		t.Error("different secrets compare equal")
	}
	if !(Value{}).Equal(FromString("")) {
		t.Error("two empty values compare unequal")
	}
}

// Every way a Value can reach output must hide the canary.
func TestNeverLeaks(t *testing.T) {
	v := FromString(canary)

	type exported struct{ Token Value }
	type unexported struct{ token Value }
	type pointer struct{ token *Value }
	wrapped := fmt.Errorf("connect failed: %v", v)

	var outputs = map[string]string{}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T"} {
		outputs["direct "+verb] = fmt.Sprintf(verb, v)
		outputs["exported field "+verb] = fmt.Sprintf(verb, exported{v})
		outputs["unexported field "+verb] = fmt.Sprintf(verb, unexported{v})
		outputs["pointer field "+verb] = fmt.Sprintf(verb, pointer{&v})
		outputs["slice "+verb] = fmt.Sprintf(verb, []Value{v})
		outputs["map "+verb] = fmt.Sprintf(verb, map[string]Value{"k": v})
	}
	outputs["Sprint"] = fmt.Sprint(v)
	outputs["Sprintln"] = fmt.Sprintln(v)
	outputs["error wrap"] = wrapped.Error()
	outputs["errors.Join"] = errors.Join(wrapped).Error()

	j, err := json.Marshal(exported{v})
	if err != nil {
		t.Fatal(err)
	}
	outputs["json"] = string(j)

	txt, err := v.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	outputs["text"] = string(txt)

	for name, h := range map[string]func(*bytes.Buffer) slog.Handler{
		"slog json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
		"slog text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
	} {
		var buf bytes.Buffer
		l := slog.New(h(&buf))
		l.Info("msg", "token", v, "struct", exported{v}, slog.Any("any", v), slog.Group("g", "t", v))
		outputs[name] = buf.String()
	}

	for name, out := range outputs {
		if strings.Contains(out, canary) {
			t.Errorf("%s leaked the secret: %s", name, out)
		}
		if strings.Contains(out, fmt.Sprintf("%x", canary)) {
			t.Errorf("%s leaked the secret as hex: %s", name, out)
		}
	}
}

func TestEncodersRefuse(t *testing.T) {
	v := FromString(canary)
	if err := gob.NewEncoder(&bytes.Buffer{}).Encode(v); err == nil {
		t.Error("gob encoding succeeded")
	}
	if _, err := v.MarshalBinary(); !errors.Is(err, ErrNotEncodable) {
		t.Errorf("MarshalBinary err = %v, want ErrNotEncodable", err)
	}
}
