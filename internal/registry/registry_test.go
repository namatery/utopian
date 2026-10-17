package registry

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestTableIsConsistent(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range methods {
		if seen[m.Name] {
			t.Errorf("%s: duplicate entry", m.Name)
		}
		seen[m.Name] = true

		switch m.Class {
		case Read, Mutating:
			if m.Scope == "" {
				t.Errorf("%s: exposed method without a scope", m.Name)
			}
		case Internal:
			if m.Scope != "" {
				t.Errorf("%s: internal method must not have a scope", m.Name)
			}
		default:
			t.Errorf("%s: invalid class %d", m.Name, m.Class)
		}
		if IsForbidden(m.Name) {
			t.Errorf("%s: listed both as a method and as forbidden", m.Name)
		}
	}
}

func TestForbiddenListHasNoDuplicates(t *testing.T) {
	if len(forbiddenSet) != len(forbidden) {
		t.Fatalf("forbidden list has %d duplicate(s)", len(forbidden)-len(forbiddenSet))
	}
}

func TestExposed(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"sendPayment", true},
		{"getBalance", true},
		{"getWebSocketState", false}, // internal
		{"setWebSocketState", false}, // internal
		{"storageWipe", false},       // forbidden
		{"acceptInvoice", false},     // deferred
		{"SendPayment", false},       // case-sensitive
		{"sendPayment ", false},
		{"", false},
		{"noSuchMethod", false},
	}
	for _, tt := range tests {
		if _, got := Exposed(tt.name); got != tt.want {
			t.Errorf("Exposed(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestMoneyMovingMethodsAreMutating(t *testing.T) {
	for _, name := range []string{"sendPayment", "createVoucher", "createVoucherBatch", "useVoucher", "deleteVoucher", "sendInvoice", "cancelInvoice", "declineInvoice"} {
		m, ok := Lookup(name)
		if !ok || m.Class != Mutating {
			t.Errorf("%s must be registered as mutating", name)
		}
	}
}

func TestVoucherSecretsAreProtected(t *testing.T) {
	for _, name := range []string{"useVoucher", "deleteVoucher", "verifyVoucherByHash"} {
		m, _ := Lookup(name)
		if len(m.RedactParams) == 0 || m.RedactParams[0] != "voucherid" {
			t.Errorf("%s must redact voucherid", name)
		}
	}
	for _, name := range []string{"getVouchers", "createVoucher", "createVoucherBatch"} {
		if m, _ := Lookup(name); !m.SensitiveResult {
			t.Errorf("%s must mark its result as sensitive", name)
		}
	}
	if m, _ := Lookup("getVouchers"); m.Scope == FinanceRead {
		t.Error("getVouchers must not be readable with finance:read")
	}
}

func TestLookupReturnsCopy(t *testing.T) {
	m, _ := Lookup("useVoucher")
	m.RedactParams[0] = "changed"
	if m2, _ := Lookup("useVoucher"); m2.RedactParams[0] != "voucherid" {
		t.Fatal("mutating a Lookup result changed the registry")
	}
}

func TestAllIsSorted(t *testing.T) {
	all := All()
	if len(all) != len(methods) {
		t.Fatalf("All() returned %d methods, want %d", len(all), len(methods))
	}
	if !sort.SliceIsSorted(all, func(i, j int) bool { return all[i].Name < all[j].Name }) {
		t.Fatal("All() is not sorted")
	}
}

// The v1 section of docs/method-registry.md must list exactly the methods in
// this table, with the same class.
func TestDocumentationInSync(t *testing.T) {
	raw, err := os.ReadFile("../../docs/method-registry.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	start := strings.Index(doc, "## v1 methods")
	end := strings.Index(doc, "## Policy conditions")
	if start < 0 || end < start {
		t.Fatal("could not find the v1 section in docs/method-registry.md")
	}
	section := doc[start:end]

	// Rows look like: | `name` | class | ...  (the Internal table has no class column).
	row := regexp.MustCompile("(?m)^\\| `([a-zA-Z]+)`(?:, `[a-zA-Z]+`)* \\| ([a-z]+)?")
	documented := map[string]string{}
	for _, line := range strings.Split(section, "\n") {
		if row.FindStringSubmatch(line) == nil {
			continue
		}
		cells := strings.Split(line, "|")
		names := regexp.MustCompile("`([a-zA-Z]+)`").FindAllStringSubmatch(cells[1], -1)
		class := strings.TrimSpace(cells[2])
		for _, n := range names {
			if _, dup := documented[n[1]]; dup {
				continue // listed in an exposed table and again under Internal usage
			}
			documented[n[1]] = class
		}
	}

	for _, m := range methods {
		class, ok := documented[m.Name]
		if !ok {
			t.Errorf("%s is in the registry but not documented", m.Name)
			continue
		}
		if m.Class != Internal && class != m.Class.String() {
			t.Errorf("%s: documented as %q, registry says %q", m.Name, class, m.Class)
		}
	}
	for name := range documented {
		if _, ok := byName[name]; !ok {
			t.Errorf("%s is documented in the v1 section but not in the registry", name)
		}
	}
}
