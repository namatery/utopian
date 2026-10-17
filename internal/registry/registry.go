// Package registry is the single source of truth for which Utopia API methods
// Utopian knows about, how they are classified, and which scope each requires.
// Any method not in the registry is denied (invariant I4).
//
// docs/method-registry.md documents this table; a test keeps them in sync.
package registry

import (
	"slices"
	"sort"
)

// Class determines how a method is exposed, retried, and audited.
type Class int

const (
	// Read methods have no side effects and may be retried (bounded).
	Read Class = iota + 1
	// Mutating methods may move money. They are never retried (ADR-0003).
	Mutating
	// Internal methods are called only by Utopian itself, never by clients.
	Internal
)

func (c Class) String() string {
	switch c {
	case Read:
		return "read"
	case Mutating:
		return "mutating"
	case Internal:
		return "internal"
	default:
		return "unknown"
	}
}

// Scope is a permission a key must hold to call a method.
type Scope string

const (
	FinanceRead    Scope = "finance:read"
	FinanceSend    Scope = "finance:send"
	VouchersRead   Scope = "vouchers:read"
	VouchersRedeem Scope = "vouchers:redeem"
	VouchersManage Scope = "vouchers:manage"
	InvoicesRead   Scope = "invoices:read"
	InvoicesWrite  Scope = "invoices:write"
	SystemRead     Scope = "system:read"
)

// Method describes one Utopia API method.
type Method struct {
	Name  string
	Class Class
	// Scope required to call the method. Empty for Internal methods.
	Scope Scope
	// RedactParams lists parameters that must never be written to the audit
	// log or logs, such as voucher codes.
	RedactParams []string
	// SensitiveResult means the response contains secrets (for example
	// redeemable voucher codes) and must never be logged.
	SensitiveResult bool
}

var methods = []Method{
	// Finance: read.
	{Name: "getBalance", Class: Read, Scope: FinanceRead},
	{Name: "getFinanceSystemInformation", Class: Read, Scope: FinanceRead},
	{Name: "getFinanceHistory", Class: Read, Scope: FinanceRead},
	{Name: "getCards", Class: Read, Scope: FinanceRead},
	{Name: "getTransactionIdByReferenceNumber", Class: Read, Scope: FinanceRead},
	{Name: "requestHistoryByDate", Class: Read, Scope: FinanceRead},
	{Name: "requestHistoryByBatch", Class: Read, Scope: FinanceRead},
	{Name: "verifyTransaction", Class: Read, Scope: FinanceRead},
	{Name: "verifyTransactionByHash", Class: Read, Scope: FinanceRead},
	{Name: "getVerifyTransactionResponse", Class: Read, Scope: FinanceRead},

	// Finance: send.
	{Name: "sendPayment", Class: Mutating, Scope: FinanceSend},
	{Name: "createVoucher", Class: Mutating, Scope: FinanceSend, SensitiveResult: true},
	{Name: "createVoucherBatch", Class: Mutating, Scope: FinanceSend, SensitiveResult: true},

	// Vouchers. Voucher codes are bearer money.
	{Name: "getVouchers", Class: Read, Scope: VouchersRead, SensitiveResult: true},
	{Name: "verifyVoucherByHash", Class: Read, Scope: VouchersRead, RedactParams: []string{"voucherid"}},
	{Name: "useVoucher", Class: Mutating, Scope: VouchersRedeem, RedactParams: []string{"voucherid"}},
	{Name: "deleteVoucher", Class: Mutating, Scope: VouchersManage, RedactParams: []string{"voucherid"}},

	// Invoices (money in).
	{Name: "getInvoices", Class: Read, Scope: InvoicesRead},
	{Name: "getInvoiceByReferenceNumber", Class: Read, Scope: InvoicesRead},
	{Name: "sendInvoice", Class: Mutating, Scope: InvoicesWrite},
	{Name: "cancelInvoice", Class: Mutating, Scope: InvoicesWrite},
	{Name: "declineInvoice", Class: Mutating, Scope: InvoicesWrite},

	// System.
	{Name: "getSystemInfo", Class: Read, Scope: SystemRead},
	{Name: "getProfileStatus", Class: Read, Scope: SystemRead},
	{Name: "getOwnContact", Class: Read, Scope: SystemRead},
	{Name: "getUnsSyncInfo", Class: Read, Scope: SystemRead},

	// Internal: used by Utopian only.
	{Name: "setWebSocketState", Class: Internal},
	{Name: "getWebSocketState", Class: Internal},
	{Name: "getNetworkConnections", Class: Internal},
}

// forbidden methods can never be exposed, not even as an opt-in pack.
var forbidden = []string{
	"storageWipe",
	"getSettingInfo", "setSettingInfo",
	"enableLogs", "getLogs",
	"clearNetHostDatabase",
	"getProxyMappings", "createProxyMapping", "enableProxyMapping", "disableProxyMapping", "removeProxyMapping",
	"uploadFile", "getFile", "deleteFile", "sendFileByMessage", "getFilesFromManager",
	"getTransfersFromManager", "abortTransfers", "hideTransfers",
	"acceptFileMessage", "abortFileMessage", "acceptAttachment", "abortAttachment",
	"addDelegate", "revokeDelegated",
	"enableMining", "enablePoS", "enableHistoryMining",
	"requestUnsTransfer", "acceptUnsTransfer", "declineUnsTransfer",
}

var (
	byName       = make(map[string]Method, len(methods))
	forbiddenSet = make(map[string]struct{}, len(forbidden))
)

func init() {
	for _, m := range methods {
		byName[m.Name] = m
	}
	for _, name := range forbidden {
		forbiddenSet[name] = struct{}{}
	}
}

// Lookup returns any known method, including Internal ones. Use Exposed for
// client requests.
func Lookup(name string) (Method, bool) {
	m, ok := byName[name]
	if !ok {
		return Method{}, false
	}
	return clone(m), true
}

// Exposed returns the method if clients may call it. Names are case-sensitive.
func Exposed(name string) (Method, bool) {
	m, ok := Lookup(name)
	if !ok || m.Class == Internal {
		return Method{}, false
	}
	return m, true
}

// IsForbidden reports whether a method must never be exposed.
func IsForbidden(name string) bool {
	_, ok := forbiddenSet[name]
	return ok
}

// All returns every known method, sorted by name.
func All() []Method {
	out := make([]Method, 0, len(methods))
	for _, m := range methods {
		out = append(out, clone(m))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func clone(m Method) Method {
	m.RedactParams = slices.Clone(m.RedactParams)
	return m
}
