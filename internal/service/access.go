// Package service holds the management plane's domain rules.
//
// A rule is a fact about the bastion's data model that more than one tool has
// to agree on: "does this permission reach this asset", "does this grant hand
// anybody a usable account", "is this asset driven through a terminal".
//
// Before this package those rules lived inside the tool bodies. Two things
// were wrong with that. They could only be exercised by calling a tool
// against a live bastion — and the interesting case, a grant that names an
// account the asset does not have, is exactly the one a live bastion rarely
// has. And each rule was written out again wherever it was needed, so two
// tools could disagree about the same fact.
//
// What belongs here: rules, as pure functions over data.
//
// What does not: the data (that is internal/repository, which knows the API) and the
// shape of the answer (that is biz/handler, which knows the agent).
package service

import (
	"fmt"
	"github.com/oekit/pkg/slicex"
	"slices"
	"strings"

	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
)

// AllAccounts is the literal a permission uses to mean "every account of
// this asset".
//
// It is a bastion convention, not a name: the grant does not enumerate the
// accounts, it says "all of them". An EMPTY account list is NOT the same
// thing — it grants nobody.
const AllAccounts = "@ALL"

// CoversAsset reports whether a permission reaches an asset.
//
// A permission reaches an asset in two ways: it names the asset directly, or
// it names a node that contains it. The second case has to consider the
// node's SUBTREE — an asset is filed under a leaf node, and a permission on
// the parent reaches everything below it. Comparing node ids directly would
// miss every asset filed in a child node.
//
// descendantsOf answers "which nodes are below this one". Where that comes
// from is the caller's business; the rule itself only needs the shape.
func CoversAsset(perm, asset map[string]any, descendantsOf func(nodeID string) []string) bool {
	id := fmt.Sprint(asset["id"])
	if id == "" || id == "<nil>" {
		return false
	}
	for _, a := range jmsapi.AsSlice(perm["assets"]) {
		if m, ok := a.(map[string]any); ok && fmt.Sprint(m["id"]) == id {
			return true
		}
	}
	if descendantsOf == nil {
		return false
	}
	// The nodes the asset is filed in.
	assetNodes := map[string]bool{}
	for _, n := range jmsapi.AsSlice(asset["nodes"]) {
		if m, ok := n.(map[string]any); ok {
			assetNodes[fmt.Sprint(m["id"])] = true
		}
	}
	if len(assetNodes) == 0 {
		return false
	}
	for _, nref := range jmsapi.AsSlice(perm["nodes"]) {
		nm, ok := nref.(map[string]any)
		if !ok {
			continue
		}
		for _, nid := range descendantsOf(fmt.Sprint(nm["id"])) {
			if assetNodes[nid] {
				return true
			}
		}
	}
	return false
}

// Grant is what a permission hands to somebody, judged against the accounts
// the asset really has.
type Grant struct {
	// Accounts are the account names the grant hands out that the asset
	// really has. Empty when the grant hands out nothing usable.
	Accounts []string

	// Usable is whether the grant lets anybody in.
	Usable bool

	// Note says what the grant amounts to, in the words a reader needs.
	Note string
}

// JudgeGrant judges a grant against the accounts an asset really has.
//
// The three cases are the three ways a permission fails to open a door:
//
//   - it names no account at all — the login fails with
//     "没有可用的授权账号或终端协议";
//   - it names accounts the asset does not have — the grant can never be
//     used, and the reason is invisible unless somebody compares the two
//     lists;
//   - it names @ALL — every account of the asset, and every one of them
//     works.
func JudgeGrant(granted []string, assetAccounts []string) Grant {
	switch {
	case len(granted) == 0:
		return Grant{
			Note: "grants NO account: a login with this permission fails with " +
				"'没有可用的授权账号或终端协议'",
		}
	case Contains(granted, AllAccounts):
		usable := append([]string{}, assetAccounts...)
		slices.Sort(usable)
		return Grant{
			Accounts: usable,
			Usable:   true,
			Note:     "grants every account of this asset",
		}
	}
	have := map[string]bool{}
	for _, a := range assetAccounts {
		have[a] = true
	}
	usable := []string{}
	for _, want := range granted {
		if have[want] {
			usable = append(usable, want)
		}
	}
	slices.Sort(usable)
	if len(usable) == 0 {
		return Grant{
			Note: fmt.Sprintf("names account(s) %s that this asset does not have, "+
				"so the grant can never be used", strings.Join(granted, ", ")),
		}
	}
	return Grant{Accounts: usable, Usable: true}
}

// ExpectsTerminalAccess reports whether an asset is driven through a terminal.
//
// A Website or a Kubernetes asset is not: it has no terminal protocol and no
// login account, and neither is a problem. Reporting them as broken produced
// six false alarms on a bastion that had no fault at all.
//
// An unknown category is assumed to be a host: flagging a real host is
// cheap, silently skipping one is not.
func ExpectsTerminalAccess(asset map[string]any) bool {
	switch jmsapi.Label(asset, "category") {
	case "web", "cloud":
		return false
	}
	return true
}

// AccountState is the state of an asset's accounts.
type AccountState struct {
	// Disabled are the accounts that are switched off.
	Disabled []string

	// AllDisabled is true when every account is off. That is not a soft
	// warning — the machine is unreachable.
	AllDisabled bool

	// Total is how many accounts the asset has.
	Total int
}

// JudgeAccounts reads the state of an asset's accounts.
//
// It takes the account rows, not the asset, because the caller usually has
// them already: the accounts of an asset are read once and then judged.
func JudgeAccounts(accounts []map[string]any) AccountState {
	st := AccountState{Total: len(accounts)}
	for _, a := range accounts {
		if v, ok := a["is_active"].(bool); ok && !v {
			st.Disabled = append(st.Disabled, fmt.Sprint(a["username"]))
		}
	}
	slices.Sort(st.Disabled)
	st.AllDisabled = st.Total > 0 && len(st.Disabled) == st.Total
	return st
}

// Contains reports whether the list holds the value.
//
// It is slicex.Contains under a name the service's own callers use; the
// oekit family has one "is this in the list" primitive and this service
// should not have a second.
func Contains(list []string, want string) bool {
	return slicex.Contains(list, want)
}
