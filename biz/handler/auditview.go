// tools_audit_view.go answers the highest-frequency operational question in
// one call: "what is the state of this machine right now, and who may log
// into it?".
//
// The information needed for that answer is spread across five endpoints --
// the asset, its accounts, the permissions that cover it, the nodes it sits
// in, and the labels it carries. An agent that has to call all five pays
// five round trips and has to correlate the results itself, and the
// correlation is where mistakes happen: a permission that covers the asset
// but grants no account looks like access, and an asset with no protocol
// looks registered.
//
// So this is a read-only composition, not new data. Everything it reports
// comes from the same endpoints the individual tools read, which is exactly
// why it is safe to add: it cannot drift from them.
//
// What it adds on top of the raw records is the VERDICT -- the part that
// takes a human to look at five tables and say "so this one is broken".
package handler

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/yi-nology/jumpserver-mgmt/biz/model/jmsms"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oekit/pkg/convert"
	"github.com/yi-nology/jumpserver-kit/model/jms"
	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
	"github.com/yi-nology/jumpserver-mgmt/internal/repository"
	"github.com/yi-nology/jumpserver-mgmt/internal/service"
)

func RegisterAuditViewTools(r *reg.Registry, c *repository.Client) {
	type assetAuditArgs struct {
		Asset string `json:"asset" jsonschema:"asset address, name or UUID, e.g. 192.0.2.71"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_asset_audit",
		Description:  "One-call view of a machine: its platform, protocols, accounts, asset tree position, labels, who may log into it and with which accounts, plus the verdict on what is broken. Use it instead of jms_asset_get + jms_accounts_list + jms_permissions_list when the question is 'is this machine properly set up and who can reach it' -- this is one call and it says which of the three silent failures (no protocol, no account, a permission that grants no account) applies. Read-only.",
		OutputSchema: render.Schema[jmsms.AssetAuditResult](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args assetAuditArgs) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(args.Asset) == "" {
			return render.Failf("asset is required")
		}
		ids, _, err := c.ResolveAssets(ctx, []string{args.Asset})
		if err != nil {
			return render.Failf("%v", err)
		}
		assetID := ids[0]

		var asset map[string]any
		if err := c.Get(ctx, jmsapi.ResAssets, assetID, &asset); err != nil {
			return render.Failf("%v", err)
		}

		// Accounts of this asset.
		accountRows, err := c.List(ctx, jmsapi.ResAccounts)
		if err != nil {
			return render.Failf("%v", err)
		}
		accounts := []jmsms.AccountSummary{}
		// The account state is judged on the bastion's own rows: the answer is
		// built from the contract, but the judgement is still made on the
		// record as it came.
		rawAccounts := []map[string]any{}
		accountNames := []string{}
		for _, a := range accountRows {
			if fmt.Sprint(jmsapi.Nested(a, "asset", "id")) != assetID {
				continue
			}
			rawAccounts = append(rawAccounts, a)
			accountNames = append(accountNames, convert.AnyToStr(a["username"]))
			accounts = append(accounts, jmsms.AccountSummary{
				Username:      jmsapi.Str(a["username"]),
				Name:          jmsapi.FieldStr(a["name"]),
				SecretType:    jmsapi.FieldStr(jmsapi.Label(a, "secret_type")),
				Privileged:    jmsapi.FieldBool(a["privileged"]),
				IsActive:      jmsapi.FieldBool(a["is_active"]),
				Connectivity:  jmsapi.FieldStr(jmsapi.Label(a, "connectivity")),
				DateLastLogin: jmsapi.FieldStr(a["date_last_login"]),
			})
		}
		slices.SortFunc(accounts, func(a, b jmsms.AccountSummary) int {
			return strings.Compare(a.Username, b.Username)
		})

		// Permissions that cover this asset, and what they actually grant.
		permRows, err := c.List(ctx, jmsapi.ResPermissions)
		if err != nil {
			return render.Failf("%v", err)
		}
		// The asset tree is loaded ONCE. The coverage rule needs it for
		// every permission, and reading the whole tree per permission
		// turned one audit into a dozen identical API calls.
		tree, _ := c.LoadNodeTree(ctx)
		descendants := tree.Descendants

		grants := []jmsms.PermissionGrant{}
		for _, p := range permRows {
			// The LIST endpoint returns assets and users as null -- only the
			// counts come back -- so coverage has to be decided on the detail.
			// Reading the list would report "nobody can reach this asset" for
			// every asset on the bastion.
			var detail map[string]any
			if err := c.Get(ctx, jmsapi.ResPermissions, convert.AnyToStr(p["id"]), &detail); err != nil {
				continue
			}
			// Coverage has to consider the node SUBTREE: a permission on
			// /DEFAULT/studio reaches the assets filed under
			// /DEFAULT/studio/arm, and the asset only lists its own leaf
			// node. Comparing node ids directly would miss every asset
			// filed in a child node.
			// The rule itself is in biz/service, where it can be tested
			// without a bastion.
			if !service.CoversAsset(detail, asset, descendants) {
				continue
			}
			holders := []string{}
			for _, u := range jmsapi.AsSlice(detail["users"]) {
				if m, ok := u.(map[string]any); ok {
					holders = append(holders, convert.AnyToStr(m["name"]))
				}
			}
			for _, g := range jmsapi.AsSlice(detail["user_groups"]) {
				if m, ok := g.(map[string]any); ok {
					holders = append(holders, "group:"+convert.AnyToStr(m["name"]))
				}
			}
			slices.Sort(holders)
			accts := asStringSlice(detail["accounts"])
			judged := service.JudgeGrant(accts, accountNames)
			grants = append(grants, jmsms.PermissionGrant{
				Permission: convert.AnyToStr(p["name"]),
				Users:      holders,
				Accounts:   accts,
				Note:       jms.Opt(judged.Note),
			})
		}
		slices.SortFunc(grants, func(a, b jmsms.PermissionGrant) int { return strings.Compare(a.Permission, b.Permission) })

		// The tree position and the labels used to be read here and carried in
		// the answer's own asset block. The contract the tool declares holds
		// the machine in the SHARED asset shape, and that shape has no field
		// for them -- so there is nowhere to put them, and they are reported
		// to the repo owner as a gap in the contract instead of being read
		// into a hole.

		protocols := []string{}
		for _, p := range jmsapi.AsSlice(asset["protocols"]) {
			if m, ok := p.(map[string]any); ok {
				port := ""
				if v, ok := m["port"]; ok {
					port = convert.AnyToStr(v)
				}
				if port != "" && port != "0" {
					protocols = append(protocols, convert.AnyToStr(m["name"])+":"+port)
				} else {
					protocols = append(protocols, convert.AnyToStr(m["name"]))
				}
			}
		}
		slices.Sort(protocols)

		// The verdict: the three silent failures, in the order they bite.
		// Each one is a check with its own status and its own fix, so the
		// answer says what is wrong AND what to do about it.
		checks := []*jms.Check{}
		category := jmsapi.Label(asset, "category")
		if !service.ExpectsTerminalAccess(asset) {
			// A Website or Kubernetes asset is not driven through a terminal,
			// so "no protocol" and "no account" are not problems for it --
			// reporting them as broken produced six false alarms.
			checks = append(checks, &jms.Check{
				Name: "terminal_protocol", Status: service.OK,
				Detail: "not a terminal asset (category=" + category + "): no protocol is expected",
			})
			checks = append(checks, &jms.Check{
				Name: "accounts", Status: service.OK,
				Detail: "not a terminal asset (category=" + category + "): no account is expected",
			})
		} else {
			if len(protocols) == 0 {
				checks = append(checks, &jms.Check{
					Name: "terminal_protocol", Status: service.Fail,
					Detail: "no terminal protocol: the asset can never be connected to",
					Fix:    service.FixText("add a terminal protocol with jms_asset_update, e.g. protocols=[\"ssh\"]"),
				})
			} else {
				checks = append(checks, &jms.Check{
					Name: "terminal_protocol", Status: service.OK,
					Detail: "the asset declares " + strings.Join(protocols, ", "),
				})
			}
			if len(accounts) == 0 {
				checks = append(checks, &jms.Check{
					Name: "accounts", Status: service.Fail,
					Detail: "no account: a login fails with '没有可用的授权账号或终端协议'",
					Fix:    service.FixText("add an account with jms_account_create"),
				})
			} else {
				names := []string{}
				for _, a := range accounts {
					names = append(names, a.Username)
				}
				checks = append(checks, &jms.Check{
					Name: "accounts", Status: service.OK,
					Detail: fmt.Sprintf("%d account(s): %s", len(accounts), strings.Join(names, ", ")),
				})
			}
		}
		usableGrants := 0
		for _, g := range grants {
			if service.JudgeGrant(g.Accounts, accountNames).Usable {
				usableGrants++
			}
		}
		switch {
		case len(grants) == 0:
			checks = append(checks, &jms.Check{
				Name: "permissions", Status: service.Fail,
				Detail: "no permission covers this asset, so nobody can log into it",
				Fix: service.FixText("grant access with jms_permission_create " +
					"(all_accounts=true, or name the accounts explicitly)"),
			})
		case usableGrants == 0:
			checks = append(checks, &jms.Check{
				Name: "permissions", Status: service.Fail,
				Detail: "every permission covering this asset grants no usable account, " +
					"so nobody can actually log in",
				Fix: service.FixText("grant a real account with jms_permission_grant " +
					"(an empty account list grants nothing)"),
			})
		default:
			checks = append(checks, &jms.Check{
				Name: "permissions", Status: service.OK,
				Detail: fmt.Sprintf("%d permission(s) cover this asset, %d of them grant an account it really has",
					len(grants), usableGrants),
			})
		}
		state := service.JudgeAccounts(rawAccounts)
		disabled := state.Disabled
		switch {
		case len(accounts) == 0:
			// There is no account state to report when there is no account;
			// the "accounts" check already says that.
		case len(disabled) == 0:
			checks = append(checks, &jms.Check{
				Name: "account_state", Status: service.OK,
				Detail: "every account is active",
			})
		case state.AllDisabled:
			// Every account is off: this is not a soft warning, the machine
			// is unreachable.
			checks = append(checks, &jms.Check{
				Name: "account_state", Status: service.Fail,
				Detail: "every account is disabled (" + strings.Join(disabled, ", ") +
					"), so nobody can log in",
				Fix: service.FixText("enable an account with jms_account_update, or add one with jms_account_create"),
			})
		default:
			// Some accounts are off but others still work, so this is worth a
			// look rather than a blocker.
			checks = append(checks, &jms.Check{
				Name: "account_state", Status: service.Warn,
				Detail: "disabled account(s): " + strings.Join(disabled, ", "),
				Fix:    service.FixText("enable them with jms_account_update if they are still needed"),
			})
		}

		// Tree position and labels: where the machine sits and what it is
		// tagged with.
		nodes := []string{}
		for _, n := range jmsapi.AsSlice(asset["nodes"]) {
			nm, ok := n.(map[string]any)
			if !ok {
				continue
			}
			if name := jmsapi.Str(nm["name"]); name != "" {
				nodes = append(nodes, name)
			}
		}
		slices.Sort(nodes)
		labels := []string{}
		for _, l := range jmsapi.AsSlice(asset["labels"]) {
			lm, ok := l.(map[string]any)
			if !ok {
				continue
			}
			if name := jmsapi.Str(lm["name"]); name != "" {
				labels = append(labels, name)
			}
		}
		slices.Sort(labels)

		res := &jmsms.AssetAuditResult{
			// The machine, in the shared asset shape: the same one the asset
			// list and the execution plane's inventory hand out, so "which
			// machine is this" has one answer whichever server is asked.
			Asset: jmsms.AuditAsset{
				AssetSummary: jms.AssetSummary{
					ID:           jmsapi.Str(asset["id"]),
					Name:         jmsapi.Str(asset["name"]),
					Address:      jmsapi.Str(asset["address"]),
					Platform:     jmsapi.FieldStr(jmsapi.Nested(asset, "platform", "name")),
					Category:     jmsapi.FieldStr(category),
					Connectivity: jmsapi.FieldStr(jmsapi.Label(asset, "connectivity")),
					IsActive:     jmsapi.FieldBool(asset["is_active"]),
					Protocols:    protocols,
				},
				NodesDisplay:  nodes,
				Labels:        labels,
				Comment:       jmsapi.Str(asset["comment"]),
				Type:          jmsapi.Label(asset, "type"),
				DateVerified:  jmsapi.Str(asset["date_verified"]),
				DateLastLogin: jmsapi.Str(asset["date_last_login"]),
			},
			Accounts:    accounts,
			Permissions: grants,
		}
		res.Diagnosis = service.Diagnosis(checks,
			service.Verdict(checks, "this machine is set up correctly and can be logged into"),
			"nothing to fix: the machine is set up correctly and can be logged into")
		return render.Text(res)
	})
}
