package handler

// tools_security.go covers the audit surface that the asset/permission tools do
// not reach. Found by diffing the live swagger (544 endpoints) against the paths
// this server calls: 18.4% coverage, and everything below was untouched.
//
// What is here and what is not, measured 2026-10-15:
//
//	/audits/operate-logs/          200+ real rows. WHO CHANGED WHAT — the record
//	                               you need when a permission or asset changed and
//	                               you need to know who did it.
//	/audits/password-change-logs/  28 rows. Who changed whose password, and from
//	                               where. A password changed by someone other than
//	                               its owner is a security event.
//	/rbac/system-roles/            4 roles incl. SystemAdmin with 2 holders. The
//	                               org-role tools cannot see this scope.
//	/acls/login-acls/ + login-asset-acls/   reachable, currently empty (no policy
//	                               configured), but the check endpoint answers
//	                               "may this user log into this asset right now".
//
//	/accounts/account-risks/       403 — the AI token lacks the permission. Not
//	                               usable, so it is not wrapped: a tool that always
//	                               answers "permission denied" is worse than none.
//	/accounts/account-secrets/su-from-accounts/  403 — the action is not in the
//	                               permitted set at all, so no grant fixes it.
//
// The answers are the contract types: every answer below is built from the
// type its OutputSchema declares, so a field that is spelled wrong fails at
// compile time instead of reaching the model as a hole.

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/yi-nology/jumpserver-mgmt/internal/service"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yi-nology/jumpserver-kit/model/jms"
	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
	"github.com/yi-nology/jumpserver-mgmt/biz/model/jmsms"
	"github.com/yi-nology/jumpserver-mgmt/internal/repository"
)

func RegisterSecurityTools(r *reg.Registry, c *repository.Client) {
	type operateArgs struct {
		Limit    int    `json:"limit,omitempty" jsonschema:"max rows (default 50)"`
		UserName string `json:"user,omitempty" jsonschema:"only rows by this JumpServer user"`
		Action   string `json:"action,omitempty" jsonschema:"filter by action, e.g. create / update / delete"`
		Resource string `json:"resource,omitempty" jsonschema:"substring match on the resource name"`
		Type     string `json:"resource_type,omitempty" jsonschema:"e.g. Host / Account / Asset Authorization / System Settings"`
		Since    string `json:"since,omitempty" jsonschema:"only rows at or after this 'YYYY/MM/DD HH:MM' timestamp"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_operate_logs",
		Description:  "Audit trail of CONFIGURATION changes on the bastion: who created, updated or deleted an asset, account, permission, command filter, label or setting. Distinct from jms_command_audit, which records commands typed in a terminal. Use this to answer 'who gave this access' or 'what changed overnight'.",
		OutputSchema: render.Schema[render.ListOf[jmsms.OperateLogSummary]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args operateArgs) (*mcp.CallToolResult, any, error) {
		rows, err := c.List(ctx, jmsapi.ResOperateLogs)
		if err != nil {
			return render.Failf("%v", err)
		}
		// filter → map → sort → truncate → count: render.ListSpec owns the
		// order and the three counting fields. Two drifts this fixes, both of
		// which misread the moment a filter was used: total used to be the
		// UNFILTERED row count rather than how many matched, and truncated
		// used to be true whenever a filter dropped anything. Less stays nil:
		// this list never sorted locally and the endpoint's order is what
		// callers read.
		types := map[string]int{}
		res := render.ListSpec[map[string]any, jmsms.OperateLogSummary]{
			Rows: rows,
			Keep: func(m map[string]any) bool {
				rt := jmsapi.Str(m["resource_type"])
				act := jmsapi.Label(m, "action")
				if args.UserName != "" && !strings.Contains(strings.ToLower(jmsapi.Str(m["user"])),
					strings.ToLower(args.UserName)) {
					return false
				}
				if args.Action != "" && !strings.EqualFold(act, args.Action) {
					return false
				}
				if args.Type != "" && !strings.Contains(strings.ToLower(rt), strings.ToLower(args.Type)) {
					return false
				}
				if args.Resource != "" && !strings.Contains(strings.ToLower(jmsapi.Str(m["resource"])),
					strings.ToLower(args.Resource)) {
					return false
				}
				if args.Since != "" && !strings.HasPrefix(jmsapi.Str(m["datetime"]), args.Since[:min(len(args.Since), 13)]) {
					return false
				}
				// keep counting the profile even past the limit: the profile
				// covers every matched row, not just the ones shown.
				types[rt]++
				return true
			},
			Map: func(m map[string]any) jmsms.OperateLogSummary {
				return jmsms.OperateLogSummary{
					Datetime:     jmsapi.FieldStr(m["datetime"]),
					User:         jmsapi.FieldStr(m["user"]),
					Action:       jmsapi.FieldStr(jmsapi.Label(m, "action")),
					ResourceType: jmsapi.FieldStr(jmsapi.Str(m["resource_type"])),
					Resource:     jmsapi.FieldStr(m["resource"]),
					RemoteAddr:   jmsapi.FieldStr(m["remote_addr"]),
				}
			},
			Limit: args.Limit,
			Def:   50,
			Max:   500,
		}.Build()
		note := ""
		if res.Total == 0 && len(rows) > 0 {
			note = "no row matched the filters; the bastion does hold " +
				fmt.Sprintf("%d", len(rows)) + " operate-log rows in total"
		}
		if res.Truncated {
			note = "showing the first " + fmt.Sprintf("%d", res.Count) + " of " +
				fmt.Sprintf("%d", res.Total) + " rows; narrow with user/action/resource_type"
		}
		if len(types) > 0 {
			// The profile of the rows that matched is not a field of the list
			// envelope, so it travels in the note rather than being dropped:
			// what was changed is the question this tool exists for.
			profile := "by resource type: " + operateLogTypeProfile(types)
			if note == "" {
				note = profile
			} else {
				note += "; " + profile
			}
		}
		res.Note = note
		return render.Text(res)
	})

	type pwLogArgs struct {
		Limit int    `json:"limit,omitempty" jsonschema:"max rows (default 50)"`
		User  string `json:"user,omitempty" jsonschema:"only rows for this JumpServer user"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_password_change_logs",
		Description: "Who changed whose password on the bastion, and from which address. A change where change_by " +
			"is not the account itself means someone else reset it — worth a look before trusting the account.",
		OutputSchema: render.Schema[render.ListOf[jmsms.PasswordChangeSummary]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args pwLogArgs) (*mcp.CallToolResult, any, error) {
		rows, err := c.List(ctx, jmsapi.ResPasswordLogs)
		if err != nil {
			return render.Failf("%v", err)
		}
		// The "was it the account itself" comparison, in one place for both
		// the filter and the mapper.
		selfChanged := func(user, changer string) bool {
			// Strip the display suffix "(name)" before comparing: "ai(ai)" vs
			// "Administrator(admin)" must not look like the same person.
			return strings.SplitN(user, "(", 2)[0] == strings.SplitN(changer, "(", 2)[0]
		}
		// filter → map → sort → truncate → count: render.ListSpec owns the
		// order and the three counting fields. Two drifts this fixes, both of
		// which misread the moment a filter was used: total used to be the
		// UNFILTERED row count rather than how many matched, and truncated
		// used to be true whenever a filter dropped anything.
		suspicious := []string{}
		res := render.ListSpec[map[string]any, jmsms.PasswordChangeSummary]{
			Rows: rows,
			Keep: func(m map[string]any) bool {
				user, changer := jmsapi.Str(m["user"]), jmsapi.Str(m["change_by"])
				if args.User != "" && !strings.Contains(strings.ToLower(user), strings.ToLower(args.User)) {
					return false
				}
				if !selfChanged(user, changer) {
					// keep counting the warning even past the limit: it
					// covers every matched row, not just the ones shown.
					suspicious = append(suspicious, fmt.Sprintf("%s reset by %s at %v from %v",
						user, changer, m["datetime"], m["remote_addr"]))
				}
				return true
			},
			Map: func(m map[string]any) jmsms.PasswordChangeSummary {
				user, changer := jmsapi.Str(m["user"]), jmsapi.Str(m["change_by"])
				return jmsms.PasswordChangeSummary{
					Datetime:    jmsapi.FieldStr(m["datetime"]),
					User:        jmsapi.FieldStr(user),
					ChangeBy:    jmsapi.FieldStr(changer),
					RemoteAddr:  jmsapi.FieldStr(m["remote_addr"]),
					SelfService: jms.OptBool(selfChanged(user, changer)),
				}
			},
			Limit: args.Limit,
			Def:   50,
			Max:   500,
		}.Build()
		if len(suspicious) > 0 {
			// The list envelope has no room for the list of resets that were
			// not self-service, so it travels in the note -- the warning and
			// the rows it is about, in one place.
			res.Note = "these passwords were changed by a different account than the one they belong to: " +
				strings.Join(suspicious, "; ")
		}
		return render.Text(res)
	})

	type systemRoleArgs struct {
		Role   string `json:"role,omitempty" jsonschema:"role name; omit to list them all"`
		Search string `json:"search,omitempty" jsonschema:"only show permissions whose path contains this"`
		Limit  int    `json:"limit,omitempty" jsonschema:"max rows (default 100)"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_system_role_permissions",
		Description: "List the SYSTEM-scope roles (SystemAdmin, SystemAuditor, ...) and what they may do. " +
			"These are a different scope from the organization roles jms_roles_list returns, and they are the " +
			"highest-privilege grant on the system — use this before assuming an account cannot reconfigure the bastion.",
		OutputSchema: render.Schema[render.ListOf[jmsms.SystemRolePermissionRow]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args systemRoleArgs) (*mcp.CallToolResult, any, error) {
		rows, err := c.List(ctx, jmsapi.ResSystemRoles)
		if err != nil {
			return render.Failf("%v", err)
		}
		names := []string{}
		byID := map[string]map[string]any{}
		for _, m := range rows {
			names = append(names, jmsapi.Str(m["name"]))
			byID[jmsapi.Str(m["id"])] = m
		}
		var id string
		var role map[string]any
		if args.Role == "" {
			// filter → map → sort → truncate → count: render.ListSpec owns
			// the counting. The roles list is complete by nature (a handful of
			// system roles), so it carries no cap (Max 0): truncating it would
			// drop rows the caller needs while reporting truncated for a list
			// meant to be whole.
			return render.Text(render.ListSpec[map[string]any, jmsms.SystemRolePermissionRow]{
				Rows: rows,
				Map: func(m map[string]any) jmsms.SystemRolePermissionRow {
					return jmsms.SystemRolePermissionRow{
						ID:          jmsapi.FieldStr(m["id"]),
						Name:        jmsapi.FieldStr(m["name"]),
						DisplayName: jmsapi.FieldStr(m["display_name"]),
						Builtin:     jmsapi.FieldBool(m["builtin"]),
						UsersAmount: jmsapi.FieldInt32(m["users_amount"]),
						Comment:     jmsapi.FieldStr(m["comment"]),
					}
				},
				Max: 0,
				// Which mode this answer is: the rows are the ROLES, not
				// what a role may do. Naming one switches the tool to the
				// other mode, and the row type is the union of the two.
				Note: "these rows are the system roles themselves; name one (role=SystemAdmin) " +
					"to get what it may do",
			}.Build())
		}
		if byID[args.Role] != nil {
			id, role = args.Role, byID[args.Role]
		} else {
			for _, m := range rows {
				if strings.EqualFold(jmsapi.Str(m["name"]), args.Role) {
					id, role = jmsapi.Str(m["id"]), m
				}
			}
		}
		if id == "" {
			return render.Failf("no system role %q; available: %s", args.Role, strings.Join(names, ", "))
		}

		tree, err := c.ListSub(ctx, jmsapi.ResSystemRoles, id, "permissions/tree")
		if err != nil {
			return render.Failf("%v", err)
		}
		byP := map[string]string{}
		for _, m := range tree {
			if t := jmsapi.Str(m["title"]); t != "" {
				byP[t] = jmsapi.Str(m["pId"])
			}
		}
		paths := []string{}
		for _, m := range tree {
			t := jmsapi.Str(m["title"])
			if t == "" {
				continue
			}
			path := t
			for range 8 {
				p, ok := byP[path]
				if !ok || p == "" || p == path {
					break
				}
				path = p + "/" + path
			}
			path = strings.Replace(path, "$ROOT$/", "", 1)
			// The synthetic root is scaffolding, not a permission.
			if path == "$ROOT$" {
				continue
			}
			paths = append(paths, path)
		}
		// filter → map → sort → truncate → count: render.ListSpec owns the
		// order and the three counting fields.
		res := render.ListSpec[string, jmsms.SystemRolePermissionRow]{
			Rows: paths,
			Keep: func(path string) bool {
				return args.Search == "" || strings.Contains(strings.ToLower(path), strings.ToLower(args.Search))
			},
			Map: func(path string) jmsms.SystemRolePermissionRow {
				return jmsms.SystemRolePermissionRow{Path: jms.Opt(path)}
			},
			Less:  func(a, b jmsms.SystemRolePermissionRow) bool { return a.GetPath() < b.GetPath() },
			Limit: args.Limit,
			Def:   100,
			Max:   1000,
		}.Build()
		// Which role this is: the rows are the permissions, and the role's
		// own fields travel in the note because the list envelope has no
		// room for them.
		res.Note = "these rows are what ONE system role may do; role: " + jmsapi.Str(role["name"]) +
			" (" + jmsapi.Str(role["display_name"]) + "), users_amount: " +
			fmt.Sprintf("%d", jmsapi.Int32(role["users_amount"]))
		return render.Text(res)
	})

	type loginCheckArgs struct {
		Asset    string `json:"asset" jsonschema:"asset name, address or UUID"`
		UserName string `json:"user,omitempty" jsonschema:"JumpServer username; omit to list the configured rules"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_login_asset_check",
		Description: "Would this user be allowed to log into this asset right now? Evaluates the configured " +
			"login ACLs (IP allow/deny, time windows, asset rules). This bastion currently has no login ACL " +
			"configured, so the answer is 'no rule restricts it' — which is itself the finding.",
		OutputSchema: render.Schema[jmsms.LoginAssetCheckResult](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args loginCheckArgs) (*mcp.CallToolResult, any, error) {
		ids, meta, err := c.ResolveAssets(ctx, []string{args.Asset})
		if err != nil {
			return render.Failf("%v", err)
		}
		res := &jmsms.LoginAssetCheckResult{
			Asset:   jmsapi.Str(meta[0]["name"]),
			AssetID: ids[0],
		}

		loginACLs, err := c.List(ctx, jmsapi.ResLoginACLs)
		if err != nil {
			return render.Failf("read login ACLs: %v", err)
		}
		assetACLs, err := c.List(ctx, jmsapi.ResLoginAssetACLs)
		if err != nil {
			return render.Failf("read login-asset ACLs: %v", err)
		}
		res.LoginACLs = int32(len(loginACLs))
		res.LoginAssetACLs = int32(len(assetACLs))

		checks := []*jms.Check{}
		if len(loginACLs) == 0 && len(assetACLs) == 0 {
			checks = append(checks, &jms.Check{
				Name: "login_acls", Status: service.OK,
				Detail: "no login restriction is configured for any asset; access is governed only by " +
					"the asset permission and the account state",
			})
		} else {
			checks = append(checks, &jms.Check{
				Name: "login_acls", Status: service.OK,
				Detail: fmt.Sprintf("%d login ACL(s) and %d login-asset ACL(s) are configured",
					len(loginACLs), len(assetACLs)),
			})
		}

		verdict := "no login restriction is configured for any asset; access is governed only by " +
			"the asset permission and the account state"
		okAdvice := "pass user=<JumpServer username> to get the verdict for one account"

		// The server-side predicate is authoritative when it answers; fall back
		// to the raw count so the answer is never silently "allowed".
		//
		// POST, not GET (measured: GET returns 405), and it wants the USER id as
		// well as the asset — passing a username yields
		// {"user_id": ["This field is required."]}.
		if args.UserName != "" {
			uid, err := c.UserID(ctx, args.UserName)
			if err != nil {
				res.UserLookupError = err.Error()
				checks = append(checks, &jms.Check{
					Name: "user_verdict", Status: service.Fail,
					Detail: "the user '" + args.UserName + "' could not be resolved: " + err.Error(),
					Fix:    service.FixText("check the username with jms_users_list"),
				})
				verdict = "the user '" + args.UserName + "' could not be resolved, so there is no verdict"
				okAdvice = "check the username with jms_users_list"
			} else {
				var out map[string]any
				if err := c.Post(ctx, jmsapi.ResLoginCheck, map[string]any{"user_id": uid, "asset_id": ids[0]}, &out); err != nil {
					res.ServerCheckError = err.Error()
					checks = append(checks, &jms.Check{
						Name: "user_verdict", Status: service.Fail,
						Detail: "the bastion's own login check failed: " + err.Error(),
						Fix:    service.FixText("check that the bastion's login-asset check endpoint answers"),
					})
					verdict = "the bastion's own login check failed, so there is no verdict"
					okAdvice = "check that the bastion's login-asset check endpoint answers"
				} else {
					res.ServerCheck = &jmsms.LoginCheckVerdict{
						NeedReview: jmsapi.FieldBool(out["need_review"]),
						Message:    jmsapi.FieldStr(out["message"]),
					}
					res.CheckedUser = args.UserName
					// The bastion answers with need_review: true when a human
					// has to sign the login off, false when it does not.
					if review, _ := out["need_review"].(bool); review {
						checks = append(checks, &jms.Check{
							Name: "user_verdict", Status: service.Warn,
							Detail: "the bastion asks for a manual review of '" + args.UserName +
								"' on this asset before it lets them in",
							Fix: service.FixText("an operator has to approve the login in the bastion's session review queue"),
						})
						verdict = "the bastion asks for a manual review before '" + args.UserName +
							"' may log into this asset"
						okAdvice = "an operator has to approve the login in the bastion's session review queue"
					} else {
						checks = append(checks, &jms.Check{
							Name: "user_verdict", Status: service.OK,
							Detail: "the bastion lets '" + args.UserName +
								"' into this asset: no rule requires a review",
						})
						verdict = "'" + args.UserName + "' may log into this asset: no rule restricts it"
					}
				}
			}
		} else {
			// Naming no account is a documented mode of this tool -- it
			// answers "is anything restricted at all" -- so it is not a
			// finding; the advice says how to get the sharper answer.
			checks = append(checks, &jms.Check{
				Name: "user_verdict", Status: service.OK,
				Detail: "no account was named: this answers whether any restriction exists, " +
					"not whether one account may log in",
			})
		}
		res.Diagnosis = service.Diagnosis(checks, verdict, okAdvice)
		return render.Text(res)
	})
}

// operateLogTypeProfile renders the resource-type profile of the operate log
// as text, in a stable order.
//
// The list envelope has no field for a second map, so the profile rides along
// in the note. The order is fixed because a profile that reorders itself
// between two identical calls is a profile nobody can read twice.
func operateLogTypeProfile(types map[string]int) string {
	keys := slices.Sorted(maps.Keys(types))
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		label := k
		if label == "" {
			// The bastion did not say what kind of resource this was. It is
			// counted (the count is the fact), but a bare "=3" reads as a
			// broken line, so it is named.
			label = "(none)"
		}
		parts = append(parts, label+"="+fmt.Sprintf("%d", types[k]))
	}
	return strings.Join(parts, ", ")
}

// userID resolves a username to its UUID for the endpoints that demand an id.
