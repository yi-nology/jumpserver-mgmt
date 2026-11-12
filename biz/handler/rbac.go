// tools_rbac.go answers "what CAN be permitted, and who holds what".
//
// Two views of the same registry, and they are not the same question:
//
//   - jms_rbac_permissions is the CATALOGUE: every permission the
//     installation defines (265 in org scope, 385 in system scope on the
//     v5 machine), one row per app.action capability such as add_account.
//     This is what "权限全景" means -- the panorama of what exists.
//   - jms_rbac_role_matrix crosses roles WITH permissions: for each
//     permission, which roles hold it; for each role, how many it holds.
//     This is the least-privilege review view: "who can do this", "why does
//     that role have so much", "this permission is held by nobody".
//
// ⚠️ These are RBAC permissions, not asset permissions. The names collide
// on purpose-ish and the difference matters:
//
//   - /rbac/permissions/ rows are CAPABILITIES ("Can add Account",
//     codename add_account) -- the verbs of the bastion itself;
//   - /perms/asset-permissions/ rows (jms_permissions_list) are GRANTS
//     ("who may reach which machines with which accounts") -- the nouns of
//     access.
//
// Asking "who can add accounts" here and "who can reach 192.0.2.41" there
// are two different questions; answering one with the other's rows is
// plausible-sounding nonsense.
//
// ⚠️ The matrix costs one request per role. That is not an optimisation
// oversight: /rbac/permissions/?role=<id> is the only endpoint that says
// what a role holds, and it answers in CATALOGUE rows, which is exactly
// what the join needs. Seven roles on the v5 machine = seven walks.
package handler

import (
	"cmp"
	"context"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oekit/pkg/slicex"
	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
	"github.com/yi-nology/jumpserver-mgmt/biz/model/jmsms"
	"github.com/yi-nology/jumpserver-mgmt/internal/repository"
)

func RegisterRBACTools(r *reg.Registry, c *repository.Client) {
	type rbacPermissionsArgs struct {
		Scope    string `json:"scope,omitempty" jsonschema:"which catalogue: org (default) or system; org is the smaller set (265 vs 385 rows on the v5 machine)"`
		Codename string `json:"codename,omitempty" jsonschema:"exact capability code filter, e.g. add_account"`
		Search   string `json:"search,omitempty" jsonschema:"substring filter over codename / name / app_label / model, e.g. 'account'"`
		Limit    int    `json:"limit,omitempty" jsonschema:"max rows (default 100)"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_rbac_permissions",
		Description: "List the RBAC permission catalogue: every capability the bastion defines, one row per " +
			"app.action permission (e.g. 'add_account' under accounts.account). This is the PANORAMA of what " +
			"can be granted -- use jms_rbac_role_matrix to see which roles hold each, and jms_role_permissions " +
			"to see one role's set. NOT the same as jms_permissions_list, which lists asset access grants " +
			"('who may reach which machines'), not capabilities.",
		OutputSchema: render.Schema[render.ListOf[jmsms.RBACPermission]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args rbacPermissionsArgs) (*mcp.CallToolResult, any, error) {
		scope := strings.ToLower(strings.TrimSpace(args.Scope))
		if scope == "" {
			scope = "org"
		}
		if scope != "org" && scope != "system" {
			return render.Failf("scope must be org or system, got %q", args.Scope)
		}
		// The catalogue is read whole and narrowed HERE. The endpoint does
		// declare a codename filter, but it is an EXACT match while an agent
		// naturally greps a substring -- and an exact filter that matches
		// nothing reads as "no such permission", which is a different claim
		// from "no permission whose name contains this". One local filter
		// keeps the two questions distinguishable.
		rows, serverTotal, err := c.ListCounted(ctx, jmsapi.ResRBACPermissions,
			map[string][]string{"scope": {scope}})
		if err != nil {
			return render.Err(err)
		}

		needle := strings.ToLower(strings.TrimSpace(args.Search))
		codename := strings.ToLower(strings.TrimSpace(args.Codename))
		// filter → map → sort → truncate → count: render.ListSpec owns the
		// counting. Less stays nil: the catalogue answers in its own order
		// and this list never sorted locally.
		res := render.ListSpec[map[string]any, jmsms.RBACPermission]{
			Rows: rows,
			Keep: func(m map[string]any) bool {
				cn := jmsapi.Str(m["codename"])
				if codename != "" && strings.ToLower(cn) != codename {
					return false
				}
				if needle != "" {
					// The same fields the mapped row carries (AppLabel/Model
					// read through the nested content_type).
					hay := strings.ToLower(cn + " " + jmsapi.Str(m["name"]) + " " +
						jmsapi.Str(jmsapi.FieldStr(jmsapi.Nested(m, "content_type", "app_label"))) + " " +
						jmsapi.Str(jmsapi.FieldStr(jmsapi.Nested(m, "content_type", "model"))))
					if !strings.Contains(hay, needle) {
						return false
					}
				}
				return true
			},
			Map: func(m map[string]any) jmsms.RBACPermission {
				item := jmsms.RBACPermission{
					ID:   jmsapi.FieldStr(m["id"]),
					Name: jmsapi.FieldStr(m["name"]),
					// content_type is a nested object
					// {"id":30,"app_label":"accounts","model":"account"} --
					// reading it as a flat field would yield "" and an entry
					// that says "some capability somewhere".
					AppLabel: jmsapi.FieldStr(jmsapi.Nested(m, "content_type", "app_label")),
					Model:    jmsapi.FieldStr(jmsapi.Nested(m, "content_type", "model")),
				}
				cn := jmsapi.Str(m["codename"])
				item.Codename = jmsapi.FieldStr(cn)
				return item
			},
			Limit: args.Limit,
			Def:   100,
			Max:   1000,
		}.Build()
		note := ""
		if res.Total == 0 {
			note = "no permission matched; the catalogue holds " + strconv.Itoa(serverTotal) + " rows in " + scope + " scope"
		} else if res.Truncated {
			note = "showing " + strconv.Itoa(int(res.Count)) + " of " + strconv.Itoa(int(res.Total)) + " matches; raise limit to see the rest"
		}
		res.Note = note
		return render.Text(res)
	})

	type rbacMatrixArgs struct {
		Scope  string `json:"scope,omitempty" jsonschema:"which roles to cross: all (default), org or system"`
		Search string `json:"search,omitempty" jsonschema:"substring filter over the permission rows (codename / name / app_label / model)"`
		Limit  int    `json:"limit,omitempty" jsonschema:"max permission rows (default 100)"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_rbac_role_matrix",
		Description: "Cross every role with the permission catalogue: for each permission, WHICH roles hold it " +
			"(holders), and per role how many it holds. Use it for access review -- 'who can do this', 'why does " +
			"that role hold so much', 'this permission is held by nobody' -- before granting or trimming a role. " +
			"Costs one request per role. Roles include both scopes (org roles and system roles).",
		OutputSchema: render.Schema[jmsms.RBACRoleMatrix](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args rbacMatrixArgs) (*mcp.CallToolResult, any, error) {
		scope := strings.ToLower(strings.TrimSpace(args.Scope))
		if scope == "" {
			scope = "all"
		}
		if scope != "all" && scope != "org" && scope != "system" {
			return render.Failf("scope must be all, org or system, got %q", args.Scope)
		}
		limit := repository.NormLimit(args.Limit, 100, 1000)

		type roleRef struct {
			id, name, scope string
			builtin         bool
			usersAmount     int32
		}
		var roles []roleRef
		fetchRoles := func(resource jmsapi.Resource, wantScope string) error {
			rows, _, err := c.ListCounted(ctx, resource, nil)
			if err != nil {
				return err
			}
			for _, m := range rows {
				builtin := false
				if b := jmsapi.FieldBool(m["builtin"]); b != nil {
					builtin = *b
				}
				roles = append(roles, roleRef{
					id:          jmsapi.Str(m["id"]),
					name:        jmsapi.Str(m["name"]),
					scope:       wantScope,
					builtin:     builtin,
					usersAmount: jmsapi.Int32(m["users_amount"]),
				})
			}
			return nil
		}
		if scope == "all" || scope == "org" {
			if err := fetchRoles(jmsapi.ResOrgRoles, "org"); err != nil {
				return render.Err(err)
			}
		}
		if scope == "all" || scope == "system" {
			if err := fetchRoles(jmsapi.ResSystemRoles, "system"); err != nil {
				return render.Err(err)
			}
		}

		// The catalogue rows come back with each role's fetch, so the join
		// does not need a separate catalogue request: a permission is a row
		// wherever it appears, and holders accumulate across roles.
		// A permission NO role holds would be missing from the matrix --
		// so the catalogue is ALSO read once per involved scope and merged
		// in, dead rows included. "Held by nobody" is a finding, not noise.
		type entry struct {
			appLabel, model, codename, name string
			holders                         []string
		}
		byID := map[string]*entry{}
		catalogue := func(scopeName string) error {
			rows, _, err := c.ListCounted(ctx, jmsapi.ResRBACPermissions,
				url.Values{"scope": {scopeName}})
			if err != nil {
				return err
			}
			for _, m := range rows {
				id := jmsapi.Str(m["id"])
				if _, ok := byID[id]; ok {
					continue
				}
				byID[id] = &entry{
					appLabel: jmsapi.Str(jmsapi.Nested(m, "content_type", "app_label")),
					model:    jmsapi.Str(jmsapi.Nested(m, "content_type", "model")),
					codename: jmsapi.Str(m["codename"]),
					name:     jmsapi.Str(m["name"]),
				}
			}
			return nil
		}
		if scope == "all" || scope == "org" {
			if err := catalogue("org"); err != nil {
				return render.Err(err)
			}
		}
		if scope == "all" || scope == "system" {
			if err := catalogue("system"); err != nil {
				return render.Err(err)
			}
		}

		// `list<struct>` generates pointer slices ([]*T) — the contract's
		// shape is what the generator decided, not what the code wishes.
		matrixRoles := []*jmsms.RBACMatrixRole{}
		for _, rr := range roles {
			rows, _, err := c.ListCounted(ctx, jmsapi.ResRBACPermissions,
				url.Values{"role": {rr.id}})
			if err != nil {
				return render.Err(err)
			}
			permIDs := map[string]bool{}
			for _, m := range rows {
				id := jmsapi.Str(m["id"])
				permIDs[id] = true
				e, ok := byID[id]
				if !ok {
					// A role holds something the catalogue walk missed
					// (a permission added between the two requests). Keep
					// it: dropping it would UNDERSTATE what the role does.
					e = &entry{
						appLabel: jmsapi.Str(jmsapi.Nested(m, "content_type", "app_label")),
						model:    jmsapi.Str(jmsapi.Nested(m, "content_type", "model")),
						codename: jmsapi.Str(m["codename"]),
						name:     jmsapi.Str(m["name"]),
					}
					byID[id] = e
				}
				// The holder is the role's name qualified by its scope. An
				// org role and a system role can share a name ("Admin" in
				// both scopes); keying the dedup on the bare name merged them
				// into one row and silently DROPPED one holder. name@scope
				// keeps the two distinct — the matrix separates the roles by
				// scope, so the holders line must too.
				holder := rr.name + "@" + rr.scope
				if !slicex.Contains(e.holders, holder) {
					e.holders = append(e.holders, holder)
				}
			}
			b := rr.builtin
			ua := rr.usersAmount
			matrixRoles = append(matrixRoles, &jmsms.RBACMatrixRole{
				ID:              jmsapi.FieldStr(rr.id),
				Name:            jmsapi.FieldStr(rr.name),
				Scope:           jmsapi.FieldStr(rr.scope),
				Builtin:         &b,
				UsersAmount:     &ua,
				PermissionCount: jmsapi.FieldInt32(len(permIDs)),
			})
		}

		needle := strings.ToLower(strings.TrimSpace(args.Search))
		entries := []*jmsms.RBACMatrixEntry{}
		matched := 0
		// Stable order: by app_label, model, codename. A matrix whose row
		// order changes between calls cannot be diffed, and diffing two
		// reviews is what an access review IS.
		all := make([]*entry, 0, len(byID))
		for _, e := range byID {
			all = append(all, e)
		}
		slices.SortFunc(all, func(a, b *entry) int {
			if c := cmp.Compare(a.appLabel, b.appLabel); c != 0 {
				return c
			}
			if c := cmp.Compare(a.model, b.model); c != 0 {
				return c
			}
			return cmp.Compare(a.codename, b.codename)
		})
		for _, e := range all {
			if needle != "" {
				hay := strings.ToLower(e.codename + " " + e.name + " " + e.appLabel + " " + e.model)
				if !strings.Contains(hay, needle) {
					continue
				}
			}
			matched++
			if len(entries) < limit {
				holders := e.holders
				if holders == nil {
					holders = []string{}
				}
				entries = append(entries, &jmsms.RBACMatrixEntry{
					AppLabel: jmsapi.FieldStr(e.appLabel),
					Model:    jmsapi.FieldStr(e.model),
					Codename: jmsapi.FieldStr(e.codename),
					Name:     jmsapi.FieldStr(e.name),
					Holders:  holders,
				})
			}
		}
		note := ""
		if matched == 0 {
			note = "no permission row matched the filter"
		} else if len(entries) < matched {
			note = "showing " + strconv.Itoa(len(entries)) + " of " + strconv.Itoa(matched) + " permission rows; raise limit to see the rest"
		}
		truncated := len(entries) < matched
		return render.Text(jmsms.RBACRoleMatrix{
			Roles:     matrixRoles,
			Entries:   entries,
			Count:     jmsapi.FieldInt32(len(entries)),
			Total:     jmsapi.FieldInt32(matched),
			Truncated: &truncated,
			Note:      jmsapi.FieldStr(note),
		})
	})
}
