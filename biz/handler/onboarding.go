// tools_onboarding.go closes the gaps that made the bastion unusable for its
// main job: getting a machine in, and answering "who can reach what".
//
// What was missing (measured against the live API on 2026-10-25):
//
//	jms_asset_create        existed
//	jms_account_create      MISSING -> an asset with no account can never be
//	                                   connected to, and the only way to add one
//	                                   was a hand-written POST
//	jms_user_create         MISSING -> the bastion had no way to make a human
//	                                   account at all
//	jms_user_password_set   MISSING -> jms_password_change_logs could REPORT a
//	                                   password change but nothing could make one
//	jms_permission_get      MISSING -> jms_permissions_list returns counts only,
//	                                   so "who is in this permission" was
//	                                   unanswerable without raw REST
//	jms_user_access         MISSING -> "what can this user reach" needed
//	                                   /perms/users/{uuid}/assets/ by hand
//
// API facts encoded here, each verified against the live bastion rather than
// read off the OpenAPI schema:
//
//   - User creation REQUIRES an email. Omit it and the API answers
//     400 {"email":["This field is required."]} -- and no user is created.
//   - Account creation takes the asset as its UUID string, not as an object.
//   - Account.secret_type is a labelled choice: {"value":"password"}. Passing
//     the bare string "password" is silently wrong.
//   - Secrets are write-only. The bastion never returns them again, so a
//     successful create can only be verified by reading the record back.
package handler

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oekit/pkg/slicex"
	"github.com/yi-nology/jumpserver-kit/model/jms"
	"github.com/yi-nology/jumpserver-kit/pkg/audit"
	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
	"github.com/yi-nology/jumpserver-mgmt/biz/model/jmsms"
	"github.com/yi-nology/jumpserver-mgmt/internal/repository"
	"github.com/yi-nology/jumpserver-mgmt/internal/service"
)

func RegisterOnboardingTools(r *reg.Registry, c *repository.Client) {
	RegisterAccountWriteTools(r, c)
	RegisterUserWriteTools(r, c)
	RegisterAccessReviewTools(r, c)
	RegisterDoctorTool(r, c)
}

// ---------------------------------------------------------------- accounts

func RegisterAccountWriteTools(r *reg.Registry, c *repository.Client) {
	type accountCreateArgs struct {
		Asset      string `json:"asset" jsonschema:"asset address, name or UUID to attach the account to"`
		Account    string `json:"account" jsonschema:"login name on that host, e.g. opsuser"`
		Secret     string `json:"secret,omitempty" jsonschema:"the password for this account. Required for secret_type=password. Write-only: the bastion never returns it again."`
		Name       string `json:"name,omitempty" jsonschema:"display name for the account record; defaults to the username"`
		SecretType string `json:"secret_type,omitempty" jsonschema:"password (default) or ssh_key"`
		Privileged bool   `json:"privileged,omitempty" jsonschema:"mark the account as privileged (sudo-capable)"`
		Active     *bool  `json:"active,omitempty" jsonschema:"create it enabled (default) or disabled"`
		Confirm    bool   `json:"confirm" jsonschema:"must be true; this writes a credential to the bastion"`
	}

	reg.Add(r, &mcp.Tool{
		Name: "jms_account_create",
		Description: "Add a login account to an asset so the bastion can actually connect to it. " +
			"Use this when registering a machine: an asset with no account fails at login with " +
			"'no authorized account or terminal protocol', and this is the tool that fixes it. " +
			"Secrets are write-only -- the bastion will never show them again, so a created account " +
			"can only be verified by reading the record back.",
		OutputSchema: render.Schema[jmsms.AccountCreated](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args accountCreateArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to create the account on the bastion")
		}
		if strings.TrimSpace(args.Asset) == "" || strings.TrimSpace(args.Account) == "" {
			return render.Failf("asset and account are required")
		}

		secretType := strings.TrimSpace(args.SecretType)
		if secretType == "" {
			secretType = "password"
		}
		switch secretType {
		case "password", "ssh_key":
		default:
			return render.Failf("secret_type must be 'password' or 'ssh_key', got %q", secretType)
		}
		if secretType == "password" && strings.TrimSpace(args.Secret) == "" {
			return render.Failf("secret is required for secret_type=password: an account with no usable secret " +
				"makes the asset show up as an authentication error on every connect")
		}

		ids, meta, err := c.ResolveAssets(ctx, []string{args.Asset})
		if err != nil {
			return render.Failf("%v", err)
		}
		assetID := ids[0]

		// A second account with the same username is the classic "why does the
		// bastion pick the wrong credential" trap, so refuse before writing.
		if _, err := c.AccountID(ctx, assetID, args.Account); err == nil {
			return render.Failf("asset %v already has an account named %q; use jms_account_update to change "+
				"its secret, or jms_account_delete to remove it", meta[0]["name"], args.Account)
		}

		name := strings.TrimSpace(args.Name)
		if name == "" {
			name = args.Account
		}
		active := true
		if args.Active != nil {
			active = *args.Active
		}

		body := map[string]any{
			"name":        name,
			"username":    args.Account,
			"secret":      args.Secret,
			"secret_type": map[string]any{"value": secretType},
			"asset":       assetID,
			"privileged":  args.Privileged,
			"is_active":   active,
		}
		var out map[string]any
		if err := c.Post(ctx, jmsapi.ResAccounts, body, &out); err != nil {
			return render.Failf("%v", err)
		}

		// Read back: a create that answered 201 is not proof that the record is
		// usable, and the secret can never be re-read to prove it.
		//
		// The fields are read with the protocol helpers, not with
		// convert.AnyToStr: a field the bastion did not send has to stay
		// absent, because "<nil>" is a string that looks like a value.
		id := jmsapi.Str(out["id"])
		var back map[string]any
		if err := c.Get(ctx, jmsapi.ResAccounts, id, &back); err != nil {
			return render.Failf("account was created (id %s) but reading it back failed: %v", id, err)
		}
		return render.Text(&jmsms.AccountCreated{
			ID:           id,
			Name:         jmsapi.FieldStr(back["name"]),
			Username:     jmsapi.FieldStr(back["username"]),
			Asset:        jmsapi.FieldStr(jmsapi.Nested(back, "asset", "name")),
			Address:      jmsapi.FieldStr(jmsapi.Nested(back, "asset", "address")),
			SecretType:   jms.Opt(jmsapi.Label(back, "secret_type")),
			Privileged:   jms.OptBool(back["privileged"] == true),
			IsActive:     jms.OptBool(back["is_active"] == true),
			Connectivity: jms.Opt(jmsapi.Label(back, "connectivity")),
			Verified:     jms.OptBool(true),
			Note:         jms.Opt("the secret is write-only; it cannot be read back from the bastion"),
		})
	})
}

// ---------------------------------------------------------------- users

func RegisterUserWriteTools(r *reg.Registry, c *repository.Client) {
	type userCreateArgs struct {
		User     string `json:"user" jsonschema:"login name, unique on the bastion"`
		Name     string `json:"name,omitempty" jsonschema:"display name; defaults to the username"`
		Password string `json:"password,omitempty" jsonschema:"initial password. Leave empty and one is generated and shown once in the result."`
		Email    string `json:"email" jsonschema:"REQUIRED by the API (v4 and v5 alike): creating a user without it is rejected with 400 {\"email\":[\"This field is required.\"]}"`
		Active   *bool  `json:"active,omitempty" jsonschema:"create it enabled (default) or disabled"`
		Confirm  bool   `json:"confirm" jsonschema:"must be true; this creates a login on the bastion"`
	}

	reg.Add(r, &mcp.Tool{
		Name: "jms_user_create",
		Description: "Create a JumpServer login so a person (or an automation account) can use the bastion. " +
			"Two API constraints are handled here: an email address is mandatory -- omitting it is rejected " +
			"with a bare 400 -- and org roles are NOT granted here, they come from an asset permission " +
			"(jms_permission_create). If no password is supplied one is generated and returned ONCE; " +
			"pass an explicit password when the caller needs to know it.",
		OutputSchema: render.Schema[jmsms.UserCreated](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args userCreateArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to create the user")
		}
		if strings.TrimSpace(args.User) == "" {
			return render.Failf("user is required")
		}
		if strings.TrimSpace(args.Email) == "" {
			return render.Failf("email is required: the API rejects a user without one with 400 " +
				"{\"email\":[\"This field is required.\"]}, and the error names no other cause")
		}

		password := args.Password
		generated := false
		if strings.TrimSpace(password) == "" {
			password = generatePassword(20)
			generated = true
		}
		name := strings.TrimSpace(args.Name)
		if name == "" {
			name = args.User
		}
		active := true
		if args.Active != nil {
			active = *args.Active
		}

		body := map[string]any{
			"username":  args.User,
			"name":      name,
			"password":  password,
			"email":     args.Email,
			"is_active": active,
		}
		var out map[string]any
		if err := c.Post(ctx, jmsapi.ResUsers, body, &out); err != nil {
			return render.Failf("%v", err)
		}

		id := jmsapi.Str(out["id"])
		var back map[string]any
		if err := c.Get(ctx, jmsapi.ResUsers, id, &back); err != nil {
			return render.Failf("user was created (id %s) but reading it back failed: %v", id, err)
		}
		res := &jmsms.UserCreated{
			ID:                 id,
			Username:           jmsapi.FieldStr(back["username"]),
			Name:               jmsapi.FieldStr(back["name"]),
			Email:              jmsapi.FieldStr(back["email"]),
			IsActive:           jms.OptBool(back["is_active"] == true),
			IsSuperuser:        jms.OptBool(back["is_superuser"] == true),
			NeedUpdatePassword: jms.OptBool(back["need_update_password"] == true),
			Verified:           jms.OptBool(true),
		}
		if generated {
			res.GeneratedPassword = jms.Opt(password)
			res.Warning = jms.Opt("this password was generated and is shown only in this response; " +
				"it cannot be read back from the bastion")
		}
		res.NextStep = jms.Opt("the user still has no asset access: grant it with jms_permission_create, " +
			"and register an RSA SSH key with jms_user_sshkey_add if it will log in over koko")
		return render.Text(res)
	})

	type userPasswordArgs struct {
		User     string `json:"user" jsonschema:"the JumpServer account to change"`
		Password string `json:"password" jsonschema:"the new password"`
		Confirm  bool   `json:"confirm" jsonschema:"must be true; this changes a credential"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_user_password_set",
		Description: "Set a JumpServer user's password. Use it after a reset or when an account is locked out. " +
			"The password is write-only, so the call is confirmed by comparing the user's " +
			"date_password_last_updated before and after -- a 200 on its own proves nothing.",
		OutputSchema: render.Schema[jmsms.PasswordSet](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args userPasswordArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to change the password")
		}
		if strings.TrimSpace(args.User) == "" || args.Password == "" {
			return render.Failf("user and password are required")
		}
		id, err := c.UserIDByName(ctx, args.User)
		if err != nil {
			return render.Failf("%v", err)
		}
		var before map[string]any
		_ = c.Get(ctx, jmsapi.ResUsers, id, &before)

		// The bastion stamps date_password_last_updated with second
		// granularity, so a write and a read-back inside the same second are
		// indistinguishable from a write that never happened. Crossing a
		// second boundary first makes the comparison meaningful.
		waitForNextSecond()

		if err := c.Put(ctx, jmsapi.ResUsers, id, "password", map[string]any{"password": args.Password}, nil); err != nil {
			return render.Failf("%v", err)
		}

		var after map[string]any
		if err := c.Get(ctx, jmsapi.ResUsers, id, &after); err != nil {
			return render.Failf("password was submitted but reading the user back failed: %v", err)
		}
		res := &jmsms.PasswordSet{
			Username:         args.User,
			ID:               id,
			PasswordChanged:  true,
			PasswordReadable: false,
		}
		beforeAt, afterAt := jmsapi.Str(before["date_password_last_updated"]), jmsapi.Str(after["date_password_last_updated"])
		res.DatePasswordLastUpdated = jms.Opt(afterAt)
		switch {
		case afterAt != "" && afterAt != beforeAt:
			res.Verified = jms.OptBool(true)
		case afterAt != "":
			// The stamp did not move even across a second boundary, so the
			// write cannot be confirmed from the record.
			res.Verified = jms.OptBool(false)
			res.Note = jms.Opt("the bastion did not advance date_password_last_updated; " +
				"the write may not have applied")
		default:
			res.Verified = jms.OptBool(false)
			res.Note = jms.Opt("the bastion reports no password timestamp for this account")
		}
		return render.Text(res)
	})
}

// waitForNextSecond sleeps until the wall clock ticks over.
//
// It exists for the second-granularity problem: a write and a read-back in
// the same second cannot be told apart from no write at all.
func waitForNextSecond() {
	d := time.Until(time.Now().Truncate(time.Second).Add(time.Second))
	if d > 0 && d < time.Second {
		time.Sleep(d + 50*time.Millisecond)
	}
}

// generatePassword returns a password that satisfies the strict policies
// JumpServer deployments commonly enable (length, mixed case, digits,
// symbols).
//
// The randomness has to be real: a deterministic shape is a password that is
// the same on every bastion, forever, which is exactly what a password must
// not be. crypto/rand is used rather than math/rand for that reason.
func generatePassword(n int) string {
	if n < 12 {
		n = 12
	}
	const (
		lower = "abcdefghijkmnopqrstuvwxyz"
		upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
		digit = "23456789"
		sym   = "!@#$%^&*-_=+"
	)
	all := lower + upper + digit + sym

	// One draw per character, plus spares: the byte range is trimmed to a
	// multiple of len(all) so every character is equally likely, and bytes
	// above the trimmed range are re-drawn rather than folded in (a plain
	// modulo would favour the first few characters).
	limit := byte(256 - (256 % len(all)))
	out := make([]byte, 0, n)
	buf := make([]byte, 64)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			// Failing loudly beats handing back a weak password.
			return ""
		}
		for _, b := range buf {
			if len(out) == n {
				break
			}
			if b >= limit {
				continue
			}
			out = append(out, all[int(b)%len(all)])
		}
	}
	// The guaranteed classes come first so the result always satisfies a
	// policy that demands one of each, whatever the draw produced.
	classes := []string{lower, upper, digit, sym}
	for i, c := range classes {
		if len(out) <= i {
			break
		}
		var pick [1]byte
		if _, err := rand.Read(pick[:]); err != nil {
			return ""
		}
		out[i] = c[int(pick[0])%len(c)]
	}
	return string(out)
}

// ---------------------------------------------------------------- access review

func RegisterAccessReviewTools(r *reg.Registry, c *repository.Client) {
	type permGetArgs struct {
		Permission string `json:"permission" jsonschema:"permission name or UUID, e.g. 'ai-全部资产'"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_permission_get",
		Description: "Show one asset permission in full: which users and groups hold it, which assets and nodes " +
			"it covers, and which accounts it actually grants. jms_permissions_list only reports counts, so " +
			"use this when the question is 'who is in this permission' or 'what does this actually open'. " +
			"Pay attention to accounts: an empty accounts list grants NO account, not all of them.",
		OutputSchema: render.Schema[jmsms.PermissionDetail](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args permGetArgs) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(args.Permission) == "" {
			return render.Failf("permission is required")
		}
		id, err := c.PermissionIDByName(ctx, args.Permission)
		if err != nil {
			return render.Failf("%v", err)
		}
		var p map[string]any
		if err := c.Get(ctx, jmsapi.ResPermissions, id, &p); err != nil {
			return render.Failf("%v", err)
		}

		// The members are the answer to "who is in this permission", so they
		// are the contract's own Ref rows -- not a free map whose keys could
		// be spelled wrong.
		users := []*jmsms.Ref{}
		for _, u := range jmsapi.AsSlice(p["users"]) {
			if m, ok := u.(map[string]any); ok {
				users = append(users, &jmsms.Ref{ID: jmsapi.FieldStr(m["id"]), Name: jmsapi.FieldStr(m["name"])})
			}
		}
		assets := []*jmsms.Ref{}
		for _, a := range jmsapi.AsSlice(p["assets"]) {
			if m, ok := a.(map[string]any); ok {
				assets = append(assets, &jmsms.Ref{ID: jmsapi.FieldStr(m["id"]), Name: jmsapi.FieldStr(m["name"])})
			}
		}
		nodes := []*jmsms.Ref{}
		for _, n := range jmsapi.AsSlice(p["nodes"]) {
			if m, ok := n.(map[string]any); ok {
				nodes = append(nodes, &jmsms.Ref{ID: jmsapi.FieldStr(m["id"]), Name: jmsapi.FieldStr(m["name"])})
			}
		}
		groups := []*jmsms.Ref{}
		for _, g := range jmsapi.AsSlice(p["user_groups"]) {
			if m, ok := g.(map[string]any); ok {
				groups = append(groups, &jmsms.Ref{ID: jmsapi.FieldStr(m["id"]), Name: jmsapi.FieldStr(m["name"])})
			}
		}
		accounts := asStringSlice(p["accounts"])
		slices.Sort(accounts)

		// The actions are the bastion's own labelled choices, so they keep
		// their value and their label.
		actions := []*jmsms.ActionRef{}
		for _, a := range jmsapi.AsSlice(p["actions"]) {
			switch t := a.(type) {
			case map[string]any:
				actions = append(actions, &jmsms.ActionRef{
					Value: jmsapi.FieldStr(t["value"]),
					Label: jmsapi.FieldStr(t["label"]),
				})
			default:
				actions = append(actions, &jmsms.ActionRef{Value: jmsapi.FieldStr(a)})
			}
		}

		res := &jmsms.PermissionDetail{
			ID:           jmsapi.FieldStr(p["id"]),
			Name:         jmsapi.FieldStr(p["name"]),
			IsActive:     jmsapi.FieldBool(p["is_active"]),
			IsValid:      jmsapi.FieldBool(p["is_valid"]),
			Users:        users,
			UserGroups:   groups,
			Assets:       assets,
			Nodes:        nodes,
			Accounts:     accounts,
			UsersAmount:  jmsapi.FieldInt32(p["users_amount"]),
			AssetsAmount: jmsapi.FieldInt32(p["assets_amount"]),
			NodesAmount:  jmsapi.FieldInt32(p["nodes_amount"]),
			Actions:      actions,
			DateCreated:  jmsapi.FieldStr(p["date_created"]),
			DateExpired:  jmsapi.FieldStr(p["date_expired"]),
			CreatedBy:    jmsapi.FieldStr(p["created_by"]),
			Comment:      jmsapi.FieldStr(p["comment"]),
		}
		// The counter the API reports counts only the directly named assets.
		// A permission that covers a node reaches everything under that node,
		// so the real reach has to be expanded or the review is wrong.
		//
		// The contract has one warning slot (warning_count), so every
		// warning this tool can raise travels in it, in the order they were
		// raised.
		warnings := []string{}
		if effective, err := c.EffectiveAssets(ctx, p); err == nil {
			res.EffectiveAssetsCount = jms.OptInt32(int32(len(effective)))
			res.DirectAssetsCount = jms.OptInt32(int32(len(assets)))
			if n, _ := p["assets_amount"].(float64); int(n) != len(effective) {
				warnings = append(warnings, fmt.Sprintf(
					"the permission reports %d assets but actually reaches %d: the difference comes from the "+
						"asset-tree nodes it covers. Do not use the counter for an access review",
					int(n), len(effective)))
			}
		}
		if len(accounts) == 0 {
			warnings = append(warnings, "this permission grants NO account: logins with it fail with "+
				"'没有可用的授权账号或终端协议'. Create it with all_accounts=true (the literal @ALL) "+
				"or name the accounts explicitly.")
		}
		if len(users) == 0 && len(groups) == 0 {
			warnings = append(warnings, "this permission is held by nobody")
		}
		if len(warnings) > 0 {
			res.Warning = jms.Opt(strings.Join(warnings, "; "))
		}
		return render.Text(res)
	})

	type userAccessArgs struct {
		User  string `json:"user" jsonschema:"the JumpServer user to review"`
		Limit int    `json:"limit,omitempty" jsonschema:"max assets to return (default 100)"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_user_access",
		Description: "List every asset a JumpServer user can actually reach, with the node it comes from, and the " +
			"permission that grants it. This is the effective-access view used for access reviews and least-privilege " +
			"audits: it answers 'what can this person get into' from the bastion's own permission graph, " +
			"including assets inherited through a node or a user group rather than named directly.",
		OutputSchema: render.Schema[jmsms.UserAccess](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args userAccessArgs) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(args.User) == "" {
			return render.Failf("user is required")
		}
		id, err := c.UserIDByName(ctx, args.User)
		if err != nil {
			return render.Failf("%v", err)
		}
		// The endpoint is keyed by UUID, not by username: passing a username
		// answers 404 "User object does not exist" even for a real user.
		rows, err := c.ListSub(ctx, jmsapi.ResPermUserAssets, id, "assets")
		if err != nil {
			return render.Failf("%v", err)
		}
		limit := args.Limit
		limit = repository.NormLimit(limit, 100, 500)
		assets := []*jmsms.AssetRef{}
		byPlatform := map[string]int32{}
		for _, a := range rows {
			nodeNames := []string{}
			for _, n := range jmsapi.AsSlice(a["nodes"]) {
				if m, ok := n.(map[string]any); ok {
					nodeNames = append(nodeNames, jmsapi.Str(m["name"]))
				}
			}
			plat := jmsapi.Str(jmsapi.Nested(a, "platform", "name"))
			byPlatform[plat]++
			if len(assets) >= limit {
				continue
			}
			assets = append(assets, &jmsms.AssetRef{
				Name:         jmsapi.FieldStr(a["name"]),
				Address:      jmsapi.FieldStr(a["address"]),
				Platform:     jmsapi.FieldStr(plat),
				Connectivity: jmsapi.FieldStr(jmsapi.Label(a, "connectivity")),
				IsActive:     jmsapi.FieldBool(a["is_active"]),
				Nodes:        nodeNames,
			})
		}
		slices.SortFunc(assets, func(a, b *jmsms.AssetRef) int {
			return strings.Compare(a.GetAddress(), b.GetAddress())
		})

		// Which grant is responsible for each reachable asset. An access
		// review that says "this person can reach 45 assets" without saying
		// "through which permission" leaves the reader with nothing to act
		// on -- the grant that has to change is the whole point.
		sources, err := c.AccessSources(ctx, id)
		if err != nil {
			sources = map[string][]string{}
		}
		for _, a := range assets {
			if src, ok := sources[a.GetName()]; ok {
				a.GrantedBy = src
			}
		}

		return render.Text(&jmsms.UserAccess{
			Username: jms.Opt(args.User),
			UserID:   jms.Opt(id),
			// count / total / truncated: the same three everywhere, so a
			// caller never has to learn a per-tool name for "how many came
			// back" and "how many matched".
			Count:      jms.OptInt32(int32(len(assets))),
			Total:      jms.OptInt32(int32(len(rows))),
			ByPlatform: byPlatform,
			Assets:     assets,
			Truncated:  jms.OptBool(len(rows) > len(assets)),
		})
	})
}

// accessSources maps each asset to the permissions that grant it to a user.
//
// The permission's node scope is expanded through the tree, because a
// permission that covers a node grants everything under it -- without that,
// the attribution would be wrong for every asset filed in a child node.

// ---------------------------------------------------------------- doctor

// registerDoctorTool installs the self-check tool. Everything here is
// mechanical: it reports what the bastion actually holds, so a wiring mistake
// shows up as a finding instead of as a confusing failure three calls later.
func RegisterDoctorTool(r *reg.Registry, c *repository.Client) {
	type doctorArgs struct {
		Verbose bool `json:"verbose,omitempty" jsonschema:"also list every affected asset instead of only the first few"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_doctor",
		Description:  "Check this MCP's wiring against the bastion and report what is wrong: unreachable API, token without permissions, assets that can never be connected (no protocol or no account), and permissions that grant nobody or no account. Run this first when a jms_* tool misbehaves, and after changing the bastion configuration; jms_status is the lighter look (does it answer, how many assets). Read-only.",
		OutputSchema: render.Schema[jmsms.DoctorResult](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args doctorArgs) (*mcp.CallToolResult, any, error) {
		out, err := Doctor(ctx, c, args.Verbose)
		if err != nil {
			return render.Failf("%v", err)
		}
		return render.Text(out)
	})
}

// trailFix says what to do about a trail that is not healthy.
//
// ⚠️ The advice itself is in the shared base (audit.Advice), because the
// execution plane's doctor has to give the SAME one — a check that is one
// check and an advice that only one doctor can give is advice half the
// operators never get.
func trailFix(reason audit.Reason) string {
	return audit.Advice(reason)
}

// Doctor runs the management-plane self-check and returns a structured report.
// It is exported through both the MCP tool and the --doctor CLI flag, so the
// same check can run inside a session or from a shell.
//
// The report follows the shared diagnostic shape (see diag.go): checks[] says
// what was examined, findings[] the part of it that is not ok, status the
// grade, verdict the conclusion and advice what to do about it -- plus the
// context the check ran against: which bastion, as whom, and how much it
// looked at.
//
// ⚠️ It does NOT check the audit trail: the trail's directory is part of
// this server's CONFIGURATION, and the tool path deliberately carries no
// configuration — so it cannot say anything about it. The CLI path can,
// and does: DoctorWithTrail.
func Doctor(ctx context.Context, c *repository.Client, verbose bool) (*jmsms.DoctorResult, error) {
	return DoctorWithTrail(ctx, c, verbose, nil)
}

// DoctorWithTrail is Doctor plus the trail's own health check.
//
// ⚠️ The trail's settings are a POINTER because there are two different
// reasons for not having them, and they call for different silences:
// "this server has no trail" (say so) and "this caller cannot know the
// configuration" (say nothing at all). A nil pointer means the second one.
func DoctorWithTrail(ctx context.Context, c *repository.Client, verbose bool, trail *audit.Settings) (*jmsms.DoctorResult, error) {
	res := &jmsms.DoctorResult{
		BaseURL: c.BaseURL,
		// The counts are filled in as the check goes; the map starts empty so
		// an early exit still answers with the shape the contract promises.
		AssetByPlatform: map[string]int32{},
	}
	checks := []*jms.Check{}
	add := func(name string, status jms.Status, detail, fix string) {
		checks = append(checks, &jms.Check{Name: name, Status: status, Detail: detail, Fix: service.FixText(fix)})
	}
	// Every early return below still has to answer in the shared shape, so
	// the verdict is assembled in one place instead of at each exit.
	finish := func() *jmsms.DoctorResult {
		res.Diagnosis = service.Diagnosis(checks,
			service.Verdict(checks, "every check passed: the MCP is wired correctly and the bastion has no silent failure"),
			"nothing to fix: every check passed")
		return res
	}

	// ⚠️ The trail's own health comes FIRST: it is about THIS machine and
	// has nothing to do with the bastion — so it is worth saying even when
	// the bastion cannot be reached, and even when there is no token at
	// all (which returns early below).
	//
	// ⚠️ It is checked here and not only in the execution plane's doctor
	// because the trail directory is CONFIGURABLE, and each server carries
	// its own configuration: the two default to the same directory, but a
	// deployment that points them at different ones would have the
	// management plane's trail stop growing while the execution plane's
	// doctor said everything was fine.
	if trail != nil {
		switch trail.Mode {
		case "file":
			status, reason, detail := audit.CheckTrail(trail.TrailDir())
			add("audit_trail", status, detail, trailFix(reason))
		default:
			add("audit_trail", service.Warn, fmt.Sprintf(
				"off (JMS_AUDIT=%s): the gate's trail goes to the log only, so a call that did NOT run "+
					"leaves no record on this machine", trail.Mode),
				"set JMS_AUDIT=file to keep the trail on this machine as well")
		}
	}

	// The credential. Two forms are accepted — a PrivateToken, or a login
	// the bastion exchanges for a Bearer token — and both work on v4 and on
	// v5 alike. Which one is in force is worth stating: a PrivateToken
	// does not expire, a login does.
	switch {
	case c.Token != "" && c.Credential.Username != "":
		add("api_token", service.Warn,
			"both JUMPSERVER_TOKEN and JUMPSERVER_USERNAME are set; the PrivateToken is used "+
				"because it does not expire",
			"unset one of them if the other was meant")
	case c.Token != "":
		add("api_token", service.OK, "JUMPSERVER_TOKEN is set (a PrivateToken, which does not expire)", "")
	case c.Credential.Username != "":
		add("api_token", service.OK,
			"JUMPSERVER_USERNAME is set; the bastion is reached with a login that is exchanged for "+
				"a Bearer token (it expires, so it is refreshed)",
			"")
	default:
		add("api_token", service.Fail, "no credential is configured",
			"set JUMPSERVER_TOKEN to a token of a user that may manage assets, or JUMPSERVER_USERNAME "+
				"together with JUMPSERVER_PASSWORD")
		return finish(), nil
	}

	// Reachability probed on /users/profile/ — a route that answers for any
	// valid credential. ⚠️ It must NOT be the users LIST (/users/users/):
	// that one needs users.view_user, so a caller without that permission
	// would see "the credential is wrong" when it is in fact fine — a
	// permission gap reported as an auth failure. The profile route has no
	// such gate (measured v4 + v5, 2026-11-01).
	var raw json.RawMessage
	if err := c.GetQuery(ctx, jmsapi.ResUsersProfile, url.Values{"page_size": {"1"}}, &raw); err != nil {
		add("api_reachable", service.Fail, err.Error(),
			"check the bastion's address (JUMPSERVER_URL) and that the credential is still valid")
		return finish(), nil
	}
	add("api_reachable", service.OK, "the bastion answered and accepted the credential", "")

	// Which version the deployment runs — and, more usefully, WHICH
	// CAPABILITIES it has.
	//
	// The capability is the actionable half: it decides whether a
	// delegation credential may be presented at all, and a 401 on that path
	// is read as "the credential is wrong" (and, on the execution side, as
	// "the fast path is unavailable" — every session walks the slow
	// terminal path). So the report says both: the release (what the
	// operator configured) and what the deployment can actually do.
	rep := c.ReportVersion(ctx)
	state := c.Profile(ctx).State(jmsapi.CapDelegation)
	// ⚠️ The judgement AND the sentences come from pkg/jmsapi: the two
	// doctors used to write this row separately, and the copies had already
	// drifted — including the part that matters most: BOTH said "it is
	// treated as available", while THIS plane's delegation tools in fact
	// REFUSE an unknown scheme ⇒ the doctor misdescribed its own plane.
	row := jmsapi.VersionRowFor(rep, state, jmsapi.UnknownRefused)
	add("version", row.Status, row.Message, row.Advice)

	// ⚠️ The identity is the CALLER (/users/profile/), not the first row of
	// the users list — the list's first row is a list fact; a non-admin
	// caller would be named as admin. See identityOf.
	if who, _, super, idErr := identityOf(ctx, c); idErr != nil {
		// Identity not established: leave BOTH fields nil. A zero value here
		// would be a claim ("this caller is not a superuser", "the caller is
		// the empty name") that no one asked and the probe never made — and
		// it would defeat root.go's "print the line only once it is known"
		// guard, which keys off these being non-nil. Missing is honest;
		// fabricated is not.
		res.Identity = jmsms.IdentityRef{}
		add("identity", service.Warn, "could not determine who the credential acts as: "+idErr.Error(),
			"the identity comes from /users/profile/; the report does not guess it from a user list")
	} else {
		res.Identity = jmsms.IdentityRef{
			Username:    jms.Opt(who),
			IsSuperuser: jms.OptBool(super),
		}
		add("identity", service.OK, "acting as "+who, "")
	}

	// TWO questions, asked separately: does the DEPLOYMENT have the scheme,
	// and is it CONFIGURED here. They used to share one answer, and the
	// answer could not say which of the two it was.
	switch state {
	case jmsapi.CapabilityAbsent:
		// The deployment does not HAVE the scheme. Nothing can be
		// configured into existence, and the consequence is worth stating
		// rather than leaving to be discovered.
		add("delegation", service.Warn, jmsapi.Explain(jmsapi.CapDelegation, state),
			jmsapi.Advice(jmsapi.CapDelegation, state))
	case jmsapi.CapabilityUnknown:
		// ⚠️ NOT "this deployment has no scheme": the presence of the
		// scheme was NOT established, and saying otherwise would send the
		// operator to configure something that may not be there.
		add("delegation", service.Warn, jmsapi.Explain(jmsapi.CapDelegation, state),
			jmsapi.Advice(jmsapi.CapDelegation, state))
	default:
		ok, why := c.DelegationConfigured()
		if ok {
			add("delegation", service.OK, "single-use Chat AI delegation is configured ("+why+")", "")
			break
		}
		// The user and org ids are resolvable from the API, so a missing
		// explicit env value is not a misconfiguration -- resolve them the way
		// the delegation tools do before declaring anything broken.
		if err := c.EnsureDelegationIdentity(ctx); err == nil {
			add("delegation", service.OK, "single-use Chat AI delegation is configured", "")
		} else {
			add("delegation", service.Warn, err.Error()+
				" -- jms_delegation_* tools will report themselves unconfigured; "+
				"the long-lived token path is unaffected",
				"set JMS_DELEGATION_SECRET if you want the jms_delegation_* tools to work; "+
					"everything else keeps working without it")
		}
	}
	// Who the delegation credential acts as decides which account the
	// single-use credential can act for, so it is worth stating out loud.
	if c.DelegationUserID != "" {
		name := c.DelegationUserID
		if rows, err := c.List(ctx, jmsapi.ResUsers); err == nil {
			for _, u := range rows {
				if jmsapi.Str(u["id"]) == c.DelegationUserID {
					name = jmsapi.Str(u["username"])
					break
				}
			}
		}
		add("delegation_identity", service.OK, "a delegated credential acts as "+name+
			" (the user id the bastion will see, not the token's owner)", "")
	}

	// Asset-level hazards: both are silent until someone tries to log in.
	assets, err := c.List(ctx, jmsapi.ResAssets)
	if err != nil {
		add("assets", service.Fail, err.Error(),
			"check the token's permission on /assets/assets/ and that the bastion is reachable")
		return finish(), nil
	}
	aj := judgeAssets(assets)
	noProto, noAccount := aj.NoProtocol, aj.NoAccount
	res.AssetTotal = int32(aj.Total)
	for k, v := range aj.ByPlatform {
		res.AssetByPlatform[k] = int32(v)
	}
	if len(noProto) == 0 {
		add("assets_without_protocols", service.OK, "every asset declares at least one terminal protocol", "")
	} else {
		add("assets_without_protocols", service.Fail, fmt.Sprintf(
			"%d asset(s) have no protocol and can never be connected to: %s", len(noProto), strings.Join(noProto, ", ")),
			"add a terminal protocol to each listed asset with jms_asset_update")
	}
	if len(noAccount) == 0 {
		add("assets_without_accounts", service.OK, "every asset has at least one account", "")
	} else {
		add("assets_without_accounts", service.Warn, fmt.Sprintf(
			"%d asset(s) have no account: they fail at login with 'no authorized account or terminal protocol': %s",
			len(noAccount), strings.Join(noAccount, ", ")),
			"add an account to each listed asset with jms_account_create")
	}

	// Permission-level hazards.
	perms, err := c.List(ctx, jmsapi.ResPermissions)
	if err != nil {
		add("permissions", service.Warn, err.Error(),
			"check the token's permission on /perms/asset-permissions/")
	} else {
		noAccount, noUser, dangling := []string{}, []string{}, []string{}
		// The account names each asset really has, so a permission that names
		// an account nobody has can be spotted. The account list is fetched
		// once and grouped, not once per asset.
		assetAccounts := map[string]map[string]bool{}
		if accRows, aerr := c.List(ctx, jmsapi.ResAccounts); aerr == nil {
			for _, a := range accRows {
				aid := fmt.Sprint(jmsapi.Nested(a, "asset", "id"))
				if aid == "" || aid == "<nil>" {
					continue
				}
				if assetAccounts[aid] == nil {
					assetAccounts[aid] = map[string]bool{}
				}
				assetAccounts[aid][jmsapi.Str(a["username"])] = true
			}
		}
		// Which assets each permission really reaches.
		//
		// ⚠️ The list endpoint answers with the related objects as NULL
		// (assets and users of a permission), so the assets of a list row are
		// always empty. Reading them from there makes every named account
		// look dangling — a false alarm that names a perfectly good grant.
		// The detail endpoint has them, and the node-scoped ones are expanded
		// the way the coverage tool expands them.
		grantedAssets := map[string][]string{}
		for _, p := range perms {
			name := jmsapi.Str(p["name"])
			detail, derr := c.PermissionDetail(ctx, name)
			if derr != nil {
				continue
			}
			effective, eerr := c.EffectiveAssets(ctx, detail)
			if eerr != nil {
				continue
			}
			ids := []string{}
			for _, a := range effective {
				ids = append(ids, jmsapi.Str(a["id"]))
			}
			grantedAssets[name] = ids
		}
		pj := judgePermissions(perms, assetAccounts, grantedAssets)
		noAccount, noUser, dangling = pj.NoAccount, pj.NoUser, pj.Dangling
		res.PermissionTotal = int32(pj.Total)
		if len(noAccount) == 0 {
			add("permissions_without_accounts", service.OK, "every permission grants at least one account", "")
		} else {
			add("permissions_without_accounts", service.Warn, fmt.Sprintf(
				"%d permission(s) grant NO account (empty is not @ALL): %s",
				len(noAccount), strings.Join(noAccount, ", ")),
				"grant an account to each listed permission with jms_permission_grant")
		}
		if len(noUser) == 0 {
			add("permissions_without_members", service.OK, "every permission is held by at least one user or group", "")
		} else {
			add("permissions_without_members", service.Warn, fmt.Sprintf(
				"%d permission(s) are held by nobody: %s", len(noUser), strings.Join(noUser, ", ")),
				"add a user or a group to each listed permission with jms_permission_grant")
		}
		if len(dangling) == 0 {
			add("permissions_with_unknown_accounts", service.OK,
				"every account named by a permission exists on the assets it grants", "")
		} else {
			add("permissions_with_unknown_accounts", service.Warn, fmt.Sprintf(
				"%d permission(s) name an account that no granted asset has, so the grant can never be used: %s",
				len(dangling), strings.Join(dangling, ", ")),
				"name an account the granted assets really have, or drop the grant with jms_permission_delete")
		}
	}

	if verbose {
		// The verbose listing is the shared asset shape, the same one the
		// asset list and the execution plane's inventory hand out.
		for _, a := range assets {
			res.AllAssets = append(res.AllAssets, jmsapi.AssetSummary(a))
		}
	}
	return finish(), nil
}

// expectsTerminalAccess reports whether an asset is supposed to be reached
// through a terminal protocol and a login account.
//
// JumpServer groups platforms into categories, and only the "host" category
// (Linux, macOS, Windows, Gateway, the database platforms) is driven through
// a terminal. A "web" asset (Website) is reached over HTTP and a "cloud"
// asset (Kubernetes) over its API; neither ever has a protocol or an account,
// and reporting them as broken produced six false alarms on this bastion --
// every one of them a service that works perfectly well.

// assetJudgment is the outcome of the asset-level checks.
type assetJudgment struct {
	Total      int
	NoProtocol []string
	NoAccount  []string
	ByPlatform map[string]int
}

// judgeAssets applies the asset-level rules to already-fetched assets.
//
// It is a pure function on purpose. The rule that decides which assets are
// supposed to carry a protocol and an account is the one that produced six
// false alarms when it was wrong, and it can only be pinned by a test if it
// does not need a bastion to run.
func judgeAssets(assets []map[string]any) assetJudgment {
	j := assetJudgment{NoProtocol: []string{}, NoAccount: []string{}, ByPlatform: map[string]int{}}
	for _, a := range assets {
		addr := jmsapi.Str(a["address"])
		j.ByPlatform[jmsapi.Str(jmsapi.Nested(a, "platform", "name"))]++
		if !service.ExpectsTerminalAccess(a) {
			continue
		}
		if len(jmsapi.AsSlice(a["protocols"])) == 0 {
			j.NoProtocol = append(j.NoProtocol, addr)
		}
		if n, ok := a["accounts_amount"].(float64); ok && n == 0 {
			j.NoAccount = append(j.NoAccount, addr)
		}
	}
	j.Total = len(assets)
	return j
}

// permissionJudgment is the outcome of the permission-level checks.
type permissionJudgment struct {
	Total     int
	NoAccount []string
	NoUser    []string
	Dangling  []string
}

// judgePermissions applies the permission-level rules to already-fetched
// permissions.
//
// assetAccounts maps an asset id to the account names that asset really has,
// so a permission naming an account nobody has can be spotted. A permission
// that grants an account no granted asset has can never be used: the login
// finds no matching account and fails exactly like a permission that grants
// none.
func judgePermissions(perms []map[string]any, assetAccounts map[string]map[string]bool, grantedAssets map[string][]string) permissionJudgment {
	j := permissionJudgment{NoAccount: []string{}, NoUser: []string{}, Dangling: []string{}}
	for _, p := range perms {
		name := jmsapi.Str(p["name"])
		accts := asStringSlice(p["accounts"])
		if len(accts) == 0 {
			j.NoAccount = append(j.NoAccount, name)
		}
		u, _ := p["users_amount"].(float64)
		g, _ := p["user_groups_amount"].(float64)
		if u == 0 && g == 0 {
			j.NoUser = append(j.NoUser, name)
		}
		if !slicex.Contains(accts, service.AllAccounts) && len(accts) > 0 {
			granted := grantedAssets[name]
			for _, acct := range accts {
				found := false
				for _, aid := range granted {
					if assetAccounts[aid][acct] {
						found = true
						break
					}
				}
				if !found {
					j.Dangling = append(j.Dangling, fmt.Sprintf("%s -> %q", name, acct))
				}
			}
		}
	}
	j.Total = len(perms)
	return j
}
