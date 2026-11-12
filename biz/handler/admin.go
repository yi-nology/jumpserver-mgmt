package handler

// tools_admin.go adds the write side of the JumpServer surface. The read tools in
// main.go only describe what already exists; these create, change and verify it.
//
// Everything here mutates the bastion, so every mutating tool takes a confirm
// flag, and each is documented with the v5 constraint that makes it silently
// no-op otherwise. The two that bite hardest:
//
//   - AssetPermission.accounts empty means NO accounts. Use "@ALL".
//   - An asset with no protocols cannot be connected to at all, and JumpServer
//     does not say so until a session fails.
//
// Secrets are write-only in the API: a secret can be set and its presence read,
// but its value can never be read back.

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/yi-nology/jumpserver-mgmt/biz/model/jmsms"

	"github.com/yi-nology/jumpserver-mgmt/internal/service"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oekit/network/sshx"
	"github.com/oekit/pkg/slicex"
	"github.com/yi-nology/jumpserver-kit/model/jms"
	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
	"github.com/yi-nology/jumpserver-mgmt/internal/repository"
)

func RegisterAdminTools(r *reg.Registry, c *repository.Client) {
	RegisterUserTools(r, c)
	RegisterPermissionTools(r, c)
	RegisterAssetWriteTools(r, c)
	RegisterOpsTools(r, c)
}

// ---------------------------------------------------------------- users & keys

func RegisterUserTools(r *reg.Registry, c *repository.Client) {
	type usersListArgs struct {
		Search string `json:"search,omitempty" jsonschema:"substring match on username or name"`
		Limit  int    `json:"limit,omitempty" jsonschema:"max rows (default 50)"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_users_list",
		Description:  "List JumpServer users with SSH key status and last login. Component accounts such as '[KoKo]-...' are internal; use search='[' to keep only the humans. Use it to find who exists before granting a permission to somebody.",
		OutputSchema: render.Schema[render.ListOf[jmsms.UserSummary]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args usersListArgs) (*mcp.CallToolResult, any, error) {
		rows, err := c.List(ctx, jmsapi.ResUsers)
		if err != nil {
			return render.Failf("%v", err)
		}
		// filter → map → sort → truncate → count: render.ListSpec owns the
		// order and the three counting fields. This replaces a loop that
		// capped BEFORE sorting — so limit=50 returned "the first 50 in the
		// endpoint's order, then sorted", not "the 50 lowest usernames" —
		// and computed the totals by hand. Sorting before the cap is what
		// makes limit mean "the top N by the sort key".
		return render.Text(render.ListSpec[map[string]any, jmsms.UserSummary]{
			Rows: rows,
			Keep: func(u map[string]any) bool {
				if args.Search == "" {
					return true
				}
				username := jmsapi.Str(u["username"])
				return strings.Contains(strings.ToLower(username), strings.ToLower(args.Search))
			},
			Map: func(u map[string]any) jmsms.UserSummary {
				return jmsms.UserSummary{
					Username:     jmsapi.Str(u["username"]),
					ID:           jmsapi.FieldStr(u["id"]),
					Name:         jmsapi.FieldStr(u["name"]),
					IsSuperuser:  jmsapi.FieldBool(u["is_superuser"]),
					IsActive:     jmsapi.FieldBool(u["is_active"]),
					HasPublicKey: jmsapi.FieldBool(u["has_public_keys"]),
					LastLogin:    jmsapi.FieldStr(u["last_login"]),
				}
			},
			Less:  func(a, b jmsms.UserSummary) bool { return a.Username < b.Username },
			Limit: args.Limit,
			Def:   50,
			Max:   200,
		}.Build())
	})

	type sshkeyAddArgs struct {
		User      string `json:"user" jsonschema:"JumpServer user to attach the key to"`
		PublicKey string `json:"public_key" jsonschema:"the RSA PUBLIC key, e.g. 'ssh-rsa AAAA... user@host'. ed25519 is rejected: koko does not accept it, and the bastion accepts it silently."`
		Confirm   bool   `json:"confirm" jsonschema:"must be true; this writes to the bastion"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_user_sshkey_add",
		Description: "Register an RSA SSH public key for a JumpServer user so they can log in to koko (port 2222) without a password. " +
			"Only ssh-rsa is accepted, because koko rejects ed25519 even though the bastion accepts it silently. " +
			"Keys live in a separate SSHKey table, NOT in the user's public_key field: writing that field answers 200 " +
			"and reports can_public_key_auth=true while storing nothing, and the key is then rejected at login. " +
			"This tool writes to the table that actually works and verifies the key landed on the requested user. " +
			"the API has no cross-user endpoint for this (v4 and v5 alike): the key is registered as the account that owns the credential, " +
			"so use it for the user this MCP acts as.",
		OutputSchema: render.Schema[jmsms.SSHKeyAdded](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args sshkeyAddArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to write the key to the bastion")
		}
		key := strings.TrimSpace(args.PublicKey)
		if err := checkRSAPublicKey(key); err != nil {
			return render.Failf("%v", err)
		}

		id, err := c.UserIDByName(ctx, args.User)
		if err != nil {
			return render.Failf("%v", err)
		}

		// POST /authentication/ssh-key/ is the only endpoint that writes the
		// SSHKey table, and it always attaches the key to the account that
		// owns the calling credential -- a "user" field in the body is
		// ignored (measured 2026-10-25: it silently registered the key on
		// the token's own admin account instead of the requested one).
		//
		// So: when the delegation credential is configured for the requested
		// user, delegation is the path that registers the key for them. The
		// long-lived token only works when the token itself belongs to them.
		body, err := json.Marshal(map[string]any{
			"name":       args.User,
			"public_key": key,
			"is_active":  true,
		})
		if err != nil {
			return render.Failf("%v", err)
		}

		var status int
		var raw []byte
		usedDelegation := false
		// The delegation identity has to be resolved here rather than assumed:
		// it is only filled in by the delegation tools or the doctor, so a
		// session that calls this tool first would otherwise take the wrong
		// path and register the key on the wrong account.
		_ = c.EnsureDelegationIdentity(ctx)
		if configured, _ := c.DelegationConfigured(); configured &&
			c.MayPresent(ctx, jmsapi.CapDelegation) && c.DelegationUserID == id {
			status, raw, err = c.DelegationRequest(ctx, repository.DelegationCall{
				Method: "POST", Path: string(jmsapi.ResSSHKeys), Body: body,
				OperationID: "users.register_ssh_key",
			})
			usedDelegation = true
		} else {
			var out map[string]any
			if err := c.Post(ctx, jmsapi.ResSSHKeys, map[string]any{"name": args.User, "public_key": key, "is_active": true}, &out); err != nil {
				return render.Failf("%v", err)
			}
			raw, _ = json.Marshal(out)
			status = 201
		}
		if err != nil {
			return render.Failf("%v", err)
		}
		if status >= 400 {
			return render.Failf("the bastion refused the key: HTTP %d: %s", status, jmsapi.Truncate(string(raw), 300))
		}

		var created map[string]any
		_ = json.Unmarshal(raw, &created)
		owner := jmsapi.Str(created["user"])
		keyID := jmsapi.Str(created["id"])

		// The response names the owner. If it is not the user we were asked
		// about, the write went to the wrong account -- undo it rather than
		// leave a stray key behind, and say what the API cannot do.
		if owner != "" && owner != id {
			// The SAME gate as the write above, asked again here rather
			// than carried over in a flag: the delegation credential acts
			// as ONE account, and only that account's key can be revoked by
			// it. Asking again also keeps the gate at the call site —
			// which is what the mechanical guard in internal/arch checks
			// for.
			//
			// The rollback runs OUTSIDE the caller's cancellation (#11):
			// it is compensation for a write that already happened, so a
			// client that went away must not leave the stray key behind —
			// the delete gets its own deadline instead of the caller's ctx.
			// WithoutCancel is the EXPLICIT spelling of that semantics
			// (workers.go keeps the same discipline for detached work).
			var rollbackErr error
			rollbackCtx, cancelRollback := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancelRollback()
			if configured, _ := c.DelegationConfigured(); configured &&
				c.MayPresent(rollbackCtx, jmsapi.CapDelegation) && c.DelegationUserID == id {
				_, _, rollbackErr = c.DelegationRequest(rollbackCtx, repository.DelegationCall{
					Method: "DELETE", Path: string(jmsapi.ResSSHKeys) + keyID + "/",
					OperationID: "users.remove_ssh_key",
				})
			} else {
				rollbackErr = c.Delete(rollbackCtx, jmsapi.ResSSHKeys, keyID)
			}
			if rollbackErr != nil {
				// The rollback failing is worth its own sentence: the old
				// message said "it was removed again" unconditionally, and a
				// caller who believed it left a key they did not know about.
				return render.Failf("the API can only register an SSH key for the account that owns the calling credential: "+
					"the key landed on user %s, not %s, and removing it again failed (%v) — "+
					"the stray key is still on that account, remove it by hand. "+
					"Register the key while authenticated as %s (the bastion UI, or koko with that user's own token), "+
					"or point this MCP's delegation at that user with JMS_DELEGATION_USER_ID.",
					owner, args.User, rollbackErr, args.User)
			}
			return render.Failf("the API can only register an SSH key for the account that owns the calling credential: "+
				"the key landed on user %s, not %s, so it was removed again. "+
				"Register the key while authenticated as %s (the bastion UI, or koko with that user's own token), "+
				"or point this MCP's delegation at that user with JMS_DELEGATION_USER_ID.",
				owner, args.User, args.User)
		}

		res := &jmsms.SSHKeyAdded{
			Username:    args.User,
			Written:     jms.OptBool(true),
			Verified:    jms.OptBool(true),
			KeyID:       jms.Opt(keyID),
			KeyType:     jms.Opt(strings.SplitN(key, " ", 2)[0]),
			OwnerUserID: jms.Opt(owner),
			PathUsed:    jms.Opt("POST /authentication/ssh-key/ (the SSHKey table)"),
		}
		if usedDelegation {
			res.Credential = jms.Opt("single-use Chat AI delegation, already spent")
		}
		res.Hint = jms.Opt("if the user still cannot log in on 2222, confirm the bastion has " +
			"SSH public-key authentication enabled for that user")
		return render.Text(res)
	})

	type sshkeyRemoveArgs struct {
		User    string `json:"user" jsonschema:"the JumpServer user whose key to remove"`
		KeyID   string `json:"key_id,omitempty" jsonschema:"the key id to remove; omit to remove every key of that user"`
		Confirm bool   `json:"confirm" jsonschema:"must be true; this revokes a login credential"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_user_sshkey_remove",
		Description: "Revoke an SSH key from a JumpServer user so it can no longer log in over koko (port 2222). " +
			"Use it when a key is compromised or an old workstation is decommissioned. " +
			"The key has to exist on the account this MCP can act as: the API scopes the key endpoints to the " +
			"calling credential, so a key belonging to another user is neither listed nor removable from here.",
		OutputSchema: render.Schema[jmsms.SSHKeyRemoved](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args sshkeyRemoveArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to remove the key")
		}
		id, err := c.UserIDByName(ctx, args.User)
		if err != nil {
			return render.Failf("%v", err)
		}
		if strings.TrimSpace(args.KeyID) == "" {
			return render.Failf("key_id is required: the key endpoints are scoped to the calling credential, " +
				"so the keys of another user cannot be listed here. Read the key id from " +
				"jms_user_sshkey_add's result, or remove it through the bastion UI")
		}
		// The same rule as the add path: the key must be removed by a
		// credential that owns it. The delegation credential acts as the AI
		// account, so it is the one that can revoke that account's keys.
		_ = c.EnsureDelegationIdentity(ctx)
		if configured, _ := c.DelegationConfigured(); configured &&
			c.MayPresent(ctx, jmsapi.CapDelegation) && c.DelegationUserID == id {
			status, raw, err := c.DelegationRequest(ctx, repository.DelegationCall{
				Method: "DELETE", Path: string(jmsapi.ResSSHKeys) + args.KeyID + "/",
				OperationID: "users.remove_ssh_key",
			})
			if err != nil {
				return render.Failf("%v", err)
			}
			if status >= 400 {
				return render.Failf("the bastion refused the removal: HTTP %d: %s", status, jmsapi.Truncate(string(raw), 300))
			}
			return render.Text(&jmsms.SSHKeyRemoved{
				Removed:    jms.OptInt32(1),
				Username:   args.User,
				UserID:     jms.Opt(id),
				Credential: jms.Opt("single-use Chat AI delegation, already spent"),
				Note:       jms.Opt("the key is revoked; sessions already open keep running until they end"),
			})
		}
		if err := c.Delete(ctx, jmsapi.ResSSHKeys, args.KeyID); err != nil {
			return render.Failf("%v", err)
		}
		return render.Text(&jmsms.SSHKeyRemoved{
			Removed:  jms.OptInt32(1),
			Username: args.User,
			UserID:   jms.Opt(id),
			Note:     jms.Opt("the key is revoked; sessions already open keep running until they end"),
		})
	})

	type userActiveArgs struct {
		User    string `json:"user"`
		Active  bool   `json:"active"`
		Confirm bool   `json:"confirm" jsonschema:"must be true; deactivating a user blocks their access"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_user_set_active",
		Description:  "Enable or disable a JumpServer user. Disabling blocks new sessions without deleting anything. Use it to revoke someone's access without losing their history; jms_user_password_set changes only the password.",
		OutputSchema: render.Schema[jmsms.UserActiveResult](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args userActiveArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to change the user's active state")
		}
		id, err := c.UserIDByName(ctx, args.User)
		if err != nil {
			return render.Failf("%v", err)
		}
		var out map[string]any
		if err := c.Patch(ctx, jmsapi.ResUsers, id, map[string]any{"is_active": args.Active}, &out); err != nil {
			return render.Failf("%v", err)
		}
		return render.Text(&jmsms.UserActiveResult{
			Username: jms.Opt(args.User),
			IsActive: jmsapi.FieldBool(out["is_active"]),
		})
	})
}

// userIDByName resolves a username to its id.

// ---------------------------------------------------------------- permissions

func RegisterPermissionTools(r *reg.Registry, c *repository.Client) {
	type permCreateArgs struct {
		Name     string   `json:"name" jsonschema:"permission name, e.g. 'ai-全部资产'"`
		Users    []string `json:"users,omitempty" jsonschema:"usernames to grant to"`
		Assets   []string `json:"assets,omitempty" jsonschema:"asset refs (name, address or UUID); addresses are the common case"`
		Nodes    []string `json:"nodes,omitempty" jsonschema:"asset tree node paths, e.g. /DEFAULT/studio"`
		AllAccts bool     `json:"all_accounts,omitempty" jsonschema:"grant every account of those assets. Required in practice: an empty accounts list means NO account, which shows up at login as '没有可用的授权账号或终端协议'."`
		Accounts []string `json:"accounts,omitempty" jsonschema:"grant ONLY these accounts, by account name (e.g. 'opsuser') -- least privilege. Mutually exclusive with all_accounts."`
		Confirm  bool     `json:"confirm" jsonschema:"must be true; this grants access to assets"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_permission_create",
		Description: "Create an asset permission granting users access to assets, optionally scoped to a set of accounts. " +
			"Pass all_accounts=true unless restricting accounts is deliberate: an empty accounts list is NOT 'all accounts', it is 'no accounts'. " +
			"For least privilege pass accounts=[\"opsuser\"] instead: it grants only that account name.",
		OutputSchema: render.Schema[jmsms.PermissionCreated](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args permCreateArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to create the permission")
		}
		if args.AllAccts && len(args.Accounts) > 0 {
			return render.Failf("all_accounts and accounts contradict each other: all_accounts grants @ALL, " +
				"accounts grants only the named ones. Pass exactly one")
		}
		if len(args.Users) == 0 && len(args.Nodes) == 0 && len(args.Assets) == 0 {
			return render.Failf("grant something: users, assets or nodes")
		}

		body := map[string]any{"name": args.Name, "is_active": true}

		userIDs := make([]string, 0, len(args.Users))
		for _, u := range args.Users {
			id, err := c.UserIDByName(ctx, u)
			if err != nil {
				return render.Failf("%v", err)
			}
			userIDs = append(userIDs, id)
		}
		if len(userIDs) > 0 {
			body["users"] = repository.IDList(userIDs)
		}

		assetIDs := []string{}
		if len(args.Assets) > 0 {
			ids, _, err := c.ResolveAssets(ctx, args.Assets)
			if err != nil {
				return render.Failf("%v", err)
			}
			assetIDs = ids
			body["assets"] = repository.IDList(assetIDs)
		}

		nodeIDs, err := c.ResolveNodePaths(ctx, args.Nodes)
		if err != nil {
			return render.Failf("%v", err)
		}
		if len(nodeIDs) > 0 {
			body["nodes"] = repository.IDList(nodeIDs)
		}

		if args.AllAccts {
			body["accounts"] = []string{service.AllAccounts}
		} else if len(args.Accounts) > 0 {
			body["accounts"] = args.Accounts
		}

		var out map[string]any
		if err := c.Post(ctx, jmsapi.ResPermissions, body, &out); err != nil {
			return render.Failf("%v", err)
		}
		res := &jmsms.PermissionCreated{
			PermissionID: jmsapi.Str(out["id"]),
			Name:         jmsapi.Str(out["name"]),
			Users:        int32(len(userIDs)),
			Assets:       int32(len(assetIDs)),
			Nodes:        int32(len(nodeIDs)),
		}
		switch {
		case args.AllAccts:
			// Always a list, even for @ALL: the same field then means the
			// same thing in every answer, and ["@ALL"] is what the rest of
			// the contract already says.
			res.Accounts = []string{service.AllAccounts}
		case len(args.Accounts) > 0:
			res.Accounts = args.Accounts
			res.Note = jms.Opt("only the named accounts are granted; any other account of these assets " +
				"will fail at login with '没有可用的授权账号或终端协议'")
		default:
			res.Warning = jms.Opt("accounts was omitted, which grants NO accounts; " +
				"pass all_accounts=true unless that is deliberate")
		}
		return render.Text(res)
	})

	type permGrantArgs struct {
		Permission string   `json:"permission" jsonschema:"permission name or UUID"`
		Users      []string `json:"users,omitempty" jsonschema:"usernames to add"`
		Assets     []string `json:"assets,omitempty" jsonschema:"asset refs to add"`
		AllAccts   bool     `json:"all_accounts,omitempty" jsonschema:"also set accounts to @ALL"`
		Accounts   []string `json:"accounts,omitempty" jsonschema:"also grant these account names (e.g. 'opsuser') for least privilege. A permission that already grants @ALL keeps it: adding names must never narrow access."`
		Confirm    bool     `json:"confirm" jsonschema:"must be true"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_permission_grant",
		Description: "Add users and/or assets to an existing asset permission, e.g. after onboarding a machine. " +
			"Can also promote the permission to @ALL accounts, or grant specific account names for least privilege. " +
			"Granting is additive: a permission that already grants @ALL keeps it, because narrowing access is a different operation.",
		OutputSchema: render.Schema[jmsms.PermissionGrantResult](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args permGrantArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to change the permission")
		}
		if args.AllAccts && len(args.Accounts) > 0 {
			return render.Failf("all_accounts and accounts contradict each other; pass exactly one")
		}
		id, err := c.PermissionIDByName(ctx, args.Permission)
		if err != nil {
			return render.Failf("%v", err)
		}

		// v5 treats a PATCH of a related-object field as REPLACE, not append.
		// Sending only the new asset would silently revoke every other one, so
		// the current set is read back and merged before writing.
		var current map[string]any
		if err := c.Get(ctx, jmsapi.ResPermissions, id, &current); err != nil {
			return render.Failf("%v", err)
		}

		body := map[string]any{}
		// The merged sets are kept aside: they are what the answer reports as
		// "what this permission now grants", and they are only set for the
		// kinds the caller actually asked to change.
		var changedUsers, changedAssets, changedAccounts []string

		if len(args.Users) > 0 {
			add := []string{}
			for _, u := range args.Users {
				uid, err := c.UserIDByName(ctx, u)
				if err != nil {
					return render.Failf("%v", err)
				}
				add = append(add, uid)
			}
			merged := mergeIDs(asStringSlice(current["users"]), add)
			body["users"] = repository.IDList(merged)
			changedUsers = merged
		}
		if len(args.Assets) > 0 {
			aids, _, err := c.ResolveAssets(ctx, args.Assets)
			if err != nil {
				return render.Failf("%v", err)
			}
			merged := mergeIDs(asStringSlice(current["assets"]), aids)
			body["assets"] = repository.IDList(merged)
			changedAssets = merged
		}
		if args.AllAccts {
			body["accounts"] = []string{service.AllAccounts}
			changedAccounts = []string{service.AllAccounts}
		} else if len(args.Accounts) > 0 {
			// PATCH replaces the field, so the current set is merged. The one
			// case where merging would NARROW access is @ALL: replacing it
			// with named accounts would silently revoke the rest, which is a
			// revoke disguised as a grant. @ALL therefore wins.
			currentAccts := asStringSlice(current["accounts"])
			if slicex.Contains(currentAccts, service.AllAccounts) {
				body["accounts"] = []string{service.AllAccounts}
				changedAccounts = []string{service.AllAccounts}
			} else {
				merged := mergeIDs(currentAccts, args.Accounts)
				body["accounts"] = merged
				changedAccounts = merged
			}
		}
		if len(body) == 0 {
			return render.Failf("nothing to grant: pass users, assets, accounts or all_accounts")
		}

		var out map[string]any
		if err := c.Patch(ctx, jmsapi.ResPermissions, id, body, &out); err != nil {
			return render.Failf("%v", err)
		}
		// What was written is the merged set — that is the thing the caller
		// actually wants to know ("now this permission covers whom"), and it
		// is a set of ids, not a yes/no.
		changed := &jmsms.PermissionGrantChange{
			Users:    changedUsers,
			Assets:   changedAssets,
			Accounts: changedAccounts,
		}
		return render.Text(&jmsms.PermissionGrantResult{
			Permission:   jmsapi.FieldStr(out["name"]),
			Changed:      changed,
			UsersAmount:  jmsapi.FieldInt32(out["users_amount"]),
			AssetsAmount: jmsapi.FieldInt32(out["assets_amount"]),
			Accounts:     asStringSlice(out["accounts"]),
			Note: jms.Opt("v5 replaces related-object sets on PATCH; the existing members " +
				"were merged in rather than dropped"),
		})
	})

	type permDeleteArgs struct {
		Permission string `json:"permission" jsonschema:"permission name or UUID"`
		Confirm    bool   `json:"confirm" jsonschema:"must be true; revokes access and cannot be undone"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_permission_delete",
		Description:  "Delete an asset permission. Irreversible: every user loses the access it granted.",
		OutputSchema: render.Schema[jmsms.PermissionDeleted](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args permDeleteArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to delete the permission")
		}
		id, err := c.PermissionIDByName(ctx, args.Permission)
		if err != nil {
			return render.Failf("%v", err)
		}
		var before map[string]any
		_ = c.Get(ctx, jmsapi.ResPermissions, id, &before)
		if err := c.Delete(ctx, jmsapi.ResPermissions, id); err != nil {
			return render.Failf("%v", err)
		}
		return render.Text(&jmsms.PermissionDeleted{
			Deleted: jmsapi.Str(before["name"]),
			ID:      id,
		})
	})
}

// moveSSHPorts moves ssh and sftp to port in a protocol list, in place.
// ssh and sftp ride the same port (sftp is served over ssh); the others
// (rdp, mysql, ...) own their ports and are left alone.
//
// The wire values are re-decoded through JSON on purpose: the resolve step's
// nested values are whatever encoding/json produced (maps and slices of any),
// and a round trip is the honest way to not care which concrete shape arrives.
// (This builds a request BODY — the bastion's own shape — so the rows stay
// maps; the answer-side rule in internal/arch is not what this is.)
// moveSSHPorts moves the ssh-family ports. applied=false means the move did
// NOT happen (the protocols could not be parsed, or carry no ssh/sftp row):
// the caller must say so instead of answering success over a change that
// silently vanished — "the port was not changed" is a fact the operator
// needs, because the repair they came for did not happen.
func moveSSHPorts(v any, port int) (rows []map[string]any, applied bool) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, false
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, false
	}
	for _, m := range rows {
		if name := jmsapi.Str(m["name"]); name == "ssh" || name == "sftp" {
			m["port"] = port
			applied = true
		}
	}
	return rows, applied
}

// resolveNodePaths turns "/DEFAULT/studio" style paths into node ids.

// ---------------------------------------------------------------- assets & accounts

func RegisterAssetWriteTools(r *reg.Registry, c *repository.Client) {
	type assetCreateArgs struct {
		Name      string   `json:"name"`
		Address   string   `json:"address" jsonschema:"IP or hostname"`
		Platform  string   `json:"platform" jsonschema:"platform name, e.g. Linux, macOS, Gateway, Website, Kubernetes"`
		Protocols []string `json:"protocols,omitempty" jsonschema:"protocol specs, e.g. ssh,sftp or with ports mysql:50306. An asset without protocols can never be connected to."`
		SSHPort   int      `json:"ssh_port,omitempty" jsonschema:"port applied to every protocol given without an explicit :port (e.g. 2222 when 22 is taken by a proxy)"`
		Nodes     []string `json:"nodes,omitempty" jsonschema:"asset tree node paths to place it under"`
		Comment   string   `json:"comment,omitempty"`
		Confirm   bool     `json:"confirm" jsonschema:"must be true"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_asset_create",
		Description:  "Register a new asset in JumpServer. Use it when a machine is not under bastion control yet — check jms_assets_list first, so the same machine is not registered twice. Always pass protocols: an asset with none appears in the UI but can never be connected to, and that failure only surfaces at login as 'no authorized account or terminal protocol'.",
		OutputSchema: render.Schema[jmsms.AssetDetail](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args assetCreateArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to create the asset")
		}
		out, err := c.CreateAsset(ctx, repository.AssetSpec{
			Name: args.Name, Address: args.Address, Platform: args.Platform,
			Protocols: args.Protocols, SSHPort: args.SSHPort,
			Nodes: args.Nodes, Comment: args.Comment,
		})
		if err != nil {
			return render.Failf("%v", err)
		}
		// The answer is the same shape as jms_asset_get's: an asset is an
		// asset, and the record that was just written is that shape too.
		detail := assetDetail(out)
		detail.Note = jms.Opt("accounts and permissions are separate; create an account " +
			"and grant access before use")
		return render.Text(detail)
	})

	type assetUpdateArgs struct {
		Asset     string   `json:"asset" jsonschema:"asset address, name or UUID"`
		Name      string   `json:"name,omitempty"`
		Comment   *string  `json:"comment,omitempty" jsonschema:"replace the note; pass an empty string to clear it (omitting leaves it unchanged)"`
		Platform  string   `json:"platform,omitempty" jsonschema:"change the platform, e.g. Gateway -> Linux when the box is a real host that was mislabelled"`
		Protocols []string `json:"protocols,omitempty" jsonschema:"replaces the whole protocol list; each spec may carry its own port, e.g. ssh:2222"`
		SSHPort   int      `json:"ssh_port,omitempty" jsonschema:"move the ssh/sftp ports to this one; with protocols given it is the default port for specs that carry no :port of their own"`
		Active    *bool    `json:"active,omitempty" jsonschema:"enable or disable the asset"`
		Confirm   bool     `json:"confirm" jsonschema:"must be true"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_asset_update",
		Description: "Change an asset. Two repairs it makes easy are common in practice: adding protocols an asset lacks " +
			"(it exists in the UI but can never be connected to), and correcting a wrong port (an HAProxy listening on 2222 " +
			"while the asset was registered on 22 shows up as an authentication error, not a connection error).",
		OutputSchema: render.Schema[jmsms.AssetUpdated](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args assetUpdateArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to change the asset")
		}
		_, meta, err := c.ResolveAssets(ctx, []string{args.Asset})
		if err != nil {
			return render.Failf("%v", err)
		}
		id := jmsapi.Str(meta[0]["id"])

		body := map[string]any{}
		if args.Name != "" {
			body["name"] = args.Name
		}
		// A pointer so "" can CLEAR the note while omitting it leaves it
		// alone — the three-state split (absent / empty / set) that a bare
		// string collapses: `!= ""` treats an intentional "" as "not given",
		// so the comment could never be emptied. (The ACL updates were fixed
		// for exactly this; the asset missed that round.)
		if args.Comment != nil {
			body["comment"] = *args.Comment
		}
		if args.Active != nil {
			body["is_active"] = *args.Active
		}
		if args.Platform != "" {
			pid, err := c.PlatformIDByName(ctx, args.Platform)
			if err != nil {
				return render.Failf("%v", err)
			}
			body["platform"] = pid
		}
		if len(args.Protocols) > 0 {
			body["protocols"] = repository.BuildProtocols(args.Protocols, args.SSHPort)
		} else if args.SSHPort > 0 {
			// ssh_port ALONE is "move the ssh-family ports" — the tool's
			// description sells exactly this repair (an HAProxy on 2222 while
			// the asset says 22 reads as an authentication error), and
			// dropping the bare int silently turned the promise into "nothing
			// to change". The other protocols keep their own ports.
			//
			// Read-modify-write: the resolve meta carries only id/name/
			// address/platform, so the current protocol list is read back
			// first (the same before-read jms_asset_delete does).
			var cur map[string]any
			if err := c.Get(ctx, jmsapi.ResAssets, id, &cur); err != nil {
				return render.Failf("%v", err)
			}
			protos, applied := moveSSHPorts(cur["protocols"], args.SSHPort)
			if !applied {
				// The move did not happen. Saying "updated" here would
				// hand back a success over a repair that never landed.
				return render.Failf("ssh_port=%d, but this asset's protocols carry no ssh/sftp entry (or could not be read back) — nothing was changed", args.SSHPort)
			}
			body["protocols"] = protos
		}
		if len(body) == 0 {
			return render.Failf("nothing to change")
		}

		var out map[string]any
		if err := c.Patch(ctx, jmsapi.ResAssets, id, body, &out); err != nil {
			return render.Failf("%v", err)
		}
		return render.Text(&jmsms.AssetUpdated{
			ID:        jms.Opt(id),
			Name:      jmsapi.FieldStr(out["name"]),
			Address:   jmsapi.FieldStr(out["address"]),
			Platform:  jmsapi.FieldStr(jmsapi.Nested(out, "platform", "name")),
			Protocols: assetProtocolRefs(out["protocols"]),
			IsActive:  jmsapi.FieldBool(out["is_active"]),
		})
	})

	type assetDeleteArgs struct {
		Asset   string `json:"asset"`
		Confirm bool   `json:"confirm" jsonschema:"must be true; deletes the asset and its accounts"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_asset_delete",
		Description:  "Delete an asset. Irreversible, and it removes the asset's accounts too. Use it when a machine is decommissioned for good; to stop a stale account being usable, use jms_account_update with active=false instead.",
		OutputSchema: render.Schema[jmsms.AssetDeleted](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args assetDeleteArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to delete the asset")
		}
		_, meta, err := c.ResolveAssets(ctx, []string{args.Asset})
		if err != nil {
			return render.Failf("%v", err)
		}
		id := jmsapi.Str(meta[0]["id"])
		var before map[string]any
		_ = c.Get(ctx, jmsapi.ResAssets, id, &before)
		if err := c.Delete(ctx, jmsapi.ResAssets, id); err != nil {
			return render.Failf("%v", err)
		}
		return render.Text(&jmsms.AssetDeleted{
			Deleted: jmsapi.Str(before["name"]),
			ID:      id,
			Address: jmsapi.FieldStr(before["address"]),
		})
	})

	type accountUpdateArgs struct {
		Asset    string `json:"asset" jsonschema:"asset address, name or UUID"`
		Account  string `json:"account" jsonschema:"account username on that asset"`
		Password string `json:"password,omitempty" jsonschema:"new secret; write-only, never readable afterwards"`
		Active   *bool  `json:"active,omitempty" jsonschema:"enable or disable this account. Disabling an account whose secret is wrong is usually the right fix: it stops the bastion testing a credential that cannot work and reporting the asset as broken."`
		Confirm  bool   `json:"confirm" jsonschema:"must be true"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_account_update",
		Description: "Change an asset account's secret or active state. Secrets are write-only. " +
			"Disabling an unusable account is the clean fix for an 'authentication error' connectivity state that is really just a stale credential.",
		OutputSchema: render.Schema[jmsms.AccountUpdated](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args accountUpdateArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to change the account")
		}
		ids, _, err := c.ResolveAssets(ctx, []string{args.Asset})
		if err != nil {
			return render.Failf("%v", err)
		}
		accID, err := c.AccountID(ctx, ids[0], args.Account)
		if err != nil {
			return render.Failf("%v", err)
		}
		body := map[string]any{}
		if args.Password != "" {
			body["secret"] = args.Password
		}
		if args.Active != nil {
			body["is_active"] = *args.Active
		}
		if len(body) == 0 {
			return render.Failf("nothing to change: pass password or active")
		}
		var out map[string]any
		if err := c.Patch(ctx, jmsapi.ResAccounts, accID, body, &out); err != nil {
			return render.Failf("%v", err)
		}
		res := &jmsms.AccountUpdated{
			ID:         jmsapi.Str(out["id"]),
			Username:   jmsapi.FieldStr(out["username"]),
			IsActive:   jmsapi.FieldBool(out["is_active"]),
			SecretType: jms.Opt(jmsapi.Label(out, "secret_type")),
			Asset:      jmsapi.FieldStr(jmsapi.Nested(out, "asset", "name")),
		}
		if args.Password != "" {
			res.SecretWritten = jms.OptBool(true)
			res.SecretReadable = jms.OptBool(false)
		}
		return render.Text(res)
	})

	type accountDeleteArgs struct {
		Asset   string `json:"asset" jsonschema:"asset name, address or UUID"`
		Account string `json:"account" jsonschema:"account username on that asset"`
		Confirm bool   `json:"confirm" jsonschema:"must be true; this removes the account from the bastion"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_account_delete",
		Description: "Delete an asset account from the bastion. This only removes JumpServer's record of it — " +
			"the user on the host is untouched. Use it to undo a jms_gather_apply, or to drop an account that no " +
			"longer exists on the machine. To keep the record but stop it being usable, use jms_account_update " +
			"with active=false instead.",
		OutputSchema: render.Schema[jmsms.AccountDeleted](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args accountDeleteArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true; this deletes the account")
		}
		ids, meta, err := c.ResolveAssets(ctx, []string{args.Asset})
		if err != nil {
			return render.Failf("%v", err)
		}
		accID, err := c.AccountID(ctx, ids[0], args.Account)
		if err != nil {
			return render.Failf("%v", err)
		}
		if err := c.Delete(ctx, jmsapi.ResAccounts, accID); err != nil {
			return render.Failf("%v", err)
		}
		// Read back, because a 204 here is the whole confirmation v5 offers and
		// the caller's assumption ("it is gone now") should not rest on that.
		if _, err := c.AccountID(ctx, ids[0], args.Account); err == nil {
			return render.Failf("delete returned without error but the account is still present; "+
				"check jms_accounts_list for asset %v", meta[0]["name"])
		}
		return render.Text(&jmsms.AccountDeleted{
			Deleted: args.Account,
			Asset:   jmsapi.FieldStr(meta[0]["name"]),
			Note:    jms.Opt("the host account itself was not touched; only the bastion's record is gone"),
		})
	})
}

// JumpServer v5 does not use one wire format for related-object fields. The
// same field name wants different shapes on different endpoints, and each
// rejects the other with a message that never states which shape it wants.
// Verified against the live API on 2026-10-14:
//
//	/perms/asset-permissions/    users, assets, nodes, accounts  -> plain arrays
//	/acls/command-filter-acls/    users                            -> envelope
//	                              accounts, command_groups        -> plain arrays
//
// So the choice is per endpoint, not per field name, which is why these two
// helpers are named for what they emit rather than for the field they fill.

// mergeIDs unions two id lists, preserving order and dropping duplicates.
func mergeIDs(existing, add []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(existing)+len(add))
	for _, id := range append(append([]string{}, existing...), add...) {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// asStringSlice pulls ids out of a related-object field. v5 returns these as
// [{"id": "...", "name": "..."}] on read, while the write side wants bare UUID
// strings, so both shapes are accepted here.
func asStringSlice(v any) []string {
	var out []string
	add := func(x any) {
		switch t := x.(type) {
		case string:
			if t != "" {
				out = append(out, t)
			}
		case map[string]any:
			if id, ok := t["id"].(string); ok && id != "" {
				out = append(out, id)
			}
		}
	}
	switch t := v.(type) {
	case []string:
		out = append(out, t...)
	case []any:
		for _, x := range t {
			add(x)
		}
	}
	return out
}

// assetProtocolRefs turns the bastion's protocol list into the contract's
// protocol references.
//
// The bastion answers with the whole protocol record; the contract keeps the
// two fields that say what the protocol IS (its name and its port).
func assetProtocolRefs(v any) []*jmsms.ProtocolRef {
	out := []*jmsms.ProtocolRef{}
	for _, p := range jmsapi.AsSlice(v) {
		switch t := p.(type) {
		case string:
			out = append(out, &jmsms.ProtocolRef{Name: jms.Opt(t)})
		case map[string]any:
			out = append(out, &jmsms.ProtocolRef{
				Name: jmsapi.FieldStr(t["name"]),
				Port: jmsapi.FieldInt32(t["port"]),
			})
		}
	}
	return out
}

// assetCreateEndpoint picks the collection to POST into for a platform.
//
// /assets/assets/ is the read/aggregate view and refuses direct creation:
// "Assets cannot be created directly; you should create a host or other asset
// instead". Each platform carries a category, and the category maps to a
// concrete collection. Posting a host to the wrong collection fails too, with
// "Platform does not match: ...".

// idList emits a plain array of UUIDs, which is what most v5 endpoints want.

// m2mEnvelope emits {type:ids|all, ...}. Only a few fields accept this;
// sending it elsewhere yields "“type” is not a valid UUID".
func m2mEnvelope(ids []string) any {
	if len(ids) == 0 {
		return map[string]any{"type": "all"}
	}
	return map[string]any{"type": "ids", "ids": ids}
}

// buildProtocols turns protocol specs into the dict form the API demands.
// Passing a plain string array instead is a 400.
//
// A spec may be "name" or "name:port", because the port override is not only
// useful for ssh: a MySQL asset on 50306 is exactly as common as an SSH one
// behind a proxy on 2222. The optional defaultPort applies to plain names.

// defaultProtocolPort mirrors the defaults a platform would have assigned.

// ---------------------------------------------------------------- ops

func RegisterOpsTools(r *reg.Registry, c *repository.Client) {
	type connCheckArgs struct {
		Assets []string `json:"assets,omitempty" jsonschema:"asset refs to test; empty means every asset"`
		Wait   int      `json:"wait,omitempty" jsonschema:"seconds to wait for the workers (default 45, max 180)"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_connectivity_check",
		Description: "Trigger a real connectivity test and report the resulting state. The value shown in the UI is only as " +
			"fresh as the last test, so re-run this before trusting it. Read it carefully: 'err' often means no service on " +
			"that port at all (a router with only 80/443), which is not something to fix. Website, Kubernetes and Redis " +
			"platforms do not support the test at all.",
		OutputSchema: render.Schema[jmsms.ConnectivityReport](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args connCheckArgs) (*mcp.CallToolResult, any, error) {
		all, err := c.List(ctx, jmsapi.ResAssets)
		if err != nil {
			return render.Failf("%v", err)
		}

		want := map[string]bool{}
		if len(args.Assets) > 0 {
			ids, _, err := c.ResolveAssets(ctx, args.Assets)
			if err != nil {
				return render.Failf("%v", err)
			}
			for _, id := range ids {
				want[id] = true
			}
		}

		tested := 0
		unsupported := []string{}
		for _, a := range all {
			id := jmsapi.Str(a["id"])
			if len(want) > 0 && !want[id] {
				continue
			}
			var resp map[string]any
			if err := c.PostSub(ctx, jmsapi.ResAssets, id, "tasks", map[string]any{"action": "test"}, &resp); err != nil {
				unsupported = append(unsupported, jmsapi.Str(a["name"]))
				continue
			}
			tested++
		}

		wait := args.Wait
		if wait <= 0 {
			wait = 45
		}
		if wait > 180 {
			wait = 180
		}

		// Poll until the states stop changing so the answer is never half-run.
		prev := ""
		for waited := 0; waited < wait; waited += 5 {
			time.Sleep(5 * time.Second)
			rows, err := c.List(ctx, jmsapi.ResAssets)
			if err != nil {
				continue
			}
			states := map[string]string{}
			for _, a := range rows {
				states[jmsapi.Str(a["id"])] = jmsapi.Label(a, "connectivity")
			}
			b, _ := json.Marshal(states)
			if string(b) == prev {
				break
			}
			prev = string(b)
		}

		rows, err := c.List(ctx, jmsapi.ResAssets)
		if err != nil {
			return render.Failf("%v", err)
		}
		byState := map[string][]*jmsms.ConnectivityRow{}
		for _, a := range rows {
			id := jmsapi.Str(a["id"])
			if len(want) > 0 && !want[id] {
				continue
			}
			st := jmsapi.Label(a, "connectivity")
			if st == "" {
				st = "-"
			}
			byState[st] = append(byState[st], &jmsms.ConnectivityRow{
				Asset:    jmsapi.FieldStr(a["name"]),
				Address:  jmsapi.FieldStr(a["address"]),
				Platform: jmsapi.FieldStr(jmsapi.Nested(a, "platform", "name")),
			})
		}

		res := &jmsms.ConnectivityReport{
			Tested:        jms.OptInt32(int32(tested)),
			WaitedSeconds: jms.OptInt32(int32(wait)),
			Summary: &jmsms.ConnectivitySummary{
				Ok:        jms.OptInt32(int32(len(byState["ok"]))),
				Err:       jms.OptInt32(int32(len(byState["err"]))),
				NotTested: jms.OptInt32(int32(len(byState["-"]))),
			},
			Ok:  byState["ok"],
			Err: byState["err"],
			// The third state: the platform has no connectivity test at all
			// (Website, Kubernetes, Redis). Those assets are neither
			// connected nor broken, and saying so is the whole point -- the
			// note below says what the state means.
			NotTested: byState["-"],
			Note: jms.Opt("state '-' means the platform has no test. For 'err' on a router or appliance with only " +
				"80/443 open, there is no SSH to find and the entry is correct as it is."),
		}
		if len(unsupported) > 0 {
			slices.Sort(unsupported)
			res.PlatformsWithoutTest = unsupported
		}
		return render.Text(res)
	})

	type liveArgs struct {
		Limit int `json:"limit,omitempty" jsonschema:"max rows (default 30)"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_sessions_live",
		Description:  "List currently open terminal sessions with user, asset and remote address. Use it to see who is connected right now; jms_sessions_list is the history behind them.",
		OutputSchema: render.Schema[render.ListOf[jmsms.SessionSummary]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args liveArgs) (*mcp.CallToolResult, any, error) {
		rows, err := c.List(ctx, jmsapi.ResSessions)
		if err != nil {
			return render.Failf("%v", err)
		}
		// filter → map → sort → truncate → count: render.ListSpec owns the
		// order and the three counting fields. Sorting before the cap is
		// what keeps the NEWEST live sessions rather than whichever rows the
		// endpoint returned first -- the old loop capped before it sorted, so
		// limit=N answered "N rows in the endpoint's order, sorted among
		// themselves". total is how many live sessions matched, before the
		// cap.
		return render.Text(render.ListSpec[map[string]any, jmsms.SessionSummary]{
			Rows: rows,
			Keep: func(s map[string]any) bool {
				// The endpoint has no user_display / asset_display fields; the
				// user and asset keys carry the "name(address)" label directly.
				// Filtering on is_finished is what makes this "live": the listing
				// endpoint returns the whole history, finished sessions included.
				if fin, ok := s["is_finished"].(bool); ok && fin {
					return false
				}
				return true
			},
			Map: func(s map[string]any) jmsms.SessionSummary {
				return jmsms.SessionSummary{
					ID:         jmsapi.Str(s["id"]),
					User:       jmsapi.FieldStr(s["user"]),
					Asset:      jmsapi.FieldStr(jmsapi.AssetField(s, "name")),
					Address:    jmsapi.FieldStr(jmsapi.AssetField(s, "address")),
					Account:    jmsapi.FieldStr(s["account"]),
					Protocol:   jmsapi.FieldStr(jmsapi.FieldName(s, "protocol")),
					Type:       jmsapi.FieldStr(jmsapi.Label(s, "type")),
					RemoteAddr: jmsapi.FieldStr(s["remote_addr"]),
					DateStart:  jmsapi.FieldStr(s["date_start"]),
					IsFinished: jmsapi.FieldBool(s["is_finished"]),
				}
			},
			Less:  func(a, b jmsms.SessionSummary) bool { return a.GetDateStart() > b.GetDateStart() },
			Limit: args.Limit,
			Def:   30,
			Max:   100,
		}.Build())
	})
}

// ---------------------------------------------------------------- helpers

// listAll fetches a collection and unpacks it into maps.
//
// Two things make this non-obvious, both measured 2026-10-15:
//
//   - v5 returns EITHER a bare array or a {count, results} envelope depending on
//     the endpoint, and sometimes on the parameters. `list` accepts both.
//   - passing `page_size` alone leaves the server on its own cap of 200 rows.
//     /audits/operate-logs/ has 335 rows and returned exactly 200 that way. Add
//     `limit` and the endpoint switches to real pagination, so page explicitly.
//
// So: walk pages with limit+offset until a short page comes back.

// assetSpec is what it takes to register one asset. It exists so the single
// and the bulk path build the same body -- a bulk registration that behaves
// slightly differently from the single one is a very hard bug to see.

// createAsset registers one asset and returns the created record.

// checkRSAPublicKey says whether this is exactly one usable ssh-rsa public
// key.
//
// Three rules, each for a reason:
//
//   - **exactly one key**: the bastion stores the WHOLE string, while the
//     public-key parser judges only the first line it can parse. A two-line
//     input (ed25519 first, rsa second) would therefore pass the check and
//     then be stored as two keys -- and the bastion accepts the ed25519 one
//     silently. That is exactly the failure this tool exists to prevent.
//   - **the first field says the type**: the type is read off the key's own
//     first field, not off "whichever line happened to parse".
//   - **the key is usable**: the type being right is not enough -- the body
//     still has to be a real public key, or the bastion stores it and the
//     login fails later, looking exactly like a permission problem.
//
// It is a pure function so it can be tested without a bastion.
func checkRSAPublicKey(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("public_key is empty")
	}
	// The multi-key check comes FIRST, before the type is read: a two-line
	// input whose first line is ed25519 would otherwise be reported as "you
	// gave me an ed25519 key", when the real problem is that the string is
	// two keys and the bastion would store both.
	if strings.ContainsAny(key, "\n\r") {
		return fmt.Errorf("public_key must be exactly one key: the bastion stores the whole " +
			"string, and the first parsable line is not the one it will use")
	}
	fields := strings.Fields(key)
	if fields[0] != "ssh-rsa" {
		if fields[0] == "ssh-ed25519" {
			return fmt.Errorf("koko does not accept ed25519 keys. Convert it first: " +
				"ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa, then register that public key")
		}
		return fmt.Errorf("public_key must start with 'ssh-rsa ', got %q", fields[0])
	}
	// ParseSinglePublicKey, not ParsePublicKey: the parser judges the first
	// parsable line, the bastion stores the whole string. Parsing must
	// answer the same question as the store.
	if _, err := sshx.ParseSinglePublicKey(key); err != nil {
		return fmt.Errorf("public_key is not a usable SSH public key: %w", err)
	}
	return nil
}
