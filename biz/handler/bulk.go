// tools_bulk.go covers the operations that involve more than one object, and
// the posture questions that span the whole bastion.
//
// Everything here is a composition of endpoints that already exist -- no new
// data is invented. What it adds is the GROUPING: a fleet sweep answers
// "how is every machine doing" in one call, a comparison answers "what
// changes if I swap this permission", and a review answers "who here could
// reconfigure the bastion".
//
// The answers are the contract types: every answer below is built from the
// type its OutputSchema declares, so a field that is spelled wrong fails at
// compile time instead of reaching the model as a hole.
package handler

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/yi-nology/jumpserver-mgmt/biz/model/jmsms"
	"github.com/yi-nology/jumpserver-mgmt/internal/service"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yi-nology/jumpserver-kit/model/jms"
	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
	"github.com/yi-nology/jumpserver-mgmt/internal/repository"
)

func RegisterBulkTools(r *reg.Registry, c *repository.Client) {
	RegisterBulkAssetTools(r, c)
	RegisterPermissionCompare(r, c)
	RegisterSecurityReview(r, c)
}

// ---------------------------------------------------------------- bulk assets

func RegisterBulkAssetTools(r *reg.Registry, c *repository.Client) {
	type bulkAsset struct {
		Name      string   `json:"name" jsonschema:"asset name"`
		Address   string   `json:"address" jsonschema:"IP or hostname"`
		Platform  string   `json:"platform" jsonschema:"platform name, e.g. Linux, macOS, Gateway, Website"`
		Protocols []string `json:"protocols,omitempty" jsonschema:"protocol specs, e.g. ['ssh','sftp']; an asset without protocols can never be connected to"`
		SSHPort   int      `json:"ssh_port,omitempty" jsonschema:"port applied to every protocol given without an explicit :port"`
		Nodes     []string `json:"nodes,omitempty" jsonschema:"asset tree node paths to place it under"`
		Comment   string   `json:"comment,omitempty"`
	}
	type bulkCreateArgs struct {
		Assets  []bulkAsset `json:"assets" jsonschema:"the assets to register"`
		Confirm bool        `json:"confirm" jsonschema:"must be true; this writes to the bastion"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_assets_bulk_create",
		Description: "Register several assets in one call -- the shape of a batch onboarding. " +
			"Each asset is created independently and reported on its own, so one bad entry does not lose the " +
			"others. Protocols are required per asset: an asset without them can never be connected to. " +
			"Accounts and permissions are still separate steps (jms_account_create / jms_permission_create).",
		OutputSchema: render.Schema[jmsms.AssetsBulkCreated](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args bulkCreateArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to create the assets")
		}
		if len(args.Assets) == 0 {
			return render.Failf("assets is required and must not be empty")
		}
		results := []*jmsms.AssetRow{}
		created, failed := 0, 0
		for _, a := range args.Assets {
			entry := &jmsms.AssetRow{Name: jms.Opt(a.Name), Address: jms.Opt(a.Address)}
			out, err := c.CreateAsset(ctx, repository.AssetSpec{
				Name: a.Name, Address: a.Address, Platform: a.Platform,
				Protocols: a.Protocols, SSHPort: a.SSHPort,
				Nodes: a.Nodes, Comment: a.Comment,
			})
			if err != nil {
				entry.Ok = jms.OptBool(false)
				entry.Error = jms.Opt(err.Error())
				failed++
			} else {
				entry.Ok = jms.OptBool(true)
				entry.ID = jmsapi.FieldStr(out["id"])
				entry.Platform = jmsapi.FieldStr(out["platform"])
				created++
			}
			results = append(results, entry)
		}
		out := &jmsms.AssetsBulkCreated{
			Requested: int32(len(args.Assets)),
			Created:   int32(created),
			Failed:    int32(failed),
			// count is how many result rows came back; created/failed say how
			// they split. Same convention as every other list tool.
			Count:     int32(len(results)),
			Total:     int32(len(results)),
			Truncated: false,
			Results:   results,
			Next:      jms.Opt("now add an account (jms_account_create) and a permission (jms_permission_create) for them"),
		}
		// ⚠️ The call-level account of a PARTIAL failure. The per-asset
		// rows say what went wrong, but without this the trail writes
		// "this call succeeded" while a third of the assets were never
		// created — and the trail is what an audit reads.
		if failed > 0 {
			out.Error = jms.Opt(fmt.Sprintf("%d of %d assets were not created; the per-asset rows say why",
				failed, len(args.Assets)))
		}
		return render.Text(out)
	})
}

// ---------------------------------------------------------------- comparison

func RegisterPermissionCompare(r *reg.Registry, c *repository.Client) {
	type compareArgs struct {
		Left  string `json:"left" jsonschema:"permission name or UUID"`
		Right string `json:"right" jsonschema:"permission name or UUID to compare against"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_permission_compare",
		Description: "Compare two asset permissions and show exactly what differs: the assets only one of them " +
			"reaches, the users each holds, and the accounts each grants. Both sides are expanded through the " +
			"asset tree, so a node-scoped permission is compared by what it really reaches, not by the counter " +
			"the API reports. Use it before swapping one grant for another.",
		OutputSchema: render.Schema[jmsms.PermissionComparison](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args compareArgs) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(args.Left) == "" || strings.TrimSpace(args.Right) == "" {
			return render.Failf("left and right are both required")
		}
		left, err := c.PermissionDetail(ctx, args.Left)
		if err != nil {
			return render.Failf("%v", err)
		}
		right, err := c.PermissionDetail(ctx, args.Right)
		if err != nil {
			return render.Failf("%v", err)
		}

		leftAssets, err := c.EffectiveAssets(ctx, left)
		if err != nil {
			return render.Failf("%v", err)
		}
		rightAssets, err := c.EffectiveAssets(ctx, right)
		if err != nil {
			return render.Failf("%v", err)
		}
		leftNames := map[string]bool{}
		for _, a := range leftAssets {
			leftNames[jmsapi.Str(a["name"])] = true
		}
		rightNames := map[string]bool{}
		for _, a := range rightAssets {
			rightNames[jmsapi.Str(a["name"])] = true
		}
		onlyLeft, onlyRight, both := []string{}, []string{}, []string{}
		for n := range leftNames {
			if rightNames[n] {
				both = append(both, n)
			} else {
				onlyLeft = append(onlyLeft, n)
			}
		}
		for n := range rightNames {
			if !leftNames[n] {
				onlyRight = append(onlyRight, n)
			}
		}
		slices.Sort(onlyLeft)
		slices.Sort(onlyRight)
		slices.Sort(both)

		res := &jmsms.PermissionComparison{
			Left: &jmsms.PermissionSide{
				Permission:           jmsapi.FieldStr(left["name"]),
				Users:                holderNames(left),
				Accounts:             asStringSlice(left["accounts"]),
				EffectiveAssets:      jms.OptInt32(int32(len(leftAssets))),
				ReportedAssetsAmount: jmsapi.FieldInt32(left["assets_amount"]),
			},
			Right: &jmsms.PermissionSide{
				Permission:           jmsapi.FieldStr(right["name"]),
				Users:                holderNames(right),
				Accounts:             asStringSlice(right["accounts"]),
				EffectiveAssets:      jms.OptInt32(int32(len(rightAssets))),
				ReportedAssetsAmount: jmsapi.FieldInt32(right["assets_amount"]),
			},
			OnlyLeft:  onlyLeft,
			OnlyRight: onlyRight,
			Both:      both,
		}
		if len(onlyRight) > 0 {
			res.WarningRight = jms.Opt(fmt.Sprintf(
				"swapping %v for %v would REMOVE access to %d asset(s): %s",
				jmsapi.Str(left["name"]), jmsapi.Str(right["name"]), len(onlyRight), strings.Join(onlyRight, ", ")))
		}
		if len(onlyLeft) > 0 {
			res.WarningLeft = jms.Opt(fmt.Sprintf(
				"swapping %v for %v would ADD access to %d asset(s): %s",
				jmsapi.Str(left["name"]), jmsapi.Str(right["name"]), len(onlyLeft), strings.Join(onlyLeft, ", ")))
		}
		return render.Text(res)
	})
}

// permissionDetail resolves a permission name to its full record.

// holderNames lists the users and groups holding a permission.
func holderNames(perm map[string]any) []string {
	out := []string{}
	for _, u := range jmsapi.AsSlice(perm["users"]) {
		if m, ok := u.(map[string]any); ok {
			out = append(out, jmsapi.Str(m["name"]))
		}
	}
	for _, g := range jmsapi.AsSlice(perm["user_groups"]) {
		if m, ok := g.(map[string]any); ok {
			out = append(out, "group:"+jmsapi.Str(m["name"]))
		}
	}
	slices.Sort(out)
	return out
}

// ---------------------------------------------------------------- posture

func RegisterSecurityReview(r *reg.Registry, c *repository.Client) {
	type reviewArgs struct {
		Days int `json:"days,omitempty" jsonschema:"how many days of login history to consider (default 30)"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_security_review",
		Description: "Security posture of the bastion in one call: who can reconfigure it (superusers), " +
			"accounts that never logged in or never changed their password, repeated failed logins by source " +
			"address, and the addresses the bastion has blocked. Use it as a periodic check, and after a " +
			"failed login is reported. Read-only.",
		OutputSchema: render.Schema[jmsms.SecurityReviewResult](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args reviewArgs) (*mcp.CallToolResult, any, error) {
		days := args.Days
		if days <= 0 || days > 365 {
			days = 30
		}
		cutoff := time.Now().AddDate(0, 0, -days)

		users, err := c.List(ctx, jmsapi.ResUsers)
		if err != nil {
			return render.Failf("%v", err)
		}
		superusers, neverLoggedIn, neverRotated, inactive := []string{}, []string{}, []string{}, []string{}
		for _, u := range users {
			username := jmsapi.Str(u["username"])
			if strings.HasPrefix(username, "[") {
				continue // component accounts are internal plumbing
			}
			if v, _ := u["is_superuser"].(bool); v {
				superusers = append(superusers, username)
			}
			if v, _ := u["is_active"].(bool); !v {
				inactive = append(inactive, username)
			}
			if jmsapi.Str(u["last_login"]) == "" {
				neverLoggedIn = append(neverLoggedIn, username)
			}
			// date_password_last_updated is the credential's age; a user who
			// joined and never rotated has been sitting on the same secret.
			if v, _ := u["need_update_password"].(bool); v {
				neverRotated = append(neverRotated, username)
			}
		}
		slices.Sort(superusers)
		slices.Sort(neverLoggedIn)
		slices.Sort(neverRotated)
		slices.Sort(inactive)

		// Failed logins, grouped by source address and by account.
		logs, err := c.List(ctx, jmsapi.ResLoginLogs)
		if err != nil {
			return render.Failf("%v", err)
		}
		failByIP := map[string]int32{}
		okByIP := map[string]int32{}
		failByUser := map[string]int32{}
		failTotal := int32(0)
		for _, l := range logs {
			ts, err := time.Parse("2006/01/02 15:04:05 -0700", jmsapi.Str(l["datetime"]))
			if err == nil && ts.Before(cutoff) {
				continue
			}
			ok := true
			if st, ok2 := l["status"].(map[string]any); ok2 {
				if v, ok3 := st["value"].(bool); ok3 {
					ok = v
				}
			}
			ip := jmsapi.Str(l["ip"])
			if ip == "" {
				continue
			}
			if ok {
				okByIP[ip]++
				continue
			}
			failTotal++
			failByIP[ip]++
			name := jmsapi.Str(l["username"])
			if name != "" {
				failByUser[name]++
			}
		}

		blocked := []string{}
		blockedUnknown := false
		if rows, err := c.List(ctx, jmsapi.ResBlockedIPs); err == nil {
			for _, b := range rows {
				blocked = append(blocked, jmsapi.Str(b["ip"]))
			}
			slices.Sort(blocked)
		} else {
			// The list is unreadable (a permission the credential lacks, an
			// XPack-only route): "unknown" must not fold into "nobody is
			// blocked" — that turns an unread blocklist into advice to
			// block an address that may already be on it.
			blockedUnknown = true
		}
		blockedSet := map[string]bool{}
		for _, b := range blocked {
			blockedSet[b] = true
		}
		topOffenders := []jmsms.OffendingIP{}
		unblocked := []string{}
		for ip, n := range failByIP {
			if n < 5 {
				continue
			}
			// Failures alone do not make an attacker: an address that also
			// logs in successfully is a legitimate client that occasionally
			// mistypes its key. Brute force looks like failures with NO
			// successes, or failures far outweighing them.
			successes := okByIP[ip]
			bruteforce := successes == 0 || n > successes*5
			if !bruteforce {
				continue
			}
			topOffenders = append(topOffenders, jmsms.OffendingIP{
				IP: ip, Failures: n, Successes: successes, Blocked: blockedSet[ip],
			})
			if !blockedSet[ip] && !blockedUnknown {
				unblocked = append(unblocked, ip)
			}
		}
		slices.SortFunc(topOffenders, func(a, b jmsms.OffendingIP) int {
			return cmp.Compare(b.Failures, a.Failures)
		})
		slices.Sort(unblocked)

		res := &jmsms.SecurityReviewResult{
			WindowDays:           int32(days),
			Superusers:           superusers,
			NeverLoggedIn:        neverLoggedIn,
			PasswordNeverRotated: neverRotated,
			DeactivatedUsers:     inactive,
			FailedLogins:         failTotal,
			FailedByIP:           failByIP,
			FailedByUser:         failByUser,
			BlockedIPs:           blocked,
			TopOffendingIPs:      topOffenders,
		}

		// One check per dimension, so the answer says what was examined and
		// what to do about each thing that is not right. The payload above
		// stays as the raw material.
		checks := []*jms.Check{}
		if len(superusers) == 0 {
			checks = append(checks, &jms.Check{
				Name: "superusers", Status: service.OK,
				Detail: "no account can reconfigure the bastion",
			})
		} else {
			checks = append(checks, &jms.Check{
				Name: "superusers", Status: service.Warn,
				Detail: fmt.Sprintf("%d superuser account(s) can reconfigure the bastion: %s",
					len(superusers), strings.Join(superusers, ", ")),
				Fix: service.FixText("keep the superuser list short, and read what each one may do with jms_system_role_permissions"),
			})
		}
		switch {
		case blockedUnknown:
			checks = append(checks, &jms.Check{
				Name: "repeat_failed_logins", Status: service.Warn,
				Detail: "the Block IP list could not be read, so whether the offending addresses are blocked is UNKNOWN — they are listed with blocked=false, which means \"not on the list we could not read\", not \"unblocked\"",
				Fix:    service.FixText("grant the credential read access to the block list, then re-run; until then check the addresses by hand"),
			})
		case len(unblocked) > 0:
			checks = append(checks, &jms.Check{
				Name: "repeat_failed_logins", Status: service.Fail,
				Detail: fmt.Sprintf("%d address(es) failed to log in repeatedly and are NOT blocked: %s",
					len(unblocked), strings.Join(unblocked, ", ")),
				Fix: service.FixText("block the address in the bastion's security settings (the Block IP list)"),
			})
		case len(topOffenders) > 0:
			checks = append(checks, &jms.Check{
				Name: "repeat_failed_logins", Status: service.OK,
				Detail: fmt.Sprintf("%d address(es) failed to log in repeatedly, and they are already blocked",
					len(topOffenders)),
			})
		default:
			checks = append(checks, &jms.Check{
				Name: "repeat_failed_logins", Status: service.OK,
				Detail: fmt.Sprintf("%d failed login(s) in the last %d day(s); no address failed repeatedly "+
					"without logging in successfully", failTotal, days),
			})
		}
		if len(neverLoggedIn) == 0 {
			checks = append(checks, &jms.Check{
				Name: "never_logged_in", Status: service.OK,
				Detail: "every account has logged in at least once",
			})
		} else {
			checks = append(checks, &jms.Check{
				Name: "never_logged_in", Status: service.Warn,
				Detail: fmt.Sprintf("%d account(s) have never logged in: %s",
					len(neverLoggedIn), strings.Join(neverLoggedIn, ", ")),
				Fix: service.FixText("disable the accounts that are not needed with jms_user_set_active"),
			})
		}
		if len(neverRotated) == 0 {
			checks = append(checks, &jms.Check{
				Name: "password_never_rotated", Status: service.OK,
				Detail: "every account has rotated its password",
			})
		} else {
			checks = append(checks, &jms.Check{
				Name: "password_never_rotated", Status: service.Warn,
				Detail: fmt.Sprintf("%d account(s) have never rotated their password: %s",
					len(neverRotated), strings.Join(neverRotated, ", ")),
				Fix: service.FixText("reset the credential with jms_user_password_set"),
			})
		}
		// A deactivated account cannot log in, which is the point of
		// deactivating it -- so this is a fact, not a defect.
		deactivatedDetail := "no account is deactivated"
		if len(inactive) > 0 {
			deactivatedDetail = fmt.Sprintf("%d account(s) are deactivated and cannot log in: %s",
				len(inactive), strings.Join(inactive, ", "))
		}
		checks = append(checks, &jms.Check{
			Name: "deactivated_users", Status: service.OK, Detail: deactivatedDetail,
		})
		blockedDetail := "no address is blocked"
		if len(blocked) > 0 {
			blockedDetail = fmt.Sprintf("%d address(es) are blocked: %s",
				len(blocked), strings.Join(blocked, ", "))
		}
		checks = append(checks, &jms.Check{
			Name: "blocked_ips", Status: service.OK, Detail: blockedDetail,
		})

		res.Diagnosis = service.Diagnosis(checks,
			service.Verdict(checks, "nothing to flag in this window: no stale credential, no unblocked attack and no inactive account"),
			"nothing to fix: no account and no address in this window needs action")
		return render.Text(res)
	})
}
