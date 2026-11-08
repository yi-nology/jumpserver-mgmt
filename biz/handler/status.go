package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/yi-nology/jumpserver-mgmt/biz/model/jmsms"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oagentkit/guardx/toolfail"
	"github.com/oekit/pkg/convert"

	"github.com/yi-nology/jumpserver-kit/model/jms"
	"github.com/yi-nology/jumpserver-kit/pkg/errs"
	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
	"github.com/yi-nology/jumpserver-mgmt/internal/repository"
)

// statusArgs is the (empty) input of jms_status.
type statusArgs struct{}

// The read-only tools: what the bastion holds and what state it is in.
// They are the entry point of an investigation — status first, then the
// lists, then the single-asset view.
func RegisterStatusTools(r *reg.Registry, c *repository.Client) {
	reg.Add(r, &mcp.Tool{
		Name:         "jms_status",
		Description:  "Check JumpServer reachability, API auth, version and asset counts. Start here for a quick look at whether the bastion answers and how big it is; use jms_doctor when you need the deeper check of what is misconfigured.",
		OutputSchema: render.Schema[jmsms.BastionStatus](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ statusArgs) (*mcp.CallToolResult, any, error) {
		out := &jmsms.BastionStatus{
			BaseURL:         c.BaseURL,
			AssetByPlatform: map[string]int32{},
		}

		// Auth check and identity in one call: /users/profile/ answers with
		// the CALLER. ⚠️ The first row of /users/users/ is NOT the caller —
		// see identityOf for the measured failure (a non-admin caller was
		// reported as admin).
		if who, disp, _, idErr := identityOf(ctx, c); idErr == nil {
			out.AuthOk = true
			out.User = jmsapi.FieldStr(who)
			out.Name = jmsapi.FieldStr(disp)
		} else {
			// The identity probe failed. That does not by itself mean the
			// credential is bad — an odd deployment could lack the route, or
			// the caller may lack users.view_user on the list. So auth is
			// settled separately, and by the FAILURE CLASS: only a 401 means
			// the credential was rejected. A 403 (no permission to list
			// users) or a 404/500 is a valid credential reaching a route it
			// cannot use — answering auth_ok=false there would blame the
			// credential for a permission gap and send the operator to
			// rotate a token that is fine.
			var raw json.RawMessage
			err := c.GetQuery(ctx, jmsapi.ResUsers, url.Values{"page_size": {"1"}}, &raw)
			// Did the API actually ANSWER (any HTTP status), or did the
			// request die in transport (connection refused / timeout / DNS)?
			// Only a response proves the token reached the API; transport
			// failure proves nothing about the credential.
			var apiErr *errs.APIError
			responded := errors.As(err, &apiErr)
			switch {
			case err == nil:
				out.AuthOk = true
				out.Error = jms.Opt(idErr.Error())
			case errs.Class(err) == toolfail.ClassAuthentication:
				out.AuthOk = false
				out.Error = jms.Opt("the credential was rejected: " + err.Error())
			case responded:
				// The API answered with a non-auth status (403 / 404 / 5xx):
				// the request reached the API and was NOT rejected as an
				// invalid credential — the route is simply unavailable to it.
				// So the token CAN call the API: auth_ok is genuinely true.
				out.AuthOk = true
				out.Error = jms.Opt(idErr.Error() + " (the credential was not rejected as invalid; " +
					"the users list is unavailable to it)")
			default:
				// Transport failure: the request never reached the API, so
				// whether the token can call it is UNPROVEN. auth_ok is a
				// required bool, so the unknown folds to its conservative
				// value (false = not proven able), and the error says plainly
				// this is NOT a verdict on the credential — asserting
				// "accepted" here would be a fabrication, the same sin as
				// inventing an identity.
				out.AuthOk = false
				out.Error = jms.Opt(idErr.Error() + " (could not reach the bastion; this is NOT a verdict " +
					"on the credential — the token was never tested)")
			}
		}

		// The total comes from the SERVER's own count on a ONE-ROW probe:
		// the envelope count is the collection size whatever the page size,
		// so "size the fleet" costs one tiny request instead of a full
		// estate walk (issue #7 — jms_status is the FIRST call an agent
		// makes, and the walk made every session open drag the whole asset
		// list just to report four numbers).
		if _, serverTotal, err := c.ListCounted(ctx, jmsapi.ResAssets, url.Values{"page_size": {"1"}}); err == nil && serverTotal > 0 {
			out.AssetTotal = jms.OptInt32(int32(serverTotal))
			// The distribution needs the rows. Up to the walk cap it is
			// exact; past it, the per-platform/connectivity numbers are
			// marked partial rather than silently wrong.
			const distributionCap = 1000
			if serverTotal <= distributionCap {
				if rows, _, err := c.ListCounted(ctx, jmsapi.ResAssets, url.Values{"page_size": {"500"}}); err == nil {
					byPlatform := map[string]int32{}
					okCount, errCount := int32(0), int32(0)
					for _, a := range rows {
						p := jmsapi.Str(jmsapi.Nested(a, "platform", "name"))
						if p == "" {
							p = "(none)"
						}
						byPlatform[p]++
						switch jmsapi.Label(a, "connectivity") {
						case "ok":
							okCount++
						case "err":
							errCount++
						}
					}
					out.AssetByPlatform = byPlatform
					out.ConnectivityOk = jms.OptInt32(okCount)
					out.ConnectivityErr = jms.OptInt32(errCount)
				}
			} else {
				out.Note = jms.Opt(fmt.Sprintf("the estate holds %d assets — platform/connectivity distribution covers the first %d rows only (the total above is exact: the server's own count)", serverTotal, distributionCap))
			}
		} else if rows, serverTotal, err := c.ListCounted(ctx, jmsapi.ResAssets, url.Values{"page_size": {"500"}}); err == nil {
			// Probe failed (an old deployment without envelope counts?):
			// the old full walk is the fallback, unchanged.
			byPlatform := map[string]int32{}
			okCount, errCount := int32(0), int32(0)
			for _, a := range rows {
				p := jmsapi.Str(jmsapi.Nested(a, "platform", "name"))
				if p == "" {
					p = "(none)"
				}
				byPlatform[p]++
				switch jmsapi.Label(a, "connectivity") {
				case "ok":
					okCount++
				case "err":
					errCount++
				}
			}
			if serverTotal > 0 {
				out.AssetTotal = jms.OptInt32(int32(serverTotal))
			} else {
				out.AssetTotal = jms.OptInt32(int32(len(rows)))
			}
			out.AssetByPlatform = byPlatform
			out.ConnectivityOk = jms.OptInt32(okCount)
			out.ConnectivityErr = jms.OptInt32(errCount)
		}
		return render.Text(out)
	})

	type platformsArgs struct{}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_platforms_list",
		Description:  "List asset platforms (Linux, macOS, Gateway, Website, Kubernetes, MySQL ...) with ids. Use it to find the platform name jms_asset_create expects, and to see which platforms this bastion supports.",
		OutputSchema: render.Schema[render.ListOf[jmsms.PlatformSummary]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ platformsArgs) (*mcp.CallToolResult, any, error) {
		raw := fetchRaw(c, ctx, jmsapi.ResPlatforms)
		if raw == nil {
			return render.Err(fmt.Errorf("cannot list platforms"))
		}
		rows, err := jmsapi.List(raw)
		if err != nil {
			return render.Err(err)
		}
		// filter → map → sort → truncate → count: render.ListSpec owns the
		// order and the counting. The platform list is complete by nature, so
		// it carries no cap (Max 0): truncating it would drop rows the caller
		// needs while reporting truncated for a list meant to be whole. Rows
		// that do not parse are filtered, not mapped into empty rows.
		return render.Text(render.ListSpec[json.RawMessage, jmsms.PlatformSummary]{
			Rows: rows,
			Keep: func(r json.RawMessage) bool {
				var p map[string]any
				return json.Unmarshal(r, &p) == nil
			},
			Map: func(r json.RawMessage) jmsms.PlatformSummary {
				var p map[string]any
				_ = json.Unmarshal(r, &p)
				return jmsms.PlatformSummary{
					ID:   jmsapi.FieldStr(p["id"]),
					Name: jmsapi.FieldStr(p["name"]),
					Type: jmsapi.FieldStr(p["type"]),
				}
			},
			Less: func(a, b jmsms.PlatformSummary) bool { return a.GetName() < b.GetName() },
			Max:  0,
		}.Build())
	})

	type assetsListArgs struct {
		Platform     string `json:"platform,omitempty" jsonschema:"filter by platform name, e.g. Linux or Kubernetes"`
		Connectivity string `json:"connectivity,omitempty" jsonschema:"filter by connectivity state: ok, err or -"`
		Search       string `json:"search,omitempty" jsonschema:"substring match on address or name"`
		Limit        int    `json:"limit,omitempty" jsonschema:"max rows to return (default 100)"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_assets_list",
		Description:  "List managed assets with address, platform and connectivity. Filter by platform, connectivity or a search string. Use it to find a machine's exact name and address before opening a session on it; the execution plane's jmsx_inventory is the same list seen from the other side.",
		OutputSchema: render.Schema[render.ListOf[jms.AssetSummary]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args assetsListArgs) (*mcp.CallToolResult, any, error) {
		rows, err := c.List(ctx, jmsapi.ResAssets)
		if err != nil {
			return render.Err(err)
		}
		// filter → map → sort → truncate → count: render.ListSpec owns the
		// order and the three counting fields (total is how many assets
		// matched the filters, before the cap).
		return render.Text(render.ListSpec[map[string]any, jms.AssetSummary]{
			Rows: rows,
			Keep: func(a map[string]any) bool {
				plat := fmt.Sprint(jmsapi.Nested(a, "platform", "name"))
				conn := jmsapi.Label(a, "connectivity")
				if args.Platform != "" && !strings.EqualFold(plat, args.Platform) {
					return false
				}
				if args.Connectivity != "" && !strings.EqualFold(conn, args.Connectivity) {
					return false
				}
				if args.Search != "" {
					s := strings.ToLower(args.Search)
					if !strings.Contains(strings.ToLower(jmsapi.Str(a["address"])), s) &&
						!strings.Contains(strings.ToLower(jmsapi.Str(a["name"])), s) {
						return false
					}
				}
				return true
			},
			Map: func(a map[string]any) jms.AssetSummary {
				// The shared asset row: the execution plane's inventory
				// produces the same one, so "which machines are there" has
				// one answer whichever server is asked.
				return jmsapi.AssetSummary(a)
			},
			Less:  func(a, b jms.AssetSummary) bool { return a.GetAddress() < b.GetAddress() },
			Limit: args.Limit,
			Def:   100,
			Max:   500,
		}.Build())
	})

	type assetGetArgs struct {
		Ref string `json:"ref" jsonschema:"asset address, name or UUID, e.g. 198.51.100.3"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_asset_get",
		Description:  "Full detail for one asset: platform, protocols, accounts, connectivity, last login and verification time. This is the bastion's raw record for that machine — use jms_asset_audit instead when you want the verdict on what is broken with it.",
		OutputSchema: render.Schema[jmsms.AssetDetail](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args assetGetArgs) (*mcp.CallToolResult, any, error) {
		_, meta, err := c.ResolveAssets(ctx, []string{args.Ref})
		if err != nil {
			return render.Err(err)
		}
		if len(meta) == 0 {
			return render.Err(fmt.Errorf("asset not found: %s", args.Ref))
		}
		id := meta[0]["id"].(string)
		var detail map[string]any
		if err := c.Get(ctx, jmsapi.ResAssets, id, &detail); err != nil {
			return render.Err(err)
		}
		return render.Text(assetDetail(detail))
	})

	type accountsArgs struct {
		Asset string `json:"asset,omitempty" jsonschema:"only accounts of this asset (address/name/uuid)"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_accounts_list",
		Description:  "List asset accounts with username, secret type and privileged flag. Secrets are never returned. Use it to see which logins a machine accepts; jms_asset_audit answers the same question together with the verdict on what else is wrong with the machine.",
		OutputSchema: render.Schema[render.ListOf[jmsms.AccountSummary]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args accountsArgs) (*mcp.CallToolResult, any, error) {
		rows, err := c.List(ctx, jmsapi.ResAccounts)
		if err != nil {
			return render.Err(err)
		}
		var assetIDs map[string]bool
		if args.Asset != "" {
			ids, _, err := c.ResolveAssets(ctx, []string{args.Asset})
			if err != nil {
				return render.Err(err)
			}
			assetIDs = map[string]bool{}
			for _, id := range ids {
				assetIDs[id] = true
			}
		}
		// filter → map → sort → truncate → count: render.ListSpec owns the
		// order and the counting. The totals used to be computed against the
		// UNFILTERED rows, so an asset filter answered total as "how many
		// accounts exist on the bastion" while showing only that asset's —
		// total is now how many matched. No cap (Max 0): this is the whole
		// set of logins per filter.
		return render.Text(render.ListSpec[map[string]any, jmsms.AccountSummary]{
			Rows: rows,
			Keep: func(a map[string]any) bool {
				if assetIDs == nil {
					return true
				}
				return assetIDs[fmt.Sprint(jmsapi.Nested(a, "asset", "id"))]
			},
			Map: func(a map[string]any) jmsms.AccountSummary {
				// The row carries the account AND the machine it belongs to:
				// a list of logins without the asset they hang on cannot be
				// acted on.
				return jmsms.AccountSummary{
					Username:      jmsapi.Str(a["username"]),
					Name:          jmsapi.FieldStr(a["name"]),
					SecretType:    jmsapi.FieldStr(jmsapi.Label(a, "secret_type")),
					Privileged:    jmsapi.FieldBool(a["privileged"]),
					IsActive:      jmsapi.FieldBool(a["is_active"]),
					Connectivity:  jmsapi.FieldStr(jmsapi.Label(a, "connectivity")),
					DateLastLogin: jmsapi.FieldStr(a["date_last_login"]),
					Asset:         jmsapi.FieldStr(jmsapi.FieldName(a, "asset")),
					Address:       jmsapi.FieldStr(jmsapi.Nested(a, "asset", "address")),
				}
			},
			Less: func(a, b jmsms.AccountSummary) bool { return a.GetAddress() < b.GetAddress() },
			Max:  0,
		}.Build())
	})

	type nodesArgs struct{}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_nodes_list",
		Description:  "List asset tree nodes (the grouping folders assets belong to). Use it to find the node path that jms_asset_move wants: each row carries the node's name and its full path in full_value (that is the path to pass on).",
		OutputSchema: render.Schema[render.ListOf[jmsms.NodeSummary]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ nodesArgs) (*mcp.CallToolResult, any, error) {
		rows, err := c.List(ctx, jmsapi.ResNodes)
		if err != nil {
			return render.Err(err)
		}
		// The node tree is a complete list: no filter, no cap (Max 0). Less
		// stays nil — this list never sorted locally, and the endpoint's
		// order is what callers already read.
		return render.Text(render.ListSpec[map[string]any, jmsms.NodeSummary]{
			Rows: rows,
			Map: func(n map[string]any) jmsms.NodeSummary {
				return jmsms.NodeSummary{
					ID:        jmsapi.Str(n["id"]),
					Name:      jmsapi.Str(n["name"]),
					FullValue: jmsapi.FieldStr(n["full_value"]),
					ParentID:  jmsapi.FieldStr(n["parent_id"]),
					Assets:    jmsapi.FieldInt32(n["assets_amount"]),
				}
			},
			Max: 0,
		}.Build())
	})

	type permsArgs struct {
		Limit int `json:"limit,omitempty" jsonschema:"max rows (default 50)"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_permissions_list",
		Description:  "List asset permissions (who may reach which asset). Use for access-review and least-privilege audits. It reports counts, so use jms_permission_get when you need to know WHO is in one permission.",
		OutputSchema: render.Schema[render.ListOf[jmsms.PermissionSummary]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args permsArgs) (*mcp.CallToolResult, any, error) {
		// The endpoint ignores page_size and answers with its own cap of
		// 200 rows, so the caller's limit is applied on this side; the
		// normalized page_size still goes out for deployments that honour it.
		q := url.Values{"page_size": {convert.AnyToStr(render.NormLimit(args.Limit, 50, 200))}, "ordering": {"-date_created"}}
		rows, err := c.ListQuery(ctx, jmsapi.ResPermissions, q)
		if err != nil {
			return render.Err(err)
		}
		// filter → map → sort → truncate → count: render.ListSpec owns the
		// counting. Less is nil: the server already answers in -date_created
		// order and re-sorting here would only disturb it.
		res := render.ListSpec[map[string]any, jmsms.PermissionSummary]{
			Rows: rows,
			Map: func(p map[string]any) jmsms.PermissionSummary {
				// The list endpoint returns assets as null; the counts are
				// what an access review actually needs.
				return jmsms.PermissionSummary{
					Name:         jmsapi.Str(p["name"]),
					IsActive:     jmsapi.FieldBool(p["is_active"]),
					AssetsAmount: jmsapi.FieldInt32(p["assets_amount"]),
					UsersAmount:  jmsapi.FieldInt32(p["users_amount"]),
					NodesAmount:  jmsapi.FieldInt32(p["nodes_amount"]),
					Accounts:     asStringSlice(p["accounts"]),
					DateCreated:  jmsapi.FieldStr(p["date_created"]),
				}
			},
			Limit: args.Limit,
			Def:   50,
			Max:   200,
		}.Build()
		if res.Truncated {
			res.Note = "showing the first " + convert.AnyToStr(res.Count) + " of " +
				convert.AnyToStr(res.Total) + " permissions"
		}
		return render.Text(res)
	})
}

// fetchRaw reads a collection as raw JSON.
//
// The status tools want the raw envelope rather than decoded rows: they
// count and group, and they must survive a shape they do not understand.
func fetchRaw(c *repository.Client, ctx context.Context, res jmsapi.Resource) json.RawMessage {
	var raw json.RawMessage
	if err := c.GetQuery(ctx, res, url.Values{"page_size": {"500"}}, &raw); err != nil {
		return nil
	}
	return raw
}

// assetDetail turns a bastion asset record into the contract type.
//
// Both jms_asset_get and jms_asset_create answer with it: "an asset" is one
// shape, and the record a create call just wrote is the same shape.
func assetDetail(m map[string]any) *jmsms.AssetDetail {
	// The tree position is the path a human reads, so the node's full_value
	// is what goes in; the leaf name is the fallback.
	nodes := []string{}
	for _, n := range jmsapi.AsSlice(m["nodes"]) {
		nm, ok := n.(map[string]any)
		if !ok {
			continue
		}
		path := jmsapi.Str(nm["full_value"])
		if path == "" {
			path = jmsapi.Str(nm["name"])
		}
		if path != "" {
			nodes = append(nodes, path)
		}
	}
	// The org comes as the id itself on some records and as the whole object
	// on others.
	orgID := jmsapi.Str(m["org_id"])
	if om, ok := m["org_id"].(map[string]any); ok {
		orgID = jmsapi.Str(om["id"])
	}
	orgName := jmsapi.FieldName(m, "org_name")
	if orgName == "" {
		orgName = jmsapi.FieldName(m, "org")
	}
	// What it runs on, how it is reached, what it is tagged with and who may
	// log into it.
	protocols := []*jmsms.ProtocolRef{}
	for _, p := range jmsapi.AsSlice(m["protocols"]) {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		protocols = append(protocols, &jmsms.ProtocolRef{
			Name: jms.Opt(jmsapi.Str(pm["name"])),
			Port: jmsapi.FieldInt32(pm["port"]),
		})
	}
	labels := []string{}
	for _, l := range jmsapi.AsSlice(m["labels"]) {
		lm, ok := l.(map[string]any)
		if !ok {
			continue
		}
		name := jmsapi.Str(lm["name"])
		if name == "" {
			continue
		}
		if v := jmsapi.Str(lm["value"]); v != "" && v != name {
			name += ":" + v
		}
		labels = append(labels, name)
	}
	accounts := []string{}
	for _, a := range jmsapi.AsSlice(m["accounts"]) {
		am, ok := a.(map[string]any)
		if !ok {
			continue
		}
		if u := jmsapi.Str(am["username"]); u != "" {
			accounts = append(accounts, u)
		}
	}
	return &jmsms.AssetDetail{
		ID:             jmsapi.Str(m["id"]),
		Name:           jmsapi.Str(m["name"]),
		Address:        jmsapi.Str(m["address"]),
		AccountsAmount: jmsapi.FieldInt32(m["accounts_amount"]),
		IsActive:       jmsapi.FieldBool(m["is_active"]),
		Comment:        jmsapi.FieldStr(m["comment"]),
		CreatedBy:      jmsapi.FieldStr(jmsapi.FieldName(m, "created_by")),
		DateCreated:    jmsapi.FieldStr(m["date_created"]),
		DateUpdated:    jmsapi.FieldStr(m["date_updated"]),
		DateVerified:   jmsapi.FieldStr(m["date_verified"]),
		DateLastLogin:  jmsapi.FieldStr(m["date_last_login"]),
		OrgID:          jmsapi.FieldStr(orgID),
		OrgName:        jmsapi.FieldStr(orgName),
		NodesDisplay:   nodes,
		Platform:       jmsapi.FieldStr(jmsapi.Nested(m, "platform", "name")),
		Protocols:      protocols,
		Connectivity:   jmsapi.FieldStr(jmsapi.Label(m, "connectivity")),
		Category:       jmsapi.FieldStr(jmsapi.Nested(m, "category", "value")),
		Labels:         labels,
		Accounts:       accounts,
	}
}
