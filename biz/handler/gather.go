package handler

// tools_gather_labels.go implements P2 (account gathering) and P3 (labels and
// roles).
//
// P2 exists because every asset in this bastion was registered by hand.
// JumpServer can instead scan a node, enumerate the accounts on it, and report
// which ones are confirmed, pending, or no longer present. That is the
// difference between an inventory you maintain and one you can trust.
//
// The shapes measured on the live v5 bastion on 2026-10-15. ⚠️ v4 is the
// same on every point here, EXCEPT that v4's lists use the standard
// {count, results} envelope where v5 answers with a bare array -- and the
// protocol layer reads both (pkg/jmsapi.List), so the tools do not care:
//	gathered-accounts   POST requires: asset
//	                    status: 0=Pending 1=Confirm, plus present/remote_present
//	                    and a `detail` blob holding groups / sudoers /
//	                    authorized_keys
//	labels              POST requires: name, value        (optional color)
//	labeled-resources   listing filters: label__name / label__value / label(uuid) /
//	                    res_id / res_type.  POSTing one is a DEAD END: the
//	                    serializer never fills org_id and LabeledResource.save()
//	                    refuses an orgless row, so every shape returns 500.
//	                    The working write path is the UI's own bulk endpoint,
//	                    see labelAttach.
//	org-roles           POST requires: name, scope        (160 content-types)
//
// Two collection endpoints return a BARE ARRAY rather than the usual
// {count, results} envelope, which is why labelLookup/roleLookup below cannot
// decode straight into a map:
//
//	/labels/labels/            bare array
//	/labels/labeled-resources/ bare array
//	/rbac/org-roles/           bare array
//	/rbac/content-types/       bare array
//
// `/rbac/org-roles/{id}/permissions/tree/` is also flat, not nested: each row
// carries its own `title` and its parent's `pId`, with no `children` array.

import (
	"context"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oekit/pkg/convert"
	"github.com/yi-nology/jumpserver-kit/model/jms"
	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
	"github.com/yi-nology/jumpserver-mgmt/biz/model/jmsms"
	"github.com/yi-nology/jumpserver-mgmt/internal/repository"
)

// ------------------------------------------------------------------ P2 gather

func RegisterGatherTools(r *reg.Registry, c *repository.Client) {
	type gatherListArgs struct {
		AssetRef string `json:"asset,omitempty" jsonschema:"only accounts gathered from this asset"`
		Status   string `json:"status,omitempty" jsonschema:"filter by state: pending / confirm / rejected / offline"`
		Limit    int    `json:"limit,omitempty" jsonschema:"max rows (default 50)"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_gathered_accounts",
		Description: "List accounts JumpServer discovered on managed hosts, with their confirmation state. " +
			"'pending' means found on the host but not adopted; 'confirm' means adopted. " +
			"A 'present: false' entry is an account we manage that has since disappeared from the host — " +
			"the cheapest inventory drift check there is.",
		OutputSchema: render.Schema[render.ListOf[jmsms.GatheredAccountSummary]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args gatherListArgs) (*mcp.CallToolResult, any, error) {
		q := url.Values{"page_size": {"500"}}
		want := map[string]bool{}
		if args.AssetRef != "" {
			ids, _, err := c.ResolveAssets(ctx, []string{args.AssetRef})
			if err != nil {
				return render.Failf("%v", err)
			}
			// ⚠️ The filter parameter is `asset_id`, NOT `asset` — measured
			// 2026-11-03: the endpoint IGNORES `asset=` and answers with
			// the whole org's rows. Same trap G1 caught in GatheredRows;
			// this entry had its own copy of the query and kept it.
			q.Set("asset_id", strings.Join(ids, ","))
			for _, id := range ids {
				want[id] = true
			}
		}
		if args.Status != "" {
			q.Set("status", args.Status)
		}
		rows, err := c.ListQuery(ctx, jmsapi.ResGathered, q)
		if err != nil {
			return render.Failf("%v", err)
		}
		// Verify the request, don't trust it: a row that names another
		// asset is dropped here whatever the server did with the query.
		kept := rows[:0]
		for _, m := range rows {
			if id := jmsapi.Str(jmsapi.Nested(m, "asset", "id")); id != "" && !want[id] && len(want) > 0 {
				continue
			}
			kept = append(kept, m)
		}
		rows = kept
		// The drift list describes the rows the answer SHOWS: the old loop
		// stopped collecting drift at the cap, and this keeps that boundary
		// (Less is nil, so the shown rows are the first N in source order).
		limit := render.NormLimit(args.Limit, 50, 500)
		drift := []string{}
		for i, m := range rows {
			if i >= limit {
				break
			}
			if m["present"] == false {
				drift = append(drift, fmt.Sprintf("%s@%v", m["username"], jmsapi.Nested(m, "asset", "name")))
			}
		}
		// filter -> map -> sort -> truncate -> count: the server-side filter
		// and the verified asset subset are applied above, so Keep is nil.
		res := render.ListSpec[map[string]any, jmsms.GatheredAccountSummary]{
			Rows: rows,
			Map: func(m map[string]any) jmsms.GatheredAccountSummary {
				entry := jmsms.GatheredAccountSummary{
					ID:            jmsapi.FieldStr(m["id"]),
					Username:      jmsapi.FieldStr(m["username"]),
					Asset:         jmsapi.FieldStr(jmsapi.Nested(m, "asset", "name")),
					Address:       jmsapi.FieldStr(jmsapi.Nested(m, "asset", "address")),
					Status:        jmsapi.FieldStr(jmsapi.Label(m, "status")),
					Present:       jmsapi.FieldBool(m["present"]),
					RemotePresent: jmsapi.FieldBool(m["remote_present"]),
					DateUpdated:   jmsapi.FieldStr(m["date_updated"]),
					DateLastLogin: jmsapi.FieldStr(m["date_last_login"]),
				}
				if d := asDetail(m["detail"]); d != "" {
					entry.Detail = jms.Opt(jmsapi.Truncate(d, 700))
				}
				return entry
			},
			Limit: args.Limit,
			Def:   50,
			Max:   500,
		}.Build()
		if len(drift) > 0 {
			slices.Sort(drift)
			// The envelope has one slot for prose and none for a list, so the
			// drift rides in the note -- the same sentence, the same names.
			res.Note = "these managed accounts are no longer present on their host: " +
				strings.Join(drift, ", ")
		}
		return render.Text(res)
	})

	type gatherRunArgs struct {
		AssetRef string `json:"asset" jsonschema:"asset to scan for accounts"`
		Confirm  bool   `json:"confirm,omitempty" jsonschema:"must be true: this runs remote automation on the host"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_gather_run",
		Description: "Log into an asset and enumerate the accounts on it. Results land as 'pending' gathered " +
			"accounts you can review with jms_gathered_accounts and adopt with jms_gather_apply. " +
			"Takes a while: the bastion runs it through Celery + automation, so it is not instant. " +
			"Needs the asset's platform to have remote automation enabled.",
		OutputSchema: render.Schema[jmsms.GatherRunResult](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args gatherRunArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true: this executes remote automation on the asset")
		}
		ids, meta, err := c.ResolveAssets(ctx, []string{args.AssetRef})
		if err != nil {
			return render.Failf("%v", err)
		}
		assetID := ids[0]

		// Snapshot what is already known so the answer can say what changed.
		before := c.GatheredUsernames(ctx, assetID)

		// POST /accounts/gathered-accounts/ is NOT the trigger — it dies with a
		// 500 because GatheredAccount.save() demands an org the create serializer
		// never sets. The endpoint that actually runs the job is the adhoc action
		// the UI uses, and it is a GET carrying asset_id in the query string.
		report, err := c.GatherAdhoc(ctx, assetID)
		if err != nil {
			return render.Failf("gather failed on %v: %v", meta[0]["name"], err)
		}

		rows, err := c.GatheredRows(ctx, assetID)
		if err != nil {
			return render.Failf("gather ran but listing the results failed: %v", err)
		}
		after := c.GatheredUsernames(ctx, assetID)
		fresh := []string{}
		for u := range after {
			if !before[u] {
				fresh = append(fresh, u)
			}
		}
		slices.Sort(fresh)

		res := &jmsms.GatherRunResult{
			Asset:      jmsapi.Str(meta[0]["name"]),
			AssetID:    jmsapi.FieldStr(assetID),
			Gathering:  jms.OptInt32(int32(len(rows))),
			NewlyFound: fresh,
			Note:       jms.Opt("review with jms_gathered_accounts (status=pending), then adopt with jms_gather_apply"),
		}
		if len(report) > 0 {
			res.Report = jms.Opt(jmsapi.Truncate(report, 1200))
		}
		// The report carries its own verdict in its header counts ("Asset
		// Success Count 0 Asset Failure Count 1" on an unreachable host,
		// "Asset not supported 1" on a platform with no remote automation —
		// both measured 2026-11-03). A run that failed, or whose discovery
		// never ran, must not be described as "completed but no new
		// accounts" — that paints a problem as an empty success and sends
		// the reader looking for the wrong problem (the platform's
		// automation instead of the network).
		scope, succ, fail, notsup, counted := reportCounts(report)
		switch {
		case counted && fail > 0:
			res.Note = jms.Opt(fmt.Sprintf(
				"the gather FAILED on %d of %d assets (the report's own counts: %d succeeded, %d failed) — "+
					"unreachable host, wrong credentials, or no remote automation on the platform. "+
					"%d new account(s) found. See the report for which asset failed.",
				fail, succ+fail+notsup, succ, fail, len(fresh)))
		case counted && notsup > 0:
			res.Note = jms.Opt(fmt.Sprintf(
				"the gather could not run on %d of %d assets: the report says 'not supported' — the platform has "+
					"no remote automation (Linux platform -> 'Ansible'), so discovery never happened. "+
					"%d new account(s) found. Nothing was discovered on those assets; this is not an empty success.",
				notsup, succ+fail+notsup, len(fresh)))
		case counted && succ+fail+notsup == 0 && scope > 0:
			// Measured 2026-11-03 11:12: a report read while the run had
			// not classified anything yet: "Asset Count 1" with all three
			// tallies at 0. The run has NOT happened as far as the report
			// shows — say so, instead of dressing it up as an empty result.
			res.Note = jms.Opt(fmt.Sprintf(
				"the report shows %d asset(s) in scope but nothing classified yet (0 succeeded, 0 failed, 0 not "+
					"supported): the report was likely read before the run finished, or the run never got scheduled. "+
					"Discovery has NOT happened as far as this report shows — re-run jms_gather_run.", scope))
		case len(fresh) == 0 && counted && succ > 0:
			res.Note = jms.Opt(fmt.Sprintf(
				"the gather ran on %d asset(s) but reported no new accounts: every account it saw is already known", succ))
		case len(fresh) == 0:
			// The verdict could not be read — say that, instead of the old
			// "the run completed", which asserted a success nobody measured.
			res.Note = jms.Opt("no new accounts were reported, and the report carries no readable counts — " +
				"read the report field to see whether discovery ran at all (a platform with no remote automation " +
				"cannot discover; Linux platform -> 'Ansible')")
		}
		return render.Text(res)
	})

	type gatherApplyArgs struct {
		AssetRef string   `json:"asset" jsonschema:"asset to apply the gathered accounts to"`
		Accounts []string `json:"accounts,omitempty" jsonschema:"usernames to adopt; empty means every pending one on this asset"`
		Confirm  bool     `json:"confirm" jsonschema:"must be true; this creates accounts on the asset"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_gather_apply",
		Description:  "Adopt pending gathered accounts as real accounts on an asset, so they can then be used for sessions and permission grants. Use it after jms_gather_run has found accounts; empty accounts adopts every pending entry for that asset.",
		OutputSchema: render.Schema[jmsms.GatherApplyResult](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args gatherApplyArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true; this creates accounts on the asset")
		}
		ids, meta, err := c.ResolveAssets(ctx, []string{args.AssetRef})
		if err != nil {
			return render.Failf("%v", err)
		}
		assetID := ids[0]

		rows, err := c.GatheredRows(ctx, assetID)
		if err != nil {
			return render.Failf("%v", err)
		}
		wanted := map[string]bool{}
		for _, a := range args.Accounts {
			wanted[a] = true
		}
		// Collect ids first: the endpoint is a bulk status change, and calling it
		// once per row would both be slower and leave a half-adopted set behind
		// if the list turned out to be huge.
		adopt, skipped, already := []string{}, []string{}, []string{}
		// One account can have SEVERAL gathered rows (every gather run
		// appends one) and they arrive in any order. Decide per ACCOUNT,
		// not per row: if ANY row for the account is confirmed, the account
		// is already adopted — claiming its pending duplicate as "newly
		// adopted" would report a bigger change than happened, and listing
		// the same name twice would read as two accounts.
		confirmed := map[string]bool{}
		for _, m := range rows {
			if u := jmsapi.Str(m["username"]); u != "" && isConfirmed(m["status"]) {
				confirmed[u] = true
			}
		}
		asking := map[string]bool{} // the accounts this call adopts
		listed := map[string]bool{} // every account seen at least once
		for _, m := range rows {
			user := jmsapi.Str(m["username"])
			if user == "" || listed[user] {
				continue
			}
			listed[user] = true
			switch {
			case len(wanted) > 0 && !wanted[user]:
				skipped = append(skipped, user)
			case confirmed[user]:
				already = append(already, user)
			default:
				asking[user] = true
				adopt = append(adopt, convert.AnyToStr(m["id"]))
			}
		}
		if len(adopt) == 0 {
			if len(already) > 0 {
				slices.Sort(already)
				return render.Text(&jmsms.GatherApplyResult{
					Asset:            jmsapi.Str(meta[0]["name"]),
					Adopted:          []string{},
					AlreadyConfirmed: already,
					Note:             jms.Opt("these accounts are already adopted on this asset; nothing to do"),
				})
			}
			return render.Failf("nothing pending on %v to adopt; run jms_gather_run first "+
				"(pending rows are the ones with status=pending)", meta[0]["name"])
		}
		var out map[string]any
		// status=1 is ConfirmOrIgnore.confirmed, and this endpoint is what
		// actually creates the Asset accounts; PATCHing each row's status does
		// NOT sync anything. It answers 204 with an empty body, so a 200 here
		// says nothing — hence the read-back below.
		if err := c.PutAll(ctx, jmsapi.ResGatheredStatus, map[string]any{"ids": adopt, "status": "1"}, &out); err != nil {
			return render.Failf("adopt failed: %v", err)
		}

		// Read back: the endpoint returning without error is not proof, and a
		// silent no-op here leaves you believing you granted an account.
		adopted := []string{}
		got := map[string]bool{}
		after, rerr := c.GatheredRows(ctx, assetID)
		if rerr != nil {
			res := &jmsms.GatherApplyResult{
				Asset:     jmsapi.Str(meta[0]["name"]),
				Requested: keys(asking),
				Warning: jms.Opt("the status call succeeded but the read-back failed, so adoption is unconfirmed: " +
					rerr.Error()),
			}
			return render.Text(res)
		}
		for _, m := range after {
			u := jmsapi.Str(m["username"])
			// Every gather run appends a fresh row per account, so dedupe or the
			// answer lists the same username two or three times.
			if asking[u] && !got[u] && isConfirmed(m["status"]) {
				got[u] = true
				adopted = append(adopted, u)
			}
		}
		slices.Sort(adopted)
		slices.Sort(skipped)
		res := &jmsms.GatherApplyResult{
			Asset:      jmsapi.Str(meta[0]["name"]),
			Adopted:    adopted,
			NotAdopted: skipped,
			Note:       jms.Opt("verify with jms_accounts_list; the asset now has these accounts"),
		}
		if len(adopted) == 0 {
			res.Warning = jms.Opt("the status call returned without error but no gathered account reached " +
				"the confirmed state, so no account was created. Check that the asset's platform has " +
				"remote automation configured and that the accounts exist on the host.")
		}
		return render.Text(res)
	})
}

// reportCounts reads the gather report's own verdict out of its header —
// "Asset Count 1 Asset Success Count 0 Asset Failure Count 0 Asset not
// supported 1", the words the HTML flattens to (every variant measured
// 2026-11-03: an unreachable Linux asset reports Failure 1, a platform with
// no remote automation reports not supported 1, a report read before the run
// classified anything reports all three as 0 while Asset Count says 1).
// Each count is read on its own, so header order does not matter. ok=true
// only when ALL THREE verdict words were found: a missing word must not
// read as a zero count ("Failure Count" gone missing would otherwise paint
// a failed run as "succeeded 1, failed 0" — an empty success, which is the
// exact lie this whole function exists to stop). ok=false means the verdict
// is not fully readable (report missing, shape changed): the caller then
// says it could not read the verdict instead of inventing one.
func reportCounts(report string) (scope, success, failure, notSupported int, ok bool) {
	read := func(word string, into *int) bool {
		m := regexp.MustCompile(regexp.QuoteMeta(word) + ` (\d+)`).FindStringSubmatch(report)
		if m == nil {
			return false
		}
		*into, _ = strconv.Atoi(m[1])
		return true
	}
	read("Asset Count", &scope)
	sawSuccess := read("Asset Success Count", &success)
	sawFailure := read("Asset Failure Count", &failure)
	sawNotSup := read("Asset not supported", &notSupported)
	return scope, success, failure, notSupported, sawSuccess && sawFailure && sawNotSup
}

// gatheredRows lists the gathered-account records for one asset.

// gatherAdhoc fires the discovery run and returns the execution report as text.
//
// The report comes back as an HTML page, so it is flattened rather than parsed:
// what matters to the caller is "it ran and what it saw", not the table styling.

// "confirmed" / "Confirm" — so accept every spelling instead of guessing one.
func isConfirmed(v any) bool {
	s := strings.ToLower(strings.TrimSpace(convert.AnyToStr(v)))
	if m, ok := v.(map[string]any); ok {
		s = strings.ToLower(strings.TrimSpace(convert.AnyToStr(m["value"])))
	}
	s = strings.Trim(s, `"`)
	switch s {
	case "1", "confirmed", "confirm", "yes", "true":
		return true
	}
	return false
}

func keys(m map[string]bool) []string {
	return slices.Sorted(maps.Keys(m))
}

// asDetail turns the gathered account's free-form detail blob into readable
// text. It is a dict of strings such as groups / sudoers / authorized_keys.
func asDetail(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	keys := slices.Sorted(maps.Keys(m))
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, m[k]))
	}
	return strings.Join(parts, " ")
}

// ------------------------------------------------------------------ P3 labels

// labelLookup resolves a label name (plus optional value) to its UUID.
//
// `/labels/labels/?name=` filters server-side, but the reply is a bare array, so
// the answer must come back through listAll; decoding it straight into a map is
// what makes a tool report "cannot unmarshal array into map" at the caller.

// roleLookup resolves a role name (or UUID) to its UUID.

// contentTypeID maps a Django model name (asset, host, user, node...) to the
// ContentType id that /labels/.../resource-types/<id>/resources expects.

// labelAttach writes the label's membership for one content type.
//
// POST /labels/labeled-resources/ is unusable: LabeledResource.save() demands an
// org and the create serializer never sets one, so the request dies as a 500 no
// matter which combination of res_id / res_type / resource is sent.
//
// The endpoint the UI itself uses is a PUT on
// /labels/labels/<label>/resource-types/<content_type_id>/resources/ taking the
// FULL desired set of res_ids — it deletes whatever is not listed before adding,
// so this has to be a read-merge-write or every attach silently detaches
// everything tagged before it.

// labelBoundIDs returns the res_ids currently carrying the label for one type.

func RegisterLabelRoleTools(r *reg.Registry, c *repository.Client) {
	type labelsArgs struct {
		Limit int `json:"limit,omitempty" jsonschema:"max rows (default 50)"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_labels_list",
		Description:  "List labels (name/value pairs used to tag assets and other resources) and how many resources each one covers. Use it to find the label key to query with, and to see which labels are actually in use.",
		OutputSchema: render.Schema[render.ListOf[jmsms.LabelSummary]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args labelsArgs) (*mcp.CallToolResult, any, error) {
		rows, err := c.List(ctx, jmsapi.ResLabels)
		if err != nil {
			return render.Failf("%v", err)
		}
		// filter -> map -> sort -> truncate -> count: endpoint order, no filter.
		return render.Text(render.ListSpec[map[string]any, jmsms.LabelSummary]{
			Rows: rows,
			Map: func(m map[string]any) jmsms.LabelSummary {
				return jmsms.LabelSummary{
					ID:       jmsapi.FieldStr(m["id"]),
					Name:     jmsapi.FieldStr(m["name"]),
					Value:    jmsapi.FieldStr(m["value"]),
					Color:    jmsapi.FieldStr(m["color"]),
					Comment:  jmsapi.FieldStr(m["comment"]),
					ResCount: jmsapi.FieldInt32(m["res_count"]),
				}
			},
			Limit: args.Limit,
			Def:   50,
			Max:   200,
		}.Build())
	})

	type labelCreateArgs struct {
		Name    string `json:"name" jsonschema:"label key, e.g. 'env'"`
		Value   string `json:"value" jsonschema:"label value, e.g. 'prod'"`
		Color   string `json:"color,omitempty"`
		Comment string `json:"comment,omitempty"`
		Confirm bool   `json:"confirm" jsonschema:"must be true"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_label_create",
		Description:  "Create a label. Empty or duplicate labels are refused by the API, which is the desired behaviour: a typo should not become a second label. Use jms_label_attach instead when all you want is to tag an asset -- it creates the label if it is missing.",
		OutputSchema: render.Schema[jmsms.LabelCreated](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args labelCreateArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to create the label")
		}
		if strings.TrimSpace(args.Name) == "" || strings.TrimSpace(args.Value) == "" {
			return render.Failf("both name and value are required")
		}
		body := map[string]any{"name": args.Name, "value": args.Value}
		if args.Color != "" {
			body["color"] = args.Color
		}
		if args.Comment != "" {
			body["comment"] = args.Comment
		}
		var out map[string]any
		if err := c.Post(ctx, jmsapi.ResLabels, body, &out); err != nil {
			return render.Failf("%v", err)
		}
		return render.Text(&jmsms.LabelCreated{
			ID:    jmsapi.Str(out["id"]),
			Name:  jmsapi.Str(out["name"]),
			Value: jmsapi.Str(out["value"]),
		})
	})

	type labelRefArgs struct {
		Label string `json:"label" jsonschema:"label name"`
		Value string `json:"value,omitempty" jsonschema:"label value, when the key has several"`
		Limit int    `json:"limit,omitempty" jsonschema:"max rows (default 100)"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_label_resources",
		Description:  "List the resources carrying a given label, so 'show me everything tagged prod' becomes one call instead of filtering 50 assets by hand. Returns the real objects (asset name, address), not just their ids.",
		OutputSchema: render.Schema[render.ListOf[jmsms.LabelResourceSummary]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args labelRefArgs) (*mcp.CallToolResult, any, error) {
		_, value, err := c.LabelLookup(ctx, args.Label, args.Value)
		if err != nil {
			return render.Failf("%v", err)
		}
		// Query by name/value rather than the uuid: asking for resources of a
		// concrete type would need a content-type id the caller should not have
		// to know, and the generic listing carries the names anyway.
		q := url.Values{"label__name": {args.Label}, "page_size": {"500"}}
		if value != "" {
			q.Set("label__value", value)
		}
		rows, err := c.ListQuery(ctx, jmsapi.ResLabeledResources, q)
		if err != nil {
			return render.Failf("%v", err)
		}
		// filter -> map -> sort -> truncate -> count: endpoint order, no filter.
		res := render.ListSpec[map[string]any, jmsms.LabelResourceSummary]{
			Rows: rows,
			Map: func(m map[string]any) jmsms.LabelResourceSummary {
				resID := jmsapi.Str(m["res_id"])
				// The bastion hands the resource over as a display string
				// ("name(address)"), so the name and the address have to be
				// split out of it. Copying it verbatim would make name a
				// duplicate of resource and leave the address empty.
				//
				// There is a second endpoint that lists the resources a label is
				// bound to, and it was consulted for the name and the address.
				// It carries neither: it answers with the id and the SAME
				// display string, so all it added was a second copy of the name
				// and an empty address.
				resource := jmsapi.Str(m["resource"])
				name, address := jmsapi.SplitAssetLabel(resource)
				return jmsms.LabelResourceSummary{
					Label:    jmsapi.FieldStr(jmsapi.Nested(m, "label", "display_name")),
					ResType:  jmsapi.FieldStr(jmsapi.Display(m, "res_type")),
					ResID:    jmsapi.FieldStr(resID),
					Resource: jmsapi.FieldStr(resource),
					Name:     jmsapi.FieldStr(name),
					Address:  jmsapi.FieldStr(address),
				}
			},
			Limit: args.Limit,
			Def:   100,
			Max:   500,
		}.Build()
		if res.Total == 0 {
			res.Note = "no resource carries this label yet; add one with jms_label_attach"
		}
		return render.Text(res)
	})

	type labelAttachArgs struct {
		Label     string   `json:"label" jsonschema:"label name to attach"`
		AssetRefs []string `json:"assets,omitempty" jsonschema:"asset names, addresses or UUIDs to tag"`
		Detach    []string `json:"detach,omitempty" jsonschema:"asset names, addresses or UUIDs to untag"`
		Confirm   bool     `json:"confirm" jsonschema:"must be true"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_label_attach",
		Description:  "Tag assets with an existing label, creating the label first if it does not exist. Use it to group assets for bulk operations and to find them by tag later. This ADDS to the label's members; it never replaces them (the underlying endpoint is a full-set PUT, so the tool reads the current members and merges before writing). Pass detach to untag.",
		OutputSchema: render.Schema[jmsms.LabelAttached](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args labelAttachArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to tag the assets")
		}
		if len(args.AssetRefs) == 0 && len(args.Detach) == 0 {
			return render.Failf("assets and/or detach is required")
		}
		var ids, detachIDs []string
		var tagNames, detachNames []string
		if len(args.AssetRefs) > 0 {
			var meta []map[string]any
			var err error
			ids, meta, err = c.ResolveAssets(ctx, args.AssetRefs)
			if err != nil {
				return render.Failf("%v", err)
			}
			for _, m := range meta {
				tagNames = append(tagNames, jmsapi.Str(m["name"]))
			}
		}
		if len(args.Detach) > 0 {
			var meta []map[string]any
			var err error
			detachIDs, meta, err = c.ResolveAssets(ctx, args.Detach)
			if err != nil {
				return render.Failf("%v", err)
			}
			for _, m := range meta {
				detachNames = append(detachNames, jmsapi.Str(m["name"]))
			}
		}

		// Resolve the label, creating it if absent.
		labelID, _, err := c.LabelLookup(ctx, args.Label, "")
		if err != nil {
			var created map[string]any
			if cerr := c.Post(ctx, jmsapi.ResLabels, map[string]any{"name": args.Label, "value": args.Label}, &created); cerr != nil {
				return render.Failf("label %q does not exist and could not be created: %v", args.Label, cerr)
			}
			labelID = jmsapi.Str(created["id"])
		}

		ctID, err := c.ContentTypeID(ctx, "asset")
		if err != nil {
			return render.Failf("%v", err)
		}
		note, err := c.LabelAttach(ctx, labelID, ctID, ids, detachIDs)
		if err != nil {
			return render.Failf("%v", err)
		}
		return render.Text(&jmsms.LabelAttached{
			Label:              args.Label,
			LabelID:            jmsapi.FieldStr(labelID),
			Tagged:             tagNames,
			Detached:           detachNames,
			ResourcesNowTagged: jmsapi.FieldStr(note),
		})
	})

	type labelDeleteArgs struct {
		Label   string `json:"label"`
		Confirm bool   `json:"confirm" jsonschema:"must be true"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_label_delete",
		Description:  "Delete a label. Resources keep whatever labels they have; only this label is removed. Use it when the label itself is no longer wanted; to untag a machine, use jms_label_attach with detach.",
		OutputSchema: render.Schema[jmsms.LabelDeleted](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args labelDeleteArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to delete the label")
		}
		rows, err := c.List(ctx, jmsapi.ResLabels)
		if err != nil {
			return render.Failf("%v", err)
		}
		for _, m := range rows {
			if strings.EqualFold(convert.AnyToStr(m["name"]), args.Label) {
				name := jmsapi.Str(m["name"])
				if err := c.Delete(ctx, jmsapi.ResLabels, convert.AnyToStr(m["id"])); err != nil {
					return render.Failf("%v", err)
				}
				return render.Text(&jmsms.LabelDeleted{Deleted: name})
			}
		}
		return render.Failf("no such label: %s", args.Label)
	})

	type rolesArgs struct {
		Limit int `json:"limit,omitempty" jsonschema:"max rows (default 50)"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_roles_list",
		Description:  "List organization roles with how many users hold each. Built-in roles cannot be deleted, only copied into custom ones. Use jms_role_permissions to see what a role may do.",
		OutputSchema: render.Schema[render.ListOf[jmsms.RoleSummary]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args rolesArgs) (*mcp.CallToolResult, any, error) {
		rows, err := c.List(ctx, jmsapi.ResOrgRoles)
		if err != nil {
			return render.Failf("%v", err)
		}
		// filter -> map -> sort -> truncate -> count: endpoint order, no filter.
		return render.Text(render.ListSpec[map[string]any, jmsms.RoleSummary]{
			Rows: rows,
			Map: func(m map[string]any) jmsms.RoleSummary {
				return jmsms.RoleSummary{
					ID:          jmsapi.FieldStr(m["id"]),
					Name:        jmsapi.FieldStr(m["name"]),
					DisplayName: jmsapi.FieldStr(m["display_name"]),
					Scope:       jmsapi.FieldStr(jmsapi.Label(m, "scope")),
					Builtin:     jmsapi.FieldBool(m["builtin"]),
					UsersAmount: jmsapi.FieldInt32(m["users_amount"]),
				}
			},
			Limit: args.Limit,
			Def:   50,
			Max:   200,
		}.Build())
	})

	type rolePermsArgs struct {
		Role   string `json:"role" jsonschema:"role name or UUID"`
		Search string `json:"search,omitempty" jsonschema:"only show permissions whose path contains this substring, e.g. 'account'"`
		Limit  int    `json:"limit,omitempty" jsonschema:"max rows (default 100)"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_role_permissions",
		Description: "List what a role is allowed to do, as 'app.action' paths. Use it to answer " +
			"'can this account actually create assets' before granting something.",
		OutputSchema: render.Schema[render.ListOf[jmsms.RolePermissionSummary]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args rolePermsArgs) (*mcp.CallToolResult, any, error) {
		id, err := c.RoleLookup(ctx, args.Role)
		if err != nil {
			return render.Failf("%v", err)
		}
		rows, err := c.ListSub(ctx, jmsapi.ResOrgRoles, id, "permissions/tree")
		if err != nil {
			return render.Failf("%v", err)
		}
		// The tree endpoint is FLAT: each row carries its own `title` and the
		// `pId` of its parent node, with no nested `children`. Rebuilding the
		// path from pId is what turns "view_account" into
		// "accounts.asset/view_account".
		byP := map[string]string{}
		for _, m := range rows {
			if t := jmsapi.Str(m["title"]); t != "" {
				byP[t] = jmsapi.Str(m["pId"])
			}
		}
		full := func(title string) string {
			path := title
			for range 8 {
				parent, ok := byP[path]
				if !ok || parent == "" || parent == path {
					break
				}
				path = parent + "/" + path
			}
			// Every permission hangs off a synthetic $ROOT$ node. Keeping it
			// would make each path read "$ROOT$/accounts.asset/view_account",
			// which matches nothing anybody would grep for.
			// The root itself is not a permission either, so it is dropped
			// too -- a list whose first row is "$ROOT$" is a list of the
			// tree's scaffolding, not of what the role may do.
			p := strings.Replace(path, "$ROOT$/", "", 1)
			if p == "$ROOT$" {
				return ""
			}
			return p
		}
		// filter -> map -> sort -> truncate -> count.
		// ⚠️ Counting correction: the old `total` was bumped BEFORE the
		// search filter (it counted every valid path, including the ones the
		// filter drops) and its Truncated bit said true whenever the filter
		// narrowed the list -- filtered-out and capped were one bit. Here
		// total is the matched set and Truncated is a real cap only (same
		// correction as jms_accounts_list).
		paths := []string{}
		for _, m := range rows {
			t := jmsapi.Str(m["title"])
			if t == "" {
				continue
			}
			if p := full(t); p != "" {
				paths = append(paths, p)
			}
		}
		res := render.ListSpec[string, jmsms.RolePermissionSummary]{
			Rows: paths,
			Keep: func(p string) bool {
				return args.Search == "" || strings.Contains(strings.ToLower(p), strings.ToLower(args.Search))
			},
			Map: func(p string) jmsms.RolePermissionSummary {
				return jmsms.RolePermissionSummary{Path: p}
			},
			Less:  func(a, b jmsms.RolePermissionSummary) bool { return a.Path < b.Path },
			Limit: args.Limit,
			Def:   100,
			Max:   1000,
		}.Build()
		// Which role these paths belong to: the rows are the
		// permissions, and the envelope has no room for the role's own
		// fields. Both the name the caller asked with and the uuid it
		// resolved to are here, because the rest of the tools take the
		// uuid.
		note := "role: " + args.Role + " (" + id + ")"
		if res.Truncated {
			note += fmt.Sprintf("; %d of %d permissions shown; raise limit or narrow with filter",
				res.Count, res.Total)
		}
		res.Note = note
		return render.Text(res)
	})
}
