// tools_acl.go is the WRITE face of the ACL families, plus the two
// families this repository could not touch at all.
//
// Three families live behind /acls/ and each answers a different question:
//
//   - login-acls: WHO MAY LOG IN TO THE BASTION (from where, when).
//     The read side existed (jms_login_asset_check lists the rules);
//     this adds create / update / delete.
//   - data-masking-rules: what gets MASKED when a secret is shown
//     (a field whose name matches the pattern comes back as ######).
//   - clipboard-acls: what a session's CLIPBOARD and file sizes may do
//     (copy / paste allowed, text and file-size ceilings).
//
// ⚠️ None of these is "who may reach which machine" -- that is asset
// permissions (/perms/asset-permissions/, jms_permission_*). These are
// session and login POLICY. Conflating them produces an answer that sounds
// right and governs the wrong thing.
//
// ⚠️ The `users` and `assets` fields are JSONManyToMany SELECTORS, not
// lists: {"type":"all"} / {"type":"ids","ids":[…]} / {"type":"attrs",
// "attrs":[{"name":"ip","match":"exact","value":"1.1.1.1"}]}. Sending
// ["*"] answers 400 with a text that only describes the selector shape --
// and a 400 that names no field is the worst hint in this API. The tool
// args take the selector as a typed object so the shape cannot drift.
//
// ⚠️ `rules.time_period` entries are {"id": <WEEKDAY>, "value":
// "HH:MM~HH:MM、HH:MM~HH:MM"} with id 0 = Sunday … 6 = Saturday. An empty
// value for a day means that day is NOT allowed; an empty list means no
// time restriction at all. A caller who reads "empty = deny nothing" per
// day writes a rule that denies everything.
//
// ⚠️ The wire carries `action` and `masking_method` as labelled pairs
// ({"value":"reject","label":"Reject"}); the contracts flatten them to
// the value, because the value is what round-trips back into an update.
package handler

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
	"github.com/yi-nology/jumpserver-mgmt/biz/model/jmsms"
	"github.com/yi-nology/jumpserver-mgmt/internal/repository"
)

// The action vocabularies. Each ACL family ships its own subset of the
// nine ActionChoices -- the serializer EXCLUDES the rest unconditionally,
// so these sets are the complete truth per family and do not move with a
// licence (only `review` is licence-gated, and the server says so itself
// when it is not available).
var (
	loginACLActions  = []string{"reject", "accept", "review", "notice"}
	maskingActions   = []string{"reject", "accept", "review", "notice"}
	clipboardActions = []string{"reject", "accept"}
	maskingMethods   = []string{"fixed_char", "hide_middle", "keep_prefix", "keep_suffix"}
	clipboardOps     = []string{"copy", "paste"}
)

func oneOf(v string, allowed []string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

// validateSelector checks the selector shape before the request goes out.
// The server only accepts type=all / ids / attrs and its 400 names no
// field, so the shape is checked here where the error can say WHERE.
func validateSelector(field string, s *jmsms.ACLSelector) error {
	if s == nil {
		return nil
	}
	t := strings.ToLower(strings.TrimSpace(jmsapi.Str(s.Type)))
	switch t {
	case "all":
		return nil
	case "ids":
		if len(s.Ids) == 0 {
			return fmt.Errorf("%s: type=ids needs a non-empty ids list", field)
		}
		return nil
	case "attrs":
		if len(s.Attrs) == 0 {
			return fmt.Errorf("%s: type=attrs needs a non-empty attrs list", field)
		}
		for _, a := range s.Attrs {
			if a == nil || jmsapi.Str(a.Name) == "" || jmsapi.Str(a.Value) == "" {
				return fmt.Errorf("%s: each attr needs name and value", field)
			}
		}
		return nil
	default:
		return fmt.Errorf("%s: type must be all / ids / attrs, got %q", field, jmsapi.Str(s.Type))
	}
}

// aclAttrWire turns one typed attr into the wire map.
//
// The wire maps live in their own named constructors (this and
// aclSelectorWire) rather than inline: an inline map literal appended to a
// list is what the answer guard flags -- and rightly so for answers, while
// this is the REQUEST body, which is the bastion's own shape and stays a
// map on purpose. The name says "wire" so nobody mistakes it for an answer.
func aclAttrWire(a *jmsms.ACLAttr) map[string]any {
	return map[string]any{
		"name":  jmsapi.Str(a.Name),
		"match": jmsapi.Str(a.Match),
		"value": jmsapi.Str(a.Value),
	}
}

// aclSelectorWire turns the typed selector into the wire map. The keys are
// the serializer's own: type / ids / attrs.
func aclSelectorWire(s *jmsms.ACLSelector) map[string]any {
	if s == nil {
		return map[string]any{"type": "all"}
	}
	m := map[string]any{"type": strings.ToLower(strings.TrimSpace(jmsapi.Str(s.Type)))}
	if len(s.Ids) > 0 {
		m["ids"] = s.Ids
	}
	if len(s.Attrs) > 0 {
		attrs := make([]map[string]any, 0, len(s.Attrs))
		for _, a := range s.Attrs {
			attrs = append(attrs, aclAttrWire(a))
		}
		m["attrs"] = attrs
	}
	return m
}

func parseACLSelector(v any) *jmsms.ACLSelector {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	s := &jmsms.ACLSelector{Type: jmsapi.FieldStr(m["type"])}
	if ids, ok := m["ids"].([]any); ok {
		for _, id := range ids {
			s.Ids = append(s.Ids, jmsapi.Str(id))
		}
	}
	if attrs, ok := m["attrs"].([]any); ok {
		for _, a := range attrs {
			am, ok := a.(map[string]any)
			if !ok {
				continue
			}
			s.Attrs = append(s.Attrs, &jmsms.ACLAttr{
				Name:  jmsapi.FieldStr(am["name"]),
				Match: jmsapi.FieldStr(am["match"]),
				Value: jmsapi.FieldStr(am["value"]),
			})
		}
	}
	return s
}

// parseStrings reads a list of scalars defensively: a relation may come
// back as ids (the common case) or as objects, and an empty parse that
// silently drops rows is a lie of omission.
func parseStrings(v any) []string {
	out := []string{}
	list, ok := v.([]any)
	if !ok {
		return out
	}
	for _, e := range list {
		switch t := e.(type) {
		case map[string]any:
			// An object form: prefer id, fall back to name.
			if s := jmsapi.Str(t["id"]); s != "" {
				out = append(out, s)
			} else if s := jmsapi.Str(t["name"]); s != "" {
				out = append(out, s)
			}
		default:
			if s := jmsapi.Str(e); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func parseLoginACLRule(v any) *jmsms.LoginACLRule {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	rule := &jmsms.LoginACLRule{}
	if g, ok := m["ip_group"].([]any); ok {
		for _, e := range g {
			rule.IPGroup = append(rule.IPGroup, jmsapi.Str(e))
		}
	}
	if tp, ok := m["time_period"].([]any); ok {
		for _, e := range tp {
			em, ok := e.(map[string]any)
			if !ok {
				continue
			}
			rule.TimePeriod = append(rule.TimePeriod, &jmsms.ACLTimePeriod{
				ID:    jmsapi.FieldInt32(em["id"]),
				Value: jmsapi.FieldStr(em["value"]),
			})
		}
	}
	return rule
}

func parseLoginACL(m map[string]any) *jmsms.LoginACL {
	return &jmsms.LoginACL{
		ID:          jmsapi.FieldStr(m["id"]),
		Name:        jmsapi.FieldStr(m["name"]),
		Action:      jmsapi.FieldStr(jmsapi.Label(m, "action")),
		Priority:    jmsapi.FieldInt32(m["priority"]),
		IsActive:    jmsapi.FieldBool(m["is_active"]),
		Users:       parseACLSelector(m["users"]),
		Rules:       parseLoginACLRule(m["rules"]),
		Reviewers:   parseStrings(m["reviewers"]),
		Comment:     jmsapi.FieldStr(m["comment"]),
		CreatedBy:   jmsapi.FieldStr(m["created_by"]),
		DateCreated: jmsapi.FieldStr(m["date_created"]),
		DateUpdated: jmsapi.FieldStr(m["date_updated"]),
	}
}

func parseMaskingRule(m map[string]any) *jmsms.DataMaskingRule {
	return &jmsms.DataMaskingRule{
		ID:            jmsapi.FieldStr(m["id"]),
		Name:          jmsapi.FieldStr(m["name"]),
		Action:        jmsapi.FieldStr(jmsapi.Label(m, "action")),
		Priority:      jmsapi.FieldInt32(m["priority"]),
		IsActive:      jmsapi.FieldBool(m["is_active"]),
		Users:         parseACLSelector(m["users"]),
		Assets:        parseACLSelector(m["assets"]),
		Accounts:      parseStrings(m["accounts"]),
		FieldsPattern: jmsapi.FieldStr(m["fields_pattern"]),
		MaskingMethod: jmsapi.FieldStr(jmsapi.Label(m, "masking_method")),
		MaskPattern:   jmsapi.FieldStr(m["mask_pattern"]),
		OrgID:         jmsapi.FieldStr(m["org_id"]),
		OrgName:       jmsapi.FieldStr(m["org_name"]),
		Reviewers:     parseStrings(m["reviewers"]),
		Comment:       jmsapi.FieldStr(m["comment"]),
		CreatedBy:     jmsapi.FieldStr(m["created_by"]),
		DateCreated:   jmsapi.FieldStr(m["date_created"]),
		DateUpdated:   jmsapi.FieldStr(m["date_updated"]),
	}
}

func parseClipboardOps(v any) []*jmsms.ClipboardOperation {
	out := []*jmsms.ClipboardOperation{}
	list, ok := v.([]any)
	if !ok {
		return out
	}
	for _, e := range list {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, &jmsms.ClipboardOperation{
			Value: jmsapi.FieldStr(em["value"]),
			Label: jmsapi.FieldStr(em["label"]),
		})
	}
	return out
}

func parseClipboardACL(m map[string]any) *jmsms.ClipboardACL {
	return &jmsms.ClipboardACL{
		ID:                    jmsapi.FieldStr(m["id"]),
		Name:                  jmsapi.FieldStr(m["name"]),
		Action:                jmsapi.FieldStr(jmsapi.Label(m, "action")),
		Priority:              jmsapi.FieldInt32(m["priority"]),
		IsActive:              jmsapi.FieldBool(m["is_active"]),
		Users:                 parseACLSelector(m["users"]),
		Assets:                parseACLSelector(m["assets"]),
		Accounts:              parseStrings(m["accounts"]),
		Operations:            parseClipboardOps(m["operations"]),
		CopyTextLimit:         jmsapi.FieldInt32(m["copy_text_limit"]),
		PasteTextLimit:        jmsapi.FieldInt32(m["paste_text_limit"]),
		DownloadFileSizeLimit: jmsapi.FieldInt32(m["download_file_size_limit"]),
		UploadFileSizeLimit:   jmsapi.FieldInt32(m["upload_file_size_limit"]),
		OrgID:                 jmsapi.FieldStr(m["org_id"]),
		OrgName:               jmsapi.FieldStr(m["org_name"]),
		Reviewers:             parseStrings(m["reviewers"]),
		Comment:               jmsapi.FieldStr(m["comment"]),
		CreatedBy:             jmsapi.FieldStr(m["created_by"]),
		DateCreated:           jmsapi.FieldStr(m["date_created"]),
		DateUpdated:           jmsapi.FieldStr(m["date_updated"]),
	}
}

// aclLookup resolves a rule reference (UUID or exact name) to its id.
//
// The endpoints address rules by id only, but an agent holds the NAME --
// it just read the rule. Resolving here keeps the write tools answerable
// with the identifier the caller actually has.
func aclLookup(ctx context.Context, c *repository.Client, resource jmsapi.Resource, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", fmt.Errorf("rule is required: the rule id or its exact name")
	}
	if repository.IsUUID(ref) {
		return ref, nil
	}
	rows, _, err := c.ListCounted(ctx, resource, nil)
	if err != nil {
		return "", err
	}
	var names []string
	for _, m := range rows {
		n := jmsapi.Str(m["name"])
		names = append(names, n)
		if strings.EqualFold(n, ref) {
			return jmsapi.Str(m["id"]), nil
		}
	}
	slices.Sort(names)
	return "", fmt.Errorf("no rule %q; available: %s", ref, strings.Join(names, ", "))
}

// validateTimePeriod checks the weekday ids before the request goes out.
// The server validates too, but its 400 names no field.
func validateTimePeriod(rule *jmsms.LoginACLRule) error {
	if rule == nil {
		return nil
	}
	for _, tp := range rule.TimePeriod {
		if tp == nil || tp.ID == nil {
			return fmt.Errorf("each time_period entry needs an id (0=Sunday … 6=Saturday)")
		}
		if *tp.ID < 0 || *tp.ID > 6 {
			return fmt.Errorf("time_period id must be a weekday 0 (Sunday) … 6 (Saturday), got %d", *tp.ID)
		}
	}
	return nil
}

func RegisterLoginACLTools(r *reg.Registry, c *repository.Client) {
	type loginACLCreateArgs struct {
		Name      string              `json:"name" jsonschema:"rule name"`
		Action    string              `json:"action" jsonschema:"reject / accept / review / notice (review needs a licence)"`
		Priority  *int32              `json:"priority,omitempty" jsonschema:"match order, lower first (default 50)"`
		IsActive  *bool               `json:"is_active,omitempty" jsonschema:"default true — an active rule affects logins immediately"`
		Users     *jmsms.ACLSelector  `json:"users,omitempty" jsonschema:"who it applies to; default {\"type\":\"all\"}"`
		Rules     *jmsms.LoginACLRule `json:"rules" jsonschema:"the rule body: ip_group (required, each entry * / IP / CIDR / range like 10.1.1.1-10.1.1.20) and time_period (weekday-keyed HH:MM~HH:MM windows)"`
		Reviewers []string            `json:"reviewers,omitempty" jsonschema:"user ids to review with (action=review)"`
		Comment   string              `json:"comment,omitempty" jsonschema:"note"`
		Confirm   bool                `json:"confirm" jsonschema:"must be true; this rule decides who may log in to the bastion"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_login_acl_create",
		Description: "Create a LOGIN ACL: a rule that decides who may log in to the BASTION itself, from " +
			"which IPs and during which time windows. NOT who may reach which machines (that is " +
			"jms_permission_create). An active rule takes effect immediately. rules.ip_group is required and " +
			"must be stated explicitly -- omitting it would default to '*', matching every IP.",
		OutputSchema: render.Schema[jmsms.LoginACL](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args loginACLCreateArgs) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(args.Name) == "" {
			return render.Failf("name is required")
		}
		if !oneOf(args.Action, loginACLActions) {
			return render.Failf("action must be one of %s, got %q", strings.Join(loginACLActions, "/"), args.Action)
		}
		if args.Rules == nil || len(args.Rules.IPGroup) == 0 {
			return render.Failf("rules.ip_group is required and cannot be empty: say explicitly which IPs the rule " +
				"matches (* / IP / CIDR / range like 10.1.1.1-10.1.1.20)")
		}
		if err := validateTimePeriod(args.Rules); err != nil {
			return render.Failf("%v", err)
		}
		if err := validateSelector("users", args.Users); err != nil {
			return render.Failf("%v", err)
		}
		body := map[string]any{
			"name":   args.Name,
			"action": strings.ToLower(strings.TrimSpace(args.Action)),
			"users":  aclSelectorWire(args.Users),
			"rules":  args.Rules,
		}
		if args.Priority != nil {
			body["priority"] = *args.Priority
		}
		if args.IsActive != nil {
			body["is_active"] = *args.IsActive
		}
		if len(args.Reviewers) > 0 {
			body["reviewers"] = args.Reviewers
		}
		if args.Comment != "" {
			body["comment"] = args.Comment
		}
		var out map[string]any
		if err := c.Post(ctx, jmsapi.ResLoginACLs, body, &out); err != nil {
			return render.Failf("%v", err)
		}
		return render.Text(parseLoginACL(out))
	})

	type loginACLUpdateArgs struct {
		Rule      string              `json:"rule" jsonschema:"the rule to change: id or exact name"`
		Action    string              `json:"action,omitempty" jsonschema:"reject / accept / review / notice"`
		Priority  *int32              `json:"priority,omitempty" jsonschema:"match order, lower first"`
		IsActive  *bool               `json:"is_active,omitempty" jsonschema:"enable or disable the rule (disable to stop it matching without deleting it)"`
		Users     *jmsms.ACLSelector  `json:"users,omitempty" jsonschema:"replace who it applies to"`
		Rules     *jmsms.LoginACLRule `json:"rules,omitempty" jsonschema:"replace the rule body"`
		Reviewers []string            `json:"reviewers,omitempty" jsonschema:"replace the reviewers"`
		Comment   *string             `json:"comment,omitempty" jsonschema:"replace the note; pass an empty string to clear it (omitting leaves it unchanged)"`
		Confirm   bool                `json:"confirm" jsonschema:"must be true; this changes who may log in to the bastion"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_login_acl_update",
		Description: "Change a login ACL (which IPs and time windows may log in to the bastion). Only the " +
			"fields given are changed; omitted fields keep their values. Set is_active=false to disable a " +
			"rule without deleting it. Find rules by name or id; jms_login_asset_check lists them.",
		OutputSchema: render.Schema[jmsms.LoginACL](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args loginACLUpdateArgs) (*mcp.CallToolResult, any, error) {
		id, err := aclLookup(ctx, c, jmsapi.ResLoginACLs, args.Rule)
		if err != nil {
			return render.Failf("%v", err)
		}
		if args.Action != "" && !oneOf(args.Action, loginACLActions) {
			return render.Failf("action must be one of %s, got %q", strings.Join(loginACLActions, "/"), args.Action)
		}
		if args.Rules != nil {
			if len(args.Rules.IPGroup) == 0 {
				return render.Failf("rules.ip_group cannot be empty: say explicitly which IPs the rule matches")
			}
			if err := validateTimePeriod(args.Rules); err != nil {
				return render.Failf("%v", err)
			}
		}
		if err := validateSelector("users", args.Users); err != nil {
			return render.Failf("%v", err)
		}
		body := map[string]any{}
		if args.Action != "" {
			body["action"] = strings.ToLower(strings.TrimSpace(args.Action))
		}
		if args.Priority != nil {
			body["priority"] = *args.Priority
		}
		if args.IsActive != nil {
			body["is_active"] = *args.IsActive
		}
		if args.Users != nil {
			body["users"] = aclSelectorWire(args.Users)
		}
		if args.Rules != nil {
			body["rules"] = args.Rules
		}
		if args.Reviewers != nil {
			body["reviewers"] = args.Reviewers
		}
		// A pointer so "" can CLEAR the note while omitting it leaves it
		// alone — the three-state split (absent / empty / set) that a bare
		// string collapses: `!= ""` treats an intentional "" as "not given",
		// so the comment could never be emptied.
		if args.Comment != nil {
			body["comment"] = *args.Comment
		}
		if len(body) == 0 {
			return render.Failf("nothing to change: give at least one of action / priority / is_active / users / rules / reviewers / comment")
		}
		var out map[string]any
		if err := c.Patch(ctx, jmsapi.ResLoginACLs, id, body, &out); err != nil {
			return render.Failf("%v", err)
		}
		return render.Text(parseLoginACL(out))
	})

	type loginACLDeleteArgs struct {
		Rule    string `json:"rule" jsonschema:"the rule to delete: id or exact name"`
		Confirm bool   `json:"confirm" jsonschema:"must be true; this deletes the login rule"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_login_acl_delete",
		Description: "Delete a login ACL. Irreversible: whoever it was letting in (or keeping out) falls back " +
			"to the remaining rules. To stop a rule matching without losing it, use jms_login_acl_update with " +
			"is_active=false instead.",
		OutputSchema: render.Schema[jmsms.LoginACL](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args loginACLDeleteArgs) (*mcp.CallToolResult, any, error) {
		id, err := aclLookup(ctx, c, jmsapi.ResLoginACLs, args.Rule)
		if err != nil {
			return render.Failf("%v", err)
		}
		// Read before delete: the answer has to say WHAT was deleted.
		var before map[string]any
		if err := c.Get(ctx, jmsapi.ResLoginACLs, id, &before); err != nil {
			// The record could not be read back before deleting. Do NOT
			// answer an all-nil rule (an empty shell that reads as "an empty
			// rule was deleted") — the only thing known for certain is the id
			// that was deleted, so that is all the answer carries.
			before = map[string]any{"id": id}
		}
		if err := c.Delete(ctx, jmsapi.ResLoginACLs, id); err != nil {
			return render.Failf("%v", err)
		}
		return render.Text(parseLoginACL(before))
	})
}

func RegisterDataMaskingTools(r *reg.Registry, c *repository.Client) {
	type maskingListArgs struct {
		Search string `json:"search,omitempty" jsonschema:"substring filter over name / fields_pattern / masking_method / comment"`
		Limit  int    `json:"limit,omitempty" jsonschema:"max rows (default 50)"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_data_masking_rules",
		Description: "List the data masking rules: which fields get MASKED (###### or a shaped remnant) when " +
			"the bastion shows a secret, for which users / assets / accounts. Use before creating one so the " +
			"new rule does not duplicate or contradict an existing rule.",
		OutputSchema: render.Schema[render.ListOf[jmsms.DataMaskingRule]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args maskingListArgs) (*mcp.CallToolResult, any, error) {
		rows, serverTotal, err := c.ListCounted(ctx, jmsapi.ResDataMaskingRules, nil)
		if err != nil {
			return render.Err(err)
		}
		needle := strings.ToLower(strings.TrimSpace(args.Search))
		// filter → map → sort → truncate → count: render.ListSpec owns the
		// order and the counting. Less is nil: this list never sorted
		// locally, and the endpoint's order is what callers already read.
		res := render.ListSpec[map[string]any, jmsms.DataMaskingRule]{
			Rows: rows,
			Keep: func(m map[string]any) bool {
				if needle == "" {
					return true
				}
				hay := strings.ToLower(jmsapi.Str(m["name"]) + " " + jmsapi.Str(m["fields_pattern"]) + " " +
					jmsapi.Str(jmsapi.Label(m, "masking_method")) + " " + jmsapi.Str(m["comment"]))
				return strings.Contains(hay, needle)
			},
			Map: func(m map[string]any) jmsms.DataMaskingRule {
				return *parseMaskingRule(m)
			},
			Limit: args.Limit,
			Def:   50,
			Max:   200,
		}.Build()
		note := ""
		if res.Total == 0 {
			if serverTotal == 0 {
				note = "no masking rule is configured on this bastion"
			} else {
				note = "no rule matched the filter (" + strconv.Itoa(serverTotal) + " configured)"
			}
		} else if res.Truncated {
			note = "showing " + strconv.Itoa(int(res.Count)) + " of " + strconv.Itoa(int(res.Total)) + "; raise limit to see the rest"
		}
		res.Note = note
		return render.Text(res)
	})

	type maskingCreateArgs struct {
		Name          string             `json:"name" jsonschema:"rule name"`
		Action        string             `json:"action" jsonschema:"reject / accept / review / notice (review needs a licence)"`
		Priority      *int32             `json:"priority,omitempty" jsonschema:"match order, lower first (default 50)"`
		IsActive      *bool              `json:"is_active,omitempty" jsonschema:"default true"`
		Users         *jmsms.ACLSelector `json:"users,omitempty" jsonschema:"which users see the masking; default {\"type\":\"all\"}"`
		Assets        *jmsms.ACLSelector `json:"assets,omitempty" jsonschema:"which assets; default {\"type\":\"all\"}"`
		Accounts      []string           `json:"accounts" jsonschema:"which accounts, e.g. [\"*\"] — required"`
		FieldsPattern string             `json:"fields_pattern" jsonschema:"field NAME pattern to mask, e.g. password"`
		MaskingMethod string             `json:"masking_method" jsonschema:"fixed_char / hide_middle / keep_prefix / keep_suffix"`
		MaskPattern   string             `json:"mask_pattern,omitempty" jsonschema:"replacement chars for fixed_char (default ######)"`
		Reviewers     []string           `json:"reviewers,omitempty" jsonschema:"user ids to review with (action=review)"`
		Comment       string             `json:"comment,omitempty" jsonschema:"note"`
		Confirm       bool               `json:"confirm" jsonschema:"must be true; this creates a masking rule on the bastion"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_data_masking_rule_create",
		Description: "Create a data masking rule: when the bastion SHOWS a secret, fields whose name matches " +
			"fields_pattern are masked (fixed chars, hidden middle, or prefix/suffix only) for the matching " +
			"users / assets / accounts. The secret itself still works — this only changes what is DISPLAYED.",
		OutputSchema: render.Schema[jmsms.DataMaskingRule](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args maskingCreateArgs) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(args.Name) == "" {
			return render.Failf("name is required")
		}
		if !oneOf(args.Action, maskingActions) {
			return render.Failf("action must be one of %s, got %q", strings.Join(maskingActions, "/"), args.Action)
		}
		if strings.TrimSpace(args.FieldsPattern) == "" {
			return render.Failf("fields_pattern is required: name the field to mask, e.g. password")
		}
		method := strings.ToLower(strings.TrimSpace(args.MaskingMethod))
		if !oneOf(method, maskingMethods) {
			return render.Failf("masking_method must be one of %s, got %q", strings.Join(maskingMethods, "/"), args.MaskingMethod)
		}
		if len(args.Accounts) == 0 {
			return render.Failf("accounts is required and cannot be empty; [\"*\"] means every account")
		}
		if err := validateSelector("users", args.Users); err != nil {
			return render.Failf("%v", err)
		}
		if err := validateSelector("assets", args.Assets); err != nil {
			return render.Failf("%v", err)
		}
		body := map[string]any{
			"name":           args.Name,
			"action":         strings.ToLower(strings.TrimSpace(args.Action)),
			"users":          aclSelectorWire(args.Users),
			"assets":         aclSelectorWire(args.Assets),
			"accounts":       args.Accounts,
			"fields_pattern": args.FieldsPattern,
			"masking_method": method,
		}
		if args.Priority != nil {
			body["priority"] = *args.Priority
		}
		if args.IsActive != nil {
			body["is_active"] = *args.IsActive
		}
		if args.MaskPattern != "" {
			body["mask_pattern"] = args.MaskPattern
		}
		if len(args.Reviewers) > 0 {
			body["reviewers"] = args.Reviewers
		}
		if args.Comment != "" {
			body["comment"] = args.Comment
		}
		var out map[string]any
		if err := c.Post(ctx, jmsapi.ResDataMaskingRules, body, &out); err != nil {
			return render.Failf("%v", err)
		}
		return render.Text(parseMaskingRule(out))
	})

	type maskingUpdateArgs struct {
		Rule          string             `json:"rule" jsonschema:"the rule to change: id or exact name"`
		Action        string             `json:"action,omitempty" jsonschema:"reject / accept / review / notice"`
		Priority      *int32             `json:"priority,omitempty" jsonschema:"match order, lower first"`
		IsActive      *bool              `json:"is_active,omitempty" jsonschema:"enable or disable"`
		Users         *jmsms.ACLSelector `json:"users,omitempty" jsonschema:"replace which users"`
		Assets        *jmsms.ACLSelector `json:"assets,omitempty" jsonschema:"replace which assets"`
		Accounts      []string           `json:"accounts,omitempty" jsonschema:"replace which accounts"`
		FieldsPattern *string            `json:"fields_pattern,omitempty" jsonschema:"replace the field pattern; empty string clears it (omit to leave unchanged)"`
		MaskingMethod string             `json:"masking_method,omitempty" jsonschema:"fixed_char / hide_middle / keep_prefix / keep_suffix"`
		MaskPattern   *string            `json:"mask_pattern,omitempty" jsonschema:"replace the replacement chars; empty string clears it (omit to leave unchanged)"`
		Reviewers     []string           `json:"reviewers,omitempty" jsonschema:"replace the reviewers"`
		Comment       *string            `json:"comment,omitempty" jsonschema:"replace the note; empty string clears it (omit to leave unchanged)"`
		Confirm       bool               `json:"confirm" jsonschema:"must be true; this changes the masking rule"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_data_masking_rule_update",
		Description: "Change a data masking rule. Only the fields given are changed. Set is_active=false to " +
			"stop the masking without deleting the rule.",
		OutputSchema: render.Schema[jmsms.DataMaskingRule](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args maskingUpdateArgs) (*mcp.CallToolResult, any, error) {
		id, err := aclLookup(ctx, c, jmsapi.ResDataMaskingRules, args.Rule)
		if err != nil {
			return render.Failf("%v", err)
		}
		if args.Action != "" && !oneOf(args.Action, maskingActions) {
			return render.Failf("action must be one of %s, got %q", strings.Join(maskingActions, "/"), args.Action)
		}
		if args.MaskingMethod != "" && !oneOf(args.MaskingMethod, maskingMethods) {
			return render.Failf("masking_method must be one of %s, got %q", strings.Join(maskingMethods, "/"), args.MaskingMethod)
		}
		if err := validateSelector("users", args.Users); err != nil {
			return render.Failf("%v", err)
		}
		if err := validateSelector("assets", args.Assets); err != nil {
			return render.Failf("%v", err)
		}
		body := map[string]any{}
		if args.Action != "" {
			body["action"] = strings.ToLower(strings.TrimSpace(args.Action))
		}
		if args.Priority != nil {
			body["priority"] = *args.Priority
		}
		if args.IsActive != nil {
			body["is_active"] = *args.IsActive
		}
		if args.Users != nil {
			body["users"] = aclSelectorWire(args.Users)
		}
		if args.Assets != nil {
			body["assets"] = aclSelectorWire(args.Assets)
		}
		if args.Accounts != nil {
			body["accounts"] = args.Accounts
		}
		// Pointers: "" clears, omitting leaves unchanged (see loginACLUpdate).
		if args.FieldsPattern != nil {
			body["fields_pattern"] = *args.FieldsPattern
		}
		if args.MaskingMethod != "" {
			body["masking_method"] = strings.ToLower(strings.TrimSpace(args.MaskingMethod))
		}
		if args.MaskPattern != nil {
			body["mask_pattern"] = *args.MaskPattern
		}
		if args.Reviewers != nil {
			body["reviewers"] = args.Reviewers
		}
		if args.Comment != nil {
			body["comment"] = *args.Comment
		}
		if len(body) == 0 {
			return render.Failf("nothing to change: give at least one field to update")
		}
		var out map[string]any
		if err := c.Patch(ctx, jmsapi.ResDataMaskingRules, id, body, &out); err != nil {
			return render.Failf("%v", err)
		}
		return render.Text(parseMaskingRule(out))
	})

	type maskingDeleteArgs struct {
		Rule    string `json:"rule" jsonschema:"the rule to delete: id or exact name"`
		Confirm bool   `json:"confirm" jsonschema:"must be true; this deletes the masking rule"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_data_masking_rule_delete",
		Description:  "Delete a data masking rule. Irreversible: the fields it masked will show in full again.",
		OutputSchema: render.Schema[jmsms.DataMaskingRule](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args maskingDeleteArgs) (*mcp.CallToolResult, any, error) {
		id, err := aclLookup(ctx, c, jmsapi.ResDataMaskingRules, args.Rule)
		if err != nil {
			return render.Failf("%v", err)
		}
		var before map[string]any
		if err := c.Get(ctx, jmsapi.ResDataMaskingRules, id, &before); err != nil {
			// Read-back failed: the delete still happened, so answer with the
			// only fact that is certain (the id) rather than an empty rule.
			before = map[string]any{"id": id}
		}
		if err := c.Delete(ctx, jmsapi.ResDataMaskingRules, id); err != nil {
			return render.Failf("%v", err)
		}
		return render.Text(parseMaskingRule(before))
	})
}

func RegisterClipboardACLTools(r *reg.Registry, c *repository.Client) {
	type clipboardListArgs struct {
		Search string `json:"search,omitempty" jsonschema:"substring filter over name / comment"`
		Limit  int    `json:"limit,omitempty" jsonschema:"max rows (default 50)"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_clipboard_acls",
		Description: "List the clipboard ACLs: which sessions may copy / paste, and the text and file-size " +
			"ceilings, for which users / assets / accounts. Use before creating one so the new rule does not " +
			"contradict an existing rule.",
		OutputSchema: render.Schema[render.ListOf[jmsms.ClipboardACL]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args clipboardListArgs) (*mcp.CallToolResult, any, error) {
		rows, serverTotal, err := c.ListCounted(ctx, jmsapi.ResClipboardACLs, nil)
		if err != nil {
			return render.Err(err)
		}
		needle := strings.ToLower(strings.TrimSpace(args.Search))
		// filter → map → sort → truncate → count: render.ListSpec owns the
		// order and the counting. Less is nil: this list never sorted
		// locally, and the endpoint's order is what callers already read.
		res := render.ListSpec[map[string]any, jmsms.ClipboardACL]{
			Rows: rows,
			Keep: func(m map[string]any) bool {
				if needle == "" {
					return true
				}
				hay := strings.ToLower(jmsapi.Str(m["name"]) + " " + jmsapi.Str(m["comment"]))
				return strings.Contains(hay, needle)
			},
			Map: func(m map[string]any) jmsms.ClipboardACL {
				return *parseClipboardACL(m)
			},
			Limit: args.Limit,
			Def:   50,
			Max:   200,
		}.Build()
		note := ""
		if res.Total == 0 {
			if serverTotal == 0 {
				note = "no clipboard ACL is configured on this bastion"
			} else {
				note = "no rule matched the filter (" + strconv.Itoa(serverTotal) + " configured)"
			}
		} else if res.Truncated {
			note = "showing " + strconv.Itoa(int(res.Count)) + " of " + strconv.Itoa(int(res.Total)) + "; raise limit to see the rest"
		}
		res.Note = note
		return render.Text(res)
	})

	type clipboardCreateArgs struct {
		Name                  string             `json:"name" jsonschema:"rule name"`
		Action                string             `json:"action" jsonschema:"reject or accept (this family takes no other action)"`
		Priority              *int32             `json:"priority,omitempty" jsonschema:"match order, lower first (default 50)"`
		IsActive              *bool              `json:"is_active,omitempty" jsonschema:"default true"`
		Users                 *jmsms.ACLSelector `json:"users,omitempty" jsonschema:"which users; default {\"type\":\"all\"}"`
		Assets                *jmsms.ACLSelector `json:"assets,omitempty" jsonschema:"which assets; default {\"type\":\"all\"}"`
		Accounts              []string           `json:"accounts" jsonschema:"which accounts, e.g. [\"*\"] — required"`
		Operations            []string           `json:"operations" jsonschema:"which clipboard operations the rule governs: copy and/or paste — required, at least one"`
		CopyTextLimit         *int32             `json:"copy_text_limit,omitempty" jsonschema:"copied text ceiling in bytes (0 = the deployment default)"`
		PasteTextLimit        *int32             `json:"paste_text_limit,omitempty" jsonschema:"pasted text ceiling in bytes"`
		DownloadFileSizeLimit *int32             `json:"download_file_size_limit,omitempty" jsonschema:"downloaded file size ceiling in bytes"`
		UploadFileSizeLimit   *int32             `json:"upload_file_size_limit,omitempty" jsonschema:"uploaded file size ceiling in bytes"`
		Comment               string             `json:"comment,omitempty" jsonschema:"note"`
		Confirm               bool               `json:"confirm" jsonschema:"must be true; this creates a clipboard rule on the bastion"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_clipboard_acl_create",
		Description: "Create a clipboard ACL: what a session's clipboard may carry (copy / paste) and the text " +
			"and file-size ceilings, for the matching users / assets / accounts. action=reject blocks the " +
			"listed operations; action=accept allows them within the limits. Operations are only copy and " +
			"paste — file transfer limits are the *_file_size_limit fields, not operations.",
		OutputSchema: render.Schema[jmsms.ClipboardACL](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args clipboardCreateArgs) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(args.Name) == "" {
			return render.Failf("name is required")
		}
		if !oneOf(args.Action, clipboardActions) {
			return render.Failf("action must be one of %s, got %q", strings.Join(clipboardActions, "/"), args.Action)
		}
		if len(args.Accounts) == 0 {
			return render.Failf("accounts is required and cannot be empty; [\"*\"] means every account")
		}
		ops := make([]string, 0, len(args.Operations))
		for _, op := range args.Operations {
			op = strings.ToLower(strings.TrimSpace(op))
			if !oneOf(op, clipboardOps) {
				return render.Failf("operations may only contain copy and paste, got %q", op)
			}
			ops = append(ops, op)
		}
		if len(ops) == 0 {
			return render.Failf("operations is required and needs at least one of copy / paste")
		}
		if err := validateSelector("users", args.Users); err != nil {
			return render.Failf("%v", err)
		}
		if err := validateSelector("assets", args.Assets); err != nil {
			return render.Failf("%v", err)
		}
		body := map[string]any{
			"name":       args.Name,
			"action":     strings.ToLower(strings.TrimSpace(args.Action)),
			"users":      aclSelectorWire(args.Users),
			"assets":     aclSelectorWire(args.Assets),
			"accounts":   args.Accounts,
			"operations": ops,
		}
		if args.Priority != nil {
			body["priority"] = *args.Priority
		}
		if args.IsActive != nil {
			body["is_active"] = *args.IsActive
		}
		if args.CopyTextLimit != nil {
			body["copy_text_limit"] = *args.CopyTextLimit
		}
		if args.PasteTextLimit != nil {
			body["paste_text_limit"] = *args.PasteTextLimit
		}
		if args.DownloadFileSizeLimit != nil {
			body["download_file_size_limit"] = *args.DownloadFileSizeLimit
		}
		if args.UploadFileSizeLimit != nil {
			body["upload_file_size_limit"] = *args.UploadFileSizeLimit
		}
		if args.Comment != "" {
			body["comment"] = args.Comment
		}
		var out map[string]any
		if err := c.Post(ctx, jmsapi.ResClipboardACLs, body, &out); err != nil {
			return render.Failf("%v", err)
		}
		return render.Text(parseClipboardACL(out))
	})

	type clipboardUpdateArgs struct {
		Rule                  string             `json:"rule" jsonschema:"the rule to change: id or exact name"`
		Action                string             `json:"action,omitempty" jsonschema:"reject or accept"`
		Priority              *int32             `json:"priority,omitempty" jsonschema:"match order, lower first"`
		IsActive              *bool              `json:"is_active,omitempty" jsonschema:"enable or disable"`
		Users                 *jmsms.ACLSelector `json:"users,omitempty" jsonschema:"replace which users"`
		Assets                *jmsms.ACLSelector `json:"assets,omitempty" jsonschema:"replace which assets"`
		Accounts              []string           `json:"accounts,omitempty" jsonschema:"replace which accounts"`
		Operations            []string           `json:"operations,omitempty" jsonschema:"replace the governed operations (copy / paste)"`
		CopyTextLimit         *int32             `json:"copy_text_limit,omitempty" jsonschema:"copied text ceiling in bytes"`
		PasteTextLimit        *int32             `json:"paste_text_limit,omitempty" jsonschema:"pasted text ceiling in bytes"`
		DownloadFileSizeLimit *int32             `json:"download_file_size_limit,omitempty" jsonschema:"downloaded file size ceiling in bytes"`
		UploadFileSizeLimit   *int32             `json:"upload_file_size_limit,omitempty" jsonschema:"uploaded file size ceiling in bytes"`
		Comment               *string            `json:"comment,omitempty" jsonschema:"replace the note; empty string clears it (omit to leave unchanged)"`
		Confirm               bool               `json:"confirm" jsonschema:"must be true; this changes the clipboard rule"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_clipboard_acl_update",
		Description: "Change a clipboard ACL. Only the fields given are changed. Set is_active=false to stop " +
			"the rule governing the clipboard without deleting it.",
		OutputSchema: render.Schema[jmsms.ClipboardACL](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args clipboardUpdateArgs) (*mcp.CallToolResult, any, error) {
		id, err := aclLookup(ctx, c, jmsapi.ResClipboardACLs, args.Rule)
		if err != nil {
			return render.Failf("%v", err)
		}
		if args.Action != "" && !oneOf(args.Action, clipboardActions) {
			return render.Failf("action must be one of %s, got %q", strings.Join(clipboardActions, "/"), args.Action)
		}
		if err := validateSelector("users", args.Users); err != nil {
			return render.Failf("%v", err)
		}
		if err := validateSelector("assets", args.Assets); err != nil {
			return render.Failf("%v", err)
		}
		body := map[string]any{}
		if args.Action != "" {
			body["action"] = strings.ToLower(strings.TrimSpace(args.Action))
		}
		if args.Priority != nil {
			body["priority"] = *args.Priority
		}
		if args.IsActive != nil {
			body["is_active"] = *args.IsActive
		}
		if args.Users != nil {
			body["users"] = aclSelectorWire(args.Users)
		}
		if args.Assets != nil {
			body["assets"] = aclSelectorWire(args.Assets)
		}
		if args.Accounts != nil {
			body["accounts"] = args.Accounts
		}
		if args.Operations != nil {
			ops := make([]string, 0, len(args.Operations))
			for _, op := range args.Operations {
				op = strings.ToLower(strings.TrimSpace(op))
				if !oneOf(op, clipboardOps) {
					return render.Failf("operations may only contain copy and paste, got %q", op)
				}
				ops = append(ops, op)
			}
			if len(ops) == 0 {
				return render.Failf("operations cannot be empty; leave the field out to keep the current set")
			}
			body["operations"] = ops
		}
		if args.CopyTextLimit != nil {
			body["copy_text_limit"] = *args.CopyTextLimit
		}
		if args.PasteTextLimit != nil {
			body["paste_text_limit"] = *args.PasteTextLimit
		}
		if args.DownloadFileSizeLimit != nil {
			body["download_file_size_limit"] = *args.DownloadFileSizeLimit
		}
		if args.UploadFileSizeLimit != nil {
			body["upload_file_size_limit"] = *args.UploadFileSizeLimit
		}
		if args.Comment != nil {
			body["comment"] = *args.Comment
		}
		if len(body) == 0 {
			return render.Failf("nothing to change: give at least one field to update")
		}
		var out map[string]any
		if err := c.Patch(ctx, jmsapi.ResClipboardACLs, id, body, &out); err != nil {
			return render.Failf("%v", err)
		}
		return render.Text(parseClipboardACL(out))
	})

	type clipboardDeleteArgs struct {
		Rule    string `json:"rule" jsonschema:"the rule to delete: id or exact name"`
		Confirm bool   `json:"confirm" jsonschema:"must be true; this deletes the clipboard rule"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_clipboard_acl_delete",
		Description:  "Delete a clipboard ACL. Irreversible: the clipboard falls back to the remaining rules.",
		OutputSchema: render.Schema[jmsms.ClipboardACL](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args clipboardDeleteArgs) (*mcp.CallToolResult, any, error) {
		id, err := aclLookup(ctx, c, jmsapi.ResClipboardACLs, args.Rule)
		if err != nil {
			return render.Failf("%v", err)
		}
		var before map[string]any
		if err := c.Get(ctx, jmsapi.ResClipboardACLs, id, &before); err != nil {
			// Read-back failed: the delete still happened, so answer with the
			// only fact that is certain (the id) rather than an empty rule.
			before = map[string]any{"id": id}
		}
		if err := c.Delete(ctx, jmsapi.ResClipboardACLs, id); err != nil {
			return render.Failf("%v", err)
		}
		return render.Text(parseClipboardACL(before))
	})
}
