package handler

// tools_filter.go covers command filtering — the part of JumpServer that decides
// whether a command may run at all. Everything else in this server either
// reports what happened or asks permission; this is where a rule can stop a
// command outright.
//
// The chain is two objects:
//
//	command-group  a named list of commands          (/acls/command-groups/)
//	command-filter-acl  group + who + what + action  (/acls/command-filter-acls/)
//
// Both were empty on this bastion (2026-10-14), so nothing is being blocked
// today. The filters are written with a confirm gate because they are blunt:
// a wrong rule silently breaks somebody's automation, and the failure shows up
// on someone else's machine at 3am.

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/yi-nology/jumpserver-mgmt/internal/service"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yi-nology/jumpserver-kit/model/jms"
	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
	"github.com/yi-nology/jumpserver-mgmt/biz/model/jmsms"
	"github.com/yi-nology/jumpserver-mgmt/internal/repository"
)

func RegisterFilterTools(r *reg.Registry, c *repository.Client) {
	RegisterCommandGuard(r, c)
	type groupListArgs struct {
		Limit int `json:"limit,omitempty" jsonschema:"max rows (default 50)"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_cmdgroup_list",
		Description:  "List command groups (named sets of commands used by command filters) and the commands each contains. Use it to see which groups exist before writing a filter, and to check what a group's commands really are (they are stored as one text block, one command per line).",
		OutputSchema: render.Schema[render.ListOf[jmsms.CommandGroupSummary]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args groupListArgs) (*mcp.CallToolResult, any, error) {
		rows, err := c.List(ctx, jmsapi.ResCmdGroups)
		if err != nil {
			return render.Failf("%v", err)
		}
		// filter → map → sort → truncate → count: render.ListSpec owns the
		// order and the three counting fields. This replaces a loop that
		// capped BEFORE sorting — so limit=50 returned the first 50 rows in
		// the endpoint's order, sorted among themselves. Sorting before the
		// cap is what makes limit mean "the top N by name".
		return render.Text(render.ListSpec[map[string]any, jmsms.CommandGroupSummary]{
			Rows: rows,
			Map: func(g map[string]any) jmsms.CommandGroupSummary {
				return jmsms.CommandGroupSummary{
					ID:         jmsapi.FieldStr(g["id"]),
					Name:       jmsapi.FieldStr(g["name"]),
					Type:       jms.Opt(jmsapi.Label(g, "type")),
					IgnoreCase: jms.OptBool(g["ignore_case"] == true),
					Comment:    jmsapi.FieldStr(g["comment"]),
					Commands:   jmsapi.FieldStr(g["content"]),
				}
			},
			Less:  func(a, b jmsms.CommandGroupSummary) bool { return a.GetName() < b.GetName() },
			Limit: args.Limit,
			Def:   50,
			Max:   200,
		}.Build())
	})

	type groupCreateArgs struct {
		Name     string   `json:"name" jsonschema:"group name, e.g. 'destructive-basic'"`
		Commands []string `json:"commands" jsonschema:"the commands to match, e.g. ['rm','reboot','shutdown','mkfs']"`
		// A pointer, so that "not given" and "explicitly false" are
		// different things: the bastion's own default for a new group is
		// case-INsensitive, and sending an explicit false would make the
		// group case-sensitive — so a rule listing "rm" would stop
		// catching "RM -rf", while the same group made in the bastion's UI
		// would still catch it.
		IgnoreCase *bool `json:"ignore_case,omitempty" jsonschema:"case-sensitive matching; leave unset for the bastion's own default (case-insensitive)"`
		Confirm    bool  `json:"confirm" jsonschema:"must be true; a rule built from this can block commands for other users"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_cmdgroup_create",
		Description: "Create a command group: a named set of commands that a command filter can then act on. " +
			"The group alone blocks nothing; bind it to a filter with jms_cmdfilter_create.",
		OutputSchema: render.Schema[jmsms.CmdGroupCreated](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args groupCreateArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to create the command group")
		}
		if len(args.Commands) == 0 {
			return render.Failf("commands is required")
		}
		content := strings.Join(args.Commands, "\n")
		body := map[string]any{
			"name":    args.Name,
			"content": content,
		}
		// Only sent when the caller said so: the bastion applies its own
		// default (case-insensitive) otherwise.
		if args.IgnoreCase != nil {
			body["ignore_case"] = *args.IgnoreCase
		}
		var out map[string]any
		if err := c.Post(ctx, jmsapi.ResCmdGroups, body, &out); err != nil {
			return render.Failf("%v", err)
		}
		return render.Text(&jmsms.CmdGroupCreated{
			ID:       jmsapi.Str(out["id"]),
			Name:     jmsapi.Str(out["name"]),
			Commands: args.Commands,
			Next:     jms.Opt("bind it with jms_cmdfilter_create, otherwise nothing changes"),
		})
	})

	type filterListArgs struct {
		Limit int `json:"limit,omitempty" jsonschema:"max rows (default 50)"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_cmdfilter_list",
		Description:  "List command filter ACLs: which command group is applied to which users, assets and accounts, and what action it takes. Use it to see what is filtered right now -- before changing a filter, and before blaming one for a refusal.",
		OutputSchema: render.Schema[render.ListOf[jmsms.CommandFilterSummary]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args filterListArgs) (*mcp.CallToolResult, any, error) {
		rows, err := c.List(ctx, jmsapi.ResCmdFilters)
		if err != nil {
			return render.Failf("%v", err)
		}
		// filter → map → sort → truncate → count: render.ListSpec owns the
		// order and the three counting fields. This replaces a loop that
		// capped BEFORE sorting — so limit=50 returned the first 50 rows in
		// the endpoint's order, sorted among themselves. Sorting before the
		// cap is what makes limit mean "the top N by priority, then name".
		return render.Text(render.ListSpec[map[string]any, jmsms.CommandFilterSummary]{
			Rows: rows,
			Map: func(f map[string]any) jmsms.CommandFilterSummary {
				return jmsms.CommandFilterSummary{
					ID:            jmsapi.FieldStr(f["id"]),
					Name:          jmsapi.FieldStr(f["name"]),
					Action:        jms.Opt(jmsapi.Label(f, "action")),
					Priority:      jmsapi.FieldInt32(f["priority"]),
					IsActive:      jms.OptBool(f["is_active"] == true),
					Users:         jmsapi.FieldInt32(f["users_amount"]),
					Assets:        jmsapi.FieldInt32(f["assets_amount"]),
					Accounts:      jmsapi.FieldInt32(f["accounts_amount"]),
					CommandGroups: idList(f["command_groups"]),
					Comment:       jmsapi.FieldStr(f["comment"]),
				}
			},
			Less: func(a, b jmsms.CommandFilterSummary) bool {
				pa, pb := a.GetPriority(), b.GetPriority()
				if pa != pb {
					return pa < pb
				}
				return a.GetName() < b.GetName()
			},
			Limit: args.Limit,
			Def:   50,
			Max:   200,
		}.Build())
	})

	type filterCreateArgs struct {
		Name     string   `json:"name"`
		Action   string   `json:"action" jsonschema:"one of reject, accept, warning, notify_and_warn"`
		Groups   []string `json:"command_groups" jsonschema:"command group names or UUIDs to apply"`
		Users    []string `json:"users,omitempty" jsonschema:"usernames the filter applies to"`
		Assets   []string `json:"assets,omitempty" jsonschema:"asset refs the filter applies to; empty with users means all their assets"`
		Accounts []string `json:"accounts,omitempty" jsonschema:"account usernames to scope to; leave empty for all"`
		Priority int      `json:"priority,omitempty" jsonschema:"lower numbers are evaluated first"`
		Comment  string   `json:"comment,omitempty"`
		Confirm  bool     `json:"confirm" jsonschema:"must be true; this can block commands for other users"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_cmdfilter_create",
		Description: "Create a command filter ACL binding a command group to users and assets. " +
			"action=reject denies the command outright; warning and notify_and_warn allow it but record it; " +
			"accept explicitly allows. Mind the scope: a filter aimed at the wrong asset silently breaks " +
			"somebody's automation, and it fails on their machine, not yours.",
		OutputSchema: render.Schema[jmsms.CmdFilterCreated](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args filterCreateArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to create the command filter")
		}
		switch args.Action {
		case "reject", "accept", "warning", "notify_and_warn":
		case "":
			return render.Failf("action is required: reject, accept, warning or notify_and_warn")
		default:
			return render.Failf("unknown action %q: use reject, accept, warning or notify_and_warn", args.Action)
		}
		if len(args.Groups) == 0 {
			return render.Failf("command_groups is required: create one with jms_cmdgroup_create first")
		}
		if len(args.Users) == 0 && len(args.Assets) == 0 {
			return render.Failf("scope the filter: pass users and/or assets")
		}

		groupIDs := make([]string, 0, len(args.Groups))
		for _, g := range args.Groups {
			id, err := c.CommandGroupID(ctx, g)
			if err != nil {
				return render.Failf("%v", err)
			}
			groupIDs = append(groupIDs, id)
		}

		userIDs := []string{}
		for _, u := range args.Users {
			uid, err := c.UserIDByName(ctx, u)
			if err != nil {
				return render.Failf("%v", err)
			}
			userIDs = append(userIDs, uid)
		}

		assetIDs := []string{}
		if len(args.Assets) > 0 {
			ids, _, err := c.ResolveAssets(ctx, args.Assets)
			if err != nil {
				return render.Failf("%v", err)
			}
			assetIDs = ids
		}

		// accounts is a plain list, and accepts either a UUID or a bare
		// username. Resolving names against the scoped assets keeps a typo from
		// silently meaning "every account".
		accountIDs := []string{}
		for _, a := range args.Accounts {
			if repository.IsUUID(a) {
				accountIDs = append(accountIDs, a)
				continue
			}
			if len(assetIDs) == 0 {
				return render.Failf("account %q given without assets: a username only resolves "+
					"within a named asset, otherwise pass the account UUID", a)
			}
			found := ""
			for _, aid := range assetIDs {
				id, err := c.AccountID(ctx, aid, a)
				if err == nil {
					found = id
					break
				}
			}
			if found == "" {
				return render.Failf("account %q not found on %s", a, strings.Join(args.Assets, ", "))
			}
			accountIDs = append(accountIDs, found)
		}

		// JumpServer's many-to-many serializers are not uniform (v4 and v5 alike), verified by
		// probing each field against the live API on 2026-10-14:
		//
		//	users           m2m envelope only   {"type":"ids","ids":[...]}
		//	assets          either shape        {"type":"all"} or [ids]
		//	accounts        plain list only     [] or [uuid] -- an envelope is 400
		//	command_groups  plain UUID array    an envelope is 400
		//
		// Getting this wrong produces "Invalid JSON many-to-many field" or
		// "Expected a list of items but got type dict", never a useful message.
		body := map[string]any{
			"name":           args.Name,
			"action":         args.Action,
			"command_groups": repository.IDList(groupIDs),
			"users":          m2mEnvelope(userIDs),
			"assets":         m2mEnvelope(assetIDs),
			"accounts":       repository.IDList(accountIDs),
			"is_active":      true,
		}
		if args.Priority != 0 {
			body["priority"] = args.Priority
		}
		if args.Comment != "" {
			body["comment"] = args.Comment
		}

		var out map[string]any
		if err := c.Post(ctx, jmsapi.ResCmdFilters, body, &out); err != nil {
			return render.Failf("%v", err)
		}
		return render.Text(&jmsms.CmdFilterCreated{
			ID:            jmsapi.Str(out["id"]),
			Name:          jmsapi.Str(out["name"]),
			Action:        jmsapi.Label(out, "action"),
			CommandGroups: jms.OptInt32(int32(len(groupIDs))),
			Users:         jmsapi.FieldInt32(out["users_amount"]),
			Assets:        jmsapi.FieldInt32(out["assets_amount"]),
			Note: jms.Opt("verify with a harmless command before assuming it is in force; " +
				"filters apply at session start, so existing sessions are unaffected"),
		})
	})

	type filterDeleteArgs struct {
		Confirm bool `json:"confirm" jsonschema:"must be true; removing a filter reopens blocked commands"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_cmdfilter_delete",
		Description:  "Delete a command filter ACL by name or UUID. Removing a filter means the commands it blocked become runnable again. Use it when a filter blocks what it should not, and know that it reopens those commands for everyone in scope.",
		OutputSchema: render.Schema[jmsms.FilterDeleted](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args struct {
		Name    string `json:"name,omitempty" jsonschema:"filter ACL name or UUID"`
		Group   string `json:"command_group,omitempty" jsonschema:"command group name or UUID"`
		Confirm bool   `json:"confirm" jsonschema:"must be true"`
	}) (*mcp.CallToolResult, any, error) {
		return deleteFilterOrGroup(ctx, c, args.Name, args.Group, args.Confirm)
	})

	reg.Add(r, &mcp.Tool{
		Name: "jms_cmdgroup_delete",
		Description: "Delete a command group by name or UUID. It blocks nothing on its own, so deleting one only " +
			"removes it from the filters that reference it -- those filters then cover fewer commands. " +
			"(jms_cmdfilter_delete does the same thing; this one exists so the group tools are symmetric.)",
		OutputSchema: render.Schema[jmsms.FilterDeleted](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args struct {
		Group   string `json:"command_group" jsonschema:"command group name or UUID"`
		Confirm bool   `json:"confirm" jsonschema:"must be true"`
	}) (*mcp.CallToolResult, any, error) {
		return deleteFilterOrGroup(ctx, c, "", args.Group, args.Confirm)
	})

	type terminateArgs struct {
		SessionID string `json:"session_id" jsonschema:"session id from jms_sessions_live or jms_sessions_list"`
		Confirm   bool   `json:"confirm" jsonschema:"must be true; this kills someone's live session"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_session_terminate",
		Description:  "Forcibly terminate a live terminal session. The user loses their shell and the session is closed; the replay recording is kept. Use it when someone is holding a session that should not be held — it stops the shell, it does not erase the audit trail.",
		OutputSchema: render.Schema[jmsms.SessionTerminated](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args terminateArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to terminate the session")
		}
		var out map[string]any
		if err := c.PostSub(ctx, jmsapi.ResSessions, args.SessionID, "terminate", nil, &out); err != nil {
			return render.Failf("%v", err)
		}
		return render.Text(&jmsms.SessionTerminated{
			Terminated: args.SessionID,
			Response:   jms.Opt(jmsapi.Str(out)),
		})
	})
}

func deleteFilterOrGroup(ctx context.Context, c *repository.Client, filter, group string, confirm bool) (*mcp.CallToolResult, any, error) {
	if !confirm {
		return render.Failf("set confirm=true; removing a filter reopens the commands it blocked")
	}
	switch {
	case filter != "":
		rows, err := c.List(ctx, jmsapi.ResCmdFilters)
		if err != nil {
			return render.Failf("%v", err)
		}
		for _, f := range rows {
			if repository.MatchesRef(f, filter) {
				name := jmsapi.Str(f["name"])
				if err := c.Delete(ctx, jmsapi.ResCmdFilters, jmsapi.Str(f["id"])); err != nil {
					return render.Failf("%v", err)
				}
				return render.Text(&jmsms.FilterDeleted{DeletedFilter: jms.Opt(name)})
			}
		}
		return render.Failf("no such command filter: %s", filter)
	case group != "":
		rows, err := c.List(ctx, jmsapi.ResCmdGroups)
		if err != nil {
			return render.Failf("%v", err)
		}
		for _, g := range rows {
			if repository.MatchesRef(g, group) {
				name := jmsapi.Str(g["name"])
				if err := c.Delete(ctx, jmsapi.ResCmdGroups, jmsapi.Str(g["id"])); err != nil {
					return render.Failf("%v", err)
				}
				return render.Text(&jmsms.FilterDeleted{DeletedCommandGroup: jms.Opt(name)})
			}
		}
		return render.Failf("no such command group: %s", group)
	default:
		return render.Failf("pass filter or command_group")
	}
}

// matchesRef matches an object by UUID or by (possibly partial) name.

// ---------------------------------------------------------------- command guard

// commandGuard answers the question an agent can only find out the expensive
// way: "will the bastion refuse this command?".
//
// A rejected command costs a full bastion session -- about ten seconds of TUI
// walk -- and the refusal arrives as a message that reads like a permissions
// problem rather than a policy one. Checking first turns a wasted session
// into a one-call answer.
//
// The matching rules are the bastion's own, not a guess:
//
//   - a command group of type "command" matches a line when that line appears
//     as a standalone word anywhere in the input: "rm" matches "rm -rf" and
//     "sudo rm", but not "rmdir";
//   - a group of type "regex" matches when the pattern is found in the input;
//   - the group's ignore_case flag decides whether the comparison folds case.
//
// A filter applies when its scope covers the caller: an empty users or assets
// list means "everyone" / "every asset", a non-empty one means exactly those.
func RegisterCommandGuard(r *reg.Registry, c *repository.Client) {
	type guardArgs struct {
		Command string `json:"command" jsonschema:"the command you are about to run"`
		Asset   string `json:"asset,omitempty" jsonschema:"the asset it would run on (address, name or UUID)"`
		Account string `json:"account,omitempty" jsonschema:"the account it would run as"`
		User    string `json:"user,omitempty" jsonschema:"the JumpServer user it would run as; defaults to the delegated/own account"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_command_guard",
		Description:  "Check whether a command will be refused by the bastion's command filters BEFORE running it. Use it when a command looks risky, when a previous attempt was rejected, or when you are about to run something destructive on someone else's machine. A rejection costs a whole bastion session and its error reads like a permissions problem, so checking first is cheaper. Pass the asset, account and user the command would run as, because a filter is scoped to them.",
		OutputSchema: render.Schema[jmsms.CommandGuardResult](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args guardArgs) (*mcp.CallToolResult, any, error) {
		command := strings.TrimSpace(args.Command)
		if command == "" {
			return render.Failf("command is required")
		}
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		// Resolve the scope first, so the answer can be specific.
		var assetID, UserID string
		var assetName string
		if args.Asset != "" {
			ids, meta, err := c.ResolveAssets(ctx, []string{args.Asset})
			if err != nil {
				return render.Failf("%v", err)
			}
			assetID = ids[0]
			assetName = jmsapi.Str(meta[0]["name"])
		}
		if args.User != "" {
			id, err := c.UserIDByName(ctx, args.User)
			if err != nil {
				return render.Failf("%v", err)
			}
			UserID = id
		} else {
			UserID = c.DelegationUserID
		}

		// The list endpoint returns null for every related object, so each
		// filter has to be read in full before it can be matched.
		filters, err := c.List(ctx, jmsapi.ResCmdFilters)
		if err != nil {
			return render.Failf("%v", err)
		}
		groups, err := c.List(ctx, jmsapi.ResCmdGroups)
		if err != nil {
			return render.Failf("%v", err)
		}
		groupByID := map[string]map[string]any{}
		for _, g := range groups {
			groupByID[jmsapi.Str(g["id"])] = g
		}

		matches := []jmsms.MatchedFilter{}
		applicable := 0
		for _, f := range filters {
			if active, ok := f["is_active"].(bool); ok && !active {
				continue
			}
			var detail map[string]any
			if err := c.Get(ctx, jmsapi.ResCmdFilters, jmsapi.Str(f["id"]), &detail); err != nil {
				continue
			}
			scope, ok := service.FilterApplies(detail, UserID, assetID, args.Account)
			if !ok {
				continue
			}
			applicable++

			hitCmd, hitGroup := "", ""
			for _, gref := range jmsapi.AsSlice(detail["command_groups"]) {
				gm, ok := gref.(map[string]any)
				if !ok {
					continue
				}
				g, ok := groupByID[jmsapi.Str(gm["id"])]
				if !ok {
					continue
				}
				if cmd, matched := service.MatchCommandGroup(command, g); matched {
					hitCmd, hitGroup = cmd, jmsapi.Str(g["name"])
					break
				}
			}
			if hitCmd == "" {
				continue
			}
			matches = append(matches, jmsms.MatchedFilter{
				Filter:         jmsapi.Str(detail["name"]),
				Action:         jmsapi.FieldStr(jmsapi.Label(detail, "action")),
				Priority:       jmsapi.FieldInt32(detail["priority"]),
				CommandGroup:   jmsapi.FieldStr(hitGroup),
				MatchedCommand: jmsapi.FieldStr(hitCmd),
				Scope:          jmsapi.FieldStr(scope),
			})
		}
		slices.SortFunc(matches, func(a, b jmsms.MatchedFilter) int {
			return cmp.Compare(a.GetPriority(), b.GetPriority())
		})

		// The verdict. The old shape was a four-value enum ("blocked",
		// "warned", "explicitly_allowed", "not_filtered"); it is now a
		// sentence plus the shared status, and the enum's meaning is kept in
		// the per-filter checks: a reject is a fail, a warning is a warn, an
		// accept and "no filter matched" are ok.
		checks := []*jms.Check{}
		rejecters := []string{}
		warners := []string{}
		accepted := false
		for _, m := range matches {
			action := m.GetAction()
			name := m.Filter
			cmd := m.GetMatchedCommand()
			ck := &jms.Check{
				Name: "filter:" + name,
				Detail: fmt.Sprintf("filter %q %s %q (command group %q, scope %s)",
					name, action, cmd, m.GetCommandGroup(),
					m.GetScope()),
			}
			switch action {
			case "reject":
				ck.Status = service.Fail
				ck.Fix = service.FixText("the bastion will REFUSE this command: do not run it as-is -- either the task " +
					"needs a different approach, or the filter's scope is wrong and the operator has to " +
					"change it (jms_cmdfilter_delete, then jms_cmdfilter_create)")
				rejecters = append(rejecters, fmt.Sprintf("%s rejects %q", name, cmd))
			case "warning", "notify_and_warn":
				ck.Status = service.Warn
				ck.Fix = service.FixText("the command will run but is recorded, and a warning is shown to the user")
				warners = append(warners, fmt.Sprintf("%s warns about %q", name, cmd))
			default:
				ck.Status = service.OK
				accepted = true
			}
			checks = append(checks, ck)
		}
		switch {
		case len(filters) == 0:
			// "No filters at all" is the answer to "will this be refused?",
			// so it belongs in the checks rather than in a free-floating note.
			checks = append(checks, &jms.Check{
				Name: "command_filters", Status: service.OK,
				Detail: "this bastion has no command filters configured at all",
			})
		case len(matches) == 0:
			checks = append(checks, &jms.Check{
				Name: "filter_match", Status: service.OK,
				Detail: "no command filter covers this command for the given scope",
			})
		}

		verdict := "no command filter covers this command for the given scope"
		okAdvice := verdict
		switch {
		case len(rejecters) > 0:
			verdict = "the bastion will REFUSE this command: " + strings.Join(rejecters, "; ")
		case len(warners) > 0:
			verdict = "the command will run, but a filter records it and shows a warning: " +
				strings.Join(warners, "; ")
		case accepted:
			verdict = "an accept rule covers this command"
		}

		res := &jmsms.CommandGuardResult{
			Command:         command,
			MatchingFilters: matches,
			FiltersExamined: int32(len(filters)),
			FiltersInScope:  int32(applicable),
			Asset:           assetName,
		}
		res.Diagnosis = service.Diagnosis(checks, verdict, okAdvice)
		return render.Text(res)
	})
}

// idList normalises a related-object field into a list of ids.
//
// The bastion answers some of them as plain strings and some as objects
// carrying an id; the contract says one thing (a list of ids), so the
// difference is settled here, once.
func idList(v any) []string {
	out := []string{}
	for _, item := range jmsapi.AsSlice(v) {
		switch t := item.(type) {
		case string:
			out = append(out, t)
		case map[string]any:
			out = append(out, jmsapi.Str(t["id"]))
		}
	}
	return out
}
