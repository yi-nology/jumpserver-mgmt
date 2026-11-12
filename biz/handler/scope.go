// tools_scope.go covers the parts of the bastion that describe WHERE things
// live, rather than what they are: the asset tree, the user groups, and the
// registered terminals.
//
// These were the last uncovered areas of the API surface (measured against
// the live swagger on 2026-10-25), and each one blocks a common task:
//
//	/assets/nodes/          the tree. jms_nodes_list showed the folders, but
//	                        nothing could create one or move an asset into it,
//	                        so a new machine could only be filed under the
//	                        default node.
//	/users/groups/         user groups. A permission can be held by a group
//	                        instead of by named users, and that was invisible:
//	                        the user list showed people and the permission list
//	                        showed counts, so group-based access looked like
//	                        nobody having access.
//	/terminal/terminals/   the terminals a bastion can hop through. A
//	                        multi-hop deployment cannot be reasoned about
//	                        without knowing what is registered.
//
// v5 facts encoded here, each verified against the live bastion rather than
// read off the OpenAPI schema:
//
//   - A node's writable field is `value`. `name` is READ-ONLY and is derived
//     from it, so POSTing {"name": "x"} creates a node with an EMPTY name.
//   - A node cannot be deleted while it still holds assets: the API answers
//     403 "Deletion failed, the node contains assets". The assets have to be
//     moved out first.
//   - AssetPermission.accounts holds ACCOUNT NAMES (["opsuser"]), not ids.
//     "@ALL" is the literal that means every account of the granted assets.
package handler

import (
	"context"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yi-nology/jumpserver-kit/model/jms"
	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
	"github.com/yi-nology/jumpserver-mgmt/biz/model/jmsms"
	"github.com/yi-nology/jumpserver-mgmt/internal/repository"
)

func RegisterScopeTools(r *reg.Registry, c *repository.Client) {
	RegisterNodeTools(r, c)
	RegisterGroupTools(r, c)
	RegisterTerminalTools(r, c)
}

// ---------------------------------------------------------------- asset tree

func RegisterNodeTools(r *reg.Registry, c *repository.Client) {
	type nodeCreateArgs struct {
		Name    string `json:"name" jsonschema:"name of the new folder, e.g. 'arm'"`
		Parent  string `json:"parent,omitempty" jsonschema:"path of the parent node, e.g. /DEFAULT/studio. Defaults to the root /DEFAULT."`
		Confirm bool   `json:"confirm" jsonschema:"must be true; this creates a folder in the asset tree"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_nodes_create",
		Description: "Create a folder in the asset tree, so a machine can be filed somewhere meaningful. " +
			"Assets are then filed into it with jms_asset_move. " +
			"Note that the bastion derives the display name from `value`: a node created with an empty name " +
			"exists but is impossible to tell apart from the root.",
		OutputSchema: render.Schema[jmsms.NodeCreated](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args nodeCreateArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to create the node")
		}
		name := strings.TrimSpace(args.Name)
		if name == "" {
			return render.Failf("name is required: a node without a name is created but cannot be told apart from the root")
		}
		parent := strings.TrimSpace(args.Parent)
		if parent == "" {
			parent = "/DEFAULT"
		}
		parent = "/" + strings.Trim(parent, "/")
		full := parent + "/" + name

		// Refuse before writing if the path is already taken: the API would
		// happily create a second node with the same name.
		rows, err := c.List(ctx, jmsapi.ResNodes)
		if err != nil {
			return render.Failf("%v", err)
		}
		for _, n := range rows {
			if strings.EqualFold(jmsapi.Str(n["full_value"]), full) {
				return render.Failf("a node already exists at %s", full)
			}
		}

		var out map[string]any
		if err := c.Post(ctx, jmsapi.ResNodes, map[string]any{"value": name, "full_value": full}, &out); err != nil {
			return render.Failf("%v", err)
		}
		id := jmsapi.Str(out["id"])
		var back map[string]any
		if err := c.Get(ctx, jmsapi.ResNodes, id, &back); err != nil {
			return render.Failf("node was created (id %s) but reading it back failed: %v", id, err)
		}
		return render.Text(&jmsms.NodeCreated{
			ID:           jmsapi.FieldStr(id),
			Name:         jmsapi.FieldStr(back["name"]),
			FullValue:    jmsapi.FieldStr(back["full_value"]),
			AssetsAmount: jmsapi.FieldInt32(back["assets_amount"]),
			Verified:     jms.OptBool(true),
			NextStep:     jms.Opt("file assets into it with jms_asset_move"),
		})
	})

	type assetMoveArgs struct {
		Assets  []string `json:"assets" jsonschema:"asset refs (address, name or UUID) to file into or out of the node"`
		Node    string   `json:"node" jsonschema:"node path, e.g. /DEFAULT/studio/arm"`
		Action  string   `json:"action" jsonschema:"add to the node, or remove from it"`
		Confirm bool     `json:"confirm" jsonschema:"must be true; this changes the asset tree"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_asset_move",
		Description: "File assets into a folder of the asset tree, or take them out of it. " +
			"Use it after jms_asset_create to put a machine under the right node, and to reorganise the tree afterwards. " +
			"Removing an asset from a node leaves it in the tree's default location rather than deleting it.",
		OutputSchema: render.Schema[jmsms.AssetMoved](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args assetMoveArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Failf("set confirm=true to change the asset tree")
		}
		if len(args.Assets) == 0 {
			return render.Failf("assets is required")
		}
		action := strings.ToLower(strings.TrimSpace(args.Action))
		if action != "add" && action != "remove" {
			return render.Failf("action must be 'add' or 'remove', got %q", args.Action)
		}
		ids, meta, err := c.ResolveAssets(ctx, args.Assets)
		if err != nil {
			return render.Failf("%v", err)
		}
		nodeIDs, err := c.ResolveNodePaths(ctx, []string{args.Node})
		if err != nil {
			return render.Failf("%v", err)
		}
		nodeID := nodeIDs[0]
		var out map[string]any
		if err := c.Put(ctx, jmsapi.ResNodes, nodeID, "assets/"+action,
			map[string]any{"assets": ids}, &out); err != nil {
			return render.Failf("%v", err)
		}
		// Read the node back: the API answers 200 without saying which assets
		// actually ended up in it.
		var node map[string]any
		_ = c.Get(ctx, jmsapi.ResNodes, nodeID, &node)
		moved := []string{}
		for _, m := range meta {
			moved = append(moved, jmsapi.Str(m["name"]))
		}
		return render.Text(&jmsms.AssetMoved{
			Action:           action,
			Node:             jmsapi.Str(node["full_value"]),
			Assets:           moved,
			NodeAssetsAmount: jmsapi.FieldInt32(node["assets_amount"]),
			Note: jms.Opt("an asset can sit in several nodes at once; removing it here does not " +
				"take it out of the others"),
		})
	})
}

// ---------------------------------------------------------------- user groups

func RegisterGroupTools(r *reg.Registry, c *repository.Client) {
	type groupListArgs struct {
		Search string `json:"search,omitempty" jsonschema:"substring match on the group name"`
		Limit  int    `json:"limit,omitempty" jsonschema:"max groups to return (default 50)"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_user_groups_list",
		Description: "List JumpServer user groups with their members, and the asset permissions each group holds. " +
			"A permission can be held by a group rather than by named users, and that is invisible from the user list " +
			"and the permission list (which only reports counts) -- so a group-based grant looks like nobody has access. " +
			"Use this to answer 'who gets in through a group'.",
		OutputSchema: render.Schema[render.ListOf[jmsms.UserGroupSummary]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args groupListArgs) (*mcp.CallToolResult, any, error) {
		rows, err := c.List(ctx, jmsapi.ResGroups)
		if err != nil {
			return render.Failf("%v", err)
		}
		// Which permissions hold which groups. The LIST rows carry
		// user_groups as null on the deployments in the field (measured:
		// v5-api-traps §3) — the membership only shows on each permission's
		// DETAIL, which is what the doctor reads. Listing without the detail
		// fetch made every group-held grant answer as "held by nothing".
		perms, err := c.List(ctx, jmsapi.ResPermissions)
		if err != nil {
			perms = nil
		}
		holds := map[string][]string{}
		for _, p := range perms {
			var detail map[string]any
			if err := c.Get(ctx, jmsapi.ResPermissions, jmsapi.Str(p["id"]), &detail); err != nil {
				continue
			}
			for _, g := range jmsapi.AsSlice(detail["user_groups"]) {
				if m, ok := g.(map[string]any); ok {
					id := jmsapi.Str(m["id"])
					holds[id] = append(holds[id], jmsapi.Str(p["name"]))
				}
			}
		}

		// filter → map → sort → truncate → count: render.ListSpec owns the
		// order and the counting. The totals used to be computed against the
		// UNFILTERED rows, so a search answered total as "how many groups
		// exist" rather than how many matched. Less is nil: this list never
		// sorted locally, and the endpoint's order is what callers read.
		res := render.ListSpec[map[string]any, jmsms.UserGroupSummary]{
			Rows: rows,
			Keep: func(g map[string]any) bool {
				name := jmsapi.Str(g["name"])
				return args.Search == "" ||
					strings.Contains(strings.ToLower(name), strings.ToLower(args.Search))
			},
			Map: func(g map[string]any) jmsms.UserGroupSummary {
				members := []string{}
				for _, u := range jmsapi.AsSlice(g["users"]) {
					if m, ok := u.(map[string]any); ok {
						members = append(members, jmsapi.Str(m["name"]))
					} else {
						members = append(members, jmsapi.Str(u))
					}
				}
				slices.Sort(members)
				id := jmsapi.Str(g["id"])
				return jmsms.UserGroupSummary{
					ID:            jmsapi.FieldStr(g["id"]),
					Name:          jmsapi.FieldStr(g["name"]),
					Members:       members,
					MembersAmount: jms.OptInt32(int32(len(members))),
					Permissions:   holds[id],
				}
			},
			Limit: args.Limit,
			Def:   50,
			Max:   200,
		}.Build()
		if res.Count == 0 {
			res.Note = "this bastion has no user groups; permissions are held by named users only"
		}
		return render.Text(res)
	})
}

// ---------------------------------------------------------------- terminals

func RegisterTerminalTools(r *reg.Registry, c *repository.Client) {
	type terminalListArgs struct {
		Search string `json:"search,omitempty" jsonschema:"substring match on name, address or type"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_terminals_list",
		Description: "List the terminals registered on the bastion, with their type, address and liveness. " +
			"A terminal is a registered host the bastion itself connects through (a jump host, a component such as " +
			"[Celery]-... or [KoKo]-...), which is what a multi-hop deployment is built on. " +
			"Component entries are internal plumbing; pass search='[' to keep only the human-named ones.",
		OutputSchema: render.Schema[render.ListOf[jmsms.TerminalSummary]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args terminalListArgs) (*mcp.CallToolResult, any, error) {
		rows, err := c.List(ctx, jmsapi.ResTerminals)
		if err != nil {
			return render.Failf("%v", err)
		}
		// filter → map → sort → truncate → count: render.ListSpec owns the
		// order and the counting. No cap (Max 0): the terminal list is
		// complete by nature and this tool takes no limit, so capping it
		// would drop rows while reporting truncated for a list meant to be
		// whole.
		return render.Text(render.ListSpec[map[string]any, jmsms.TerminalSummary]{
			Rows: rows,
			Keep: func(t map[string]any) bool {
				name := jmsapi.Str(t["name"])
				typ := jmsapi.Str(t["type"])
				addr := jmsapi.Str(t["remote_addr"])
				return args.Search == "" ||
					strings.Contains(strings.ToLower(name), strings.ToLower(args.Search)) ||
					strings.Contains(strings.ToLower(addr), strings.ToLower(args.Search)) ||
					strings.Contains(strings.ToLower(typ), strings.ToLower(args.Search))
			},
			Map: func(t map[string]any) jmsms.TerminalSummary {
				name := jmsapi.Str(t["name"])
				return jmsms.TerminalSummary{
					Name:          jmsapi.FieldStr(t["name"]),
					Type:          jmsapi.FieldStr(t["type"]),
					RemoteAddr:    jmsapi.FieldStr(t["remote_addr"]),
					IsActive:      jms.OptBool(t["is_active"] == true),
					IsAlive:       jms.OptBool(t["is_alive"] == true),
					SessionOnline: jms.OptBool(t["session_online"] == true),
					Comment:       jmsapi.FieldStr(t["comment"]),
					IsComponent:   jms.OptBool(strings.HasPrefix(name, "[")),
				}
			},
			Less: func(a, b jmsms.TerminalSummary) bool { return a.GetName() < b.GetName() },
			Max:  0,
		}.Build())
	})
}
