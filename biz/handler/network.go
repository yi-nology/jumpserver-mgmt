// tools_network.go answers "how do I reach this machine, and what is the
// network laid out like".
//
// Why this exists.
//
// The bastion knows a network topology that no tool here could see: a ZONE
// is a field on an asset, and the GATEWAYS of a zone are the assets whose
// platform is "Gateway" and whose zone is that one. Between them they say
// which machines are reached through which hop.
//
// ⚠️ Three facts that make this harder than it looks, and that the tool has
// to report honestly rather than paper over:
//
//   - "Gateway" is a PLATFORM NAME, not a role. On this deployment the
//     seven gateways include ordinary network gear (a router, a WiFi AP, an
//     nginx front end) beside the real jump hosts. So "a gateway" does not
//     mean "a jump host" -- the zone it belongs to is what makes it one.
//
//   - MOST ASSETS HAVE NO ZONE. The zone field is null on nearly
//     everything. ⇒ "which zone is this machine in" is usually "none",
//     and "how do I reach it" is usually "directly, no hop". A tool that
//     answered "direct" for everything would be right but useless; one
//     that invented a path would be wrong.
//
//   - A zone's `assets_amount` counts the assets in it whose platform is
//     NOT "Gateway" (upstream: `self.assets.gateways(0).count()`) ⇒ the
//     number is the machines BEHIND the zone, not the zone's size.
package handler

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/yi-nology/jumpserver-mgmt/biz/model/jmsms"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oekit/pkg/convert"
	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
	"github.com/yi-nology/jumpserver-mgmt/internal/repository"
)

func RegisterNetworkTools(r *reg.Registry, c *repository.Client) {
	registerZonesTool(r, c)
	registerGatewaysTool(r, c)
	registerNetPathTool(r, c)
}

// zoneNameOf reads the zone NAME off a row.
//
// ⚠️ The zone is a nested object {"id","name"} that is NULL on most
// assets -- and a null nested object read through jmsapi.Nested comes
// back as an untyped nil, which convert.AnyToStr renders as the four
// characters "<nil>". That string is not empty, so a check like
// `if zone == ""` would NOT catch it: the asset would be reported as
// belonging to a zone called "<nil>", and every machine with no zone
// would be given an invented route.
//
// ⇒ The read goes through jmsapi.Str, which maps that to "".
func zoneNameOf(row map[string]any) string {
	return jmsapi.Str(jmsapi.Nested(row, "zone", "name"))
}

// zoneIDOf reads the zone ID off a row. Same null handling as zoneNameOf.
func zoneIDOf(row map[string]any) string {
	return jmsapi.Str(jmsapi.Nested(row, "zone", "id"))
}

// zoneGatewayNames reads the names out of a zone's `gateways`.
//
// ⚠️ Those arrive as OBJECTS {"id","name"}, so the shared asStringSlice
// (which takes the id of an object) would report ids where the reader
// expects names -- and a zone's gateways are what a person names.
func zoneGatewayNames(v any) []string {
	var out []string
	for _, item := range jmsapi.AsSlice(v) {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if name := jmsapi.Str(m["name"]); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// registerZonesTool lists the network zones.
func registerZonesTool(r *reg.Registry, c *repository.Client) {
	type zonesArgs struct {
		Search string `json:"search,omitempty" jsonschema:"substring match on the zone name"`
		Limit  int    `json:"limit,omitempty" jsonschema:"max rows (default 20)"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_net_zones_list",
		Description: "List the bastion's network ZONES: a group of machines plus the gateways that reach them. " +
			"Use it to understand the network layout -- which machines sit behind which hop -- before asking jms_net_path for a specific machine. " +
			"⚠️ Most machines on this deployment are in NO zone (the zone field is null on them), so a short zone list is the normal state, not a sign that the tool found little. Read-only.",
		OutputSchema: render.Schema[render.ListOf[jmsms.NetZone]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args zonesArgs) (*mcp.CallToolResult, any, error) {
		rows, err := c.List(ctx, jmsapi.ResZones)
		if err != nil {
			return render.Failf("%v", err)
		}
		// filter → map → sort → truncate → count: render.ListSpec owns the
		// order and the three counting fields. This list already sorted
		// before the cap and counted the matches, so the collection changes
		// nothing about what the answer says.
		res := render.ListSpec[map[string]any, jmsms.NetZone]{
			Rows: rows,
			Keep: func(row map[string]any) bool {
				if args.Search == "" {
					return true
				}
				name := convert.AnyToStr(row["name"])
				return strings.Contains(strings.ToLower(name), strings.ToLower(args.Search))
			},
			Map: func(row map[string]any) jmsms.NetZone {
				name := convert.AnyToStr(row["name"])
				return jmsms.NetZone{
					ID:           jmsapi.FieldStr(row["id"]),
					Name:         jmsapi.FieldStr(name),
					Gateways:     zoneGatewayNames(row["gateways"]),
					Cidrs:        asStringSlice(row["cidrs"]),
					AssetsAmount: jmsapi.FieldInt32(row["assets_amount"]),
					AutoAssign:   jmsapi.FieldBool(row["auto_assign"]),
					Comment:      jmsapi.FieldStr(row["comment"]),
				}
			},
			Less:  func(a, b jmsms.NetZone) bool { return a.GetName() < b.GetName() },
			Limit: args.Limit,
			Def:   20,
			Max:   100,
		}.Build()
		if res.Total == 0 {
			res.Note = "this bastion has no network zone; every machine is reached directly"
		}
		return render.Text(res)
	})
}

// registerGatewaysTool lists the gateway assets.
func registerGatewaysTool(r *reg.Registry, c *repository.Client) {
	type gatewaysArgs struct {
		Zone         string `json:"zone,omitempty" jsonschema:"only gateways in this zone (zone name or id)"`
		Connectivity string `json:"connectivity,omitempty" jsonschema:"only gateways with this connectivity (ok / err)"`
		Search       string `json:"search,omitempty" jsonschema:"substring match on the name or the address"`
		Limit        int    `json:"limit,omitempty" jsonschema:"max rows (default 30)"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_net_gateways_list",
		Description: "List the bastion's gateway assets -- the machines whose platform is Gateway, with the zone each belongs to, whether it is reachable, and how many accounts it has. " +
			"Use it to find the hop a machine is reached through, or to see which hops are down. " +
			"⚠️ 'Gateway' is a PLATFORM NAME, not a role: the list includes ordinary network gear (routers, appliances) beside the real jump hosts -- the zone a gateway belongs to is what makes it a hop. Read-only.",
		OutputSchema: render.Schema[render.ListOf[jmsms.NetGateway]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args gatewaysArgs) (*mcp.CallToolResult, any, error) {
		rows, err := c.List(ctx, jmsapi.ResGateways)
		if err != nil {
			return render.Failf("%v", err)
		}
		zoneFilter := strings.ToLower(strings.TrimSpace(args.Zone))
		// filter → map → sort → truncate → count: render.ListSpec owns the
		// order and the three counting fields. This list already sorted
		// before the cap and counted the matches, so the collection changes
		// nothing about what the answer says.
		res := render.ListSpec[map[string]any, jmsms.NetGateway]{
			Rows: rows,
			Keep: func(row map[string]any) bool {
				name := convert.AnyToStr(row["name"])
				addr := convert.AnyToStr(row["address"])
				zone := zoneNameOf(row)
				zoneID := zoneIDOf(row)
				if zoneFilter != "" &&
					!strings.EqualFold(zone, zoneFilter) && !strings.EqualFold(zoneID, zoneFilter) {
					return false
				}
				if args.Connectivity != "" &&
					!strings.EqualFold(jmsapi.Label(row, "connectivity"), args.Connectivity) {
					return false
				}
				if args.Search != "" {
					q := strings.ToLower(args.Search)
					if !strings.Contains(strings.ToLower(name+" "+addr), q) {
						return false
					}
				}
				return true
			},
			Map: func(row map[string]any) jmsms.NetGateway {
				return jmsms.NetGateway{
					ID:             jmsapi.FieldStr(row["id"]),
					Name:           jmsapi.FieldStr(convert.AnyToStr(row["name"])),
					Address:        jmsapi.FieldStr(convert.AnyToStr(row["address"])),
					Zone:           jmsapi.FieldStr(zoneNameOf(row)),
					Connectivity:   jmsapi.FieldStr(jmsapi.Label(row, "connectivity")),
					AccountsAmount: jmsapi.FieldInt32(row["accounts_amount"]),
					NodesDisplay:   asStringSlice(row["nodes_display"]),
					DateVerified:   jmsapi.FieldStr(row["date_verified"]),
					DateLastLogin:  jmsapi.FieldStr(row["date_last_login"]),
					Comment:        jmsapi.FieldStr(row["comment"]),
				}
			},
			Less:  func(a, b jmsms.NetGateway) bool { return a.GetName() < b.GetName() },
			Limit: args.Limit,
			Def:   30,
			Max:   200,
		}.Build()
		notes := []string{}
		if res.Total == 0 {
			notes = append(notes, "no gateway asset matches")
		}
		down := 0
		for _, g := range res.Items {
			if g.GetConnectivity() == "err" {
				down++
			}
		}
		if down > 0 {
			notes = append(notes, convert.AnyToStr(down)+" gateway(s) report connectivity=err")
		}
		res.Note = strings.Join(notes, "; ")
		return render.Text(res)
	})
}

// registerNetPathTool answers "how do I reach this machine".
//
// It is the composition of the two: the asset's own zone, the gateways of
// that zone, and whether they are up. It is one call because the question
// is one question, and an agent that had to make three calls to answer it
// would correlate them itself -- which is where mistakes happen.
func registerNetPathTool(r *reg.Registry, c *repository.Client) {
	type pathArgs struct {
		Asset string `json:"asset" jsonschema:"asset address, name or UUID, e.g. 192.0.2.71"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_net_path",
		Description: "How is this machine reached: the zone it belongs to, the gateways of that zone, and whether those gateways are up. " +
			"Use it before a multi-hop connection, or when a machine is unreachable and the question is 'through which hop'. " +
			"⚠️ Most machines on this deployment belong to NO zone, and the honest answer for those is 'directly, no hop' -- the tool says so rather than inventing a route. Read-only.",
		OutputSchema: render.Schema[jmsms.NetPath](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args pathArgs) (*mcp.CallToolResult, any, error) {
		ref := strings.TrimSpace(args.Asset)
		if ref == "" {
			return render.Failf("asset is required")
		}
		ids, meta, err := c.ResolveAssets(ctx, []string{ref})
		if err != nil {
			return render.Failf("%v", err)
		}
		assetID := ids[0]
		name, address := "", ""
		if len(meta) > 0 {
			name = convert.AnyToStr(meta[0]["name"])
			address = convert.AnyToStr(meta[0]["address"])
		}

		// The asset's own record carries the zone.
		var asset map[string]any
		if err := c.Get(ctx, jmsapi.ResAssets, assetID, &asset); err != nil {
			return render.Failf("%v", err)
		}
		zoneName := zoneNameOf(asset)
		zoneID := zoneIDOf(asset)

		res := &jmsms.NetPath{
			Asset:   jmsapi.FieldStr(name),
			Address: jmsapi.FieldStr(address),
			Zone:    jmsapi.FieldStr(zoneName),
		}

		if zoneName == "" {
			// ⚠️ The honest answer for an asset with no zone: it is
			// reached directly. Saying "no path" would read as "there is
			// no way in", and inventing a gateway would be worse.
			res.Verdict = jmsapi.FieldStr("this machine is in no zone, so it is reached directly -- " +
				"no gateway hop is involved")
			res.Steps = []*jmsms.NetPathStep{{
				Kind:         jmsapi.FieldStr("target"),
				Name:         jmsapi.FieldStr(name),
				Address:      jmsapi.FieldStr(address),
				Connectivity: jmsapi.FieldStr(jmsapi.Label(asset, "connectivity")),
				Note:         jmsapi.FieldStr("the machine itself"),
			}}
			return render.Text(res)
		}

		// The zone's gateways are the gateways whose zone is that one --
		// the same records the zone list carries.
		gwRows, err := c.List(ctx, jmsapi.ResGateways)
		if err != nil {
			return render.Failf("%v", err)
		}
		steps := []*jmsms.NetPathStep{}
		gateways := []string{}
		up, down, unknown := 0, 0, 0
		for _, row := range gwRows {
			if zoneIDOf(row) != zoneID {
				continue
			}
			gwName := convert.AnyToStr(row["name"])
			gateways = append(gateways, gwName)
			conn := jmsapi.Label(row, "connectivity")
			note := "the hop this machine is reached through"
			switch conn {
			case "ok":
				up++
			case "err":
				down++
				note = "this hop is DOWN (connectivity=err) -- a connection through it will fail"
			default:
				// ⚠️ Not "ok" and not "err" is UNKNOWN, and it must not be
				// counted as up: the verdict says "1 of its 1 gateways are
				// up" and the one it means has never been tested. A hop
				// whose state is unknown is reported as such.
				unknown++
				note = "this hop's state is unknown (the bastion has no connectivity verdict for it)"
			}
			steps = append(steps, &jmsms.NetPathStep{
				Kind:         jmsapi.FieldStr("gateway"),
				Name:         jmsapi.FieldStr(gwName),
				Address:      jmsapi.FieldStr(row["address"]),
				Connectivity: jmsapi.FieldStr(conn),
				Note:         jmsapi.FieldStr(note),
			})
		}
		slices.SortStableFunc(steps, func(a, b *jmsms.NetPathStep) int {
			return strings.Compare(a.GetName(), b.GetName())
		})
		slices.Sort(gateways)
		res.ZoneGateways = gateways

		// The machines behind the zone, and the zone's own record.
		zoneRows, err := c.List(ctx, jmsapi.ResZones)
		if err != nil {
			return render.Failf("%v", err)
		}
		for _, z := range zoneRows {
			if convert.AnyToStr(z["id"]) == zoneID {
				res.ZoneAssetsAmount = jmsapi.FieldInt32(z["assets_amount"])
				break
			}
		}

		steps = append(steps, &jmsms.NetPathStep{
			Kind:         jmsapi.FieldStr("target"),
			Name:         jmsapi.FieldStr(name),
			Address:      jmsapi.FieldStr(address),
			Connectivity: jmsapi.FieldStr(jmsapi.Label(asset, "connectivity")),
			Note:         jmsapi.FieldStr("the machine itself"),
		})
		res.Steps = steps

		switch {
		case len(gateways) == 0:
			res.Verdict = jmsapi.FieldStr(fmt.Sprintf(
				"this machine is in zone %q but that zone has no gateway -- "+
					"the bastion has no hop to reach it through", zoneName))
		case down > 0 && up == 0 && unknown == 0:
			res.Verdict = jmsapi.FieldStr(fmt.Sprintf(
				"this machine is in zone %q and EVERY gateway of that zone is down (%d of %d) -- "+
					"a connection through the zone will fail", zoneName, down, down))
		case down > 0:
			res.Verdict = jmsapi.FieldStr(fmt.Sprintf(
				"this machine is in zone %q; %d of its %d gateways are up (%d down)",
				zoneName, up, up+down, down))
		case up == 0 && unknown > 0:
			// ⚠️ No gateway is KNOWN to be up. Saying "reached through X"
			// would be a claim the bastion has not made.
			res.Verdict = jmsapi.FieldStr(fmt.Sprintf(
				"this machine is in zone %q; none of its %d gateways is known to be up "+
					"(%d untested) -- the bastion has no connectivity verdict for them",
				zoneName, unknown, unknown))
		default:
			res.Verdict = jmsapi.FieldStr(fmt.Sprintf(
				"this machine is in zone %q and is reached through %s",
				zoneName, strings.Join(gateways, ", ")))
		}
		return render.Text(res)
	})
}
