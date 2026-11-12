package handler

// tools_touch.go answers "who touched this machine, when, from where and as
// which account" -- the per-asset view of the bastion's session trail.
//
// The session is the spine of that answer, and the reason is a property of
// the data, not a design choice:
//
//   - /terminal/sessions/ carries the asset (as a flat "name(address)" label
//     plus a separate asset_id), the JumpServer user, the asset account, the
//     source address, the protocol and the timestamps.
//   - /terminal/commands/ carries NO asset_id at all -- only a session id. A
//     command row can therefore be attributed to a machine only by way of the
//     session that owns it.
//   - /audits/login-logs/ carries no asset either: it records that somebody
//     authenticated to the bastion, never to a machine. A login row CANNOT be
//     folded into a per-asset history, and this tool says so rather than
//     pretending otherwise.
//
// The recording is indexed, not downloaded: has_replay and replay_size arrive
// with the session row, so the tool can point at a recording without pulling
// hundreds of megabytes of asciinema off the bastion.

import (
	"cmp"
	"context"
	"fmt"
	"github.com/yi-nology/jumpserver-kit/model/jms"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/yi-nology/jumpserver-mgmt/internal/service"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oekit/pkg/convert"
	"github.com/oekit/pkg/slicex"
	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
	"github.com/yi-nology/jumpserver-mgmt/biz/model/jmsms"
	"github.com/yi-nology/jumpserver-mgmt/internal/repository"
)

// touchAsset is one asset's bucket of contact history.
type touchAsset struct {
	id      string
	name    string
	address string

	first string
	last  string
	total int

	users     map[string]bool
	accounts  map[string]bool
	ips       map[string]bool
	protocols map[string]bool

	withReplay int
	withCmds   int
	// withEvidence counts the sessions that carry real audit value: no
	// error_reason. A session that merely has a recording is not evidence --
	// the 518 replay_unsupported ones on this bastion are half-finished koko
	// handshakes that recorded the negotiation bytes and nothing else.
	withEvidence int
	// evidenceWithCmds counts the sessions that carry BOTH evidence and a
	// command trail. It has to be tracked separately from withCmds: a few of
	// the replay_unsupported sessions do have command rows, so dividing one
	// by the other yields a rate over 100%.
	evidenceWithCmds int
	// recent holds the contract rows: the shape the answer declares, so a
	// field that goes missing is a compile error and not a hole in the JSON.
	recent []*jmsms.TouchRecent
}

// replayBytesOpt reads a byte count as the int64 the contract asks for.
//
// The API carries numbers as JSON floats, and a byte count is not a small
// number, so it cannot go through the int32 helper the counts use.
func replayBytesOpt(v any) *int64 {
	if v == nil {
		return nil
	}
	n := convert.AnyToInt64(v)
	return &n
}

func (t *touchAsset) add(s map[string]any, cmdCount int) {
	start := convert.AnyToStr(s["date_start"])
	if t.first == "" || start < t.first {
		t.first = start
	}
	t.last = max(t.last, start)
	t.total++
	if s["user"] != nil {
		t.users[convert.AnyToStr(s["user"])] = true
	}
	if s["account"] != nil {
		t.accounts[convert.AnyToStr(s["account"])] = true
	}
	if s["remote_addr"] != nil && convert.AnyToStr(s["remote_addr"]) != "" {
		t.ips[convert.AnyToStr(s["remote_addr"])] = true
	}
	if p := jmsapi.FieldName(s, "protocol"); p != "" {
		t.protocols[p] = true
	}
	if ok, _ := s["has_replay"].(bool); ok {
		t.withReplay++
	}
	if service.SessionErrorReason(s) == "" {
		t.withEvidence++
		if cmdCount > 0 {
			t.evidenceWithCmds++
		}
	}
	if cmdCount > 0 {
		t.withCmds++
	}
}

// sortedSet returns the members of a set in a stable order.
//
// It uses slicex rather than slices.Sorted on purpose: slices.Sorted returns
// a NIL slice for an empty input, which serialises as JSON null instead of
// an empty array. An empty set and an absent value are different answers,
// and the baseline comparison caught that difference.
func sortedSet(m map[string]bool) []string {
	out := slicex.Unique(slices.Collect(maps.Keys(m)))
	sort.Strings(out)
	return out
}

// normDate accepts the two date spellings people actually type and returns the
// "YYYY/MM/DD" prefix that a session's date_start carries.
func normDate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 10 {
		return ""
	}
	if s[4] == '-' && s[7] == '-' {
		return s[:4] + "/" + s[5:7] + "/" + s[8:10]
	}
	if s[4] == '/' && s[7] == '/' {
		return s[:10]
	}
	return ""
}

// touchResult is the aggregate of a set of sessions.
type touchResult struct {
	Assets        []*touchAsset
	TotalSessions int
	UserSessions  map[string]int
	UserAssets    map[string]map[string]bool
}

// aggregateTouch buckets sessions per asset.
//
// It is a pure function over rows so the bucketing can be tested without a
// bastion, and so the tool handler holds no logic of its own.
func aggregateTouch(sessions []map[string]any, cmdCount map[string]int, lastInput map[string]string,
	matcher *repository.AssetMatcher, userFilter, since string) *touchResult {
	res := &touchResult{UserSessions: map[string]int{}, UserAssets: map[string]map[string]bool{}}
	buckets := map[string]*touchAsset{}

	for _, s := range sessions {
		if !matcher.Match(s) {
			continue
		}
		if userFilter != "" && !repository.UserMatches(convert.AnyToStr(s["user"]), userFilter) {
			continue
		}
		start := convert.AnyToStr(s["date_start"])
		if since != "" {
			if len(start) < 10 || start[:10] < since {
				continue
			}
		}
		res.TotalSessions++
		id := fmt.Sprint(jmsapi.AssetField(s, "id"))
		if id == "" || id == "<nil>" {
			id = fmt.Sprint(jmsapi.AssetField(s, "name"))
		}
		b := buckets[id]
		if b == nil {
			b = &touchAsset{
				id: id, name: fmt.Sprint(jmsapi.AssetField(s, "name")),
				address: fmt.Sprint(jmsapi.AssetField(s, "address")),
				users:   map[string]bool{}, accounts: map[string]bool{},
				ips: map[string]bool{}, protocols: map[string]bool{},
			}
			buckets[id] = b
		}
		uid := convert.AnyToStr(s["id"])
		n := cmdCount[uid]
		b.add(s, n)
		u := convert.AnyToStr(s["user"])
		res.UserSessions[u]++
		if res.UserAssets[u] == nil {
			res.UserAssets[u] = map[string]bool{}
		}
		res.UserAssets[u][b.name] = true
		b.recent = append(b.recent, &jmsms.TouchRecent{
			SessionID:   jmsapi.FieldStr(s["id"]),
			Time:        jmsapi.FieldStr(s["date_start"]),
			End:         jmsapi.FieldStr(s["date_end"]),
			User:        jmsapi.FieldStr(s["user"]),
			Account:     jmsapi.FieldStr(s["account"]),
			SourceIP:    jmsapi.FieldStr(s["remote_addr"]),
			Protocol:    jmsapi.FieldStr(jmsapi.FieldName(s, "protocol")),
			Duration:    jmsapi.FieldStr(s["duration"]),
			Replay:      jmsapi.FieldBool(s["has_replay"]),
			ReplayBytes: replayBytesOpt(s["replay_size"]),
			Commands:    jmsapi.FieldInt32(n),
			LastInput:   jmsapi.FieldStr(lastInput[uid]),
			ErrorReason: jmsapi.FieldStr(service.SessionErrorReason(s)),
			HasEvidence: jms.OptBool(service.SessionErrorReason(s) == ""),
		})
	}

	// Newest contact first.
	for _, b := range buckets {
		res.Assets = append(res.Assets, b)
	}
	slices.SortStableFunc(res.Assets, func(a, b *touchAsset) int {
		if c := cmp.Compare(b.last, a.last); c != 0 {
			return c
		}
		return cmp.Compare(a.name, b.name)
	})
	return res
}

func RegisterTouchTools(r *reg.Registry, c *repository.Client) {
	type touchArgs struct {
		AssetRef string `json:"asset,omitempty" jsonschema:"only this asset (name, address or UUID); omit for every asset"`
		UserName string `json:"user,omitempty" jsonschema:"only sessions opened by this JumpServer user"`
		Since    string `json:"since,omitempty" jsonschema:"only contacts at or after this date, e.g. 2026/10/20 or 2026-10-20"`
		Limit    int    `json:"limit,omitempty" jsonschema:"how many recent sessions to list per asset (default 8, max 50)"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_asset_touch_history",
		Description: "Who touched which machine, when, from where and under which account -- the per-asset view of " +
			"the bastion's session trail. Use it when you need to know what happened on a box (\"who has been on " +
			"this server?\", \"was this host touched last week?\") instead of reading session lists one at a time. " +
			"Returns one block per asset, newest contact first, and flags assets that more than one person touched. " +
			"Recordings are indexed, not downloaded: a session with a replay is reported so you can pull it with " +
			"jms_session_replay. Login records are NOT part of this: the bastion's login log carries no asset, so " +
			"a login to the bastion cannot be attributed to a machine.",
		OutputSchema: render.Schema[jmsms.AssetTouchHistoryResult](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args touchArgs) (*mcp.CallToolResult, any, error) {
		limit := args.Limit
		limit = repository.NormLimit(limit, 8, 50)
		since := normDate(args.Since)
		if args.Since != "" && since == "" {
			return render.Failf("cannot read since=%q; use 2026/10/20 or 2026-10-20", args.Since)
		}

		sessions, err := c.List(ctx, jmsapi.ResSessions)
		if err != nil {
			return render.Failf("%v", err)
		}

		var matcher *repository.AssetMatcher
		if args.AssetRef != "" {
			ids, meta, err := c.ResolveAssets(ctx, []string{args.AssetRef})
			if err != nil {
				return render.Failf("%v", err)
			}
			matcher = repository.NewAssetMatcher(ids, meta)
		}

		// Command counts per session. The command endpoint has no asset_id, so
		// the session id is the only bridge from a command to a machine.
		cmdCount := map[string]int{}
		lastInput := map[string]string{}
		lastAt := map[string]string{}
		recs, err := c.FetchCommands(ctx, nil)
		if err != nil {
			return render.Failf("%v", err)
		}
		for _, r := range recs {
			if r.Session == "" || r.Session == "<nil>" {
				continue
			}
			cmdCount[r.Session]++
			if r.When > lastAt[r.Session] {
				lastAt[r.Session] = r.When
				lastInput[r.Session] = jmsapi.Truncate(r.Input, 200)
			}
		}

		buckets := aggregateTouch(sessions, cmdCount, lastInput, matcher, args.UserName, since)

		out := []jmsms.TouchAsset{}
		multiUser := []jmsms.TouchMultiUser{}
		withReplay, withCmds, withEvidence, evidenceWithCmds := 0, 0, 0, 0
		for _, b := range buckets.Assets {
			slices.SortStableFunc(b.recent, func(a, b *jmsms.TouchRecent) int {
				return cmp.Compare(b.GetTime(), a.GetTime())
			})
			recent := b.recent
			if len(recent) > limit {
				recent = recent[:limit]
			}
			withReplay += b.withReplay
			withCmds += b.withCmds
			withEvidence += b.withEvidence
			evidenceWithCmds += b.evidenceWithCmds
			out = append(out, jmsms.TouchAsset{
				Asset:                b.name,
				Address:              jmsapi.FieldStr(b.address),
				AssetID:              jmsapi.FieldStr(b.id),
				Sessions:             jmsapi.FieldInt32(b.total),
				FirstContact:         jmsapi.FieldStr(b.first),
				LastContact:          jmsapi.FieldStr(b.last),
				Users:                sortedSet(b.users),
				Accounts:             sortedSet(b.accounts),
				SourceIps:            sortedSet(b.ips),
				Protocols:            sortedSet(b.protocols),
				SessionsWithReplay:   jmsapi.FieldInt32(b.withReplay),
				SessionsWithCommands: jmsapi.FieldInt32(b.withCmds),
				SessionsWithEvidence: jmsapi.FieldInt32(b.withEvidence),
				EvidenceWithCommands: jmsapi.FieldInt32(b.evidenceWithCmds),
				Recent:               recent,
			})
			if len(b.users) > 1 {
				multiUser = append(multiUser, jmsms.TouchMultiUser{
					Asset:    b.name,
					Users:    sortedSet(b.users),
					Sessions: jmsapi.FieldInt32(b.total),
				})
			}
		}

		topUsers := []jmsms.TouchTopUser{}
		for u, n := range buckets.UserSessions {
			topUsers = append(topUsers, jmsms.TouchTopUser{
				User:     u,
				Sessions: jmsapi.FieldInt32(n),
				Assets:   jmsapi.FieldInt32(len(buckets.UserAssets[u])),
			})
		}
		slices.SortStableFunc(topUsers, func(a, b jmsms.TouchTopUser) int {
			if c := cmp.Compare(b.GetSessions(), a.GetSessions()); c != 0 {
				return c
			}
			return cmp.Compare(a.User, b.User)
		})

		res := &jmsms.AssetTouchHistoryResult{
			Assets:        out,
			AssetsTouched: len(buckets.Assets),
			Sessions:      buckets.TotalSessions,
			TopUsers:      topUsers,
			Coverage: service.Coverage{
				TotalSessions:        buckets.TotalSessions,
				SessionsWithEvidence: withEvidence,
				SessionsWithCommand:  withCmds,
				EvidenceWithCommand:  evidenceWithCmds,
				SessionsWithReplay:   withReplay,
				CommandsIndexed:      len(recs),
			}.Fields(),
			Note: "sessions_with_evidence counts the sessions with no error_reason: those are real " +
				"interactions. A session with a recording is not evidence by itself -- one flagged " +
				"replay_unsupported recorded only a half-finished handshake, so has_replay alone overstates " +
				"the audit trail. A session with commands:0 means no command was recorded for it, not that " +
				"nothing was typed -- use jms_asset_evidence for the recorded activity, or jms_session_replay " +
				"for the recording. Login records are absent by nature: the bastion's login log has no asset field.",
		}
		if len(multiUser) > 0 {
			res.AssetsTouchedBySeveralUsers = multiUser
		}
		if since != "" {
			res.Since = since
		}
		if args.AssetRef != "" {
			res.FilteredToAsset = args.AssetRef
		}
		return render.Text(res)
	})
}
