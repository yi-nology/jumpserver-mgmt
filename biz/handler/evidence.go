package handler

// tools_evidence.go answers the question behind every audit: "what was actually
// done on this machine, and by whom".
//
// It exists because the two sources that carry the answer are both awkward to
// use one row at a time:
//
//   - The command log is keyed by SESSION, and the session endpoint is keyed by
//     ASSET, and the command endpoint carries no asset id at all. The two have
//     to be joined before anything can be said about a machine.
//   - The recording is the reliable fallback for a session that has no command
//     rows, but jms_session_replay fetches exactly one session per call.
//
// So this tool does the join and the batch in one call: pick the sessions that
// carry audit value, pull their command rows, and optionally fetch the
// recording text for the ones that have none.
//
// Which sessions carry audit value? The ones with no error_reason. On this
// bastion 518 of 617 sessions are flagged replay_unsupported: they recorded
// half-finished koko handshakes, so a recording EXISTS (has_replay is true)
// and contains nothing worth reading. Counting those as recorded activity
// makes the audit trail look complete when it is not -- the "100% replay
// coverage" number that has_replay produces is exactly that illusion.

import (
	"cmp"
	"context"
	"fmt"
	"github.com/yi-nology/jumpserver-kit/model/jms"
	"slices"
	"strings"

	"github.com/yi-nology/jumpserver-mgmt/internal/service"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oekit/pkg/convert"
	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
	"github.com/yi-nology/jumpserver-mgmt/biz/model/jmsms"
	"github.com/yi-nology/jumpserver-mgmt/internal/repository"
)

// sessionAssetIDs finds the asset ids of the sessions whose asset label
// matches the reference.
//
// It exists for the assets that have been deleted from the bastion: the
// session trail still carries their name and address, and "who touched this
// machine" is still worth answering for a machine that is no longer
// registered. The label is matched on both halves, so an address works as
// well as a name.

func RegisterEvidenceTools(r *reg.Registry, c *repository.Client) {
	type evidenceArgs struct {
		AssetRef  string `json:"asset" jsonschema:"asset name, address or UUID"`
		UserName  string `json:"user,omitempty" jsonschema:"only sessions of this JumpServer user"`
		Since     string `json:"since,omitempty" jsonschema:"only contacts at or after this date, e.g. 2026/10/20"`
		Limit     int    `json:"limit,omitempty" jsonschema:"how many sessions to report (default 5, max 20)"`
		PerSess   int    `json:"commands_per_session,omitempty" jsonschema:"how many command rows per session (default 20, max 100)"`
		Replay    bool   `json:"include_replay,omitempty" jsonschema:"also fetch the recording text for sessions that have no command rows"`
		ReplayLen int    `json:"replay_chars,omitempty" jsonschema:"cap the recording text per session (default 2000)"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_asset_evidence",
		Description: "What was actually done on one machine, and by whom -- the command-level trail for an asset, " +
			"joined across sessions and returned as one timeline. Use it when you need to know WHAT someone did on " +
			"a box, not just that someone was there: jms_asset_touch_history says who touched the machine, this " +
			"says what they typed and what came back. Only sessions that carry audit value are reported -- a " +
			"recording on its own does not mean anything was done. Pass include_replay to pull the terminal " +
			"recording for sessions that have no command rows.",
		OutputSchema: render.Schema[jmsms.AssetEvidenceResult](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args evidenceArgs) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(args.AssetRef) == "" {
			return render.Failf("asset is required; give the asset name, address or UUID")
		}
		limit := args.Limit
		limit = repository.NormLimit(limit, 5, 20)
		perSess := args.PerSess
		if perSess <= 0 || perSess > 100 {
			perSess = 20
		}
		replayLen := args.ReplayLen
		if replayLen <= 0 || replayLen > 20000 {
			replayLen = 2000
		}
		since := normDate(args.Since)
		if args.Since != "" && since == "" {
			return render.Failf("cannot read since=%q; use 2026/10/20 or 2026-10-20", args.Since)
		}

		ids, meta, err := c.ResolveAssets(ctx, []string{args.AssetRef})
		matcher := repository.NewAssetMatcher(ids, meta)
		deleted := false
		if err != nil {
			// The asset may have been deleted from the bastion while its
			// sessions still sit in the trail. That is exactly when the audit
			// question ("who touched this machine") still matters, so fall
			// back to the label the sessions carry instead of failing with
			// "no such asset".
			//
			// Assignment, not := -- a short declaration here would shadow the
			// outer ids/meta and leave them nil.
			var ferr error
			ids, meta, ferr = c.SessionAssetIDs(ctx, args.AssetRef)
			if ferr != nil {
				return render.Failf("%v", err)
			}
			if len(ids) == 0 {
				return render.Failf("%v", err)
			}
			matcher = repository.NewAssetMatcher(ids, meta)
			deleted = true
		}

		sessions, err := c.List(ctx, jmsapi.ResSessions)
		if err != nil {
			return render.Failf("%v", err)
		}
		recs, err := c.FetchCommands(ctx, nil)
		if err != nil {
			return render.Failf("%v", err)
		}
		bySession := map[string][]repository.CommandRecord{}
		for _, r := range recs {
			bySession[r.Session] = append(bySession[r.Session], r)
		}
		for _, rs := range bySession {
			slices.SortStableFunc(rs, func(a, b repository.CommandRecord) int { return cmp.Compare(b.Timestamp, a.Timestamp) })
		}

		type cand struct {
			s map[string]any
		}
		var mine, evidence []cand
		for _, s := range sessions {
			if !matcher.Match(s) {
				continue
			}
			if args.UserName != "" && !repository.UserMatches(convert.AnyToStr(s["user"]), args.UserName) {
				continue
			}
			start := convert.AnyToStr(s["date_start"])
			if since != "" {
				if len(start) < 10 || start[:10] < since {
					continue
				}
			}
			mine = append(mine, cand{s})
			if service.HasAuditValue(s) {
				evidence = append(evidence, cand{s})
			}
		}
		slices.SortStableFunc(evidence, func(a, b cand) int {
			return strings.Compare(convert.AnyToStr(b.s["date_start"]), convert.AnyToStr(a.s["date_start"]))
		})
		// The evidence list is NOT capped here: the cap applies to the
		// timeline, and the blind spots are collected from the whole set, so
		// that "keep the newest N" cannot bury exactly the sessions that
		// need explaining.
		timeline := []jmsms.EvidenceSession{}
		blind := []jmsms.EvidenceSession{}
		commandTotal := 0
		replaysPulled := 0
		for _, cd := range evidence {
			s := cd.s
			sid := convert.AnyToStr(s["id"])
			cmds := bySession[sid]
			kept := cmds
			truncated := false
			if len(kept) > perSess {
				kept = kept[:perSess]
				truncated = true
			}
			rows := []*jmsms.EvidenceCommand{}
			redacted := false
			for _, r := range kept {
				out := r.Output
				if looksSecretive(out) {
					out = redactSecrets(out)
					redacted = true
				}
				in := r.Input
				if looksSecretive(in) {
					in = redactSecrets(in)
					redacted = true
				}
				rows = append(rows, &jmsms.EvidenceCommand{
					Time:      jmsapi.FieldStr(r.When),
					Input:     jmsapi.FieldStr(jmsapi.Truncate(in, 400)),
					Output:    jmsapi.FieldStr(jmsapi.Truncate(out, 600)),
					RiskLevel: jmsapi.FieldStr(r.RiskLevel),
				})
			}
			commandTotal += len(rows)
			entry := &jmsms.EvidenceSession{
				SessionID:         jmsapi.FieldStr(sid),
				Time:              jmsapi.FieldStr(s["date_start"]),
				End:               jmsapi.FieldStr(s["date_end"]),
				User:              jmsapi.FieldStr(s["user"]),
				Account:           jmsapi.FieldStr(s["account"]),
				SourceIP:          jmsapi.FieldStr(s["remote_addr"]),
				Duration:          jmsapi.FieldStr(s["duration"]),
				Commands:          rows,
				CommandCount:      jmsapi.FieldInt32(len(cmds)),
				CommandsTruncated: jms.OptBool(truncated),
				HasReplay:         jmsapi.FieldBool(s["has_replay"]),
				ReplayBytes:       replayBytesOpt(s["replay_size"]),
			}
			if redacted {
				entry.Redacted = jms.OptBool(true)
			}
			// A session that carried real interaction but left no command row
			// is a hole in the audit trail, not an empty session. It is
			// collected separately below, because a limit that keeps the
			// newest sessions would otherwise bury exactly the ones that
			// need explaining.
			if len(cmds) == 0 {
				entry.NoCommands = jms.OptBool(true)
				blind = append(blind, jmsms.EvidenceSession{
					SessionID:   jmsapi.FieldStr(sid),
					Time:        jmsapi.FieldStr(s["date_start"]),
					User:        jmsapi.FieldStr(s["user"]),
					Account:     jmsapi.FieldStr(s["account"]),
					SourceIP:    jmsapi.FieldStr(s["remote_addr"]),
					Duration:    jmsapi.FieldStr(s["duration"]),
					ReplayBytes: replayBytesOpt(s["replay_size"]),
					HasReplay:   jmsapi.FieldBool(s["has_replay"]),
				})
			}
			// The recording is the fallback for a session the command log did
			// not capture. It is only worth pulling when there is no command
			// trail, or when the caller asked for it explicitly.
			if args.Replay && s["has_replay"] == true {
				text, rerr := c.DownloadReplayText(ctx, sid)
				if rerr != nil {
					entry.ReplayError = jms.Opt(rerr.Error())
				} else {
					if looksSecretive(text) {
						text = redactSecrets(text)
						entry.Redacted = jms.OptBool(true)
					}
					if len(text) > replayLen {
						text = text[:replayLen] + "\n... (capped at replay_chars)"
					}
					entry.ReplayText = jms.Opt(text)
					replaysPulled++
				}
			}
			// The timeline keeps the newest sessions only; the blind spots
			// above were collected from the whole set, so the cap cannot bury
			// exactly the sessions that need explaining.
			if len(timeline) < limit {
				timeline = append(timeline, *entry)
			}
		}

		res := &jmsms.AssetEvidenceResult{
			Asset:                jmsapi.Str(meta[0]["name"]),
			Address:              jmsapi.Str(meta[0]["address"]),
			Timeline:             timeline,
			SessionsOnAsset:      len(mine),
			SessionsWithEvidence: len(evidence),
			CommandsReported:     commandTotal,
		}
		notes := []string{}
		if deleted {
			res.AssetDeletedFromBastion = true
			notes = append(notes, "this asset is no longer registered on the bastion; the trail below comes from "+
				"the sessions it left behind.")
		}
		if skipped := len(mine) - len(evidence); skipped > 0 {
			res.SessionsWithoutEvidence = skipped
			notes = append(notes, fmt.Sprintf("%d session(s) on this asset carry an error_reason and were left out: "+
				"they recorded a half-finished handshake, not real activity.", skipped))
		}
		notes = append(notes, fmt.Sprintf("Sessions are reported newest first and the list is capped at %d.", limit))
		res.Note = strings.Join(notes, " ")
		// The blind spots: sessions that carried a real interaction but left
		// no command row. They are listed on their own because they are the
		// part of the trail the command log cannot speak for -- and a long
		// session with a near-empty recording is usually an idle shell, not a
		// missing one.
		if len(blind) > 0 {
			res.SessionsWithoutCommands = blind
			res.BlindSpotNote = fmt.Sprintf(
				"%d session(s) had real interaction but NO command record, so the command log cannot "+
					"speak for them. Check their recording (replay_bytes) and duration: a long session "+
					"with a near-empty recording is an idle shell, not a missing one. They are listed "+
					"separately so a session limit cannot bury them.", len(blind))
		}
		res.ReplaysPulled = replaysPulled
		return render.Text(res)
	})
}
