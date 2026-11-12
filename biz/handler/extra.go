package handler

// tools_extra.go covers the four gaps found by diffing our tool surface against
// JumpServer's swagger (544 paths):
//
//	P0  command transcript  -- /terminal/commands/ records input AND output
//	                          per session, so a whole terminal stream can be
//	                          replayed. This is the fallback for whenever the
//	                          live PTY screen cannot be parsed.
//	P1  session replay      -- /terminal/sessions/{id}/replay/download/
//	                          returns a tar of asciinema cast + metadata.
//	P2  account gathering   -- /accounts/gathered-accounts/ implements
//	                          "scan this node and tell me which accounts exist".
//	P3  labels and roles    -- /labels/ and /rbac/ for organising assets and
//	                          reviewing who can do what.
//
// A correction to an earlier conclusion, found while building this: command
// recording was never disabled. /terminal/commands/ already held 200 records
// including our own sessions. The earlier "v5 does not expose job stdout" is
// still true for jobs (they run through ansible, not koko), but for anything
// executed over koko the output *is* retrievable.

import (
	"cmp"
	"context"
	"net/url"
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

// ------------------------------------------------------------------ P0 transcript

type transcriptArgs struct {
	SessionID string `json:"session_id" jsonschema:"session id, from jms_commands_search or a session listing"`
	MaxChars  int    `json:"max_chars,omitempty" jsonschema:"cap the returned text (default 20000)"`
}

func RegisterExtraTools(r *reg.Registry, c *repository.Client) {
	RegisterTranscriptTools(r, c)
	RegisterReplayTools(r, c)
}

// commandRecord is one row of /terminal/commands/.

func RegisterTranscriptTools(r *reg.Registry, c *repository.Client) {
	reg.Add(r, &mcp.Tool{
		Name: "jms_session_transcript",
		Description: "Replay a recorded session's entire terminal stream from JumpServer's command audit log. " +
			"Commands are stored as fragments (input plus output), so this reconstructs what was actually typed and " +
			"printed, in order. Use it as the fallback when a live session's output cannot be parsed, and as the " +
			"authoritative answer to 'what did someone run on that box, and what came back'.",
		OutputSchema: render.Schema[jmsms.SessionTranscript](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args transcriptArgs) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(args.SessionID) == "" {
			return render.Failf("session_id is required; get one from jms_sessions_list or jms_commands_search")
		}
		recs, err := c.FetchCommands(ctx, url.Values{"session": {args.SessionID}})
		if err != nil {
			return render.Failf("%v", err)
		}
		if len(recs) == 0 {
			return render.Text(&jmsms.SessionTranscript{
				Session:   args.SessionID,
				Count:     jms.OptInt32(0),
				Total:     jms.OptInt32(0),
				Truncated: jms.OptBool(false),
				Records:   []*jmsms.CommandRecord{},
				Note: jms.Opt("no command records for this session; recording is disabled on this " +
					"bastion, or the session predates it"),
			})
		}
		slices.SortStableFunc(recs, func(a, b repository.CommandRecord) int { return cmp.Compare(a.Timestamp, b.Timestamp) })

		limit := args.MaxChars
		limit = repository.NormLimit(limit, 20000, 200000)

		var b strings.Builder
		for _, r := range recs {
			if r.Input != "" {
				b.WriteString(redactSecrets(r.Input))
			}
			if r.Output != "" {
				b.WriteString(redactSecrets(r.Output))
			}
		}
		text := b.String()
		truncated := false
		if len(text) > limit {
			text = text[:limit]
			truncated = true
		}

		risks := map[string]int32{}
		for _, r := range recs {
			risks[r.RiskLevel]++
		}
		// records is the list, as in every other tool -- it used to be a
		// number here, and the same name meant a different shape in two
		// tools.
		rows := make([]*jmsms.CommandRecord, 0, len(recs))
		for _, r := range recs {
			rows = append(rows, &jmsms.CommandRecord{
				Time:      jms.Opt(r.When),
				Input:     jms.Opt(jmsapi.Truncate(redactSecrets(r.Input), 400)),
				Output:    jms.Opt(jmsapi.Truncate(redactSecrets(r.Output), 800)),
				RiskLevel: jms.Opt(r.RiskLevel),
			})
		}
		res := &jmsms.SessionTranscript{
			Session:    args.SessionID,
			Count:      jms.OptInt32(int32(len(recs))),
			Total:      jms.OptInt32(int32(len(recs))),
			Records:    rows,
			User:       jms.Opt(recs[0].User),
			Asset:      jms.Opt(recs[0].Asset),
			Address:    jms.Opt(recs[0].Address),
			Account:    jms.Opt(recs[0].Account),
			FirstSeen:  jms.Opt(recs[0].When),
			LastSeen:   jms.Opt(recs[len(recs)-1].When),
			RiskLevels: risks,
			Transcript: jms.Opt(text),
			Chars:      jms.OptInt32(int32(len(text))),
			// The list itself is never truncated here; only the transcript
			// text is, so the two flags are separate.
			Truncated:     jms.OptBool(false),
			TextTruncated: jms.OptBool(truncated),
		}
		if truncated {
			res.Note = jms.Opt("transcript capped at max_chars; raise it to see the rest")
		}
		if len(risks) > 1 {
			res.Warning = jms.Opt("session contains more than one risk level; a rejected command " +
				"would appear here without its output")
		}
		return render.Text(res)
	})

	type cmdSearchArgs struct {
		Search   string `json:"search,omitempty" jsonschema:"substring match on the typed command or its output"`
		UserName string `json:"user,omitempty" jsonschema:"filter by JumpServer username"`
		AssetRef string `json:"asset,omitempty" jsonschema:"filter by asset name or address"`
		Session  string `json:"session,omitempty" jsonschema:"filter to one session id"`
		Limit    int    `json:"limit,omitempty" jsonschema:"max rows (default 50)"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_command_audit",
		Description:  "Search the command audit log with the recorded OUTPUT included, and filter by session. Fragments are merged so a long command appears whole. Use it when you need what a command RETURNED; jms_commands_search reads the whole log instead (so its filters never truncate it) but gives you the command without its output.",
		OutputSchema: render.Schema[render.ListOf[jmsms.CommandAuditSummary]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args cmdSearchArgs) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		if args.Search != "" {
			q.Set("search", args.Search)
		}
		if args.UserName != "" {
			q.Set("user", args.UserName)
		}
		if args.Session != "" {
			q.Set("session", args.Session)
		}
		recs, err := c.FetchCommands(ctx, q)
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
		// The sort key is the NUMERIC Timestamp, which the contract row does
		// not carry (it only has the display string), so the rows are put in
		// that order here and ListSpec keeps it (Less nil).
		slices.SortStableFunc(recs, func(a, b repository.CommandRecord) int { return cmp.Compare(b.Timestamp, a.Timestamp) })
		// filter → map → sort → truncate → count: render.ListSpec owns the
		// counting. total is how many command rows matched, before the cap.
		return render.Text(render.ListSpec[repository.CommandRecord, jmsms.CommandAuditSummary]{
			Rows: recs,
			Keep: func(r repository.CommandRecord) bool {
				return matcher.MatchNameAddress(r.Asset, r.Address)
			},
			Map: func(r repository.CommandRecord) jmsms.CommandAuditSummary {
				return jmsms.CommandAuditSummary{
					When:      jms.Opt(r.When),
					Session:   jms.Opt(r.Session),
					User:      jms.Opt(r.User),
					Asset:     jms.Opt(r.Asset),
					Address:   jms.Opt(r.Address),
					Account:   jms.Opt(r.Account),
					Input:     jms.Opt(jmsapi.Truncate(redactSecrets(r.Input), 400)),
					Output:    jms.Opt(jmsapi.Truncate(redactSecrets(r.Output), 800)),
					RiskLevel: jms.Opt(r.RiskLevel),
				}
			},
			Limit: args.Limit,
			Def:   50,
			Max:   500,
		}.Build())
	})
}

// ------------------------------------------------------------------ P1 replay

func RegisterReplayTools(r *reg.Registry, c *repository.Client) {
	type replayArgs struct {
		SessionID string `json:"session_id" jsonschema:"session id from jms_sessions_list"`
		MaxText   int    `json:"max_text,omitempty" jsonschema:"cap the extracted terminal text (default 8000)"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_session_replay",
		Description: "Fetch a recorded session: its metadata plus the terminal text extracted from the asciinema " +
			"recording. The raw download is a tar of a .cast.gz (asciinema JSONL, where each row is " +
			"[time, \"o\", \"data\"]) and a .json sidecar. Prefer jms_session_transcript for command-level detail; " +
			"use this when you need the raw terminal rendering or the record is not in the command log.",
		OutputSchema: render.Schema[jmsms.SessionReplay](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args replayArgs) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(args.SessionID) == "" {
			return render.Failf("session_id is required")
		}
		var meta map[string]any
		if err := c.Get(ctx, jmsapi.ResSessions, args.SessionID, &meta); err != nil {
			return render.Failf("%v", err)
		}

		res := &jmsms.SessionReplay{
			Session:       args.SessionID,
			User:          jmsapi.FieldStr(firstNonEmpty(meta, "user_display", "user")),
			Asset:         jmsapi.FieldStr(firstNonEmpty(meta, "asset_display", "asset")),
			Account:       jmsapi.FieldStr(firstNonEmpty(meta, "account_display", "account")),
			DateStart:     jmsapi.FieldStr(meta["date_start"]),
			DateEnd:       jmsapi.FieldStr(meta["date_end"]),
			Duration:      jmsapi.FieldStr(meta["duration"]),
			HasReplay:     jmsapi.FieldBool(meta["has_replay"]),
			HasCommand:    jmsapi.FieldBool(meta["has_command"]),
			CanReplay:     jmsapi.FieldBool(meta["can_replay"]),
			CanJoin:       jmsapi.FieldBool(meta["can_join"]),
			CommandAmount: jmsapi.FieldInt32(meta["command_amount"]),
			ReplaySize:    jmsapi.FieldInt32(meta["replay_size"]),
			ErrorReason:   jmsapi.FieldStr(jmsapi.Label(meta, "error_reason")),
		}
		// has_replay says a recording EXISTS; can_replay says THIS caller may
		// watch it. Both have to hold, otherwise the download is a 403 that looks
		// like a broken tool.
		if meta["has_replay"] != true {
			res.Note = jms.Opt("no recording stored for this session; " +
				"jms_session_transcript may still have it if the command log has it")
			return render.Text(res)
		}
		if meta["can_replay"] != true {
			res.Note = jms.Opt("a recording exists but your JumpServer account is not permitted to replay it " +
				"(can_replay=false); grant terminal.replay on the session's asset or use jms_session_transcript")
			return render.Text(res)
		}

		text, err := c.DownloadReplayText(ctx, args.SessionID)
		if err != nil {
			res.ReplayError = jms.Opt(err.Error())
			return render.Text(res)
		}
		limit := args.MaxText
		limit = repository.NormLimit(limit, 8000, 100000)
		res.TerminalTextChars = jms.OptInt32(int32(len(text)))
		// A recording contains whatever was on screen, including any secret
		// that was typed. Mask the credential-looking values before the text
		// reaches a context window or a scrollback buffer.
		if looksSecretive(text) {
			text = redactSecrets(text)
			res.Redacted = jms.OptBool(true)
		}
		if len(text) > limit {
			res.TerminalText = jms.Opt(text[:limit])
			res.Note = jms.Opt("terminal text capped at max_text; " + trimSecretNote)
		} else {
			res.TerminalText = jms.Opt(text)
		}
		return render.Text(res)
	})
}

// firstNonEmpty returns the first key that holds a non-empty value. Session
// metadata exposes both a nested object and a *_display variant, and which one
// is populated depends on the endpoint that produced the row.
func firstNonEmpty(m map[string]any, keys ...string) any {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			if s, isStr := v.(string); isStr && s == "" {
				continue
			}
			return v
		}
	}
	return nil
}

// downloadReplayText pulls the tar, unpacks the asciinema cast and flattens it
// into plain text.

// castToText walks the tar, finds the .cast.gz member, and renders the
// asciinema stream as text.

// asciinemaToText flattens asciinema JSONL. Each row is
// [elapsed_seconds, "o"|"i", data]; only the output stream is kept, since that
// is what a reader wants to see.
