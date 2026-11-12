package handler

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oekit/pkg/convert"
	"github.com/yi-nology/jumpserver-kit/model/jms"
	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
	"github.com/yi-nology/jumpserver-kit/pkg/risk"
	"github.com/yi-nology/jumpserver-mgmt/biz/model/jmsms"
	"github.com/yi-nology/jumpserver-mgmt/internal/repository"
)

// maxAssetsPerRun bounds a single batch so a mistyped selector cannot fan out
// across the whole fleet in one shot.
const maxAssetsPerRun = 20

// maxFailedList bounds the failed-execution list, which is not capped by the
// caller's limit because it is the part the caller came for.
const maxFailedList = 50

func RegisterJobTools(r *reg.Registry, c *repository.Client) {
	type jobRunArgs struct {
		Assets  []string `json:"assets" jsonschema:"asset addresses, names or UUIDs to target, e.g. 198.51.100.11"`
		Command string   `json:"command" jsonschema:"shell command to run on every target"`
		Runas   string   `json:"runas,omitempty" jsonschema:"account name to run as; JumpServer does NOT auto-elevate, use 'sudo -n' in the command when root is needed"`
		DryRun  bool     `json:"dry_run,omitempty" jsonschema:"classify and resolve targets without executing"`
		Confirm bool     `json:"confirm,omitempty" jsonschema:"must be true to execute a DANGEROUS command (reboot, delete, network-fatal, privilege change)"`
		Wait    int      `json:"wait,omitempty" jsonschema:"seconds to wait for completion before returning (default 0 = return a task_id immediately; 60 is usually enough for a short command)"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_job_run",
		Description:  "Run a shell command on one or more managed assets through JumpServer's audit engine, so every execution is recorded. Use it when the run has to show up in the bastion's own audit trail; jmsx_exec_multi is the multi-host call that actually returns per-host output. Commands are risk-classified; DANGEROUS ones are refused unless confirm=true. Note: the command runs AS THE ASSET ACCOUNT - JumpServer does not elevate, so prefix privileged commands with 'sudo -n'.",
		OutputSchema: render.Schema[jmsms.JobPlan](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args jobRunArgs) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(args.Command) == "" {
			return render.Err(fmt.Errorf("command is required and cannot be blank"))
		}
		cmdClass := risk.Classify(args.Command)
		ids, meta, err := c.ResolveAssets(ctx, args.Assets)
		if err != nil {
			return render.Err(err)
		}
		if len(ids) == 0 {
			return render.Err(fmt.Errorf("no targets resolved"))
		}
		if len(ids) > maxAssetsPerRun {
			return render.Err(fmt.Errorf("%d targets exceeds the per-run limit of %d", len(ids), maxAssetsPerRun))
		}

		targets := []*jmsms.AssetRef{}
		for _, m := range meta {
			targets = append(targets, &jmsms.AssetRef{
				ID:       jmsapi.FieldStr(m["id"]),
				Name:     jmsapi.FieldStr(m["name"]),
				Address:  jmsapi.FieldStr(m["address"]),
				Platform: jmsapi.FieldStr(m["platform"]),
			})
		}
		plan := &jmsms.JobPlan{
			// The enum carries its own wire form: CommandClass marshals as
			// its name, so this is the word "READ" / "DANGEROUS" and not the
			// number behind it.
			Risk:      jms.Opt(cmdClass.String()),
			Command:   jms.Opt(args.Command),
			Runas:     jmsapi.FieldStr(args.Runas),
			DryRun:    jms.OptBool(args.DryRun),
			Targets:   targets,
			TargetCnt: jms.OptInt32(int32(len(ids))),
		}

		// The three answers of this tool -- the rehearsal, the refusal and
		// the run -- are ONE contract type; which fields are filled says
		// which one this is.
		//
		// The judgement and the hint come from risk.Rehearsal, the ONE place
		// "would this run?" is answered for both planes: the hint was
		// spelled here twice before (once built by hand for the rehearsal,
		// once hard-coded as "DANGEROUS" for the refusal — a sentence that
		// was supposed to name the class it actually found), and two
		// spellings of one contract drift.
		would, blocked := risk.Rehearsal(cmdClass, args.Confirm)
		if args.DryRun {
			// The verdict vocabulary (executed / would_execute / blocked /
			// note) is filled by the shared writer, so this plane's
			// rehearsal says what the execution plane's says.
			//
			// ⚠️ The trail knows this is not a refusal: a rehearsal that
			// carries a `blocked` hint is still a rehearsal, and the trail
			// tells the two apart (see pkg/audit).
			render.FillRehearsal(plan, cmdClass.String(), would, blocked, render.RehearsalNote)
			return render.Text(plan)
		}
		if !would {
			render.FillRefusal(plan, cmdClass.String(), blocked)
			return render.Text(plan)
		}

		body := map[string]any{
			"name":        fmt.Sprintf("mcp-%s", time.Now().Format("20060102-150405")),
			"type":        "adhoc",
			"module":      "shell",
			"args":        args.Command,
			"assets":      ids,
			"instant":     true,
			"is_periodic": false,
			"timeout":     900,
		}
		if args.Runas != "" {
			// An explicit runas means "use exactly this account", so the account
			// selector must not try to substitute another one.
			body["runas"] = args.Runas
			body["runas_policy"] = "skip"
		} else {
			// No runas given: the selector only accepts privileged accounts.
			// With "skip" it silently resolves to "No available account" on the
			// assets whose only account is a non-privileged one (e.g. opsuser).
			body["runas_policy"] = "privileged_first"
		}

		var resp map[string]any
		if err := c.Post(ctx, jmsapi.ResJobs, body, &resp); err != nil {
			return render.Err(err)
		}
		plan.TaskID = jmsapi.FieldStr(resp["task_id"])
		plan.Executed = jms.OptBool(true)

		// Waiting here beats making the caller poll. A short command finishes in
		// well under 10s, and an agent that never polls is left believing the job
		// is still queued.
		if args.Wait > 0 {
			wait := args.Wait
			if wait > 300 {
				wait = 300
			}
			id := jmsapi.Str(resp["task_id"])
			for waited := 0; waited < wait; waited += 3 {
				time.Sleep(3 * time.Second)
				var ex map[string]any
				if err := c.Get(ctx, jmsapi.ResJobExecutions, id, &ex); err != nil {
					continue
				}
				plan.IsFinished = jmsapi.FieldBool(ex["is_finished"])
				plan.IsSuccess = runSucceeded(ex)
				plan.Summary = jobSummary(ex["summary"])
				plan.TimeCost = jmsapi.FieldStr(ex["time_cost"])
				if ex["is_finished"] == true {
					break
				}
			}
			if plan.GetIsFinished() {
				stdout := "the API returns no job stdout. Use jmsx_exec (jms-exec MCP) when the output matters."
				// The note carries what the fields cannot: WHY there is no
				// per-host outcome, and what "nothing ran" means for the
				// caller's next move (retrying a command that never left
				// the bastion is safe; retrying one that did is not).
				switch {
				case plan.Summary == nil && plan.IsSuccess == nil:
					plan.Note = jms.Opt("finished, but the record carries no per-host recap, so whether the command ran on any target cannot be verified (this record is final — polling again will not add the recap). " + stdout)
				case plan.Summary == nil && !plan.GetIsSuccess():
					plan.Note = jms.Opt("the task finished but the recap lists no host that ran the command (0 ok / 0 failed / 0 skipped): nothing ran on any target. Check the asset has a usable account and is reachable. " + stdout)
				case !plan.GetIsSuccess():
					plan.Note = jms.Opt("the run did not succeed on every target; the summary is the per-host outcome. " + stdout)
				default:
					plan.Note = jms.Opt(stdout)
				}
			} else {
				plan.Note = jms.Opt("still running after the wait; poll jms_job_status with this task_id")
			}
		} else {
			plan.Note = jms.Opt("poll with jms_job_status using this task_id, or pass wait=N to block until it finishes")
		}
		return render.Text(plan)
	})

	type jobStatusArgs struct {
		TaskID string `json:"task_id" jsonschema:"task_id returned by jms_job_run, or an execution id"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_job_status",
		Description: "Get the outcome of a batch execution started by jms_job_run: which hosts succeeded, which failed and why, plus timings. " +
			"NOTE: JumpServer's API does NOT expose the captured stdout/stderr of a job execution (v4 and v5 alike). Verified 2026-10-14: " +
			"/ops/job-executions/{id}/ carries no result field and none of its sub-resources exist, so a per_host output " +
			"block would always be empty. When you need the actual output, use jmsx_exec from the jms-exec server.",
		OutputSchema: render.Schema[jmsms.JobExecutionResult](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args jobStatusArgs) (*mcp.CallToolResult, any, error) {
		var raw json.RawMessage
		if err := c.Get(ctx, jmsapi.ResJobExecutions, args.TaskID, &raw); err != nil {
			return render.Err(err)
		}
		var e map[string]any
		if err := json.Unmarshal(raw, &e); err != nil {
			return render.Err(err)
		}
		out := &jmsms.JobExecutionResult{
			TaskID:       jmsapi.FieldStr(e["id"]),
			IsFinished:   jmsapi.FieldBool(e["is_finished"]),
			IsSuccess:    runSucceeded(e),
			Material:     jmsapi.FieldStr(e["material"]),
			DateStart:    jmsapi.FieldStr(e["date_start"]),
			DateFinished: jmsapi.FieldStr(e["date_finished"]),
			TimeCost:     jmsapi.FieldStr(e["time_cost"]),
			Summary:      jobSummary(e["summary"]),
		}
		// The summary is flattened as well, so a caller does not have to know
		// its shape to ask "which hosts worked".
		if hosts := out.GetSummary(); hosts != nil {
			out.Succeeded = hosts.Ok
			out.Failed = hosts.Failed
			out.Skipped = hosts.Skipped
		}
		// the API does not expose the output of a job execution at all, so saying
		// so is part of the answer: a caller who needs the output has to go
		// to the execution plane.
		out.StdoutAvailable = jms.OptBool(false)
		out.Note = jms.Opt("the API returns no job stdout over the API. Use jmsx_exec (jms-exec MCP) when the output matters.")
		return render.Text(out)
	})

	type jobListArgs struct {
		Limit  int    `json:"limit,omitempty" jsonschema:"max rows (default 20)"`
		Search string `json:"search,omitempty" jsonschema:"substring match on the executed command material"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_job_list",
		Description:  "List recent batch executions with outcome and command material. Use it for 'what did the last batch do'; jms_job_audit adds who ran it and the command as it was issued, and jms_job_status adds the per-host outcome of one execution.",
		OutputSchema: render.Schema[render.ListOf[jmsms.JobExecutionSummary]](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args jobListArgs) (*mcp.CallToolResult, any, error) {
		rows, err := c.List(ctx, jmsapi.ResJobExecutions)
		if err != nil {
			return render.Err(err)
		}
		// filter → map → sort → truncate → count: the order and the three
		// counting fields come from render.ListSpec, not from this loop.
		// Two drifts this fixes, both of which misread the moment a search
		// was used: the loop used to stop at `limit` matches BEFORE sorting
		// (so the answer was "the first N matches", not "the top N by date"),
		// and it reported total as the UNFILTERED row count rather than how
		// many matched.
		return render.Text(render.ListSpec[map[string]any, jmsms.JobExecutionSummary]{
			Rows: rows,
			Keep: func(e map[string]any) bool {
				if args.Search == "" {
					return true
				}
				material := convert.AnyToStr(e["material"])
				return strings.Contains(strings.ToLower(material), strings.ToLower(args.Search))
			},
			Map: func(e map[string]any) jmsms.JobExecutionSummary {
				return jmsms.JobExecutionSummary{
					TaskID:    jms.Opt(convert.AnyToStr(e["id"])),
					IsSuccess: runSucceeded(e),
					Summary:   jobSummary(e["summary"]),
					DateStart: jms.Opt(convert.AnyToStr(e["date_start"])),
					Material:  jms.Opt(jmsapi.Truncate(convert.AnyToStr(e["material"]), 200)),
				}
			},
			Less:  func(a, b jmsms.JobExecutionSummary) bool { return a.GetDateStart() > b.GetDateStart() },
			Limit: args.Limit,
			Def:   20,
			Max:   100,
		}.Build())
	})

	type jobStopArgs struct {
		TaskID  string `json:"task_id" jsonschema:"execution id to stop"`
		Confirm bool   `json:"confirm" jsonschema:"must be true; stopping a running batch cuts work off on every target"`
	}
	reg.Add(r, &mcp.Tool{
		Name:         "jms_job_stop",
		Description:  "Stop a running batch execution. Requires confirm: stopping cuts the work off on every target. Use it when a batch run is going wrong and has to be halted everywhere at once.",
		OutputSchema: render.Schema[jmsms.JobStopped](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args jobStopArgs) (*mcp.CallToolResult, any, error) {
		if !args.Confirm {
			return render.Err(fmt.Errorf("set confirm=true to stop the execution; it cuts work off on every target"))
		}
		var out map[string]any
		// ⚠️ The field is `task_id`, not `ids`: the live v5 serializer
		// 400s anything else with {"error":{"task_id":["This field is
		// required."]}} (captured 2026-11-03). The old `ids` body never
		// worked against a real bastion and survived only because the
		// contract test's fake answered {"ok":true} to any body — the fake
		// agreed with the code instead of with the API. The fake now
		// validates the body the way the serializer does.
		if err := c.Post(ctx, jmsapi.ResJobExecutionsStop, map[string]any{
			"task_id": args.TaskID,
		}, &out); err != nil {
			return render.Err(err)
		}
		return render.Text(&jmsms.JobStopped{
			Stopped:  args.TaskID,
			Response: jms.Opt(convert.AnyToStr(out)),
		})
	})

	RegisterJobAuditTool(r, c)
}

// registerJobAuditTool installs the audit-side view of batch work.
//
// jms_job_list answers "how did the last executions end" from the operational
// side: it lists /ops/job-executions/, which carries the per-host outcome and
// nothing else. The audit side lives in /audits/job-logs/ and carries what
// the operational side does not: WHO ran it, the command as it was actually
// issued, how long it took, and whether it finished.
//
// Joining the two on task_id gives the answer to the question a batch is
// actually run for: who ran what, on which machines, and why did those fail.
//
// The join is best-effort and says so: a job-log carries a task_id for most
// executions but not all, and an execution may have been reaped from the
// operational side already. Unlinked rows are still reported, with their own
// command, because the command is the audit record.
func RegisterJobAuditTool(r *reg.Registry, c *repository.Client) {
	type auditArgs struct {
		Job        string `json:"job,omitempty" jsonschema:"substring match on the command or on a job definition name"`
		Since      string `json:"since,omitempty" jsonschema:"only executions at or after this date, e.g. 2026/10/12"`
		Limit      int    `json:"limit,omitempty" jsonschema:"how many executions to report (default 20, max 100)"`
		OnlyFailed bool   `json:"only_failed,omitempty" jsonschema:"only executions that failed"`
		Defs       *bool  `json:"include_definitions,omitempty" jsonschema:"also list the batch job definitions (default true)"`
	}
	reg.Add(r, &mcp.Tool{
		Name: "jms_job_audit",
		Description: "Audit trail of batch work: who ran it, when, the command as it was actually issued, how long " +
			"it took, and which target failed and why. Use it to trace a bulk change across the fleet -- jms_job_list " +
			"only shows the per-host outcome, and jms_job_status shows no command at all. Failed executions are " +
			"listed on their own. Credential-looking values in the commands are masked.",
		OutputSchema: render.Schema[jmsms.JobAudit](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args auditArgs) (*mcp.CallToolResult, any, error) {
		withDefs := args.Defs == nil || *args.Defs
		limit := repository.NormLimit(args.Limit, 20, 100)
		since := normDate(args.Since)
		if args.Since != "" && since == "" {
			return render.Failf("cannot read since=%q; use 2026/10/12 or 2026-10-12", args.Since)
		}

		logs, err := c.List(ctx, jmsapi.ResAuditJobLogs)
		if err != nil {
			return render.Failf("%v", err)
		}
		execs, err := c.List(ctx, jmsapi.ResJobExecutions)
		if err != nil {
			return render.Failf("%v", err)
		}
		byTask := map[string]map[string]any{}
		for _, e := range execs {
			byTask[convert.AnyToStr(e["id"])] = e
		}
		byLogID := map[string]map[string]any{}
		for _, l := range logs {
			byLogID[convert.AnyToStr(l["id"])] = l
		}

		type execRow struct {
			id       string
			created  string
			creator  string
			command  string
			success  bool
			finished bool
			taskID   string
			cost     string
			started  string
			ended    string
		}
		var picked []execRow
		for _, l := range logs {
			command := convert.AnyToStr(l["material"])
			created := convert.AnyToStr(l["date_created"])
			creator := convert.AnyToStr(l["creator_name"])
			if since != "" {
				if len(created) < 10 || created[:10] < since {
					continue
				}
			}
			if args.Job != "" {
				q := strings.ToLower(args.Job)
				if !strings.Contains(strings.ToLower(command), q) && !strings.Contains(strings.ToLower(creator), q) {
					continue
				}
			}
			ok, _ := l["is_success"].(bool)
			fin, _ := l["is_finished"].(bool)
			picked = append(picked, execRow{
				id: convert.AnyToStr(l["id"]), created: created, creator: creator,
				command: command, success: ok, finished: fin,
				taskID:  convert.AnyToStr(l["task_id"]),
				cost:    convert.AnyToStr(l["time_cost"]),
				started: convert.AnyToStr(l["date_start"]),
				ended:   convert.AnyToStr(l["date_finished"]),
			})
		}
		slices.SortStableFunc(picked, func(a, b execRow) int {
			return cmp.Compare(b.created, a.created)
		})
		total := len(picked)
		// The counts describe the whole matching set, not the part that
		// survives the limit: reporting "failed: 2" when ten runs failed
		// because the caller asked for two rows is the same kind of lie as
		// reporting a truncated count as the real one.
		succeeded, failedCount := 0, 0
		for _, e := range picked {
			if e.success {
				succeeded++
			} else {
				failedCount++
			}
		}
		if args.OnlyFailed {
			kept := picked[:0]
			for _, e := range picked {
				if !e.success {
					kept = append(kept, e)
				}
			}
			picked = kept
		}

		out := []*jmsms.JobAuditExecution{}
		failed := []*jmsms.JobAuditExecution{}
		unlinked, empty := 0, 0
		for _, e := range picked {
			command := strings.TrimPrefix(e.command, "shell:")
			if strings.TrimSpace(command) == "" {
				// The bastion recorded the run but not what it ran; say so
				// rather than printing an empty command.
				command = "(the bastion recorded no command for this run)"
				empty++
			}
			entry := &jmsms.JobAuditExecution{
				ID:       jms.Opt(e.id),
				Creator:  jms.Opt(e.creator),
				Created:  jms.Opt(e.created),
				Command:  jms.Opt(jmsapi.Truncate(redactSecrets(command), 1200)),
				Success:  jms.OptBool(e.success),
				Finished: jms.OptBool(e.finished),
				TimeCost: jms.Opt(e.cost),
				TaskID:   jms.Opt(e.taskID),
				Started:  jms.Opt(e.started),
				Ended:    jms.Opt(e.ended),
			}
			if !e.success {
				failed = append(failed, entry)
			}
			// The per-host outcome lives on the operational side and is
			// joined on task_id; when it is missing the execution is still
			// reported, with its own command.
			if hosts := hostOutcome(byTask, e.taskID); hosts != nil {
				entry.Hosts = hosts
			} else {
				unlinked++
			}
			out = append(out, entry)
		}
		// The timeline is capped, but the failed list is not: it is the part
		// the caller came for, so it stays complete (up to a bound).
		if len(out) > limit {
			out = out[:limit]
		}
		failedTruncated := false
		if len(failed) > maxFailedList {
			failed = failed[:maxFailedList]
			failedTruncated = true
		}

		res := &jmsms.JobAudit{
			Count:             int32(len(out)),
			Total:             int32(total),
			Truncated:         len(out) < total,
			Succeeded:         int32(succeeded),
			Failed:            int32(failedCount),
			WithoutHostDetail: jms.OptInt32(int32(unlinked)),
			WithoutCommand:    jms.OptInt32(int32(empty)),
			Executions:        out,
		}
		if failedCount > 0 {
			res.FailedExecutions = failed
			if failedTruncated {
				res.FailedTruncated = jms.OptBool(true)
			}
		}
		if withDefs {
			if defs := jobDefinitions(ctx, c, args.Job); len(defs) > 0 {
				res.Definitions = defs
			}
		}
		res.Note = jms.Opt("the command is shown as it was actually issued, with credential-looking values masked. " +
			"A batch execution without host detail means the operational record for it is no longer held.")
		return render.Text(res)
	})
}

// hostOutcome pulls the per-target result out of an execution record.
//
// The shape is {"ok": [...], "failed": {host: reason}, "skipped": [...]}. The
// failure reasons are free text from the target host, so they are masked like
// any other audit output.
func hostOutcome(byTask map[string]map[string]any, taskID string) *jmsms.JobAuditHosts {
	if taskID == "" || taskID == "<nil>" {
		return nil
	}
	e, ok := byTask[taskID]
	if !ok {
		return nil
	}
	// The SAME mapper the run and status tools use: one shape for one piece
	// of data, whatever tool is reading it.
	return jobSummary(e["summary"])
}

// jobDefinitions lists the batch job definitions, so the audit can be read
// next to what the job was set up to do.
func jobDefinitions(ctx context.Context, c *repository.Client, filter string) []*jmsms.JobAuditDefinition {
	rows, err := c.List(ctx, jmsapi.ResAuditJobs)
	if err != nil {
		return nil
	}
	out := []*jmsms.JobAuditDefinition{}
	for _, j := range rows {
		name := convert.AnyToStr(j["name"])
		if filter != "" && !strings.Contains(strings.ToLower(name), strings.ToLower(filter)) {
			continue
		}
		entry := &jmsms.JobAuditDefinition{
			Name:      jms.Opt(name),
			CreatedBy: jms.Opt(convert.AnyToStr(j["created_by"])),
			LastRun:   jms.Opt(convert.AnyToStr(j["date_last_run"])),
			// The bastion says "True"/"False" here, not a boolean.
			Periodic:    jms.Opt(convert.AnyToStr(j["is_periodic_display"])),
			Interval:    jms.Opt(convert.AnyToStr(j["interval"])),
			CommandHead: jms.Opt(jmsapi.Truncate(redactSecrets(convert.AnyToStr(j["args"])), 400)),
		}
		// The summary is the bastion's own free structure; only its numeric
		// keys are kept, so the contract can say what they are.
		if summary, ok := j["summary"].(map[string]any); ok {
			nums := map[string]int32{}
			for k, v := range summary {
				if n, ok := v.(int); ok {
					nums[k] = int32(n)
				}
			}
			if len(nums) > 0 {
				entry.Summary = nums
			}
		}
		out = append(out, entry)
	}
	return out
}

// jobSummary turns the bastion's free-form execution summary into the
// contract's shape.
//
// It is the same summary the audit tool reads (JobAuditHosts) — one shape for
// one piece of data, whatever tool is reading it.
func jobSummary(v any) *jmsms.JobAuditHosts {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := &jmsms.JobAuditHosts{}
	if ok := asStringSlice(m["ok"]); len(ok) > 0 {
		out.Ok = ok
	}
	if skipped := asStringSlice(m["skipped"]); len(skipped) > 0 {
		out.Skipped = skipped
	}
	redacted := map[string]string{}
	if fails, ok := m["failures"].(map[string]any); ok {
		for host, reason := range fails {
			redacted[host] = jmsapi.Truncate(redactSecrets(convert.AnyToStr(reason)), 400)
		}
	}
	// "dark" is the recap's own name for the hosts that could not even be
	// REACHED. A host that was unreachable did not run the command, and
	// "which hosts worked" has to say so — dropping it on the floor left
	// only the hosts that worked, which reads as "everything worked".
	if dark, ok := m["dark"].(map[string]any); ok {
		for host := range dark {
			if _, dup := redacted[host]; !dup {
				redacted[host] = "unreachable"
			}
		}
	}
	if len(redacted) > 0 {
		out.Failed = redacted
	}
	// A recap with nothing in it is not a summary of anything: render it as
	// "nothing to report" (absent), not as an empty object that reads like
	// "zero problems".
	if len(out.Ok) == 0 && len(out.Skipped) == 0 && len(out.Failed) == 0 {
		return nil
	}
	return out
}

// runSucceeded derives "did the command actually succeed on its targets"
// from the execution record — the ONE place this question is answered, so
// jms_job_run, jms_job_status and jms_job_list cannot read it three
// different ways.
//
// The upstream is_success does NOT answer this question: it says the task
// itself did not error. Measured 2026-11-03 on an unreachable host — the
// recap {"ok":[],"dark":{},"skipped":[],"failures":{}} (nothing ran
// anywhere) carried is_success=true in one run and false in the next. The
// recap is the hard evidence, so:
//
//   - recap names a host that ran ok and nothing failed/unreachable → true
//   - recap exists otherwise → false (nothing succeeded — that is a fact,
//     not an omission)
//   - no recap at all → NOT GIVEN, whatever the upstream label says. The
//     label is the thing that lied (true for "nothing ran"); and even a
//     false label only says the TASK errored — the command may have run
//     fine on every target before the task tripped. Without the recap the
//     per-host truth is unknown, and "无法确认就不说" is the only honest
//     answer (IDL JobPlan.is_success spells this out; this is the code
//     that keeps the spelling true).
func runSucceeded(e map[string]any) *bool {
	recap, hasRecap := e["summary"].(map[string]any)
	if !hasRecap {
		return nil
	}
	okHosts := asStringSlice(recap["ok"])
	fails, _ := recap["failures"].(map[string]any)
	dark, _ := recap["dark"].(map[string]any)
	return jms.OptBool(len(okHosts) > 0 && len(fails) == 0 && len(dark) == 0)
}
