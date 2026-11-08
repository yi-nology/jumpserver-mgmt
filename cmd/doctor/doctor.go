// Package doctor is the "doctor" subcommand: the wiring self-check.
//
// ⚠️ 它回答的是「这个 server 能不能开会话？」—— 不用 MCP 会话就能问，
// 而这正是接线出问题时，运维手边唯一能问的问题。
package doctor

import (
	"context"
	"fmt"
	"io"

	"github.com/oekit/pkg/cli"

	"github.com/yi-nology/jumpserver-kit/model/jms"
	"github.com/yi-nology/jumpserver-mgmt/biz/handler"
	"github.com/yi-nology/jumpserver-mgmt/biz/model/jmsms"
	"github.com/yi-nology/jumpserver-mgmt/internal/config"
	"github.com/yi-nology/jumpserver-mgmt/internal/repository"
)

// Run checks the wiring and prints the report.
//
// It takes its streams from the caller and returns the exit code instead of
// terminating the process, so a test can drive it directly.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(stderr, "FATAL  %v\n", err)
		return cli.ExitError
	}
	c, err := repository.New(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "FATAL  %v\n", err)
		return cli.ExitError
	}
	// ⚠️ The CLI knows this server's configuration, so the doctor can also
	// report on the trail this machine keeps — the one check that does not
	// need the bastion at all. The tool path (jms_doctor) cannot: it
	// carries no configuration on purpose.
	trail := cfg.AuditSettings()
	report, err := handler.DoctorWithTrail(ctx, c, true, &trail)
	if err != nil {
		fmt.Fprintf(stderr, "FATAL  %v\n", err)
		return cli.ExitError
	}
	fmt.Fprint(stdout, Render(report))
	// 退出码只反映 FAIL（mgmt#10，与执行面对齐）：WARN 是「值得看的建议」
	// （delegation secret 未配这类部署选择），不是「不健康」——带 WARN 的
	// doctor 退出非零曾迫使发版自动化 --no-doctor 跳过整个 doctor，
	// 丢掉真 koko 登录自检去换一个部署选择的提醒。Result 行仍写
	// "needs attention"（人读的分级不变），机器读的退出码只认 FAIL。
	if report.Status == jms.Status_fail {
		return cli.ExitError
	}
	return cli.ExitOK
}

// Render turns the doctor report into the text the CLI prints.
//
// It is a pure function so the wording can be checked without a bastion. The
// grade comes from the shared status field: a WARN is "needs attention" for
// the exit code, exactly as before.
//
// The report is the contract type the doctor answers with, so the CLI reads
// the same fields the tool hands out.
func Render(report *jmsms.DoctorResult) string {
	r := cli.NewReport("jumpserver-mgmt doctor")
	r.Header(fmt.Sprintf("base_url: %v", report.BaseURL))
	// The identity is only known once the bastion answered, so the line is
	// printed only then -- the same as before, when it was a map that was
	// either there or not.
	if report.Identity.Username != nil || report.Identity.IsSuperuser != nil {
		r.Header(fmt.Sprintf("identity: %v (superuser=%v)",
			report.Identity.GetUsername(), report.Identity.GetIsSuperuser()))
	}
	for _, ck := range report.Checks {
		status := cli.StatusOK
		switch ck.Status {
		case jms.Status_warn:
			status = cli.StatusWarn
		case jms.Status_fail:
			status = cli.StatusFail
		}
		fix := ""
		if ck.Fix != nil {
			fix = *ck.Fix
		}
		r.AddFix(status, ck.Name, ck.Detail, fix)
	}
	if report.Verdict != nil && *report.Verdict != "" {
		r.AddConclusion("verdict: " + *report.Verdict)
	}
	if report.Advice != nil && *report.Advice != "" {
		r.AddConclusion("advice: " + *report.Advice)
	}
	// This side counts a WARN as "needs attention" -- that is the grading
	// rule it has always had, so the wording stays its own.
	if report.Status == jms.Status_ok {
		r.Result("result: healthy")
	} else {
		r.Result("result: needs attention (see WARN/FAIL above)")
	}
	return r.String()
}
