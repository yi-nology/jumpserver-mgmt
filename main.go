// Command jumpserver-mgmt exposes a curated JumpServer REST API surface as
// MCP tools.
//
// Design note: the upstream official server (github.com/jumpserver/mcp) derives
// its tools from JumpServer's OpenAPI schema, which yields 544 tools for v5.0.
//
// The surface is the same on JumpServer v4: the endpoint paths, the field
// shapes and the constraints below were checked against the upstream v4.10.20-lts
// source (see skills/jumpserver-ops/references/version-compat.md).
// That is too many for reliable tool selection, and the repository carries no
// LICENSE file. This server deliberately exposes a small, explicit set instead,
// and puts a risk gate in front of every one of them.
//
// Transport: stdio. Credential: a JumpServer PrivateToken, because v5 dropped
// AccessKey/Bearer auth and its OAuth tokens expire after 24h.
//
// This is the command line of the management plane. The normal mode is
// serving MCP over stdio: the agent runtime starts the binary with no
// arguments and speaks JSON-RPC over stdin/stdout. The subcommands exist for
// the moments when there is no session yet — the wiring is suspect and the
// tools are not answering.
//
// The exit codes are oekit's: 0 ok, 1 error, 2 usage. The doctor command
// follows the same rule the tool does: a WARN means "needs attention", so it
// exits non-zero.
//
// ⚠️ **入口层在仓根**：这一面是一个仓一个二进制，二进制就是仓根那个
// package main（main.go / init.go / server.go / workers.go / shutdown.go）。
// 子命令的**实现**在 cmd/ 下（cmd/serve、cmd/doctor、cmd/tools）——
// 那是**入口层 import 的普通包**，不是各自的二进制。
//
// ⚠️ 子命令的实现为什么不住在仓根：仓根那个 package 是 `main`，
// 而 Go **不许 import 一个 main 包** ⇒ 住在仓根的实现，子命令用不了；
// 反过来也一样 —— 子命令的实现住在 cmd/ 下，入口层 import 它们。
//
// 这一面的布局（CloudWeGo hz 的标准骨架）：
//
//	main.go / init.go / server.go / workers.go / shutdown.go  ← 入口层（仓根）
//	cmd/{serve,doctor,tools}/     ← 子命令（入口层 import 的包）
//	biz/handler/                   ← 工具
//	biz/model/jmsms/               ← 契约，IDL 生成的
//	biz/router/                    ← 工具目录与装配
//	internal/config/               ← 配置（环境变量）
//	internal/repository/            ← 数据访问层（堡垒机的资源）
//	internal/service/               ← 领域规则
//	idl/                           ← 契约，thrift（摊平布局）
//
// 共用底座（协议层、门禁、结果整形、留痕、脱敏、失败分类）在**另一个仓**：
// github.com/yi-nology/jumpserver-kit。

package main

// Version is the version of the management-plane server.
//
// ⚠️ **它必须与本仓的 tag 一致** —— `go install ...@v0.5.0` 装出来的二进制
// 要自己说对版本；说错的话，用户看 `--version` 会以为装错了版本。
const Version = "0.14.9"

func main() {
	dispatch()
}
