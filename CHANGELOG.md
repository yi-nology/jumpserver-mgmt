# jumpserver-mgmt CHANGELOG

> 本文件由 `matrix-tools/scripts/gen_changelogs.py` 从 git 历史生成，按 tag 切段、取每段内的 conventional commit 渲染。

## [v0.14.11] — 2026-11-12

- 杂务：吃高版本 Go 语言特性做纯现代化重构——sort→slices/maps、range N、builtin max

- sort.Strings / sort.Slice(自然序) → slices.Sort；sort.Slice/Stable 的字段比较器 →
  slices.SortFunc / slices.SortStableFunc（cmp.Compare / strings.Compare），升降序
  方向逐处核对；元素自然序的多键比较器（rbac 矩阵、touch 桶）改链式 cmp.Compare
- map 键收集+排序 → slices.Sorted(maps.Keys(m))（gather.keys / gather.asDetail /
  security.operateLogTypeProfile；空 map 仍得 nil，与旧行为逐字节一致）
- 计数循环 for i := 0; i < 8; i++（i 未用）→ for range 8（gather / security 的
  权限树父链上溯）
- 手写 inline max → builtin max（touchAsset.add 的 last 联系时间；first 因含
  空串哨兵语义不等价，保持原样）
- 保守跳过：touch.sortedSet（注释明确钉住 nil/空数组契约，禁用 slices.Sorted）、
  job/admin 的 for waited += 3/5 步进循环（range 整数不支持步长）
不改行为、不动 go.mod、不碰 kitex_gen 生成代码。门禁：gofmt -l 空、vet 零输出、
build 过、test 全量与基线一致，改动包 -race 抽查通过。


## [v0.14.10] — 2026-11-11

- release v0.14.10
- 委派请求透传调用方 ctx（#11）

- repository 层 DelegationRequest / SendWithDelegation 改为接受 ctx
  并透传底层 jmsapi（底层本就接受，这层包装原先主动换成
  context.Background()）：MCP 客户端取消后出站请求随之取消，
  不再把单次凭据消费成客户端读不到的成功。
- 六个调用点（delegation.go 三处、admin.go 三处）传 handler 的 ctx。
- admin.go 的回滚 DELETE 例外：已发生写操作的补偿不能被客户端
  取消打断——显式 context.WithoutCancel(ctx)+30s 预算；回滚失败
  不再吞掉（原错误信息无条件宣称已删除）。
- 测试：httptest 观测服务端 ctx.Done（两方法各一条+未取消对照）。
地板：go 1.26.0→1.27.0；go get -u 全量（kit→v0.12.5）；
restore 清单同步；guardx/tools 与底座钉版对齐。


## [v0.14.9] — 2026-11-09

- release v0.14.9
- 底座抬 v0.12.4：env 值裁剪步收编（Token/HTTP-TOKEN/RPCToken/AuditDir 等字段带尾随空格不再静默 401、枚举字段带空白不再拒载——两面统一在 confload 裁）；恢复清单钉同步

## [v0.14.8] — 2026-11-09

- release v0.14.8
- 底座抬 v0.12.2：sed/awk 深检（脚本内容级写/执行原语判 DANGEROUS）；恢复清单 kit 钉同步

## [v0.14.7] — 2026-11-09

- release v0.14.7
- 底座抬 v0.12.1：只读表除名 sed/awk（tools#81 同款穿透的下游修复——sed 's/x/y/e' 曾以 READ 穿过条件确认门；awk system()/管道执行同族）

## [v0.14.6] — 2026-11-09

- release v0.14.6
- 底座抬 v0.12.0 + oekit/oagentkit 全组件升级：pkg v0.40.0 / concurrency v0.31.0 / logx v0.8.12 / network v0.7.14 / core v0.13.5 / bootstrap v0.7.0 / kitex v0.7.14 / guardx v0.23.4 / tools v0.13.4；restore 清单 12 个版本钉同步；恢复清单守卫绿

## [v0.14.5] — 2026-11-09

- release v0.14.5：底座抬 v0.11.2

## [v0.14.4] — 2026-11-08

- release v0.14.4
- mgmt#10：doctor 退出码只反映 FAIL（与执行面对齐）——WARN 是部署选择的提醒（delegation secret），非零退出曾迫使发版自动化 --no-doctor 跳过整个 doctor（丢真 koko 登录自检）。Result 行保留 needs attention 文案（人读分级不变），机器读的退出码只认 FAIL。真机实测：WARN-only 现在 exit 0

## [v0.14.3] — 2026-11-08

- release v0.14.3
- issue 批收编：#7 jms_status 轻路径（total 走 page_size=1 的 envelope count——一次小请求换掉全量资产清单；分布仅 ≤1000 台全量拉，超出显式标 partial）+ #8 AccessSources 组短路（无组部署一次组列表换掉逐权限×2 详情；列表拉不到不短路——未知≠没有）。底座抬 v0.11.0 + BastionStatus 加 note 字段（field 10）

## [v0.14.2] — 2026-11-07

- release v0.14.2：底座抬 v0.10.5

## [v0.14.1] — 2026-11-07

- restore 清单同步 v0.10.4 级联地板（guardx v0.23 / oekit pkg v0.37.1）
- go.sum 补全 h1 内容哈希（v0.10.4 级联地板的离线可构建性）
- release v0.14.1：底座抬 v0.10.4
- CI 钉 Go 1.27.2：govulncheck 逮到 stable=1.27.1 的 stdlib 带 12 个 html/template 漏洞——go-version-file 钉语言地板不管工具链安全，toolchain 必须显式

## [v0.14.0] — 2026-11-06

- release v0.14.0：底座抬 v0.10.2
- kit#7 收尾：AGENTS 补 97 名全量清单的 tools:mgmt 标记块（守卫同时查「块里有注册表没有」与「注册表有块里没提」）+ check_tool_docs 进 CI

## [v0.13.1] — 2026-11-06

- release v0.13.1: swagger 版本同步（抬了 Version 就要重生成）
- release v0.13.1

## [v0.13.0] — 2026-11-06

### 修复：restore 清单的 kit 版本同步 v0.9.0（底座 GetBinaryTo 收编的那次 bump 漏了这份清单）

TestTheDependenciesArePinned 抓到的：go.mod 抬了、restore-go-modcache.sh
没跟——module cache 被清后这份依赖装不回来。

### 修复：网关写侧收编 + 流式落盘 + 映射钉子 + 有界并发（issue #2 #3 #4 #5）

#2 LabelAttach 收编网关 Put 形状：
- kit 网关本就有 Put(res, id, sub, ...) 写侧子资源形状（用户密码、节点
  资产走的就是它），label 的 full-set PUT 与之完全同形——之前是没认出来，
  不是缺形状。改走 c.Put，删除已无调用者的 labelResourcePath；
  repository.go 的 Client 注释同步（Raw Do 豁免清单里移除 label PUT，
  写侧路径与 listing 同一纪律）
#3 repository 三处映射补 httptest 钉子测试：
- FetchCommands：嵌套 asset/risk_label/timestamp 全字段映射 + 稀疏行
  现状行为显式钉住（AnyToStr(nil) == "<nil>"，修 nil 处理时这里会响）
- LabelBoundIDs：bound=1 视图路径 + 查询参数（并钉住 walk 接管分页——
  调用方 page_size 不上 wire，函数注释同步修正）
- AssetsUnderNode：子资源路径 + 行透传
#4 回放与采集报告流式落盘（kit v0.9.0 的 GetBinaryTo）：
- DownloadReplayText：GB 级 replay tar 直写临时文件，用完即删；
  tar 流式走文件、cast 成员解压后仅在文本转换处整读
- GatherAdhoc：同样经临时文件（HTMLToText 需要全文，收益在传输不双倍峰值）
#5 access_matrix 逐用户 reach 改有界并发（oekit/concurrency fanout.Map，
4 路 worker + panic 收编 + ctx fail-fast）：
- N 次串行往返 → 池化并行；限流器仍逐调用生效
- 失败显式计数进 Note（半答矩阵可见而非静默）；Note 报告调用数与并发度
Closes #2, closes #3, closes #4, closes #5

- release v0.13.0：底座抬 v0.9.1

## [v0.12.0] — 2026-11-06

- release v0.12.0：底座抬 v0.8.1
- 收编审阅遗留：仓层 3 处裸 ListAll 全改网关形状（nodes→ListSub / commands→ListQuery / labels→ListSubQuery），listing 不再手写路径与查询串。守卫边界不扩到本层——本层是协议层本体，Do 留给无网关形状的端点；注释写明这条分工
- gen-idl.sh 修复审阅发现：entryOf 失败路径静默成功——set -e 不传播 $(...) 参数位失败，generate 拿到空串自称完成。调用方改 || exit 1，入口文件存在性一并检查

## [v0.11.0] — 2026-11-05

- IDL 摊平：idl/jmsms/ → idl/（单词汇仓不再多一层目录；包名由全目录一致的 namespace go 命名，入口仍 jmsms.thrift）。gen-idl.sh 入口改问命名空间；底座抬 v0.8.0（守卫认平铺+嵌套两种布局）；版本 0.11.0；OpenAPI 重生成

## [v0.10.0] — 2026-11-05

- gofmt：bulk.go 对齐
- 评审修复收编（0.10.0）：回放下载/Adhoc 改走 GetBinary（v4 登录凭据下不再 401-as-tar-EOF）+ 组授权不再静默丢失 + jms_status 翻页 + 封禁未知不降级为'没有封禁'

- DownloadReplayText/GatherAdhoc 改走底座 GetBinary：凭据自己的头（Token/自动刷新 Bearer）+ 限流 + 状态检查
- AccessSources 组分支：列表解析详情路由（ShapeError 即跳过=死代码）改读组详情 members
- jms_user_groups_list 改读授权详情（列表行 user_groups 实测恒 null）
- jms_status 改 ListAllCounted 翻页 + 服务器 count 作总数
- security_review：封禁列表读不到 → Warn 明说未知，不当'没有封禁'指示重复封禁
- evidence note 不再相互覆盖；access_matrix 排序修复
- 工具层 9 处裸路径调用改走底座 ListCounted（rawCalls 守卫补登后抓到的存量违规）
- 危险命令分类随底座 v0.7.0 变严

- gitignore：ZCode 会话工具的工作目录（.video_agent/.v2c）——它让 vcs.modified 恒真，发布出来的二进制失去 commit 可追溯性

## [v0.9.0] — 2026-11-05

- 判定词汇与配置装载收编进底座（0.9.0）：jms_job_run 改用 render.FillRehearsal/FillRefusal，Load 改用 confload

- mgmt#1：演练/被拒答复的手写填充收编为底座写侧；顺带补齐演练答复缺失的 dry_run 字段（agent 此前无法从答复本身认出演练）
- kit#1：Load 的三段式读档、HTTP/RPC 配对纪律、密码/OTP 回退改用底座 confload
- 底座抬 v0.6.0；OpenAPI 文档随版本常量重生成；restore 清单与 go.mod 同步

- README/AGENTS 三张脸同步 + access_matrix API 调用数备注补记
- verifier 审阅修复：ExampleAddr 直达 faces.plan + RPC 配置去死字段

- serve 接线改为无条件构造 opts.HTTP（拒绝句需要的示例端口只在构造的
  选项上旅行）
- rpcapi.Options 的 Name/Version 死字段停止传递（底座已删）
- 空层 README 去掉悬空反引号

- kitex RPC 面接线 + serve 启动模型（0.8.0）

- serve 子命令变成数据：''（stdio+rides）/ http / rpc（新）/ all（新，
  HTTP+RPC 常驻，两者都没配拒绝启动，不含 stdio）；生命周期交给底座
  pkg/faces（唯一主人，oekit/bootstrap 组合根）
- 新环境变量 JMS_RPC_ADDR / JMS_RPC_TOKEN：ADDR 配了 TOKEN 缺 ⇒ 启动即拒
- RPC 面与其他两张脸同门同纪：同一注册表、同一道门禁、同一份留痕
  （caller=rpc），拒绝与失败是 is_error 答案不是传输错误
- 底座升 jumpserver-kit v0.5.0（go.sum/restore/go.work 同步钉版）


## [v0.7.0] — 2026-11-05

- 结构深化收编（0.7.0）：35 处列表样板收编 + 演练判定唯一源 + 入口层共用生命周期

- 列表样板收编 render.ListSpec（35 处全量）：列表信封只有一份形状
  （filter→map→sort→truncate→count，total=匹配数，截断才报 truncated）
- 收编时修正 7 处计数/顺序漂移（users/job/accounts/filter_list/filter_preview/
  scope_user_groups/role_permissions）：先截断后排序改为先排序后截断，
  total 从未过滤数改为匹配数（详见 CHANGELOG）
- 演练判定与措辞收编 risk.Rehearsal：jms_job_run 不再硬编码 'classified
  DANGEROUS'，报实际类别
- 入口层收编：cmd/serve/http.go 删除，生命周期交给 httpapi.Run（示例端口
  ExampleAddr 传本面文档端口 8731）；cmd/tools 表格交给 reg.CatalogueTable；
  openapi_test 缩为 testsupport.CheckOpenAPI
- 工具计数单源：policy_test 两处硬编码 97 并为 wantTools 常量（头注释过时的
  76 一并消掉）
- 底座升 jumpserver-kit v0.4.0（go.sum/restore 脚本同步钉版）


## [v0.6.0] — 2026-11-04

- 新增 HTTP API 面（REST + MCP over streamable HTTP）与 OpenAPI 契约链（0.6.0）

- 同一工具目录的第二个面：REST /api/v1/… + MCP over streamable HTTP /mcp，
  与 stdio 共用同一个注册表 ⇒ 同一道风险门禁、同一套确认语义、同一份留痕。
- 新环境变量 JMS_HTTP_ADDR / JMS_HTTP_TOKEN：Bearer 令牌认证（常量时间比较），
  没有「不开认证」模式（ADDR 有 TOKEN 无 ⇒ 启动即拒）。两种跑法：serve（stdio）
  配了 ADDR 顺带开 HTTP；serve http 只开 HTTP 面，长跑到信号。
- 结果的读法与 stdio 逐字相同：拒绝、失败、入参不合形状一律 200 + is_error；
  请求坏才 400，没有这个工具才 404。留痕 client 列记 rest。
- OpenAPI 契约入库：tools openapi 生成 swagger/openapi.json（./script/gen-openapi.sh，
  生成不需要任何秘密），仓根 openapi_test.go 逐字节守卫（含版本联动），
  script/mutate-swagger-guard.py 变异自证（对照 + canary + 4 条变异全红）。
- 底座升 jumpserver-kit v0.3.0（pkg/httpapi + pkg/reg 服务面）。


## [v0.5.0] — 2026-11-04

- 改名落地：jumpserver-mcp → jumpserver-mgmt

把项目名里的 mcp 字样去掉，为后续 REST API / MCP over HTTP 双面做准备：
- GitHub 仓库：yi-nology/jumpserver-mcp → yi-nology/jumpserver-mgmt
- Go 模块路径：github.com/yi-nology/jumpserver-mgmt
- 二进制名：jumpserver-mgmt（发布目录 ~/.local/jumpserver-mgmt-runtime/）
- 共用底座换新模块路径 github.com/yi-nology/jumpserver-kit@v0.2.0
  （旧路径 jumpserver-mcp-kit 停在 v0.1.9，旧消费者不受影响）
- 全仓文本（文档 / CI / 脚本 / 技能）同步改名；CHANGELOG 记旧→新映射表
行为不变：97 个工具、门禁与留痕契约、输出契约均不动。


## [v0.4.4] — 2026-11-04

### 修复：--version 抬到 0.4.4（v0.4.3 发版漏抬版本常量，被版本守卫逮住）

- 6ebb715

## [v0.4.3] — 2026-11-04

- 杂务：底座抬到 v0.1.9（凭据守卫第二轮补齐）

- 豁免标记锚定识别（散文/裸标记行不再豁免）；补 :=、URL 内嵌/查询串、
  .netrc 空白分隔、无后缀 PEM、Dockerfile.prod 变体等漏报形态。
- go.mod/go.sum/restore-go-modcache.sh 三处同步抬到 kit v0.1.9。


## [v0.4.2] — 2026-11-04

### 修复(arch)：底座抬到 v0.1.8 —— 凭据守卫补齐「事故原形」

⚠️ 上一版（v0.1.6）的守卫**抓不住它要防的那件事**：独立审阅把归档仓历史里
**真实带令牌的那几个文件**原样喂给守卫，结果是 **0 命中**。⇒ v0.1.8 补齐：
- 缩写键名（TOK = "…"）：守卫另立一份**窄名单**（tok / auth / credentials，
  **精确匹配**）。⚠️ 刻意**没有**把它们加进 pkg/redact 的词表 —— 那张表决定
  留痕记什么、答复掩什么，加词会改变另外两条路径的行为。
- 位置参数（env.setdefault("K", "…")）与 shell 默认值（$K:-…}）：键与值之间
  不是冒号或等号 ⇒ 原来那一条规则看不见它们。
- JSON 成员（{"token": "…"}）：键与冒号之间隔着闭引号 ⇒ 闭引号改成可选。
- 非十六进制的凭据（base64 形态的密钥 / GitHub PAT / AWS secret）：值形态
  从「必须是 hex」放宽为「hex 或**不透明**的 base64」。
- 豁免记账改为打印（go test 在包通过时会丢掉 stdout ⇒ 记在 log 里等于没记；
  本地要加 -v 才看得到，CI 跑 go test -v ⇒ CI 里可见）。
另：biz/handler/redact.go 的文档举例与 redact_test.go 的夹具多了豁免标记 ——
base64 形态的私钥例子现在会被守卫看见 ⇒ 它们是「关于凭据的形状」，不是
「一份凭据」。
版本抬到 0.4.2。

## [v0.4.1] — 2026-11-04

### 新增(arch)：明文凭据不许进仓（接上底座 v0.1.6 的新守卫）

- 底座抬到 v0.1.6：pkg/arch 多了一条扫工作树的凭据守卫。
- internal/arch/management_test.go 接上 TestThePlaintextCredentialsAreNotInTheRepository
  ⇒ 判据是「形状 + 语境」两半：形状（PEM 私钥块 / Authorization 头带值 /
  凭据键下的长 hex，长度窗口 [32,64]）+ 语境（键名经 redact.IsCredentialKey
  判定为凭据）。⇒ .github/workflows/ 里每个 commit SHA pin 不会被误伤
  （40 位十六进制与堡垒机令牌同长）。
- 背景：本机一个未推送远端的归档仓，其 git 历史里明文躺着一枚堡垒机 admin
  用户的 PrivateToken；三个公开仓全历史 0 命中（公网没有它），但它是被人
  手工翻历史才发现的 —— 构建抓不到它，因为脚本里的凭据是一个完全合法的程序。
- biz/handler/redact.go 的 PEM 替换模板与 redact_test.go 的 PEM/JWT 夹具
  逐行加 jms:allow-credential 豁免标记：它们**必须**长得一模一样才能匹配
  ⇒ 标记的是「这一行是关于凭据的代码」，不是「这一行是一个凭据」。
- 版本抬到 0.4.1。

- 文档：修断链（管理面/执行面细节那份笔记搬到 docs/ 之后，链接没跟上）

## [v0.4.0] — 2026-11-04

### 修复(review)：独立审阅指出的问题（路径错指 / 跨面工具名 / 假「生成物」头）

独立审阅（verifier 子代理）的结论：**无阻断问题**，4 处「应当修」+ 5 处建议。
应当修：
- AGENTS.md 三处路径错指：`internal/client`（应为 `internal/repository`，
  本次重排新引入）、`biz/service/`（应为 `internal/service/`）、
  `biz/policy/policy.go`（应为 `internal/service/policy/policy.go`）。
- monitoring/README.md 写了 `jmsx_audit_query` —— 那是**执行面**的工具，
  管理面没有 ⇒ 改成「用 tail 读」（那句是从执行面抄过来的）。
建议（也一并做了）：
- 九份空层 README 在两个仓之间**逐字相同**（抄本会漂）⇒ 每份补一段
  「这一面的对应物」，两份不再逐字相同。
- internal/repository/requests.go 的头写着「Code generated by
  script/split-client.py -- DO NOT EDIT BY HAND」—— 那个脚本早就不在仓里
  ⇒ 照着它办的人会以为改不动 ⇒ 改成「这里是手写的，要改就改」。
- CHANGELOG 点名版本号 0.3.3 → 0.4.0。
- script/check-skill-drift.sh 里的仓名清单与底座 workset.py 的 REPO_NAMES
  是两份拷贝 ⇒ 加一句互相指认。
- 底座要求抬到 jumpserver-mcp-kit v0.1.5（入口层守卫的允许集合补上了
  「cmd/ 根上那个包」）。

### 修复(release)：少了 go mod download ⇒ 版本依赖守卫可能卡住发版

kit 的 v0.1.2 实测卡在 TestTheDependenciesArePinned（依赖没在 module cache
里解包）—— go vet / go test 只会拉被编译到的那些依赖 ⇒ 加 go mod download。
本仓当时侥幸过了（多依赖了 kit 的传递依赖、被编译到了）⇒ 同一个坑在
另一个仓等着。

### 重构(layout)：目录按 hz 骨架重排 —— 入口层搬到仓根

⚠️ 行为变化：
- `go install github.com/yi-nology/jumpserver-mcp/cmd/jumpserver-mcp@latest`
  ⇒ `go install github.com/yi-nology/jumpserver-mcp@latest`（旧路径没有了，
  用旧命令装的人要改一次；release 页的二进制下载不受影响）。
- 底座要求抬到 jumpserver-mcp-kit v0.1.4：入口层的新布局要底座的守卫认。
目录：
- 入口层搬到仓根：main.go / init.go / server.go / workers.go / shutdown.go
  那个 package main；
- cmd/ 改成放子命令：cmd/serve、cmd/doctor、cmd/tools（入口层 import 的普通包，
  不是各自的二进制）；
- biz/ 去掉服务名前缀：biz/jumpserver/ → biz/；
- 数据访问层统一叫 internal/repository/：internal/jumpserver/client/ →
  internal/repository/；
- 配置挪到 internal/config/（原 conf/jumpserver/），包名 conf → config；
- 领域规则挪到 internal/service/（原 biz/jumpserver/service/），风险表在
  internal/service/policy/；
- 补齐模板里的其余层（pkg/ etc/ swagger/ deploy/ monitoring/
  internal/middleware/ internal/rpchandler/ rpcx/ kitex_gen/）——
  每一层都有自己的 README，写着它为什么空、什么时候不再是空的。
⚠️ 子命令的实现为什么不住在仓根：仓根那个 package 是 main，而 Go 不许
import 一个 main 包 ⇒ 子命令的实现只能在 cmd/ 下；而「最外层」的守卫
（底座的 CheckBinariesAreOutermost）也据此改判据，并新增「一个仓一个
二进制」的守卫（CheckTheEntryLayerIsOneBinaryAtTheRoot）。
验证：gofmt / vet / go build / go test -race 全绿（JMS_REQUIRE_PUBLISHED=1，
对着**已发布**的 kit v0.1.4 跑）；mutate-identity-guard.py 6/6。

## [v0.3.3] — 2026-11-04

### 修复(release)：checksums 里的路径要是扁平的，否则校验形同虚设

实测 v0.3.2 的 checksums.txt 里写的是
  ./jumpserver-mcp-linux-amd64/jumpserver-mcp-linux-amd64
而**下载页上的资产是扁平的**（jumpserver-mcp-linux-amd64）
⇒ 用户在下载目录跑 sha256sum -c checksums.txt 会报「文件不存在」
⇒ 校验这一步要么被忽略，要么被当成 checksum 坏了。
原因：actions/download-artifact 把每个 artifact 解到自己的子目录里，
直接 find . | xargs sha256sum 出来就是带目录前缀的路径。
⇒ 算哈希时读源文件，只把输出里的路径换成 basename。
   （别去「把文件拍平再算」：资产名与目录名同名时会把目录当文件，
   而且那一步会动下载下来的东西。）
本地用同样的目录结构验证过输出。

- 杂务(release)：版本号 0.3.2 → 0.3.3（checksums 路径修复随之发布）

## [v0.3.2] — 2026-11-04

### 修复(version)：版本号抬到 0.3.2，并把版本守卫改成对着 tag 比

v0.3.1 装出来的二进制 `--version` 说「0.3.0」⇒ 用户以为自己装错了版本。
而版本常量不在任何测试、也不在任何守卫里 ⇒ 没人拦。
- 版本常量 0.3.1 → 0.3.2
- 版本守卫改成对着**构建所在的 tag**比（不是「仓里最新的 tag」）：
  - 对着「最新 tag」⇒ 「版本号先抬、tag 后打」这条正常流程会把自己的
    CI 弄红 ⇒ 守卫会被第一个被它烦到的人关掉
  - 对着硬编码清单 ⇒ 每次发版都要手改清单，忘改就正是它要抓的那个失败
  ⇒ 在 tag 触发的构建里比对（CI 传 JMS_RELEASE_TAG）；在 main 上跳过
    并写清「tag 触发的 CI 才查」
  ⇒ 验证过它有牙齿：JMS_RELEASE_TAG=v0.3.9 而常量是 0.3.1 ⇒ 变红
- CI：test job 的 checkout 加 fetch-depth: 0（浅克隆拿不到 tag 对象
  ⇒ 守卫会永远跳过 ⇒ 又变成「看着有、其实没跑」）
- CHANGELOG：说明为什么是 v0.3.2 而不是重打 v0.3.1（v0.3.1 已被
  proxy.golang.org 与 sum.golang.org 收录 ⇒ 移动 tag 会让哈希对不上）

### 修复(version)：二进制要自己说对版本 —— 并加一道守卫钉住它

v0.3.1 发布后，`go install ...@v0.3.1` 装出来的二进制 `--version` 说
「0.3.0」⇒ 用户会以为自己装错了版本。原因是版本常量忘了跟着 tag 抬，
而**它不在任何测试里、也不在任何守卫里** ⇒ 没人拦。
- cmd/jumpserver-mcp/root.go：Version 0.3.0 → 0.3.1
- 新增 cmd/jumpserver-mcp/version_test.go：读**本仓的 tag**（不是硬编码
  清单）⇒ 二进制说的版本必须等于最新的发布 tag
  ⇒ 发了版忘了抬常量会红；抬了常量没打 tag 也会红
- 验证过它有牙齿：把常量改成 0.9.9 ⇒ 守卫变红并指出「最新 tag 是 0.3.1」

- CI(release)：tag 触发发 GitHub Release（六个平台 + checksums）

README 承诺了「方式二：release 二进制（见 Releases 页）」，
但**从来没有发过 Release** ⇒ 照着做的人下到的��� 404。
（org 的惯例也是发 Release：git-ferry / agent-harness 都带产物 + checksums。）
- .github/workflows/release.yml：
  - test job：先跑 vet + 测试，**红了就不发**（tag 已经发出去了，
    但至少不会把一个编译不过的版本当「已发布」推给用户）
  - release job：linux/darwin/windows × amd64/arm64 交叉编译
    （CGO_ENABLED=0 —— 纯 Go 的 sqlite，六个平台不需要 C 工具链）
  - publish job：生成 checksums.txt + 变更清单 + 发 Release
- 资产名与 README 里写的下载链接一致：
  jumpserver-mcp-<os>-<arch>[.exe]


## [v0.3.1] — 2026-11-04

### 新增：初始发布 —— JumpServer 堡垒机的管理面 MCP 服务（97 个工具）

管堡垒机本身：资产、账号、授权、节点树、命令过滤、登录 ACL、剪贴板 ACL、
数据脱敏规则、批量作业、审计检索、网络拓扑、接触史、文件传输留痕、取证时间线。
回答的是「这个堡垒机现在是什么样子、谁能干什么」。
共用底座（协议层、门禁、输出契约、留痕、脱敏、风险分类、契约守卫机械）在
github.com/yi-nology/jumpserver-mcp-kit —— 本仓 require 它的一个版本，不写 replace。
守卫（internal/arch/）的体在底座，判据在本仓：答复必须是契约类型、凭据词表不许
误判自家参数、两个服务不得互相 import、每个依赖都被 go.sum 钉住。

### 修复(publish)：二进制起来后因缺配置而退出 —— 那不是「起不来」

发布自检脚本把「进程退出」一律判成 FAIL ⇒ 管理面**按设计**
没有 JUMPSERVER_URL 就不启动（它只有 REST 一条路，没配置就没有服务）
⇒ 每次发布都报一个假红，而真坏的时候反而没人看了。
- 它自己说了原因地退出 ⇒ 二进制是好的（把原因带出来，判 OK）
- 没说话就退出（被系统杀掉 / 段错误 / 没输出）⇒ 才是真的起不来
- panic 也说话，但它的话里有 "panic:" 与 goroutine 栈 ⇒ 那是崩了，仍判 FAIL
- 判 OK 时也要把那行说明打出来：OK 不等于「它应答了 initialize」
同时（同一轮审阅的其他几条）：
- README §3.1 的事实错误：「没有凭据只能注册一部分工具」—— 实测**无凭据时
  仍然是 97 个**（注册看工具目录，不看凭据；没凭据是**调用时**失败）。
  改成「管理面始终注册 97 个」，并说清执行面才是 14/15 那个
- CI 加 on: push: tags —— tag 也必须能编译（v0.3.0 就是红的时打的）

### 修复(git)：gitignore 的 coverage.* 把源码文件 coverage.go 也吞了

`coverage.*` 本意是挡覆盖率**产物**（coverage.out），但它同样匹配
`biz/jumpserver/handler/coverage.go` —— 那不是产物，是工具实现的源码。
后果：CI 上 `go vet ./...` 报 `undefined: handler.RegisterCoverageTools`
（本地没事，因为文件在，只是没进版本库）。
⇒ 改成只挡 coverage.out / coverage.html 两个产物名。

- 杂务(deps)：底座抬到 jumpserver-mcp-kit v0.1.1

底座 v0.1.1 修掉了「三条守卫其实从未执行过」的问题
（protocolLayerFile 拿带 .go 的名字比导入路径 ⇒ 永不相等 ⇒
状态词汇/能力监视名单/发行版词汇三条检查一条都没跑过，而守卫仍报绿）。
⚠️ 本仓的守卫住在底座里 ⇒ 底座发了新 tag，本仓**必须**跟着抬 require，
否则本仓 CI 与底座 CI 跑的不是同一份底座（行为不一致）。
- go.mod：require v0.1.0 → v0.1.1；go.sum 同步（删掉不再 require 的旧条目）
- script/restore-go-modcache.sh：恢复列表跟着抬版本
  （守卫 TestTheDependenciesArePinned 当场逮到了这条 —— 它守的就是它）
- CHANGELOG：补 0.3.1 条目（坏 tag 的来龙去脉 + 发布自检的判定改动 +
  README 的事实更正）；并把首个发布的版本号从 0.1.0 改成 0.3.0
  （对外发的 tag 是 v0.3.0，CHANGELOG 写 0.1.0 是笔误）


- 文档：底座版本号抬到 v0.1.1（与 go.mod 一致）
