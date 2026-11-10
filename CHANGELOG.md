# 变更记录

本文件遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
本项目遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 变更

### 新增

### 修复

## [0.14.10] - 2026-11-11
### 变更
- **地板提升**：go 指令 1.26.0 → 1.27.0；`go get -u ./...` 全量升级（含底座
  jumpserver-kit v0.12.4 → v0.12.5——带上 risk 门四个漏判修复）；
  restore-go-modcache.sh 清单与 go.mod 逐版本同步。guardx/tools 与底座钉住的
  v0.23.4 / v0.13.4 对齐（v0.24.1 的 logredact 过度脱敏是全车队契约问题）。

### 修复
- **委派请求透传调用方 ctx**（#11）：repository 层的
  `DelegationRequest` / `SendWithDelegation` 原来硬编码
  `context.Background()`——MCP 客户端取消/断开后，handler 侧 ctx 已死、
  JumpServer 侧的委派调用照跑到底（单次凭据在服务端被消费，客户端却把
  静默当失败可重试）。两个方法改为接受 ctx 并透传给底层 jmsapi（底层本就
  接受）；六个调用点（delegation.go 三处、admin.go 三处）改传 handler 拿到的
  ctx。admin.go 的**回滚 DELETE** 例外：那是已发生写操作的补偿，不能被客户端
  取消打断——显式 `context.WithoutCancel(ctx)` + 自带 30s 预算（与 workers.go
  的纪律同款），且回滚失败不再被吞（原错误信息无条件说「已删除」，失败时
  现在明说钥匙还挂在错误账号上）。测试：httptest 服务端观测请求取消
  （两方法各一条 + 未取消对照组）。
## [0.12.0] - 2026-11-06

### 变更

- 底座抬 v0.8.1（网关 `ListSubQuery`）。
- **仓层 listing 全部收编进网关**：`internal/repository` 的 3 处裸 `ListAll`
  （nodes→`ListSub` / commands→`ListQuery` / labels→`ListSubQuery`）不再手写
  路径与查询串。守卫边界刻意不扩到本层——repository 是协议层本体，裸 `Do`
  留给无网关形状的端点（分工写进了 `repository.go` 类型注释）。

## [0.11.0] - 2026-11-05

### 变更

- **IDL 摊平**：`idl/jmsms/` → `idl/`（单词汇仓不再多一层目录，17 份按域拆的
  thrift 直接住在 `idl/`）。包名由全目录一致的 `namespace go jmsms` 命名，入口
  仍是 `jmsms.thrift`；生成物 `biz/model/jmsms/` 零变化，工具的契约形状与对外
  行为不变。
- `script/gen-idl.sh` 的入口推导改问文件一致声明的 `namespace go`，不再取目录名。

### 新增

- 契约命名守卫（底座 v0.8.0）认**两种布局**：平铺 `idl/`（单词汇仓）与嵌套
  `idl/<pkg>/`（多词汇仓），并首次有了仓内夹具测试（7 场景）与变异脚本
  `mutate-naming-guard.py`（6/6 变异被杀，边界登记在案）。

## [0.10.0] - 2026-11-05

### 修复

- **回放下载/Adhoc 采集改走底座 GetBinary**：两处原先手拼 `Authorization: Token `+token——
  登录凭据下（v4 的唯一路径）是空 key 必 401，且 401 的 JSON 体被送进 tar 读成
  "unexpected EOF"。现在走与 JSON 调用相同的凭据（自动刷新 Bearer）、限流与状态检查。
- **AccessSources 的组授权不再静默丢失**：原先对组详情路由用列表解析（ShapeError 即跳过），
  "只经由组拿到的授权"永远答不出 held；改读组详情的 members。
- **jms_user_groups_list 改读授权详情**：列表行的 user_groups 实测恒 null，"组持有哪些
  授权"此前恒空答。
- **jms_status 资产计数改翻页**：单页抓取在超窗口部署上静默少报；改走 ListAllCounted，
  总数用服务器自己的 count。
- **jms_security_review 不再把"封禁列表读不到"当"没有封禁"**：未知降级为 Warn 并明说，
  不再指示去封禁一个可能已在列表上的地址。
- jms_asset_evidence 的 Note 不再相互覆盖（资产已删除 + 有跳过会话时两个事实都在）。
- jms_access_matrix 的排序修复（原对空 key 的 sort 是死代码）。

### 变更

- 危险命令分类随底座 v0.7.0 变严（同执行面）；工具层 9 处裸路径调用改走网关形状的
  ListCounted（底座新增，rawCalls 守卫补登后抓到的存量违规）。

## [0.9.0] - 2026-11-05

### 变更

- **判定词汇收编为单一写法**：`jms_job_run` 的演练/被拒答复改用底座的
  `render.FillRehearsal`/`FillRefusal`（见 kit v0.6.0）。顺带补齐：演练答复此前
  未填 `dry_run` 字段，agent 侧无法从答复本身认出演练——现在与其他工具一致。
- **配置装载走底座 `confload`**：三段式读档、HTTP/RPC 拒绝文案、密码/OTP 回退收编，
  与执行面同一份实现。

## [0.8.0] - 2026-11-05

### 新增

- **kitex RPC 面（第三张脸）**：其他服务可经 thrift 同步调用本面的工具——
  `JMS_RPC_ADDR` + `JMS_RPC_TOKEN`（逐调用凭据；ADDR 配了 TOKEN 缺 ⇒ 启动即拒）。
  语义与 stdio/REST 逐字同构：同一道门禁、同一套确认、同一份留痕（caller=`rpc`），
  拒绝与失败是 is_error **答案**不是传输错误，目录（`Catalogue`）也要求凭据——
  无匿名访问。契约与生命周期都在底座（kit 的 `idl/jmsrpc`/`kitex_gen/jmsrpc`/
  `pkg/rpcapi`/`pkg/faces`）。
- **启动模型**：`serve`（无参）= stdio + 配置了地址的面 ride-along；
  `serve http` = 只 HTTP；**`serve rpc` = 只 kitex**（新）；**`serve all` =
  HTTP+RPC 常驻**（新；两者都没配拒绝启动；不含 stdio）。常驻模式组合在
  `oekit/bootstrap` 上。

## [0.7.0] - 2026-11-04

### 变更

- **列表样板收编到底座 `render.ListSpec`**（本仓 35 处全量）：列表信封的形状只有一份
  （filter → map → sort → truncate → count，`total` = 匹配数，截断才报 `truncated`）。
- **演练判定与措辞收编到 `risk.Rehearsal`**（两个面唯一源）。
- **入口层收编**：`cmd/serve/http.go` 删除，serve 生命周期（listen / 后台 serve / 信号 /
  5s 优雅关闭）交给底座 `httpapi.Run`；`cmd/tools` 的表格循环交给 `reg.CatalogueTable`；
  `openapi_test.go` 缩为一次 `testsupport.CheckOpenAPI`（守卫身两仓一份）。
- **日志措辞统一到共用生命周期**（行为变化）：stdio 失败行 `FATAL  server failed: …` →
  `FATAL  serve: …`；`serve http` 缺地址的提示改为
  `serve http needs an address to listen on — JMS_HTTP_ADDR, …`；HTTP 面后台失败行不再
  带服务前缀（`http: …`）。
- **底座升 `jumpserver-kit` v0.4.0**。
- **工具计数单源**：`policy_test` 的两处硬编码 97 并为一个 `wantTools` 常量
  （文件头注释里过时的「76」一并消掉——三处数字就是三个漂移点）。

### 修复

- **`jms_access_matrix` 的 API 调用数不再受 limit 约束**（有意，收编的必然代价）：
  「先排序后截断」要求先为**全部**候选行算出排序键 ⇒ limit=5 在用户很多的堡垒机上
  会多调若干次 ListSub。部署上可感知，发布说明里记一笔。
- **列表的顺序 / 计数漂移修正**（收编时暴露；九处：`jms_users_list`、`jms_sessions_live`、
  `jms_job_list`、`jms_accounts_list`、`jms_filter_list`、`jms_filter_preview`、
  `jms_scope_user_groups`、`jms_operate_logs`、`jms_password_change_logs`）：
  - **先截断后排序** ⇒ 先排序后截断（`jms_users_list`、`jms_sessions_live`）：limit 的语义
    从「随便 N 个再排序」修正为「按排序键的前 N」。
  - **`total` 语义** ⇒ 一律 = 匹配数（上述站点原先多处报**未过滤**行数、或在过滤前自增）。
  - **`truncated`** ⇒ 只在真截断时为真（上述站点原先多处把「被过滤掉」也算成「被截断」）。
  （`jms_role_permissions` 等其余站点是收编**等价**，旧口径本就正确，不在修正之列。）

## [0.6.0] - 2026-11-04

### 变更

### 新增

- **HTTP API 面（REST + MCP over streamable HTTP）**：同一份工具目录的第二个面，
  与 stdio **共用同一个注册表** ⇒ 同一道风险门禁、同一套确认语义、同一份留痕
  （HTTP 面不是后门：stdio 拒的，这里一样拒）：
  - 路由：`GET /api/v1/health`（**唯一**免认证，只报名字 / 版本 / 只读与否 / 工具数）、
    `GET /api/v1/tools`（目录：风险、确认要求、入参 / 出参形状）、
    `POST /api/v1/tools/{name}/invoke`、`/mcp`（MCP over streamable HTTP）。
  - 认证：Bearer 令牌（`JMS_HTTP_TOKEN`，常量时间比较）；**没有「不开认证」模式**
    （`JMS_HTTP_ADDR` 有、`JMS_HTTP_TOKEN` 无 ⇒ 启动即拒）。
  - **结果的读法与 stdio 逐字相同**：拒绝、失败、入参不合形状一律 HTTP 200 +
    `is_error=true`；请求本身坏才 400，没有这个工具才 404。
  - 两种跑法：`serve`（默认，stdio）配了 `JMS_HTTP_ADDR` **顺带**开 HTTP；
    `serve http` 只开 HTTP，长跑到信号（当服务部署用这个）。
  - 留痕的 `client` 列记 **`rest`**（HTTP 面认证的是令牌不是人，不记「alice」）。
- **OpenAPI 契约**：`swagger/openapi.json` 由 `tools openapi` 生成
  （`./script/gen-openapi.sh`，产物入库，生成不需要任何秘密），与 MCP 工具目录**同源**
  （入参 = Go 类型派生，出参 = `idl/` 契约生成物）。守卫 `openapi_test.go` 拿签入的
  文档与再生成的**逐字节**比对（含版本号）；「这道守卫会红」由
  `script/mutate-swagger-guard.py` 机械证明（对照 + canary + 4 条变异全红）。
- 新环境变量 `JMS_HTTP_ADDR` / `JMS_HTTP_TOKEN`（见 docs/CONFIGURATION.md §3.6）。
- **底座升 `jumpserver-kit` v0.3.0**：`pkg/httpapi`（REST + MCP over HTTP，两面共用
  同一注册表）、`pkg/reg` 的 schema 捕获与 `CallTool` / `StreamableHTTPHandler`。

### 修复

## [0.5.0] - 2026-11-04

### ⚠️ 更名（breaking）

- 项目名去掉 `mcp`（本服务不止 MCP——接下来同时提供 HTTP API）：
  - **`jumpserver-mcp` → `jumpserver-mgmt`**（本仓）
  - `jumpserver-mcp-exec` → `jumpserver-exec`
  - 底座 `jumpserver-mcp-kit` → `jumpserver-kit`（**v0.2.0**，模块路径
    `github.com/yi-nology/jumpserver-kit`）
- 接线影响：`go install` 路径变为 `github.com/yi-nology/jumpserver-mgmt@latest`，
  二进制名 `jumpserver-mgmt`；本机 MCP 配置里的 `command` 指向的运行时目录变为
  `~/.local/jumpserver-mgmt-runtime/<时间戳>/`（发布脚本同一套规矩）。
- GitHub 仓名同步更名（旧 URL 自动跳转）；历史条目里的旧名已统一改写为新名，
  旧 → 新映射以本条为准。
- 本次只动名字，工具面（97 个工具）与行为不变。

## [0.4.4] - 2026-11-04

### 修复

- **`--version` 报的版本号抬到 0.4.4**：v0.4.3 发版时 `main.go` 的 `Version`
  常量忘了跟着抬（仍报 0.4.2）⇒ 被 `TestTheVersionMatchesTheTagItWasBuiltFrom`
  逮住。⚠️ v0.4.3 的 tag 已推送、不可移动 ⇒ 这一版补发；装了 v0.4.3 的用户
  `--version` 会看到 0.4.2，以本版为准。

## [0.4.3] - 2026-11-04

### 变更

- **底座抬到 v0.1.9**：凭据守卫第二轮补齐（独立审阅的 3 条跟进项 + 漏报）：
  - **豁免标记改锚定识别**：散文里**提到**标记的行不再豁免下一行（文档不再
    自造盲区）；裸标记行（无注释前缀）也不是标记。整行标记豁免下一行、
    行尾注释标记豁免当行。
  - **补漏报形态**：Go 短声明 `:=`、URL 内嵌凭据、URL 查询串参数（JWT 形态）、
    空白分隔（`.netrc`）、无后缀文件的 PEM 嗅探（`id_rsa`）、已知名字变体
    （`Dockerfile.prod`）。缩写键名改分隔符边界后缀（`MY_TOK`/`api-tok` 命中）。
  - **URL 值判定收紧**（URL 凭据字母表）⇒ 守卫扫自己仓零误报。
  - 变异 12→24 条，自证 24/24 全被测试杀掉。

### 新增

### 修复

## [0.4.2] - 2026-11-04

### 变更

- **底座抬到 v0.1.8**：上一版（v0.1.6）的凭据守卫**抓不住它要防的那件事**
  —— 独立审阅把归档仓历史里**真实带令牌的那几个文件**原样喂给守卫，结果是
  **0 命中**。⇒ v0.1.8 补齐了判据：
  - **缩写键名**（`TOK = "…`）：共享词表不认识这个缩写
    ⇒ 守卫另立一份**窄名单**（`tok`/`auth`/`credentials`，**精确匹配**）。
    ⚠️ 刻意**没有**把它们加进 `pkg/redact` 的词表 —— 那张表决定留痕记什么、
    答复掩什么，加词会改变另外两条路径的行为。
  - **位置参数**（`env.setdefault("JUMPSERVER_TOKEN", "…")`）与
    **shell 默认值**（`JUMPSERVER_TOKEN=${JUMPSERVER_TOKEN:-…}`）：键与值
    之间不是冒号或等号 ⇒ 原来那一条规则看不见它们。
  - **JSON 成员**（`{"token": "…"}`）：键与冒号之间隔着闭引号
    ⇒ 键的闭引号改成**可选**。
  - **非十六进制的凭据**（base64 形态的密钥 / GitHub PAT / AWS secret）：值形态
    从「必须是 hex」放宽为「hex 或**不透明**的 base64」。
- **豁免记账改为打印**（不是 `t.Logf`）：`go test` 在包通过时会丢掉
  stdout ⇒ 记在 log 里等于没记。⚠️ 本地要加 `-v` 才看得到（CI 跑的是
  `go test -v` ⇒ CI 里可见）。

### 新增

### 修复

- `biz/handler/redact.go` 的文档举例与 `redact_test.go` 的夹具**多了豁免
  标记：base64 形态的私钥例子现在会被守卫看见 ⇒ 它们是「关于凭据的形状」，
  不是「一份凭据」。

## [0.4.1] - 2026-11-04

### 变更

- **底座抬到 v0.1.6**（多了明文凭据那条守卫的机械）。

### 新增

- ⚠️ **明文凭据不许进仓**（守卫体在底座 `pkg/arch/credential.go`，本仓的入口是
  `internal/arch/management_test.go` 里那条
  `TestThePlaintextCredentialsAreNotInTheRepository`）：
  - **动机**：本机一个未推送远端的归档仓，其 git 历史里明文躺着一枚堡垒机
    **admin 用户的 PrivateToken**（40 位十六进制，在发布脚本、校验脚本与
    e2e 测试里）。三个公开仓全历史 **0 命中**（公网没有它），但它是被人
    **手工翻历史**才发现的 —— 构建抓不到它，因为脚本里的凭据是一个完全
    合法的程序。
  - **判据是「形状 + 语境」两半**：形状（PEM 私钥块 / `Authorization:` 头
    带值 / 长的十六进制串）说「这可能是秘密」；语境（键名经
    `redact.IsCredentialKey` 判定为凭据）说「它本来就是一个凭据」。
    ⚠️ **只认形状会误伤** `.github/workflows/` 里每个 commit SHA pin
    （40 位十六进制，与令牌同长）。
  - **行级显式豁免**：`jms:allow-credential` 写在当行或上一行 ⇒ 豁免当行；
    **每一处豁免都被守卫列出来**（豁免是**记账**的，不是静默的）。
  - ⚠️ 本仓的 `biz/handler/redact.go`（PEM 替换模板）与
    `biz/handler/redact_test.go`（PEM/JWT 夹具）逐行加了豁免标记 ——
    它们**必须**长得一模一样才能匹配。

### 修复

## [0.4.0] - 2026-11-04

### 变更

- ⚠️ **目录按 CloudWeGo hz 的标准骨架重排**：
  - **入口层搬到仓根**：`main.go` / `init.go` / `server.go` /
    `workers.go` / `shutdown.go` 是仓根那个 `package main`；
  - **`cmd/` 改成放子命令**：`cmd/serve`、`cmd/doctor`、`cmd/tools`
    是入口层 import 的**普通包**（不是各自的二进制）；
  - **`biz/` 去掉服务名前缀**：`biz/jumpserver/` → `biz/`；
  - **数据访问层统一叫 `internal/repository/`**：
    `internal/jumpserver/client/` → `internal/repository/`；
  - **配置挪到 `internal/config/`**（原 `conf/jumpserver/`），
    包名 `conf` → `config`；
  - **领域规则挪到 `internal/service/`**（原 `biz/jumpserver/service/`），
    风险表在 `internal/service/policy/`；
  - 补齐模板里的其余层（`pkg/`、`etc/`、`swagger/`、`deploy/`、
    `monitoring/`、`internal/middleware/`、`internal/rpchandler/`、
    `rpcx/`、`kitex_gen/`），**每一层都有自己的 README**，写着它为什么
    空、什么时候不再是空的。

- ⚠️ **`go install` 的路径变了**：
  `go install github.com/yi-nology/jumpserver-mgmt/cmd/jumpserver-mgmt@latest`
  ⇒ `go install github.com/yi-nology/jumpserver-mgmt@latest`。
  ⚠️ **旧路径不再存在** ⇒ 用旧命令装的人要改一次。
  release 页的二进制下载**不受影响**。

- ⚠️ **底座要求抬到 `jumpserver-kit v0.1.4`**：入口层的新布局要底座
  的守卫认（新判据 + 新增的「一个仓一个二进制」守卫）。
- 版本号 0.3.3 → 0.4.0（目录重排是**破坏性**改动 ⇒ 抬 minor；
  旧 tag 不可移动，所以只能往前发）。
- 内部包名跟着改：`client` → `repository`（`repository.Client`），
  `conf` → `config`（`config.Config`）。

## [0.3.3] - 2026-11-04

### 修复

- ⚠️ **`checksums.txt` 里的路径带目录前缀 ⇒ 校验形同虚设**：
  实测 `v0.3.2` 的 checksums 里写的是
  `./jumpserver-mgmt-linux-amd64/jumpserver-mgmt-linux-amd64`，
  而**下载页上的资产是扁平的** ⇒ 用户在下载目录跑
  `sha256sum -c checksums.txt` 会报「文件不存在」。
  ⇒ 算哈希时读源文件，只把输出里的路径换成 basename。

### 变更

- 版本号 0.3.2 → 0.3.3。

## [0.3.2] - 2026-11-04

### 修复

- ⚠️ **`v0.3.1` 装出来的二进制 `--version` 说「0.3.0」**：
  版本常量忘了跟着 tag 抬，而**它不在任何测试里、也不在任何守卫里** ⇒
  没人拦。`go install ...@v0.3.1` 装到的是功能正常、但版本号说错的二进制。
  ⇒ 版本常量抬到 `0.3.2`，并加一道守卫（见下）。

- **新增版本守卫**：二进制说的版本必须等于**它是从哪个 tag 构建出来的**
  （`version_test.go`）。
  ⇒ 在 **tag 触发**的 CI 里它有牙齿：忘了抬版本常量 ⇒ 发版构建当场红。
  ⇒ 在 main 上它**跳过**并说明原因 —— 否则「版本号先抬、tag 后打」这条正常
  流程会把自己的 CI 弄红，守卫就会被第一个被它烦到的人关掉。

### 变更

- ⚠️ **为什么是 `v0.3.2` 而不是重打 `v0.3.1`**：`v0.3.1` 已经被 Go 的模块代理
  （`proxy.golang.org`）与校验和库（`sum.golang.org`）**收录** ⇒
  **移动或删除那个 tag 会让已经记录了哈希的版本对不上** ⇒ 用户装不上。
  ⇒ 只能往前发一个新的。

- **新增 GitHub Release**（`.github/workflows/release.yml`）：tag 触发 ⇒
  六个平台（linux/darwin/windows × amd64/arm64）交叉编译 + `checksums.txt`。
  ⚠️ README 一直写着「方式二：release 二进制（见 Releases 页）」，
  但**从来没有发过 Release** ⇒ 照着做的人下到的��� 404。
  （CI 先跑测试，**红了就不发**。）

## [0.3.1] - 2026-11-04

### 修复

- ⚠️ **`v0.3.0` 那个 tag 是坏的**（已删除）：它在 CI 还红的时候被打出来 ⇒
  `.gitignore` 的 `coverage.*` 把同名**源码** `biz/handler/coverage.go`
  吞掉 ⇒ 那个 tag 缺文件 ⇒ `go install github.com/yi-nology/jumpserver-mgmt@v0.3.0`
  **编译失败**。现在 `v0.3.1` 是第一个可用的 tag。
  ⇒ 三个仓的 CI 都加了 `on: push: tags` ⇒ **tag 也会跑 CI**，坏掉的 tag 会当场红。

- **发布自检不再把「缺配置」误判成「二进制坏了」**
  （`script/publish-mcp.py`）：管理面**按设计**没有 `JUMPSERVER_URL` 就不启动
  ⇒ 以前每次发布都报一个假红，而真坏的时候反而没人看了。
  ⇒ 现在：它**自己说了原因**地退出 ⇒ 判 OK（并把原因带出来）；
  没说话就退出（被系统杀掉 / 段错误）⇒ 才是真的起不来；
  panic 仍判 FAIL（它的话里有 `panic:` 与 goroutine 栈 ⇒ 那是崩了）。

### 变更

- **底座版本抬到 `jumpserver-kit v0.1.1`**：那一版修掉了
  「三条底座守卫其实从未执行过」的问题（`protocolLayerFile` 拿带 `.go` 的
  文件名去比导入路径 ⇒ 永不相等 ⇒ 状态词汇 / 能力监视名单 / 发行版词汇
  三条检查一条都没跑过，而守卫仍报绿）。
  ⚠️ 本仓的守卫依赖底座 ⇒ 底座发了新 tag，本仓**必须**跟着抬 require
  （否则两边 CI 跑的不是同一份底座）。

- **README §3.1 的事实更正**：原文说「没有凭据只能注册一部分工具」——
  **实测是错的**：无凭据时仍然注册**全部 97 个**（注册看工具目录，不看凭据；
  没凭据是**调用时**失败，不是注册时少注册）。
  ⇒ 改成「管理面始终注册 97 个」，并说清**执行面**才是 14/15 那个
  （`jmsx_inventory` 需要 REST client）。

## [0.3.0] - 2026-11-04

首个发布（**这个 tag 后来被删除了** —— 它缺一个源码文件，编译不过；
可用的是 `v0.3.1`，见上一条）。

### 新增

- **97 个工具**，覆盖：资产（列表/详情/创建/改/删/批量登记/移动）、
  账号（增删改、自动改密、账号发现）、授权（创建/授予/删除/覆盖范围/对比/有效权限视图）、
  用户与用户组、标签、命令组与命令过滤（登录/剪贴板/脱敏 ACL）、
  角色与权限、资产树与终端、连通性、审计检索（登录日志/操作日志/密码变更/文件传输）、
  取证时间线与接触历史、委派凭据、批量作业、节点继承与覆盖范围、平台与节点杂项读、
  安全体检。
- **`--doctor` 自检**：接线 + 堡垒机配置体检 —— 报出静默失败
  （资产没有 protocols、资产没有账号、授权一个账号都没授予、授权点名的账号不存在）。
  退出码 `0`/`1`/`2`（问帮助是 `0`）。
- **只读模式**（`JMS_READ_ONLY=1`）：结构性拒掉所有写工具。
- **门禁与留痕接线**：`confirm=true` 规则、风险分级、每次调用一行留痕
  （含脱敏后的参数、门禁每一段的判定与理由、放行与否、耗时、失败标记）。
- **共用底座**：协议层、门禁、输出契约、留痕、脱敏、风险分类、失败分类、共用词汇 ——
  在 [jumpserver-kit](https://github.com/yi-nology/jumpserver-kit) 仓。

### 变更

- ⚠️ **改名**：本项目从单体仓 `jms-mcp` 拆成独立仓 `jumpserver-mgmt`。
  - 二进制：`jumpserver-mgmt`（单体仓时代就叫这个名字，现在它是独立仓的产物；
    产物落在 `./bin/`，发布落在 `~/.local/jumpserver-mgmt-runtime/<时间戳>/`）。
  - MCP 服务名：客户端配置里的 key 默认为 `jumpserver`（部署时可改）；
    留痕（审计）里的 `service` 字段是 `jumpserver-mgmt`。
  - ⚠️ **老留痕不会自动迁移**：留痕目录从 `~/.local/state/jms-mcp/audit` 改为
    `~/.local/state/jumpserver-mgmt/audit`（见 kit 仓的 CHANGELOG）。
