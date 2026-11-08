# JumpServer v5 的 API 坑（管理面笔记）

> 这份文件原来住在 `biz/jumpserver/README.md`（单仓时期）。现在它是一份
> **笔记**：仓库怎么用、目录怎么摆，看仓根的 `README.md` 与 `AGENTS.md`；
> 这里留的是**踩过的坑** —— 那些「API 说是 200，其实路根本走不通」的地方。

JumpServer **v5.0** 堡垒机的精简 MCP（Model Context Protocol）工具集，用 Go 实现。

## 为什么不用官方的那个

上游 [jumpserver/mcp](https://github.com/jumpserver/mcp)（40★，Python）是可用的，技术上也兼容 v5——但它从
`/api/swagger.json` **动态生成工具**，v5.0 的 OpenAPI 有 **544 个端点**，也就是 544 个 MCP 工具。工具数量到这个
量级，agent 的工具选择会明显失准，每轮对话还要为工具定义付出大量上下文。另外该仓库**没有 LICENSE 文件**。

本仓暴露 **97 个**经过挑选的工具：只读/审计、批量作业、以及一批带 confirm 闸门的写操作
（**准确**的清单与每个工具的风险见 `jumpserver-mgmt tools`）。

工具的返回契约由 `idl/`（摊平布局）定义（入口 `jmsms.thrift` include 各域文件；
诊断报告 / 列表元信息 / 工具声明 / 失败），生成物在 `biz/model/jmsms/`；工具的风险与确认要求集中在
`internal/service/policy/policy.go`，门禁在底座仓（kit）的 `pkg/reg/` —— 那是**唯一**的注册入口，
所以「写操作必须 confirm」是结构性的，不是每个处理器自觉遵守的约定。

## 目录结构

这一面在仓里的位置（hz 的标准骨架，服务的部分）：

```
仓根（main.go / init.go / server.go / workers.go / shutdown.go）
                             ← 入口层（package main）：serve / doctor / tools / version
cmd/{serve,doctor,tools}/    ← 子命令（入口层 import 的普通包，不是二进制）
biz/                         ← 这一面（handler / model / router）
internal/config/             ← 配置（环境变量）
internal/repository/         ← JumpServer REST API 客户端 + 委派凭据
internal/repository/livetest/← 打真堡垒机的测试助手
internal/service/            ← 领域规则（纯函数）
internal/service/policy/     ← 工具目录的风险侧
idl/                         ← 输出契约（thrift，摊平布局）
```

契约词汇是这一面自己的（`idl/` → `biz/model/jmsms/`），
这一面的代码都依赖它；门禁与协议层在**共用底座**（kit 仓）：`pkg/reg`、`pkg/jmsapi`、
`pkg/audit`、`pkg/redact`、`pkg/render`、`model/jms`。

共用词汇（两个面都要说的词）在 kit 仓的 `model/jms/` —— 资产就是其中之一：两个面读的
是同一批堡垒机记录，问的也是同一个问题，形状必须只有一份。

## 认证方式（v5 的坑）

JumpServer v5 **移除了 `AccessKeyAuthentication`**，只剩 HTTP Signature 与 Session/OAuth。对一个长期运行的
MCP 进程来说：

| 方案 | 问题 |
|---|---|
| `POST /api/v1/authentication/tokens/` 拿 token | **24 小时过期**，MCP 每天都会断 |
| AccessKey + HMAC 签名 | 可行，但每次请求都要签名，时钟敏感 |
| **PrivateToken** | ✅ 采用。`Authorization: Token <key>`，长期有效 |

```bash
# 在堡垒机上签发
docker exec -w /opt/jumpserver/apps jms_core python manage.py shell -c \
  "from users.models import User; from authentication.models import PrivateToken; \
   u=User.objects.get(username='admin'); \
   print((PrivateToken.objects.filter(user=u).first() or PrivateToken.objects.create(user=u)).key)"
```

## 环境变量

| 变量 | 必填 | 说明 |
|---|---|---|
| `JUMPSERVER_TOKEN` | 是 | PrivateToken 明文 |
| `JUMPSERVER_URL` | 是 | 部署根地址，例如 `https://jumpserver.example.com`（**无默认值**；不带 `/api/v1`，不带结尾斜杠） |

## 工具清单

**只读 / 资产视图**

| 工具 | 作用 |
|---|---|
| `jms_status` | 连通性、认证、资产总数与平台分布。排查入口 |
| `jms_platforms_list` | 平台列表（Linux / Kubernetes / Website …） |
| `jms_assets_list` | 资产清单，可按 platform / connectivity / 关键字过滤 |
| `jms_asset_get` | 单资产详情：协议、账号、连通性、最近登录 |
| `jms_accounts_list` | 账号清单（**不返回任何密钥**） |
| `jms_nodes_list` | 资产分组节点 |
| `jms_permissions_list` | 资产授权，用于最小权限审计 |

> **`jms_status` 资产计数走哪条路（issue #7）**：先探一次 `/api/v1/assets/assets_amount/`
> 聚合端点——答上来就用它（一次小请求出 total + 平台分布，`connectivity_ok/err` 留空，
> 因为没有聚合端点会报连通性）。上游 v3.10 之后已不再注册该路由，v4/v5 实测 404 ⇒
> **回退全量走表**：按 1000/页把 `/assets/assets/` 全部行拉下来本地计数。这条回退路的代价
> 要心里有数——**500+ 台的部署上，一次 `jms_status` 就是全量资产 JSON 过网络 + 全量解析**，
> 而它是每个 agent 会话开头都会调的工具；探测只多花一个 404 请求（404 不可重试，不放大）。
> 分页包装开启的部署上，走表首页响应就带 `count`，总数取的是服务端自己的计数；但平台分布
> 与连通性没有轻端点可拿，只能来自实际读到的行——这是上游能力缺口，不是本工具偷懒。

**批量作业**（经 JumpServer 执行，全程留痕）

| 工具 | 作用 |
|---|---|
| `jms_job_run` | 对选定资产执行命令。**带风险分级**，DANGEROUS 需 `confirm=true`；`dry_run=true` 只解析不执行，并给出 `would_execute`（这次演练若真跑，会不会跑 —— 缺这一格是「没说」，不是「不会跑」）。`wait=N` 让它阻塞到完成，**免去手动轮询** |
| `jms_job_status` | 执行状态与汇总（成功/失败的资产名及原因）。⚠️ v5 不提供 stdout |
| `jms_job_list` | 最近执行记录 |
| `jms_job_audit` | **批量作业的审计线**：谁跑的、什么时候、实际下发的命令、耗时、**哪台目标失败且原因**（`jms_job_list` 只有 per-host 结果，`jms_job_status` 没有命令） |
| `jms_job_stop` | 停止执行中的作业（需 `confirm`） |

**审计**

| 工具 | 作用 |
|---|---|
| `jms_asset_touch_history` | **按资产聚合的接触史**：谁、何时、从哪、用什么账号碰过它；录像只索引不下载 |
| `jms_asset_evidence` | **一台机器的命令级时间线**：谁、什么时候、敲了什么、返回了什么；只报有审计价值的会话；凭证样式的值自动遮蔽 |
| `jms_sessions_list` | 终端会话（用户 / 资产 / 协议 / 是否有录像） |
| `jms_sessions_live` | **当前**在线会话，带 remote_addr |
| `jms_commands_search` | 命令记录检索（读全量命令日志后本地过滤） |
| `jms_login_logs` | 登录日志，用于发现撞库 |

⚠️ 这几个端点的**资产字段是扁平字符串**（`"name(address)"` + 平级的 `asset_id`），
不是资产端点那种嵌套对象 —— 详见 `skills/jumpserver-ops/references/v5-api-traps.md` 第 23 节。

**写操作**（2026-10-14 新增 12 个，全部要 `confirm=true`）

| 工具 | 作用 |
|---|---|
| `jms_users_list` | 用户清单，含 SSH key 状态与最后登录 |
| `jms_user_sshkey_add` | 注册 **RSA** SSH 公钥（走 v5 真正生效的路径） |
| `jms_user_set_active` | 启用/停用用户 |
| `jms_permission_create` | 建资产授权 |
| `jms_permission_grant` | 给已有授权加用户/资产，或提升为 `@ALL` |
| `jms_permission_delete` | 删授权（不可逆） |
| `jms_asset_create` | 登记新资产，**强制要求 protocols** |
| `jms_asset_update` | 改资产：补协议 / 改端口 / 改平台 / 停用 |
| `jms_asset_delete` | 删资产（不可逆，连带删账号） |
| `jms_account_update` | 改账号密码或启停 |
| `jms_account_delete` | 删账号（只删堡垒机记录，**不碰机器上的用户**），用于回滚 `jms_gather_apply` |
| `jms_connectivity_check` | 触发真实连通性测试，**等到状态稳定**再返回 |

**命令过滤 / 会话**（同样要 `confirm=true`）

| 工具 | 作用 |
|---|---|
| `jms_cmdgroup_list` / `jms_cmdgroup_create` | 命令组（命名命令集合） |
| `jms_cmdfilter_list` / `jms_cmdfilter_create` | 把命令组绑到用户+资产，决定 reject / accept / warning |
| `jms_cmdfilter_delete` | 删过滤（`name`）或删命令组（`command_group`） |
| `jms_session_terminate` | 强制断开在线会话（录像保留） |

**取证 / 自动化 / 组织**（2026-10-15 新增 13 个）

| 工具 | 作用 |
|---|---|
| `jms_session_transcript` | **按会话还原完整命令流**。`/terminal/commands/` 带 `output` 字段，按 `session` 聚合就能还原终端流水 —— 这是 `jmsx_exec` 解析失败时的回退通道 |
| `jms_command_audit` | 命令记录审计（用户 / 资产 / 风险等级 / 远端地址），比 `jms_commands_search` 多带 `output`、`session` |
| `jms_session_replay` | 取录像：元数据 + 从 asciinema tar 里解出的终端文本 |
| `jms_gathered_accounts` | 堡垒机发现的账号，含确认状态。`present:false` = **你管理的账号在机器上消失了**，最便宜的清单漂移检查 |
| `jms_gather_run` | 登录资产扫账号（真跑远程自动化） |
| `jms_gather_apply` | 把发现的 pending 账号收编成真实账号 |
| `jms_labels_list` / `jms_label_create` / `jms_label_delete` | 标签增删查 |
| `jms_label_attach` | **给资产打标签 / 解标签**（合并语义，不是替换） |
| `jms_label_resources` | 列出带某标签的资源，回出资源名和地址而不只是 id |
| `jms_roles_list` | 组织角色清单 |
| `jms_role_permissions` | 角色能干什么，输出 `app.action` 路径，支持 `search` 收窄 |

**安全审计**（2026-10-15 补，按"对权限审计的价值"排序挑的）

这批是拿 swagger 的 **544 个端点**和代码里实际调用的路径做差集挑出来的 ——
起初只覆盖 100 个（18.4%）。

| 工具 | 补的能力 | 实测 |
|---|---|---|
| `jms_operate_logs` | **谁改了配置**：资产 / 账号 / 权限 / 命令过滤 / 标签 / 系统设置。与 `jms_command_audit`（终端里敲的命令）互补，不是同一件事 | 335 条真实记录 |
| `jms_password_change_logs` | 谁改了谁的密码、来源 IP。**他人重置会单独列在 `reset_by_someone_else`** | 28 条 |
| `jms_system_role_permissions` | **系统级**角色权限 —— `jms_roles_list` 只能看到 org scope，SystemAdmin 是另一个 scope | 4 个角色，SystemAdmin 2 人 |
| `jms_login_asset_check` | 该不该给某账号开某资产，以及是否配了登录限制策略 | 当前**无任何登录 ACL**（这本身就是结论） |

⚠️ **两个端点不可用，所以没有包成工具**：

- `/accounts/account-risks/` → **403**，token 无该权限
- `/accounts/account-secrets/su-from-accounts/`（谁能 sudo 到谁）→ **403**，
  该 action 根本不在允许集里，**授权也修不了**

包一个永远返回"权限不足"的工具比不包更糟 —— 调用方会以为查过了。

## 列表类工具的返回约定

所有返回列表的工具一律带这三个字段，**无条件存在**（即使没截断也有）：

| 字段 | 含义 |
|---|---|
| `count` | 这次**返回**了几条 |
| `total` | 过滤后**匹配**了多少条 |
| `truncated` | 返回的条数是否少于匹配数（被 limit 截掉了） |

⇒ 调用方不必为每个工具学一套名字，也不必猜「这个字段存在吗」。

⚠️ **`total` 是匹配数，不是「全部行数」**：过滤条件先算 `total`，再截断。
「有多少条被截掉了」= `total - count`。

⚠️ 少数工具的「截断」不是列表而是**文本**：`jms_session_transcript` 的
`max_chars` 截的是转写文本，所以它的 `truncated` 恒为 false，文本截断另用
`text_truncated` 表示。

⚠️ 参数命名约定（破坏性变更后）：
- `user` = JumpServer 用户（人）；`users` = 它的列表
- `account` = 资产上的登录账号；`accounts` = 它的列表
- `asset` = 单个资产；`assets` = 它的列表
- `search` = 模糊子串匹配；`name` = 精确标识符（name 或 UUID）

## 诊断类工具的返回约定

`jms_doctor` / `jms_asset_audit` / `jms_command_guard` / `jms_security_review` /
`jms_login_asset_check` 回答的是同一类问题 ——「哪里不对，怎么修」。
它们看的对象不同，但**读法统一**：

| 字段 | 含义 |
|---|---|
| `checks[]` | 逐项检查结果，每项 `{name, status, detail, fix?}` |
| `findings[]` | `checks[]` 里 status ≠ ok 的那些（子集） |
| `status` | 总体评级：`ok` / `warn` / `fail` |
| `verdict` | 一句话结论 |
| `advice` | 一句话怎么修 |

三个 status 只有一种含义：

| status | 含义 |
|---|---|
| `ok` | 没问题 |
| `warn` | 值得看一眼，但不挡路 |
| `fail` | 真的坏了 |

`fix` 挂在**每一项**上，且尽量点名能修它的工具（`jms_asset_update` /
`jms_account_create` / `jms_permission_grant` …），这样调用方不需要自己猜下一步。

⚠️ **统一的是说法，不是判定口径**。每个工具对「什么算坏」有自己的规矩，改动时要保留：

| 工具 | 它自己的规矩 |
|---|---|
| `jms_doctor` | WARN 也算「不健康」（CLI 退出码非 0） |
| `jms_asset_audit` | 网站 / Kubernetes 资产本就没有协议和账号，不算问题；**全部**账号被停用 = fail，部分停用 = warn |
| `jms_command_guard` | 「没有过滤器匹配」= ok，不是问题 |
| `jms_security_review` | 有超级用户 = warn（不是 fail）；被停用的账号 = ok（停用本就是锁死） |
| `jms_login_asset_check` | 不传 `user` 是**文档化用法**（只回答「有没有限制」），不是问题 |

⚠️ 破坏性变更：旧的 `healthy`（布尔）、`problems`（字符串列表）、
`note`（散落备注）、以及 `jms_command_guard` 的四值枚举 `verdict`
（`blocked` / `warned` / `explicitly_allowed` / `not_filtered`）**都已删除**。
枚举信息没丢：它现在落在 `status`（blocked→fail、warned→warn、余下→ok）
和每条 filter 的 check 里。

## Chat AI delegation：JumpServer 官方的 AI 凭证方案

不是我们自己发明的包装。v5 core 里本来就有 `chat_ai` app，`X-JMS-AI-Delegation`
是**全局 DRF 认证类**（`jumpserver/settings/libs.py`），也就是**任何 API 都接受它**。
本机 `CHAT_AI_DELEGATION_SECRET` 已配置 64 字节，机制是活的（2026-10-15 实测）。

| 工具 | 作用 |
|---|---|
| `jms_delegation_status` | 是否已配置，以及每个请求被绑定了什么 |
| `jms_delegation_call` | 用一次性凭证调任意 API |
| `jms_delegation_probe` | 端到端验证，并展示**每种篡改被 core 如何拒绝** |

### 它和长期 Token 的区别（重点）

| | 长期 Token | Delegation |
|---|---|---|
| 有效期 | 长期 | **< 60 秒**（core 的 `MAX_TTL=60`） |
| 次数 | 无限 | **一次**（nonce 一次性） |
| 绑定 | 无 | **method + path + query + body 全绑定** |
| 泄露后果 | 该用户全部权限，长期有效 | 已耗尽，且用不到别的接口 |

实测 core 对每种篡改给出**不同的**理由，这就是凭证被"绑定"而非只被"签名"的证据：

| 篡改 | core 的回应 |
|---|---|
| header 的 operation 与 token 不符 | `Chat AI delegation operation mismatch` |
| 换路径 | `Chat AI delegation request mismatch` |
| 换 method | `Chat AI delegation request mismatch` |
| 换 query | `Chat AI delegation request body mismatch` |
| 重放同一 token | `Chat AI delegation credential was already used` |

### ⚠️ 它**不会**给你更多权限

必须说清楚，否则会被误当成提权通道：

- 返回的 user 走**正常 RBAC**，没有任何额外授权
- `allowed_operation_id` 只校验 **header 与 token 是否一致**，不校验它是否对应这个端点
  （实测填 `assets.view_asset` 和 `audits.view_operatelog` 都能过同一端点）

所以它的价值是**审计与暴露面**，不是能力。高危写操作（删资产 / 改权限 / 重置账号）
用 delegation，凭证落地即废；常规查询用 Token。

### 配置

secret 是堡垒机级别的"AI 调用根信任"，**不要**写进 MCP 配置文件 —— 那等于让每个
能读那个目录的进程都拿到它：

```bash
ssh root@<bastion> 'docker exec -w /opt/jumpserver/apps jms_core python -c "
import os,sys; sys.path.insert(0,\"/opt/jumpserver/apps\")
os.environ.setdefault(\"DJANGO_SETTINGS_MODULE\",\"jumpserver.settings\")
import django; django.setup()
from django.conf import settings
sys.stdout.write(settings.CHAT_AI_DELEGATION_SECRET)"' \
  > ~/.config/jumpserver-mgmt/delegation.key
chmod 600 ~/.config/jumpserver-mgmt/delegation.key
```

`user_id` / `org_id` 用现有 Token 自动解析（查 `ai` 用户与 DEFAULT 组织），
也可用 `JMS_DELEGATION_USER_ID` / `JMS_DELEGATION_ORG_ID` 显式指定。
**任何工具都不会回显 secret。**

两个易踩的实现细节，都写进了代码注释：

- core 比对的是 `request.path_info`，**含 `/api/v1` 前缀**。签相对路径会让每次调用
  都变成 `request mismatch`，而手写的探针恰好用绝对路径时又是通的 —— 两者不一致
  才暴露出来。
- 发起请求时 **`X-JMS-ORG` header 必需**；同名 Cookie 只是 fallback，可省略（实测）。

## 三个「API 返回 200/500 但路径根本走不通」的地方

这三条都不是参数写错，而是 **v5 这个部署的 REST 写入路径本身不通**。工具绕开了它们。

**1. `POST /labels/labeled-resources/` 永远 500。**
`LabeledResource.save()` 要求 `org_id`，而 create serializer 从不填，于是必然抛
`Please select an organization before saving`。换 `res_id` / `res_type` / `resource`
的任意组合都救不回来 —— 字符串报 `Not a valid string.`，dict 报 `"None" is not a valid choice.`，
合法字符串则 500。

能用的是 UI 自己那条路：

```
PUT /api/v1/labels/labels/<label_uuid>/resource-types/<content_type_id>/resources/
body: {"res_ids": ["<uuid>", ...]}
```

`content_type_id` 从 `/rbac/content-types/` 查 `model == "asset"`（本机是 **6**）。
⚠️ **尾斜杠不能少**，少了返回 301。
⚠️ **这是全量替换**：先把不在 `res_ids` 里的删掉再批量加。
所以 `jms_label_attach` 必须先读当前成员再合并写入 —— 否则第二次打标签会悄悄把第一次的清掉。

**2. `POST /accounts/gathered-accounts/` 永远 500**（同样的 org 问题）。
真正触发账号发现的是 UI 用的 adhoc 动作，而且**是 GET**：

```
GET /api/v1/accounts/gather-account-executions/adhoc/?asset_id=<asset_uuid>
→ 返回 HTML 执行报告
```

所以 `jms_gather_run` 走这条，跑完回读 `gathered-accounts` 对比 before/after，
告诉调用方「新增了哪些账号」，而不是丢一个 execution id 就完事。

**3. 改 gathered 账号状态不能 PATCH 单条。**
`PATCH /gathered-accounts/{id}/` 改 `status` **不会**真正创建资产账号。
生效的是批量端点 `PUT /accounts/gathered-accounts/status/`，body `{"ids": [...], "status": "1"}`，
它在服务端调 `sync_accounts()`。`jms_gather_apply` 走这条。

⚠️ **这个端点成功时返回 204 空 body。** 硬解 JSON 会得到
`unexpected end of JSON input`，把一次**成功的写**报成失败 ——
`Client.Do` 现在对空 body 直接放行，但所有写工具仍然**回读验证**，因为 204 什么都没证明。

## 集合端点有两个坑，都在 `listAll` 里处理了

**1. 五个端点返回裸数组，不是 `{count, results}`。**
```
/labels/labels/            裸数组
/labels/labeled-resources/ 裸数组
/rbac/org-roles/           裸数组
/rbac/content-types/       裸数组
```
直接解到 `map[string]any` 会报 `cannot unmarshal array into Go value of type map[string]interface {}`。
`list()` 两种形状都吃；但"按 name 取一个对象"的代码也得先 list 再筛。

**2. 只发 `page_size` 会停在服务端的 200 条上限。**
`/audits/operate-logs/` 实有 **335 条**，带 `page_size=500` 只回 **200 条**，
而且**不报错、不提示**。加上 `limit` 才切到真分页。

所以 `listAll` 按 `limit=1000` + `offset` 翻页，并用 id 去重防止端点忽略 offset 时死循环；
端点若拒绝 `limit`/`offset` 会退回只发 `page_size`。

labeled-resources 的过滤参数是 **`label__name` / `label__value`**，
不是 `name` / `label`（后者要 UUID，传名字报 `“xxx” is not a valid UUID`）。

## `/rbac/org-roles/{id}/permissions/tree/` 是平的，不是树

每行只有自己的 `title` 和父节点的 `pId`，**没有 `children` 数组**。
按 children 递归的实现会静默返回空列表 —— 这正是之前 `jms_role_permissions` 只报一个数字的原因。

现在按 `pId` 回溯拼路径，得到 `accounts.add_account` 这样的形式（共 352 个权限点）。
根节点叫 `$ROOT$`，拼接时剔掉。

## 写操作最要命的三个 v5 陷阱

这三个都是**静默失败**的：API 返回 200，看起来成功了，实际没生效。工具的描述里都写了。

**1. `AssetPermission.accounts` 为空 ≠ 全部账号，而是「一个账号都没有」。**
表现是登录时 TUI 报 `没有可用的授权账号或终端协议`。表达「全部」的唯一正确值是字面量 `["@ALL"]`。
`jms_permission_create` 因此有 `all_accounts` 参数，并且不传时会返回 warning。

**2. 资产没有 `protocols` 就永远连不上。** 清单里能看见、搜索得到，但连不上。
补协议用 `jms_asset_update`，并且 `protocols` 支持每个协议各自带端口：

```
protocols: [ssh, sftp]        # 默认 22
protocols: [ssh:2222, sftp:2222]   # HAProxy 占了 22
protocols: [mysql:50306]      # QNAP 上的 MySQL
```

REST 里 `protocols` 必须是 **dict 数组** `[{"name":"ssh","port":22}]`，传字符串数组 `["ssh"]` 会 400。

**3. 用户公钥不在 `User.public_key` 字段里。**
往那个字段 PATCH 会返回成功、`can_public_key_auth` 报 True，但 koko 登录仍然 `Permission denied`。
v5 实际存在独立的 `SSHKey` 表。`jms_user_sshkey_add` 走的是真正生效的那条路径。

⚠️ **`private_key` 字段同样是假的**：给账号 PATCH `private_key` 会返回 200 且 `secret_type` 也变了，
但私钥根本没写进去。**`secret`（密码）字段能正常写** ✓
想配 ssh_key 账号，只能在堡垒机上用 ORM 写。

⚠️ **ed25519 一律被拒**：堡垒机会安静地接受 ed25519 公钥，但 koko 不认，登录照样被拒。
所以工具直接挡掉并提示先转 RSA。

## 多对多字段：每个 endpoint 的格式都不一样

这是 v5 最容易让人白折腾的地方。同名字段在不同 endpoint 上要的形状不同，而**错误信息从不说它要哪种**：

| 字段 | `/perms/asset-permissions/` | `/acls/command-filter-acls/` |
|---|---|---|
| `users` | **普通数组** `["uuid"]` | **envelope** `{"type":"ids","ids":[...]}` |
| `assets` | 普通数组 | 两种都收 |
| `nodes` | 普通数组 | — |
| `accounts` | 普通数组 `["@ALL"]` | 普通数组 |
| `command_groups` | — | 普通数组 |

两种失败长这样，都不提正确答案：

```
"Invalid JSON many-to-many field, should be {'type': 'all'} or {'type': 'ids', ...}"
"“type” is not a valid UUID."
```

代码里因此拆成两个语义明确的函数 —— `idList()` 发普通数组、`m2mEnvelope()` 发 envelope ——
而不是一个万能 `m2m()`，因为**选择取决于 endpoint，不是字段名**。

## PATCH 关联字段是「替换」不是「追加」

对权限 PATCH `users` 或 `assets`，v5 会**整组替换**。直接发新增项，等于把其余成员全部踢掉 ——
而且接口返回 200，看起来完全成功。

所以 `jms_permission_grant` 先 GET 回现有成员、合并后再写，并在返回里说明做了合并。
工具命名保留 `grant` 正是因为它对外表现为追加，而底层是 replace-then-write。

⚠️ 另一个随之而来的坑：GET 回来的关联字段是 `[{id, name}, ...]` 对象数组，
**不是** UUID 字符串数组。只处理字符串的解析器会静默返回空列表，
于是"合并"退化成"替换" —— 症状和没做合并一模一样。

## 连通性怎么读

`jms_connectivity_check` 之所以要轮询到状态稳定，是因为 **UI 里的 connectivity 只是上次测试的缓存**。
2026-10-14 全量重测后，表面 43 ok 变成真实 42 ok —— 差的那几个是陈旧值。

结果还要会读：

- **`err` 不一定是故障。** 路由器 / 网关只有 80/443、根本没有 SSH 时，`err` 就是正确状态。
- **端口错会报 `auth_err` 而不是连接错。** gitlab-proxy 的 SSH 实际在 2222（22 被 HAProxy 占），
  配成 22 时报的是认证失败，极易误判成凭据问题。
- **`auth_err` 也可能只是某个账号的密钥不匹配**，而另一个账号是好的（Jenkins-CI 就是这样：
  `root` 的私钥对不上，但 `opsuser` + 密码能通）。先确认是哪个账号再动手。

## 两个必须知道的运行时陷阱

**1. JumpServer 不会自动提权。** `runas=root` + `runas_policy=privileged_first` **不会**切到 root——shell 模块
以**资产账号本身**的身份执行。需要 root 就自己在命令里写 `sudo -n`。

**2. 不传 `runas` 时必须用 `privileged_first`。** 若传了空 `runas` 却用 `runas_policy=skip`，那些唯一账号是非
特权的资产（例如只有 `opsuser`）会被静默跳过，作业报 `No available account`。本工具已按此处理。

## 并发行为（实测 2026-10-14）

服务器是**并发**的，慢操作不会阻塞其他请求：

- 6 个并发 `jms_status`：1.3 秒全部完成（各约 1.3s，并行而非排队）
- 一个 `jms_connectivity_check`（30s 预算）在跑时，并发进来的 `jms_platforms_list`
  **0.1 秒**就返回

所以可以放心并行发起只读查询。唯一会互相竞争的是写操作：两个并发的
`jms_permission_grant` 仍可能互相覆盖（合并是 read-then-write，不是原子操作）。

## 构建

```bash
cd ~/my_project/jumpserver-mgmt
go build -o jumpserver-mgmt .
go vet ./...
python3 e2e_test.py     # 端到端测试，会在真实资产上跑一条只读命令
```

> `go.mod` 里的 `replace` 指向 `$GOPATH/pkg/mod` 下已解压的 SDK 副本。当前沙箱禁止 `rename(2)`，而 Go 的模块
> 缓存强依赖它，所以在正常网络环境下可以直接 `go mod tidy` 去掉这行。

## 注册到 MiniMax Code

```bash
# 已完成：
# mcp create name=jumpserver command=/usr/local/bin/jumpserver-mgmt \
#   env: JUMPSERVER_URL=https://jumpserver.example.com, JUMPSERVER_TOKEN=<PrivateToken>
```
