# PromptGov — 大模型提示模板版本治理与可重演服务

零第三方依赖（仅 Python 3.11 标准库：`http.server` + `sqlite3` + `hashlib`），
离线即可运行。内建确定性“假模型”，让评估与重演结果稳定可断言。

## 它解决什么

模板 = 系统指令 + 变量契约 + 工具权限 + 模型参数（+ 绑定模型标识）。

- 发布前必须在**固定测试集**上生成**评估证据**（逐用例渲染提示、输出、断言、摘要）。
- 线上请求固化**精确三元组**：模板版本、模型标识、输入摘要（外加模板内容哈希、输出摘要）。
- 重演按**原元数据**复核，能区分四种结论：
  `reproduced` / `input_changed` / `model_changed` / `template_changed`，
  三元组不变但输出不同则为 `output_drift`。
- 热更新 / 契约升级 / 评估迟到 / 并发回滚时，线上流量只看到**一个完整版本**；
  旧请求不受当前指针影响，永远可按原元数据复核。
- **工具权限扩大必须重新审批**（独立的 `tool_expansion` 审批，区别于 `release`）。
  专项授权支持**有效期与主动撤销**：审批人可设置生效/失效时刻（半开区间
  `[valid_from, valid_until)`，两界均空=永久授权，旧的永久审批持续兼容），
  并可用审批版本号（`expected_version`）做并发控制**提前撤销**。创建放量批次、
  候选首次（以及每一次）命中、放量完成转正、一步发布四处都按**业务请求发生时刻**
  在写锁事务内重新确认授权仍有效（未撤销、在有效期内）且**覆盖候选新增的全部
  工具**；尚未生效 / 恰好到期 / 已撤销 / 只覆盖部分工具，任一不满足都不会改变
  线上指针或放量状态。撤销后可重新审批产生新记录；已产生的调用按命中时保存的
  **授权快照**复查，不因随后到期或撤销改写历史结论。
- **分批放量**：已审核构件可建立带权重的放量批次，调用方携带 `routing_key`，
  系统用稳定散列决定走当前构件还是候选构件；批次代次不变时同键路由不漂移。
  批次支持升档 / 冻结 / 恢复 / 完成 / 撤销，全部以 `expected_generation` 做 CAS。
- **自动止损**：业务方为一次试投配置滚动观察窗口、最小样本量与失败占比上限，
  用 `request_id + feedback_id` 回报生产推理成败。只有"真实由该试投产生、命中
  候选构件、当前代次、窗口内"的回执入账（同一 feedback_id / request_id 仅一次）；
  重复、旧代次、基线/无关、迟到回执只写审计、不触发状态变化。窗口样本达门槛且
  失败占比严格越界时，**单事务**冻结批次、新流量回落基线并保存触发快照；
  并发越界只触发一次。人工恢复开启新代次并重置统计窗口，旧窗口与历史请求保留复核。

## 运行

```bash
python3 -m promptgov
# 可选：PROMPTGOV_PORT=8080 PROMPTGOV_DATA=./data PROMPTGOV_PASS_THRESHOLD=1.0
# 打开 http://127.0.0.1:8080
```

首启自动建表并灌入演示数据：模板族 `support-router`，线上 v1，候选
v1.1.0（已建 20% 权重放量批次，并配置止损：1 小时窗口 / 最小样本 10 / 失败上限 30%，
已入账 8 成功 2 失败，批次仍放量）、v1.2.0（扩大了 `refund.execute`，仅有一张
**已过期**的专项审批，建放量批次与发布都会被门禁拦下，可在审批页重新授权）、
v1.3.0（绑定弱模型 mini，评估 0.5 不达标）。

## 分批放量

- **批次**：`rollouts` 表记录候选构件、基线构件（建批时的线上版本）、权重
  （候选流量百分比 0~100）、状态（`ramping/frozen/completed/cancelled`）与
  **代次 generation**（每次状态/权重切换 +1）。一个族同一时间最多一个进行中批次。
- **路由**：`bucket = sha256(rollout_id | routing_key)[:8] % 100`，
  `bucket < weight` 走候选，否则走当前构件。桶号不含权重与代次，因此
  **代次不变时同键决定绝不漂移**；升档（权重单调增大）时已走候选的 key 不会掉回。
- **冻结**：期间所有新调用（含本应命中候选的 key）一律走当前构件；恢复后权重不变，
  同 key 决定与冻结前一致。**撤销**：线上指针从未移动，流量天然回归。
  **完成**：单事务内翻转线上指针 + 终结批次（要求指针仍等于批次基线）。
- **证据固化**：调用记录保存实际命中构件、推理配置快照、参数指纹、批次代次与
  routing_key；之后复查该调用（`/requests/{id}/replay`）不受权重/批次变化影响。
- **门禁**：仅"已审核构件"（passed 证据 + approved release 审批）可建批；
  候选新增可调用工具时，建批、候选命中、完成转正（与一步发布 promote）四个路径
  都按业务时刻复查 `tool_expansion` 专项授权——授权在该时刻必须**生效中**
  （半开区间，恰好到期即失效）、**未撤销**且覆盖候选的**全部**工具；首个请求
  命中前授权必须就位，命中时把所依据的授权固化为快照随请求保存。
- **并发**：所有状态切换以 `expected_generation` 做原子 CAS
  （`UPDATE ... WHERE generation=? AND status IN (...)`，rowcount≠1 即 409），
  任何失败或冲突都回滚，不改变已生效路由表；原有一步切换接口
  （promote/rollback）继续工作。

## 自动止损（生产推理效果回执）

- **配置**：`stoploss_configs` 每批次一份——`window_seconds`（滚动观察窗口，秒，
  按请求**产生时间**计）、`min_sample`（最小样本量）、`fail_ratio_limit`（失败占比
  上限，[0,1]，**严格越过**才触发；0 表示任何失败都越界）。窗口开启后（已有入账
  回执）门槛冻结，改配需先人工恢复开新窗，避免窗口中途移动球门。
- **回执入账**：`POST /api/rollouts/{rid}/feedback {feedback_id, request_id, outcome}`。
  全部判定在单个 `BEGIN IMMEDIATE` 事务内，写入天然串行化：
  1. 同一 `feedback_id` 全局唯一（主键，先于一切校验，重试安全）→ 重复返回 **409**；
  2. 请求必须存在（404）、且 `requests.rollout_id` 等于本批次，否则 `unrelated_request`；
  3. 同一 `request_id` 只能入账一次 → 重复返回 **409**；
  4. 请求实际命中版本必须是候选构件，否则 `hit_baseline`；
  5. 命中代次必须等于批次**当前代次**，否则 `stale_generation`（冻结/升档/止损前的
     旧请求只留审计）；
  6. 批次必须仍在 `ramping`；自动止损冻结后为 `stoploss_tripped`；
  7. 批次必须已配置止损（否则 `stoploss_not_configured`）；
  8. 请求产生时间必须在滚动窗口内，否则 `late_receipt`。
  
  2–8 为业务拒绝：HTTP 200 + `credited=false` + `reject_reason`，**只写 `audit_log`，
  绝不改变任何状态**；1/3 为幂等冲突 409。冻结期（含止损）产生的调用仍固化
  `rollout_id/rollout_generation`（命中基线），因此其回执能与"完全无关请求"区分。
- **滚动窗口统计**：仅统计 `request_created_at ∈ [t-window, t]` 的入账回执
  （`t` = 当前回执对应请求的产生时间，用 SQLite `datetime(...,'-N seconds')`）。
  迟到回执按真实产生时刻落入或落在窗口外；窗口前的旧回执不影响当前判定。
- **触发（单事务）**：窗口内 `total ≥ min_sample` 且 `fails/total > limit` 时，
  同一事务内：批次 `ramping → frozen`、`stoploss_tripped=1`、`generation+1`，
  窗口 `active → tripped`，写 `stoploss_triggers` 快照（样本/失败/占比、候选与基线
  构件、权重、代次、触发回执 id、路由处置）。路由层对 `frozen` 的既有语义即
  "所有新流量（含本应命中候选的 key）回落基线"，无需移动线上指针。
- **并发只触发一次**：写锁串行 + `UPDATE ... WHERE status='ramping'` 行守卫；
  后到事务看到 frozen，回执走 `stoploss_tripped` 审计路径，快照只有一个、代次只 +1。
- **人工恢复**：`POST /api/rollouts/{rid}/recover {expected_generation}` 仅对
  止损冻结生效（普通手动冻结走 resume）。单事务 CAS 回 `ramping`、清标记、
  代次 +1、关闭 `tripped` 窗并按当前配置开 `seq+1` 新窗（计数清零）；权重不变，
  恢复后同 key 路由与冻结前一致。旧窗口、触发快照、入账回执与 `requests`
  全部保留，调用详情页（replay）与止损历史页可持续复核。
- **页面**：`/rollouts/{rid}/stoploss` 止损配置、实时窗口统计、人工恢复、
  触发快照、窗口历史、被拒回执审计流、入账回执明细（链到调用详情）；
  `/requests/{id}/replay` 增加回执面板（归属/代次/配置状态、报告成功或失败、
  已入账回执展示）。

## 提示治理证据包（可迁移归档）

把**一次发布所依赖的全部证据**整理成可迁移的 ``.pgpack`` 归档：模板内容（版本/
固定测试集）、评估证据（逐用例）、审批、线上调用快照、放量批次与事件、止损
配置/窗口/触发快照/回执、相关审计。支持按**模板族、版本或调用范围**选择。

- **选择集合严格可见**：按模板族导出仍是该族在切点上的完整关联闭包；但按
  **单个版本**或**调用范围**导出时，包内证据**严格等于勾选集合 + 最小依赖**：
  - 版本范围 = 勾选版本 + 所属族头（不跟随活动指针）+ 该版本审批 + 该版本
    评估（run/逐用例）+ 评估实际使用的固定测试集及用例（共享测试集随评估整组）
    + **命中该版本**的调用及其历史重演 + 这些调用已入账的回执；
  - 调用范围 = 勾选调用 + 各调用实际命中版本（四要素）+ 族头 + 历史重演 +
    已入账回执。
  未勾选的同族修订版及其审批/评估/请求、放量批次、止损配置/窗口/触发快照
  **一律不入包**。落在范围外的结构边（族活动指针指向未勾选版本、调用/回执→
  未纳入批次、回执→风控窗口）不展开选择集合，而在清单逐项记入
  `external_refs`（范围边界外部引用）；验证侧以记录本身重算出边，区分
  "包内引用 / 已声明边界 / 断链"，既不夹带也不留悬空引用。窄包审计只收与
  包内对象直接相关的条目和针对所选调用的回执拒绝/重复审计，族级
  promote/rollback 审计（明细含兄弟版本 id）排除。
- **最小依赖可打开**：窄包导入后，包内版本评估页（版本/审批/run/逐用例/
  固定测试集）与调用复查页（调用/命中版本/重演/回执归属快照）完整可用；
  边界对象（批次/窗口/未勾选版本）不在包内，指向它们的页面入口按缺失降级，
  直接访问返回 404 而非断链错误。
- **稳定切点**：导出在单个只读快照事务（WAL 同一 read mark）内标定切点并做闭包
  收集；归档期间其他连接继续写入提交，本包也**只能看到切点前的完整已提交数据**，
  切点后的行（含写了一半的状态）对本事务不可见。闭包沿外键/固化指针 + 子实体边
  不动点展开，保证**无悬空引用、无半个状态**。
- **内容寻址**：归档 = 信封行 + 清单行 + 若干对象行，全部规范化 JSON + SHA-256。
  每个对象以其字节哈希寻址；清单逐项记录 `表/主键/对象哈希/大小/人工可核对摘要/
  出边引用/范围边界引用（external_refs）` 与各表计数；信封记录切点、来源实例、
  分片布局与清单/载荷哈希。
- **分片**：载荷（清单+对象）按固定字节边界切成数据分片（分片 1..N，可配置大小），
  支持大包裹**分片上传、断点续传、进程中断后继续**（会话持久化在
  `evidence_imports`，重新打开页面或换进程都能找回未完成会话）。
- **落库前独立验证**：提交时先组装再全量校验——信封/清单自哈希、分片重切哈希、
  载荷哈希、**逐对象内容寻址哈希与清单是否相符**、主键/计数一致、**全部出边引用
  可解析或以 external_refs 声明为范围边界（以记录重算出边，谎报/漏报/断链均拒绝）**、
  以及语义不变量（版本四要素重哈希、评估 passed/比率与逐用例一致、评估固定测试集
  随包、回执归属批次/窗口/调用、调用模型==版本绑定模型、活动指针闭合或声明边界、
  触发快照完整）。任意对象被改、对象/分片缺失、摘要不符都在落库前拒绝（HTTP 422），
  **失败路径不写入任何证据数据**。
- **原子切换**：提交在单 `BEGIN IMMEDIATE` 事务内插入归档；`pack_id` 主键保证
  **并发提交只有一方新建成功**，其余同摘要提交幂等返回原包。**同 pack_id 但清单
  哈希不同 = 冲突包**：初始化/提交时 409 拒绝，不留部分数据。同摘要再次执行
  （含上传完成后重复提交）始终返回原结果。
- **导入后只读**：归档原文整体存入 `evidence_packs.archive_blob`（可再次逐字节
  下载/再迁移），导入证据**绝不回写线上业务表**；经只读 `PackView` 打开：
  - 包内评估 `/evidence/packs/{pid}/versions/{vid}/eval`（证据逐用例 + 审批）；
  - 包内调用复查 `/evidence/packs/{pid}/requests/{rid}/replay`（三元组、固化
    推理配置、命中批次/代次、回执归属、归档时的历史重演记录）；
  - 包内放量/止损历史 `/evidence/packs/{pid}/rollouts/{rid}/stoploss`（配置、
    窗口、触发快照、入账回执、被拒回执审计流）。
- **溯源**：清单与信封保留来源实例 `source_instance_id` 与导出切点
  （`audit_max_id`/`db_time`）；每次导出/初始化/续传/拒绝/提交写
  `evidence_audit`（同时进总审计流），包详情页展示范围、依赖计数、校验状态、
  下载入口与完整导入审计。

## 页面

- `/` 总览：模板族/线上版本（含放量中标记）、模型注册表、审计流。
- `/families/{id}` 版本治理：建版本（四要素）、热发布/回滚、线上调用（可带 routing_key）、最近请求。
- `/families/{id}/rollout` **放量操作页**：建批次、升档/冻结/恢复/完成/撤销、批次历史、最近命中。
- `/rollouts/{id}/stoploss` **自动止损页**：止损配置、实时窗口统计、人工恢复、
  触发快照、统计窗口历史、被拒回执审计流、入账回执明细。
- `/versions/{id}/eval` **评估页面**：证据列表（含迟到标记）、逐用例渲染提示与输出、审批
  （含有效期设置、有效状态、剩余时间、提前撤销与历史记录）。
- `/approvals[?version=]` **扩权审批操作页**：全部 tool_expansion/release 审批的当前
  有效状态（永久/生效中/未生效/已到期/已撤销）、有效期与剩余时间、覆盖工具、
  撤销版本号与撤销操作、按版本过滤。
- `/requests/{id}/replay` **调用复查页**：原三元组与放量命中证据（命中构件/批次代次/参数指纹/
  推理配置快照）、精确重演、单轴反事实、漂移注入、历史重演记录与结论、生产效果回执面板。
- `/evidence` **证据包列表/导入页**：导出入口、包清单（范围/来源/切点/校验状态/下载）、
  浏览器分片上传（断点续传、中断后继续）、导入会话恢复。
- `/evidence/export` **导出页**：按模板族/版本/调用范围选择，可配置分片大小。
- `/evidence/packs/{id}` **包详情页**：范围、切点、来源实例、依赖计数、清单逐项摘要、
  校验状态、下载，版本/放量/止损/调用入口。

## 关键不变量与实现

| 需求 | 实现 |
|---|---|
| 版本不可变 | 四要素规范化后 SHA-256 存 `content_hash`；重复哈希拒绝创建；版本行只做受控状态迁移 |
| 模型即版本一部分 | `model_id` 写入 `model_params._bound_model` 并进哈希；证据模型须等于绑定模型 |
| 固定测试集 + 证据 | `testsets/testcases` 不可变；`eval_runs/eval_cases` 记录每用例渲染提示/输出/断言/摘要 |
| 评估迟到 | 证据永远落库；提交时版本已离开候选态则打 `late=1`；不改变版本历史 |
| 原子热更新/回滚 | `BEGIN IMMEDIATE` 单事务翻转 `families.active_version_id` 唯一指针 + 状态迁移 |
| 并发只一胜 | 发布/回滚带 `expected_active` 做 CAS，指针已变即 409（压测：30 竞争，13 成 17 冲突，0 半状态）|
| 旧请求可复核 | `requests` 行固化版本/模型/输入摘要/模板哈希/输出摘要；重演读版本快照而非当前指针 |
| 放量同键稳定 | 路由桶号只依赖 `(rollout_id, routing_key)` 的稳定散列，不含权重/代次 |
| 放量并发只一胜 | 批次切换带 `expected_generation` 做代次 CAS，冲突 409 且路由表不变 |
| 回执唯一入账 | `feedback_receipts.feedback_id` 主键（全局）+ `request_id UNIQUE`；重复 409，仅审计 |
| 回执归属 | 必须 `requests.rollout_id` 匹配且命中候选、命中代次==当前代次、窗口内；其余只留审计 |
| 越界只触发一次 | 回执/触发在同一 `BEGIN IMMEDIATE` 事务；`UPDATE...WHERE status='ramping'` 行守卫，并发只一胜 |
| 止损单事务 | 冻结批次+代次+1+窗口 tripped+`stoploss_triggers` 快照同事务；frozen 语义即流量回落基线 |
| 恢复开窗重置 | 人工恢复 CAS 回 ramping、代次+1、旧窗 tripped 保留、新窗 seq+1 计数清零；历史请求仍可重演 |
| 调用可复查 | `requests` 固化命中构件/推理配置/参数指纹/批次代次；复查不读当前批次状态 |
| 权限扩大重新审批 | 相对线上基线新增工具即要求覆盖该工具集的 `tool_expansion` approved；回滚只收窄故免新审批 |
| 授权有效期 | 半开区间 `[valid_from, valid_until)`，建批/命中/转正/一步发布按业务时刻复查；恰好到期即失效，两界 NULL=永久（旧审批兼容） |
| 授权主动撤销 | `POST .../revoke` 以 `expected_version` 做审批版本号 CAS；撤销即时封死四门禁，不动指针/批次 |
| 授权覆盖完整 | 门禁要求 granted_tools ⊇ 候选**全部**工具；部分覆盖视同缺失 |
| 授权快照复查 | 候选命中把授权（id/工具/有效期/撤销状态/复查时刻）固化进 `requests.authz_snapshot_json`；历史调用只按快照复查，事后到期/撤销不改写结论 |
| 契约升级分级 | 删变量/加必填/改类型=breaking；仅加可选变量=compatible；网关按声明字段投影输入 |
| 审计 | 所有生命周期动作写 `audit_log`（总览页可见） |

发布门禁（单事务内全部满足才翻指针）：
1. 存在 `passed` 评估证据，且证据模型 = 版本绑定模型、通过率 ≥ 门槛（默认 1.0）；
2. 存在 approved 的 `release` 审批；
3. 工具权限若扩大，存在覆盖全部工具的 approved `tool_expansion` 审批，且该审批在
   **业务时刻仍有效**（半开区间 `[valid_from, valid_until)`：尚未生效/恰好到期都
   不算有效）、未被主动撤销（撤销以审批版本号 CAS，见授权接口）；
4. CAS：当前线上指针 == 调用方提供的 `expected_active`。

### 工具扩权审批的有效期与主动撤销

- **有效期**：`POST /api/versions/{vid}/approve` 的 `tool_expansion` 可带
  `valid_from` / `valid_until`（`YYYY-MM-DD HH:MM:SS`，可只到分钟）：
  - 两者均空（缺省）= **永久授权**，旧审批行（有效期列 NULL）同样按永久兼容；
  - 半开区间：`valid_from ≤ t < valid_until` 为生效中；`t < valid_from` = `pending`
    （尚未生效）；`t ≥ valid_until` = `expired`（**恰好到期即失效**）；
  - `granted_tools` 可显式给出覆盖的工具子集（缺省=候选全部工具），**只覆盖部分
    工具的授权过不了任何门禁**。
- **有效状态/剩余时间**：`GET /api/approvals[?version=]` 与
  `GET /api/approvals/{id}` 返回动态状态 `permanent/approved/pending/expired/
  revoked/rejected`、`remaining_seconds`（剩余）/`wait_seconds`（距生效）与
  `revoke_version`；页面 `/approvals`、版本评估页提供同样视图与历史记录。
- **主动撤销**：`POST /api/approvals/{id}/revoke {expected_version, reason}` 以审批
  版本号做乐观锁 CAS（rowcount≠1 即 409）；撤销后建批/命中/转正/一步发布立即失效，
  但不移动任何指针，也不改变已固化快照的历史结论；需要恢复就重新审批（新记录）。
- **授权快照**：候选命中通过门禁时，把授权 id/结论/覆盖工具/有效期/撤销状态/复查
  时刻固化进 `requests.authz_snapshot_json`；调用复查页（含证据包包内复查）展示
  命中时状态与当前状态对照，`replay` 只按快照与三元组复核。

## JSON API（摘要）

```
GET  /api/models
GET  /api/families            POST /api/families
GET  /api/families/{fid}
GET  /api/families/{fid}/versions
POST /api/families/{fid}/versions            # 四要素 + model_id
POST /api/families/{fid}/invoke              # {inputs, routing_key?} 稳定散列分流
POST /api/families/{fid}/promote             # {version_id, expected_active}
POST /api/families/{fid}/rollback            # {target_version_id, expected_active}
POST /api/families/{fid}/rollouts            # {candidate_version_id, weight} 建批次
GET  /api/families/{fid}/rollouts
GET  /api/rollouts/{rid}
POST /api/rollouts/{rid}/ramp                # {weight, expected_generation} 升档
POST /api/rollouts/{rid}/freeze              # {expected_generation} 冻结
POST /api/rollouts/{rid}/resume              # {expected_generation} 恢复
POST /api/rollouts/{rid}/complete            # {expected_generation} 完成（候选转正）
POST /api/rollouts/{rid}/cancel              # {expected_generation} 撤销（流量回归）
POST /api/rollouts/{rid}/stoploss/config     # {window_seconds,min_sample,fail_ratio_limit}
GET  /api/rollouts/{rid}/stoploss/config
GET  /api/rollouts/{rid}/stoploss            # 配置/窗口/统计/快照/回执聚合（历史页数据）
POST /api/rollouts/{rid}/feedback            # {feedback_id,request_id,outcome} 效果回执
POST /api/rollouts/{rid}/recover             # {expected_generation} 人工恢复（新代次+重置窗口）
GET  /api/stoploss/triggers[?rollout=]       # 触发快照列表
GET  /api/stoploss/triggers/{tid}            # 单个触发快照
GET  /api/feedback[?rollout=&window=]        # 入账回执列表
GET  /api/feedback/{feedback_id}             # 单条入账回执
POST /api/versions/{vid}/eval/start
POST /api/eval-runs/{rid}/run
GET  /api/versions/{vid}/eval-runs
POST /api/versions/{vid}/approve             # {kind, decision, valid_from?, valid_until?, granted_tools?}
GET  /api/approvals[?version=]               # 审批列表（动态有效状态/剩余时间/版本号）
GET  /api/approvals/{aid}                    # 单张审批（含 state/remaining_seconds）
POST /api/approvals/{aid}/revoke             # {expected_version, reason?} 主动撤销（CAS）
GET  /api/eval-runs/{rid}
GET  /api/requests[?family=]
GET  /api/requests/{rid}
POST /api/requests/{rid}/replay              # override_version_id/override_model_id/override_inputs/inject_drift
GET  /api/requests/{rid}/replays
GET  /api/audit

# —— 证据包 ——
POST /api/evidence/exports                   # {scope_kind: family|version|requests, family_id|version_id|request_ids, shard_size_bytes?}
GET  /api/evidence/packs                     # 包列表（范围/来源/切点/计数）
GET  /api/evidence/packs/{pid}               # 包详情（含 cutpoint/counts/evidence_audit）
GET  /api/evidence/packs/{pid}/manifest      # 可复核清单（逐项对象哈希/摘要/引用）
POST /api/evidence/packs/{pid}/verify        # 对已落库归档再校验
GET  /api/evidence/packs/{pid}/download      # 逐字节 .pgpack
GET  /api/evidence/packs/{pid}/eval-runs[?version=]
GET  /api/evidence/packs/{pid}/requests[?family=]
GET  /api/evidence/packs/{pid}/rollouts
GET  /api/evidence/packs/{pid}/audit
POST /api/evidence/imports                   # body=信封行原文（分片0）；同摘要已导入则幂等返回原结果
GET  /api/evidence/imports                  # 导入会话（staging 可断点续传/中断恢复）
GET  /api/evidence/imports/{iid}            # {received, missing, status}
PUT  /api/evidence/imports/{iid}/shards/{n} # 数据分片原文（X-SHA256 可选预检；可乱序/重试）
POST /api/evidence/imports/{iid}/commit     # 组装+落库前全量校验+原子切换（422=被改/不符，409=缺片/冲突）
POST /api/evidence/imports/{iid}/abort
```

## 代码地图

- `db.py`：SQLite schema（含 `rollouts` 批次表、`requests` 放量证据列与
  `authz_snapshot_json` 授权快照列、`approvals` 的有效期/撤销版本列，
  `stoploss_configs/windows/triggers/feedback_receipts` 止损四表，以及证据包
  `evidence_packs/evidence_imports/evidence_audit` 归档表与 `app_meta` 实例元数据）、
  WAL、`write_tx()` 立即写锁事务、`snapshot_tx()` 稳定切点只读快照事务、审计、
  老库增量迁移。
- `core.py`：内容/输入/输出哈希、参数指纹、放量稳定散列分桶、变量契约校验与升级分级、
  权限集合比较、受限渲染入口。
- `jinja_compat.py`：零依赖沙箱模板（`{{ }}`、`{% if/for %}`、过滤器、比较/三元）。
- `llm.py`：模型注册表 + 确定性假模型（输出由 model/template/input 三轴决定）+ 断言器。
- `services.py`：版本生命周期、评估证据、审批、CAS 发布/回滚、分批放量
  （建批门禁、代次 CAS 状态机、稳定散列路由）、调用、重演归因，以及自动止损
  （配置、滚动窗口统计、回执入账判定、单事务触发冻结与快照、人工恢复开窗重置）。
- `app.py`：HTTP 路由（JSON API + 服务端渲染页面）。
- `evidence.py`：证据包——稳定快照切点上的关联闭包收集、清单/内容寻址对象/信封与
  确定性分片归档、落库前全量校验（哈希/引用闭包/语义不变量）、分片暂存与断点续传
  会话、原子提交与同摘要幂等/同标识异内容冲突拒绝、只读 `PackView`（导入证据的
  评估/调用复查/放量止损历史页面数据源）。
- `seed.py`：幂等演示数据。
- `tests/test_rollout.py`：放量机制端到端验证（同键稳定/按比例分流/并发升档/
  冻结/撤销/复查复现/专项授权/HTTP 冒烟），`python3 -m unittest discover -s tests`。
- `tests/test_approval_ttl.py`：扩权审批有效期与撤销端到端验证——永久授权（含旧库
  NULL 行）兼容、尚未生效/恰好到期在 建批/命中/转正/一步发布 四门禁被拦、
  授权只覆盖部分工具被拦、撤销版本号 CAS 与 8 路并发只一胜、撤销与放量完成竞争
  不出半状态、撤销后重新审批恢复、命中快照在事后撤销/到期后仍复现旧调用、
  JSON API 与页面冒烟。
- `tests/test_stoploss.py`：自动止损端到端验证——重复回执、阈值临界（等上限不触发/
  样本不足不触发/严格越界触发）、20 路并发越界只触发一次、迟到回执、旧代次只审计、
  无关/基线请求拒绝、人工恢复开窗重置与旧窗口复核、批次终结关窗、JSON API 与页面冒烟。
- `tests/test_evidence.py`：证据包端到端验证——并发写入下导出稳定切点（切点后数据
  不入包）、按族闭包无悬空引用、**按版本/调用范围严格不夹带未勾选修订版及其请求/
  灰度批次/风控记录（活动指针/批次/窗口以 external_refs 声明边界、自检通过、
  窄包导入空实例后评估页与复查页可打开、漏报边界引用即 422 拒绝）**、
  正常包完整导入空实例、篡改单个对象
  422 拒绝且无半数据、缺失分片 409 后续传成功、进程中断后续传、同摘要再导入幂等、
  同标识异内容 409、6 路并发提交恰好一方新建、坏分片当场拒绝、JSON API 与页面冒烟。
