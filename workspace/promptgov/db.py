"""SQLite 存储层。

并发模型：
- 读连接：默认延迟事务，多线程共享只读快照。
- 写连接：统一使用 ``BEGIN IMMEDIATE`` 立即拿写锁，发布/审批/回滚/评估提交等
  关键写操作天然串行化，配合 families.active_version_id 上的 CAS 条件，
  保证"线上流量只能看到一个完整版本"。
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from typing import Iterator

from . import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS families (
    family_id        TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    active_version_id TEXT,                 -- 当前线上唯一指针，NULL=未发布
    active_guard_ruleset_id TEXT,            -- 当前生效的敏感隔离规则版本，NULL=未配置
    updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS versions (
    version_id       TEXT PRIMARY KEY,
    family_id        TEXT NOT NULL REFERENCES families(family_id),
    semver           TEXT NOT NULL,         -- 1.4.0
    status           TEXT NOT NULL DEFAULT 'draft',
        -- draft / evaluating / evaluated / failed_eval / approved / active / superseded / abandoned
    system_instruction TEXT NOT NULL,
    variable_contract TEXT NOT NULL,        -- JSON: {name: {type, required}}
    tool_permissions TEXT NOT NULL,         -- JSON: [tool_id,...]
    model_params     TEXT NOT NULL,         -- JSON: {temperature, top_p, ...}
    content_hash     TEXT NOT NULL,        -- 四要素规范化哈希
    contract_change  TEXT NOT NULL DEFAULT 'none',
        -- none / compatible / breaking（相对上一版本）
    permission_expanded INTEGER NOT NULL DEFAULT 0, -- 相对当时线上版本
    pass_rate        REAL,
    created_by       TEXT NOT NULL DEFAULT 'cli',
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    promoted_at      TEXT,
    UNIQUE(family_id, semver)
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id      TEXT PRIMARY KEY,
    version_id       TEXT NOT NULL REFERENCES versions(version_id),
    kind             TEXT NOT NULL,         -- release / tool_expansion
    decision         TEXT NOT NULL,         -- approved / rejected
    approver         TEXT NOT NULL,
    reason           TEXT NOT NULL DEFAULT '',
    granted_tools    TEXT NOT NULL DEFAULT '[]', -- 审批时确认的权限快照
    -- 有效期（UTC，格式 'YYYY-MM-DD HH:MM:SS'，半开区间 [valid_from, valid_until)）：
    -- 两者均 NULL = 旧的永久授权（持续兼容）；valid_from 可单独设置（尚未生效）。
    valid_from       TEXT,
    valid_until      TEXT,
    revoke_version   INTEGER NOT NULL DEFAULT 1, -- 撤销乐观锁版本号（CAS）
    revoked_at       TEXT,
    revoked_by       TEXT NOT NULL DEFAULT '',
    revoke_reason    TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 固定测试集：一个模板族一份不可变集合（可用新集合版本，演示中每族一份）
CREATE TABLE IF NOT EXISTS testsets (
    testset_id       TEXT PRIMARY KEY,
    family_id        TEXT NOT NULL REFERENCES families(family_id),
    name             TEXT NOT NULL,
    immutable        INTEGER NOT NULL DEFAULT 1,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS testcases (
    case_id          TEXT PRIMARY KEY,
    testset_id       TEXT NOT NULL REFERENCES testsets(testset_id),
    seq              INTEGER NOT NULL,
    name             TEXT NOT NULL,
    inputs           TEXT NOT NULL,         -- JSON
    expect           TEXT NOT NULL          -- JSON: {assert: contains|equals|json_field,...}
);

-- 评估证据：一次评估运行一条头记录，逐用例明细在 eval_cases
CREATE TABLE IF NOT EXISTS eval_runs (
    run_id           TEXT PRIMARY KEY,
    version_id       TEXT NOT NULL REFERENCES versions(version_id),
    testset_id       TEXT NOT NULL REFERENCES testsets(testset_id),
    model_id         TEXT NOT NULL,         -- 证据绑定的模型标识
    status           TEXT NOT NULL DEFAULT 'running', -- running / passed / failed
    pass_rate        REAL,
    total            INTEGER NOT NULL DEFAULT 0,
    passed           INTEGER NOT NULL DEFAULT 0,
    late             INTEGER NOT NULL DEFAULT 0,  -- 提交时版本是否已离开 evaluated 候选态
    -- 评估开始时族上生效的敏感隔离规则版本（与线上请求同一规则来源；历史评估
    -- 永远按此版本复核）；NULL=评估时该族未配置隔离。
    guard_ruleset_id TEXT,
    guard_ruleset_version INTEGER,
    guard_ruleset_hash TEXT NOT NULL DEFAULT '',
    note             TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at      TEXT
);
CREATE TABLE IF NOT EXISTS eval_cases (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           TEXT NOT NULL REFERENCES eval_runs(run_id),
    case_id          TEXT NOT NULL,
    seq              INTEGER NOT NULL,
    name             TEXT NOT NULL,
    input_digest     TEXT NOT NULL,
    rendered_prompt  TEXT NOT NULL,
    output           TEXT NOT NULL,
    output_digest    TEXT NOT NULL,
    ok               INTEGER NOT NULL,
    detail           TEXT NOT NULL DEFAULT ''
);

-- 线上推理记录（绑定精确三元组 + 放量命中证据）
CREATE TABLE IF NOT EXISTS requests (
    request_id       TEXT PRIMARY KEY,
    family_id        TEXT NOT NULL,
    version_id       TEXT NOT NULL,           -- 实际命中的构件（可能是放量候选）
    model_id         TEXT NOT NULL,
    input_digest     TEXT NOT NULL,
    inputs_json      TEXT NOT NULL,
    rendered_prompt  TEXT NOT NULL,
    output_digest    TEXT NOT NULL,
    output           TEXT NOT NULL,
    template_hash_at_call TEXT NOT NULL,
    routing_key      TEXT,                    -- 调用方携带的路由键（无则未参与分流）
    rollout_id       TEXT,                    -- 命中时所属放量批次
    rollout_generation INTEGER,               -- 命中时的批次代次
    params_json      TEXT NOT NULL DEFAULT '',   -- 调用时推理配置快照
    params_fingerprint TEXT NOT NULL DEFAULT '', -- 推理配置指纹
    -- 首个命中候选且候选工具扩大时，当场复核通过所依据的授权快照（approval_id/
    -- 结论/覆盖工具/有效期/撤销状态/复查时刻）。之后复查只按本快照，不随后续
    -- 到期或撤销改写结论；NULL = 该命中未走权限扩大复核（基线/未扩大候选/旧调用）。
    authz_snapshot_json TEXT NOT NULL DEFAULT '',
    -- 敏感内容隔离：请求在写事务内固定的规则版本与遮盖映射；规则更新不改变
    -- 在途/历史请求的版本与遮盖结果（映射明细见 guard_request_masks）。
    guard_ruleset_id TEXT,
    guard_ruleset_version INTEGER,
    guard_ruleset_hash TEXT NOT NULL DEFAULT '',
    raw_input_digest TEXT NOT NULL DEFAULT '',  -- 隔离前原始输入摘要（重复请求判定）
    guard_status TEXT NOT NULL DEFAULT 'none',  -- none / clean / masked
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 分批放量批次：一个模板族同一时间最多一个进行中批次（ramping/frozen）
CREATE TABLE IF NOT EXISTS rollouts (
    rollout_id       TEXT PRIMARY KEY,
    family_id        TEXT NOT NULL REFERENCES families(family_id),
    candidate_version_id TEXT NOT NULL REFERENCES versions(version_id), -- 候选构件
    base_version_id  TEXT NOT NULL,          -- 建批时的线上构件（对照组）
    weight           INTEGER NOT NULL,       -- 候选分流权重 0~100（百分比）
    status           TEXT NOT NULL DEFAULT 'ramping',
        -- ramping / frozen / completed / cancelled
    generation       INTEGER NOT NULL DEFAULT 1,  -- 批次代次：每次状态/权重切换 +1
    stoploss_tripped INTEGER NOT NULL DEFAULT 0,  -- 1=曾被自动止损冻结（恢复后重置为0）
    created_by       TEXT NOT NULL DEFAULT 'api',
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 自动止损配置：业务方为一次流量试投设置观察窗口、最小样本量与失败占比上限。
-- 一份配置对应一个放量批次；统计窗口开启后（已有入账回执）配置冻结，修改需先
-- 人工恢复重置窗口，避免窗口中途移动门槛。
CREATE TABLE IF NOT EXISTS stoploss_configs (
    rollout_id       TEXT PRIMARY KEY REFERENCES rollouts(rollout_id),
    window_seconds   INTEGER NOT NULL,        -- 滚动观察窗口长度（秒，按请求产生时间）
    min_sample       INTEGER NOT NULL,        -- 最小样本量（窗口内入账回执数达到才评估）
    fail_ratio_limit REAL NOT NULL,           -- 失败占比上限 (0,1]，严格越过才止损
    created_by       TEXT NOT NULL DEFAULT 'api',
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 止损统计窗口：首条有效回执惰性开窗；人工恢复关闭旧窗并开启 seq+1 的新窗。
-- 旧窗口与其回执永久保留，供历史页面与请求复核回溯。
CREATE TABLE IF NOT EXISTS stoploss_windows (
    window_id        TEXT PRIMARY KEY,
    rollout_id       TEXT NOT NULL REFERENCES rollouts(rollout_id),
    seq              INTEGER NOT NULL,        -- 批次内窗口序号（恢复一次 +1）
    status           TEXT NOT NULL DEFAULT 'active',  -- active / tripped / closed
    window_seconds   INTEGER NOT NULL,        -- 开窗时的配置快照
    min_sample       INTEGER NOT NULL,
    fail_ratio_limit REAL NOT NULL,
    started_at       TEXT NOT NULL DEFAULT (datetime('now')),
    closed_at        TEXT,
    trigger_id       TEXT,
    UNIQUE(rollout_id, seq)
);

-- 止损触发快照：越界当时的样本/失败/占比与批次路由现场，单事务写入。
CREATE TABLE IF NOT EXISTS stoploss_triggers (
    trigger_id       TEXT PRIMARY KEY,
    window_id        TEXT NOT NULL REFERENCES stoploss_windows(window_id),
    rollout_id       TEXT NOT NULL,
    rollout_generation INTEGER NOT NULL,       -- 触发时（冻结前）批次代次
    candidate_version_id TEXT NOT NULL,
    candidate_semver TEXT NOT NULL DEFAULT '',
    base_version_id  TEXT NOT NULL,
    base_semver      TEXT NOT NULL DEFAULT '',
    weight           INTEGER NOT NULL,
    total_sample     INTEGER NOT NULL,
    fail_count       INTEGER NOT NULL,
    fail_ratio       REAL NOT NULL,
    trigger_feedback_id TEXT NOT NULL,        -- 压过阈值的那一条回执
    snapshot_json    TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 效果回执：只存"入账"回执（feedback_id 主键天然去重；request_id 唯一保证一条
-- 请求只能入账一次）。未入账回执（重复/旧代次/无关/迟到/未配置/批次非放量态）
-- 只写 audit_log，不触发任何状态变化。
CREATE TABLE IF NOT EXISTS feedback_receipts (
    feedback_id      TEXT PRIMARY KEY,
    rollout_id       TEXT NOT NULL,
    window_id        TEXT NOT NULL REFERENCES stoploss_windows(window_id),
    request_id       TEXT NOT NULL UNIQUE,
    outcome          TEXT NOT NULL,           -- success / failure
    request_created_at TEXT NOT NULL,         -- 复制自 requests.created_at，滚动窗口据此判定
    actor            TEXT NOT NULL DEFAULT 'api',
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 重演报告
CREATE TABLE IF NOT EXISTS replays (
    replay_id        TEXT PRIMARY KEY,
    request_id       TEXT NOT NULL REFERENCES requests(request_id),
    mode             TEXT NOT NULL,         -- exact / counterfactual
    changed_axis     TEXT NOT NULL DEFAULT 'none', -- input/model/template/none
    ov_version_id    TEXT,
    ov_model_id      TEXT,
    ov_input_digest  TEXT,
    verdict          TEXT NOT NULL,         -- reproduced / input_changed / model_changed / template_changed / output_drift
    same_template    INTEGER NOT NULL,
    same_model       INTEGER NOT NULL,
    same_input       INTEGER NOT NULL,
    same_output      INTEGER NOT NULL,
    replay_output_digest TEXT NOT NULL,
    replay_output    TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    actor            TEXT NOT NULL DEFAULT 'system',
    action           TEXT NOT NULL,
    entity           TEXT NOT NULL,
    entity_id        TEXT NOT NULL,
    detail           TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ============================================================ 证据包（迁移归档）
-- 一个证据包 = 同一数据库快照切点上，一次发布依赖的模板内容、评估证据、审批、
-- 线上调用快照、放量事件、止损事件与相关审计的完整闭包。归档原文（信封+清单+
-- 内容寻址对象）以字节形式整体保存：导出包可再次下载，导入包经只读 PackView
-- 打开证据页面，绝不把导入行写回线上业务表。
CREATE TABLE IF NOT EXISTS app_meta (
    key              TEXT PRIMARY KEY,
    value            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_packs (
    pack_id              TEXT PRIMARY KEY,
    status               TEXT NOT NULL,          -- exported（本实例导出）/ imported（外部导入）
    outer_manifest_sha   TEXT NOT NULL,          -- 信封（分片0）内容哈希
    manifest_sha         TEXT NOT NULL,          -- 清单内容哈希（包内容身份）
    archive_sha          TEXT NOT NULL,          -- 归档除信封外载荷哈希（清单+对象）
    archive_blob         BLOB NOT NULL,          -- 归档原始字节（逐字节可再下载/再迁移）
    scope_json           TEXT NOT NULL,          -- 选择范围 {kind, family_id/version_id/request_ids}
    cutpoint_json        TEXT NOT NULL,          -- 导出切点 {audit_max_id, db_time}
    source_instance_id   TEXT NOT NULL,          -- 来源实例标识
    exported_at          TEXT NOT NULL,          -- 清单内声明的导出时刻
    shard_count          INTEGER NOT NULL,
    object_count         INTEGER NOT NULL,
    byte_count           INTEGER NOT NULL,
    counts_json          TEXT NOT NULL,          -- 各表逐项计数（清单摘要）
    imported_at          TEXT,                   -- 导入包：提交时刻
    import_actor         TEXT,
    created_at           TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 分片上传会话：进程中断后仍可按 import_id 找回、续传、提交。
CREATE TABLE IF NOT EXISTS evidence_imports (
    import_id            TEXT PRIMARY KEY,
    pack_id              TEXT NOT NULL,
    outer_manifest_sha   TEXT NOT NULL,
    envelope_json        TEXT NOT NULL,          -- 初始化时提交的信封（分片长度/数量/哈希）
    status               TEXT NOT NULL,          -- staging / committed / failed / aborted
    received_shards_json TEXT NOT NULL DEFAULT '{}', -- {idx: {"sha":..., "blob_b64":...}}
    created_by           TEXT NOT NULL DEFAULT 'api',
    note                 TEXT NOT NULL DEFAULT '',
    result_pack_id       TEXT,
    created_at           TEXT NOT NULL DEFAULT (datetime('now')),
    committed_at         TEXT
);

-- ============================================================ 敏感内容隔离（Guard）
-- 规则按**模板族**配置；每次配置生成不可变的规则版本（ruleset），族上的唯一
-- 指针 families.active_guard_ruleset_id 决定新请求所用版本。线上请求在进入写
-- 事务时把规则版本号与内容哈希固化进 requests，之后规则更新（新版本+翻指针）
-- 不影响任何在途/历史请求——评估回放、证据包复核共用同一确定版本。
CREATE TABLE IF NOT EXISTS guard_rulesets (
    ruleset_id       TEXT PRIMARY KEY,
    family_id        TEXT NOT NULL REFERENCES families(family_id),
    version          INTEGER NOT NULL,         -- 族内单调递增的规则版本号
    rules_json       TEXT NOT NULL,            -- 规范化规则数组（不可变）
    content_hash     TEXT NOT NULL,            -- 规则集内容哈希（复核/证据校验重算）
    status           TEXT NOT NULL DEFAULT 'draft',  -- draft / active / superseded
    note             TEXT NOT NULL DEFAULT '',
    created_by       TEXT NOT NULL DEFAULT 'api',
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    activated_at     TEXT,
    UNIQUE(family_id, version)
);

-- 隔离复核人授权：哪些复核人可以为哪个模板族签发短期还原凭据（可撤销，CAS）。
CREATE TABLE IF NOT EXISTS guard_reviewer_grants (
    grant_id         TEXT PRIMARY KEY,
    family_id        TEXT NOT NULL REFERENCES families(family_id),
    reviewer         TEXT NOT NULL,
    granted_by       TEXT NOT NULL,
    revoke_version   INTEGER NOT NULL DEFAULT 1,
    revoked_at       TEXT,
    revoked_by       TEXT NOT NULL DEFAULT '',
    reason           TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 每个被隔离请求一张遮盖映射（不含明文，也不含密文；密文在 guard_secrets）。
-- 随请求固化规则版本/哈希、逐占位符的规则与字段位置、动作统计、原始输入摘要。
CREATE TABLE IF NOT EXISTS guard_request_masks (
    request_id       TEXT PRIMARY KEY REFERENCES requests(request_id),
    ruleset_id       TEXT NOT NULL,
    ruleset_version  INTEGER NOT NULL,
    ruleset_hash     TEXT NOT NULL,
    raw_input_digest TEXT NOT NULL,            -- 原始输入（隔离前）摘要：重复请求判定
    tokens_json      TEXT NOT NULL,            -- [{token,rule_id,kind,field,path}]
    actions_json     TEXT NOT NULL,            -- {masked: n, blocked: n, rules:[...]}
    output_actions_json TEXT NOT NULL DEFAULT '[]', -- 输出侧遮盖记录
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 原始明文值的唯一存放处：确定性加密的密文。不进证据包（导出/复核不携带还原
-- 能力），数据库其他任何列都不得出现被遮盖原值。
CREATE TABLE IF NOT EXISTS guard_secrets (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id       TEXT NOT NULL REFERENCES requests(request_id),
    token            TEXT NOT NULL,            -- 遮盖占位符（映射键，本身不含原值）
    ciphertext       BLOB NOT NULL,            -- ⟨iv|ct|tag⟩，主密钥不落库
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(request_id, token)
);

-- 还原凭据：绑定单个请求、绑定复核人、短期有效、单次消费。库里只存令牌哈希。
CREATE TABLE IF NOT EXISTS guard_credentials (
    credential_id    TEXT PRIMARY KEY,
    request_id       TEXT NOT NULL REFERENCES requests(request_id),
    family_id        TEXT NOT NULL,
    reviewer         TEXT NOT NULL,
    grant_id         TEXT NOT NULL,
    token_hash       TEXT NOT NULL UNIQUE,     -- 只存令牌 SHA-256；明文仅返回一次
    ttl_seconds      INTEGER NOT NULL,
    status           TEXT NOT NULL DEFAULT 'issued', -- issued / consumed / revoked
    issued_at        TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at       TEXT NOT NULL,
    consumed_at      TEXT
);

-- 被策略拒绝（阻断）的请求本身不产生 requests 行；单独留审计式记录用于重复
-- 请求给出确定结论与逐请求追溯（明细只含规则标识/字段/计数，绝无原值）。
CREATE TABLE IF NOT EXISTS guard_block_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id       TEXT NOT NULL,
    family_id        TEXT NOT NULL,
    ruleset_id       TEXT NOT NULL,
    ruleset_version  INTEGER NOT NULL,
    ruleset_hash     TEXT NOT NULL,
    raw_input_digest TEXT NOT NULL,
    rule_id          TEXT NOT NULL,
    rule_name        TEXT NOT NULL DEFAULT '',
    kind             TEXT NOT NULL,
    fields_json      TEXT NOT NULL DEFAULT '[]',
    match_count      INTEGER NOT NULL DEFAULT 1,
    actor            TEXT NOT NULL DEFAULT 'api',
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(request_id, raw_input_digest)
);

-- 还原审计：签发、成功还原、以及每一次失败（未授权/过期/重复/令牌错误）。
-- 明细绝不写入任何原值。
CREATE TABLE IF NOT EXISTS guard_reveals (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id       TEXT NOT NULL,
    credential_id    TEXT NOT NULL DEFAULT '',
    reviewer         TEXT NOT NULL DEFAULT '',
    result           TEXT NOT NULL,            -- issued / revealed / denied_unauthorized /
                                               -- denied_expired / denied_reused / denied_token
    detail           TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 评估回放隔离记录：eval_run 固定规则版本，逐用例固化遮盖/阻断统计
-- （规则更新不改变历史评估的复核结论；明细不含原值）。
CREATE TABLE IF NOT EXISTS guard_eval_fixtures (
    run_id           TEXT PRIMARY KEY REFERENCES eval_runs(run_id),
    ruleset_id       TEXT,                     -- 评估时族上无规则版本则为 NULL（不隔离）
    ruleset_version  INTEGER,
    ruleset_hash     TEXT NOT NULL DEFAULT '',
    cases_json       TEXT NOT NULL,            -- 逐用例 [{seq, masked, blocked, output_masked}]
    masked_total     INTEGER NOT NULL DEFAULT 0,
    blocked_total    INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 证据包审计：每个实例各自记录本包在本地的导出/导入/校验/冲突事件
-- （来源实例与导出切点保存在清单中，包内还固化了切点前的来源 audit_log）。
CREATE TABLE IF NOT EXISTS evidence_audit (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    pack_id          TEXT NOT NULL,
    actor            TEXT NOT NULL DEFAULT 'system',
    action           TEXT NOT NULL,
    detail           TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_versions_family ON versions(family_id);
CREATE INDEX IF NOT EXISTS idx_eval_version ON eval_runs(version_id);
CREATE INDEX IF NOT EXISTS idx_requests_version ON requests(version_id);
CREATE INDEX IF NOT EXISTS idx_replays_request ON replays(request_id);
CREATE INDEX IF NOT EXISTS idx_rollouts_family ON rollouts(family_id);
CREATE INDEX IF NOT EXISTS idx_windows_rollout ON stoploss_windows(rollout_id);
CREATE INDEX IF NOT EXISTS idx_receipts_window ON feedback_receipts(window_id);
CREATE INDEX IF NOT EXISTS idx_receipts_rollout ON feedback_receipts(rollout_id);
CREATE INDEX IF NOT EXISTS idx_triggers_rollout ON stoploss_triggers(rollout_id);
"""

# 老库增量迁移：requests 的放量证据列（新库已由 _SCHEMA 建全）
_REQUESTS_NEW_COLUMNS = {
    "routing_key": "ALTER TABLE requests ADD COLUMN routing_key TEXT",
    "rollout_id": "ALTER TABLE requests ADD COLUMN rollout_id TEXT",
    "rollout_generation": "ALTER TABLE requests ADD COLUMN rollout_generation INTEGER",
    "params_json": "ALTER TABLE requests ADD COLUMN params_json TEXT NOT NULL DEFAULT ''",
    "params_fingerprint":
        "ALTER TABLE requests ADD COLUMN params_fingerprint TEXT NOT NULL DEFAULT ''",
    "authz_snapshot_json":
        "ALTER TABLE requests ADD COLUMN authz_snapshot_json TEXT NOT NULL DEFAULT ''",
}

# 老库增量迁移：rollouts 的自动止损标记列
_ROLLOUTS_NEW_COLUMNS = {
    "stoploss_tripped": "ALTER TABLE rollouts ADD COLUMN stoploss_tripped INTEGER NOT NULL DEFAULT 0",
}

# 老库增量迁移：approvals 的有效期与主动撤销列（旧行 NULL/默认值 = 永久授权）
_APPROVALS_NEW_COLUMNS = {
    "valid_from": "ALTER TABLE approvals ADD COLUMN valid_from TEXT",
    "valid_until": "ALTER TABLE approvals ADD COLUMN valid_until TEXT",
    "revoke_version":
        "ALTER TABLE approvals ADD COLUMN revoke_version INTEGER NOT NULL DEFAULT 1",
    "revoked_at": "ALTER TABLE approvals ADD COLUMN revoked_at TEXT",
    "revoked_by": "ALTER TABLE approvals ADD COLUMN revoked_by TEXT NOT NULL DEFAULT ''",
    "revoke_reason": "ALTER TABLE approvals ADD COLUMN revoke_reason TEXT NOT NULL DEFAULT ''",
}

# 老库增量迁移：families 的敏感隔离规则指针
_FAMILIES_NEW_COLUMNS = {
    "active_guard_ruleset_id":
        "ALTER TABLE families ADD COLUMN active_guard_ruleset_id TEXT",
}

# 老库增量迁移：requests 的敏感隔离固化列（无规则版本的旧调用一律为默认值）
_REQUESTS_GUARD_COLUMNS = {
    "guard_ruleset_id":
        "ALTER TABLE requests ADD COLUMN guard_ruleset_id TEXT",
    "guard_ruleset_version":
        "ALTER TABLE requests ADD COLUMN guard_ruleset_version INTEGER",
    "guard_ruleset_hash":
        "ALTER TABLE requests ADD COLUMN guard_ruleset_hash TEXT NOT NULL DEFAULT ''",
    "raw_input_digest":
        "ALTER TABLE requests ADD COLUMN raw_input_digest TEXT NOT NULL DEFAULT ''",
    "guard_status":
        "ALTER TABLE requests ADD COLUMN guard_status TEXT NOT NULL DEFAULT 'none'",
    # none（未启用隔离）/ masked（发生遮盖）/ clean（扫描无命中）
}

# 老库增量迁移：eval_runs 固定所用隔离规则版本
_EVALRUNS_GUARD_COLUMNS = {
    "guard_ruleset_id":
        "ALTER TABLE eval_runs ADD COLUMN guard_ruleset_id TEXT",
    "guard_ruleset_version":
        "ALTER TABLE eval_runs ADD COLUMN guard_ruleset_version INTEGER",
    "guard_ruleset_hash":
        "ALTER TABLE eval_runs ADD COLUMN guard_ruleset_hash TEXT NOT NULL DEFAULT ''",
}

_lock = threading.Lock()
_tls = threading.local()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db() -> None:
    with _lock:
        conn = _connect()
        try:
            conn.executescript(_SCHEMA)
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(requests)")}
            for col, ddl in _REQUESTS_NEW_COLUMNS.items():
                if col not in cols:
                    conn.execute(ddl)
            rcols = {r["name"] for r in conn.execute("PRAGMA table_info(rollouts)")}
            for col, ddl in _ROLLOUTS_NEW_COLUMNS.items():
                if col not in rcols:
                    conn.execute(ddl)
            acols = {r["name"] for r in conn.execute("PRAGMA table_info(approvals)")}
            for col, ddl in _APPROVALS_NEW_COLUMNS.items():
                if col not in acols:
                    conn.execute(ddl)
            fcols = {r["name"] for r in conn.execute("PRAGMA table_info(families)")}
            for col, ddl in _FAMILIES_NEW_COLUMNS.items():
                if col not in fcols:
                    conn.execute(ddl)
            rgcols = {r["name"] for r in conn.execute("PRAGMA table_info(requests)")}
            for col, ddl in _REQUESTS_GUARD_COLUMNS.items():
                if col not in rgcols:
                    conn.execute(ddl)
            egcols = {r["name"] for r in conn.execute("PRAGMA table_info(eval_runs)")}
            for col, ddl in _EVALRUNS_GUARD_COLUMNS.items():
                if col not in egcols:
                    conn.execute(ddl)
            # 预置敏感隔离实例主密钥（app_meta）：避免首次请求在写事务内惰性建键
            # 导致嵌套 BEGIN；密钥值随机，只存库（也可由 PROMPTGOV_GUARD_KEY 覆盖）。
            import secrets as _sec
            conn.execute(
                "INSERT OR IGNORE INTO app_meta(key,value) VALUES ('guard_key',?)",
                (_sec.token_hex(32),))
            conn.commit()
        finally:
            conn.close()


def get_conn() -> sqlite3.Connection:
    """每线程一个连接（HTTP 服务器为多线程）。"""
    conn = getattr(_tls, "conn", None)
    if conn is None:
        conn = _connect()
        _tls.conn = conn
    return conn


@contextmanager
def write_tx() -> Iterator[sqlite3.Connection]:
    """立即取写锁的串行写事务。"""
    conn = get_conn()
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


@contextmanager
def snapshot_tx() -> Iterator[sqlite3.Connection]:
    """稳定切点的只读快照事务（独立连接）。

    普通 ``BEGIN``（DEFERRED）下首条 SELECT 即获取共享读锁；WAL 模式中同一事务
    内所有读取都锚定在同一个 read mark 上——期间其他连接继续提交的写入对本
    事务不可见。因此证据包导出的闭包收集与切点标定在同一事务内完成时，只能
    看到切点之前的完整已提交数据，不可能读到"半个状态"。
    """
    conn = _connect()
    try:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        try:
            yield conn
        finally:
            conn.rollback()
    finally:
        conn.close()


def audit(actor: str, action: str, entity: str, entity_id: str, detail: str = "") -> None:
    get_conn().execute(
        "INSERT INTO audit_log(actor,action,entity,entity_id,detail) VALUES (?,?,?,?,?)",
        (actor, action, entity, entity_id, detail),
    )
    get_conn().commit()
