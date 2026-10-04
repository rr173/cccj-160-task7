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
    -- 当前生效的敏感内容隔离规则版本行 id（NULL=未配置隔离，线上输入原样渲染）。
    -- 翻转只影响之后的新请求；每个请求固化当时的规则版本号，规则更新不改写历史。
    mask_active_version_id TEXT,
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
    -- 评估开始时固定的敏感内容隔离规则版本（与线上请求同一套版本化规则）；
    -- 0/''=评估时族未启用隔离。评估运行期间规则再发布不影响本次证据。
    mask_rule_version_no INTEGER NOT NULL DEFAULT 0,
    mask_rule_version_id TEXT NOT NULL DEFAULT '',
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
    -- 敏感内容隔离：请求固定的规则版本（版本号+行 id）与实际处置（''/redact/deny）。
    -- 规则随后再发布不改写在途/历史请求；0/''=隔离功能上线前的旧调用。
    mask_rule_version_no INTEGER NOT NULL DEFAULT 0,
    mask_rule_version_id TEXT NOT NULL DEFAULT '',
    mask_action      TEXT NOT NULL DEFAULT '',
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

-- ============================================================ 敏感内容隔离
-- 规则按模板族配置、版本化且不可变：每次"发布新版本"产生新行，族上唯一指针
-- families.mask_active_version 指向当前生效版本。线上请求在写锁事务内**固定**
-- 当时的规则版本（rule_version_no 固化进 requests），随后规则再发布也不能
-- 改写在途/历史请求——重放隔离永远按请求固化的版本号执行。
CREATE TABLE IF NOT EXISTS mask_rule_versions (
    rule_version_id  TEXT PRIMARY KEY,
    family_id        TEXT NOT NULL REFERENCES families(family_id),
    version_no       INTEGER NOT NULL,       -- 族内单调递增（1,2,3...）
    status           TEXT NOT NULL DEFAULT 'draft',  -- draft / active / retired
    action           TEXT NOT NULL DEFAULT 'redact', -- redact（替换）/ deny（拒绝）
    -- 规则集规范化 JSON：[{"rule_id","field","match","pattern","replacement"}]。
    -- field=* 表示任意变量字符串值；pattern 为字面量子串（演示用确定性识别）。
    rules_json       TEXT NOT NULL,
    rules_hash       TEXT NOT NULL,          -- rules_json+action 的规范化 SHA-256
    note             TEXT NOT NULL DEFAULT '',
    created_by       TEXT NOT NULL DEFAULT 'api',
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    activated_at     TEXT,
    retired_at       TEXT,
    UNIQUE(family_id, version_no)
);

-- 逐请求遮盖映射：只存**密文**（零依赖演示加密：sha256 派生密钥流 XOR +
-- base64；生产可替换为 KMS 信封加密，存储/接口不变）。明文绝不进数据库、
-- 审计与导出文件。一个 request_id 一行（UNIQUE）：重复推理返回同一遮盖
-- 结果时直接复用本行；还原凭据一次性消费，重复还原不再暴露原值。
CREATE TABLE IF NOT EXISTS mask_hits (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id       TEXT NOT NULL UNIQUE,
    family_id        TEXT NOT NULL,
    rule_version_id  TEXT NOT NULL,
    rule_version_no  INTEGER NOT NULL,       -- 请求固定的规则版本（不受后续发布影响）
    action           TEXT NOT NULL,          -- 该请求实际执行的动作 redact/deny
    token_count      INTEGER NOT NULL DEFAULT 0,
    -- 密文条目 JSON：[{"token":⟨遮盖标记⟩,"field","rule_id","ct":⟨base64 密文⟩}]。
    -- 同一请求内同一原值复用同一 token（确定性遮盖）；密文只在此列出现一次。
    entries_json     TEXT NOT NULL DEFAULT '[]',
    masked_digest    TEXT NOT NULL DEFAULT '', -- 遮盖后输入摘要（实际渲染/推理的那一版）
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 短期还原凭据：绑定单个请求、单次消费。凭据只以 SHA-256 哈希存储（数据库泄露
-- 也无法反推凭据）；消费以行守卫 UPDATE ... WHERE consumed_at IS NULL 保证
-- 并发/重复还原恰好一次成功。过期（半开区间：t >= expires_at 即失效）、未授权
-- 复核人、绑定别的请求都拒绝，且只写审计。
CREATE TABLE IF NOT EXISTS mask_reveal_tokens (
    token_id         TEXT PRIMARY KEY,
    request_id       TEXT NOT NULL,
    family_id        TEXT NOT NULL,
    reviewer         TEXT NOT NULL,          -- 获授权的复核人（凭据绑定身份）
    token_sha        TEXT NOT NULL UNIQUE,    -- 明文凭据只在创建响应中出现一次
    status           TEXT NOT NULL DEFAULT 'issued', -- issued / consumed / revoked
    ttl_seconds      INTEGER NOT NULL,
    expires_at       TEXT NOT NULL,          -- 半开区间：created ≤ t < expires 有效
    consumed_at      TEXT,
    consumed_by      TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_mask_versions_family ON mask_rule_versions(family_id);
CREATE INDEX IF NOT EXISTS idx_mask_hits_family ON mask_hits(family_id);
CREATE INDEX IF NOT EXISTS idx_mask_tokens_request ON mask_reveal_tokens(request_id);
CREATE INDEX IF NOT EXISTS idx_mask_tokens_sha ON mask_reveal_tokens(token_sha);

-- 获授权的原值复核人名册（按模板族）：只有名册内复核人能为该族请求申请/使用
-- 短期还原凭据。管理员维护，所有变更写审计；凭据本身仍绑定请求且单次消费。
CREATE TABLE IF NOT EXISTS mask_reviewers (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    family_id        TEXT NOT NULL REFERENCES families(family_id),
    reviewer         TEXT NOT NULL,
    note             TEXT NOT NULL DEFAULT '',
    active           INTEGER NOT NULL DEFAULT 1,
    created_by       TEXT NOT NULL DEFAULT 'admin',
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(family_id, reviewer)
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
    # 敏感内容隔离：请求固定的规则版本号/规则版本行 id 与处置结果。
    # 0/'' = 隔离上线前的旧调用（复查时按"无隔离"兼容）；deny 的请求输出为
    # 固定拒绝答复，不接触模型。规则再发布不改写本列，在途/历史请求永远按此复查。
    "mask_rule_version_no":
        "ALTER TABLE requests ADD COLUMN mask_rule_version_no INTEGER NOT NULL DEFAULT 0",
    "mask_rule_version_id":
        "ALTER TABLE requests ADD COLUMN mask_rule_version_id TEXT NOT NULL DEFAULT ''",
    "mask_action":
        "ALTER TABLE requests ADD COLUMN mask_action TEXT NOT NULL DEFAULT ''",
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

# 老库增量迁移：families 的隔离规则当前版本指针（NULL=未配置隔离）
_FAMILIES_NEW_COLUMNS = {
    "mask_active_version_id":
        "ALTER TABLE families ADD COLUMN mask_active_version_id TEXT",
}

# 老库增量迁移：eval_runs 的隔离规则固定列
_EVAL_RUNS_NEW_COLUMNS = {
    "mask_rule_version_no":
        "ALTER TABLE eval_runs ADD COLUMN mask_rule_version_no INTEGER NOT NULL DEFAULT 0",
    "mask_rule_version_id":
        "ALTER TABLE eval_runs ADD COLUMN mask_rule_version_id TEXT NOT NULL DEFAULT ''",
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
            ecols = {r["name"] for r in conn.execute("PRAGMA table_info(eval_runs)")}
            for col, ddl in _EVAL_RUNS_NEW_COLUMNS.items():
                if col not in ecols:
                    conn.execute(ddl)
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
