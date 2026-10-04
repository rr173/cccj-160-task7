"""提示治理证据包：一次发布依赖物的可迁移归档。

一个证据包 = 在**同一数据库快照切点**上收集的：
模板内容（版本/测试集）、评估证据（eval_runs/eval_cases）、审批、
线上调用快照（requests）、放量事件（rollouts/replays，仅族范围）、止损事件
（stoploss_configs/windows/triggers/feedback_receipts，仅族范围/回执最小依赖）
与相关审计。

**范围即包内可见证据全集**：``family`` 范围是该族在切点上的完整关联闭包；
``version`` / ``requests`` 范围只含勾选对象与"打开所选评估、复查所选调用"的
最小依赖，绝不沿 族→全部版本 / 版本→全部调用 / 批次→止损记录 等边夹带未勾选
修订版及其请求、灰度与风控记录。落在选择集合之外的结构边（活动指针、调用/
回执→未纳入批次、回执→风控窗口）不展开集合，而逐项记入清单
``external_refs``（范围边界外部引用），验证侧以记录本身重算出边，区分
"包内引用 / 已声明边界 / 断链"。

归档格式（``.pgpack``，全部确定性、仅标准库）::

    {"kind":"envelope","sha256":<信封哈希>,"data":<base64 信封>}\n   # 分片 0
    {"kind":"manifest","sha256":<清单哈希>,"data":<base64 清单>}\n   # 载荷首行
    {"kind":"object","sha256":<对象哈希>,"data":<base64 记录>}\n     # 内容寻址对象…

- 信封（分片 0）：pack_id、范围、切点、来源实例、分片布局、清单/载荷哈希；
- 清单（载荷首行）：逐项对象（表/主键/对象 sha256/大小/摘要/出边引用）与计数；
- 对象：数据库行规范化 JSON，以其字节 SHA-256 内容寻址；
- 载荷（清单+对象）按固定字节边界切成数据分片（分片 1..N），支持大包裹
  分片上传、断点续传、进程中断后继续。

导入侧所有分片先进 *staging*；提交前执行全量校验（信封/清单/逐对象哈希/
引用闭包/语义不变量），校验失败或同标识异内容冲突都不会留下任何证据数据；
提交在单 ``BEGIN IMMEDIATE`` 事务内原子落库，并发提交只有一方成功。
导入证据只写入归档表，经 :class:`PackView` 提供只读证据页面，永不回写线上
业务表。
"""
from __future__ import annotations

import base64
import contextvars
import hashlib
import json
import re
import sqlite3
import uuid
from contextlib import contextmanager
from typing import Any, Callable, Iterator

from . import core
from . import guard
from . import db as dbmod
from .db import get_conn, snapshot_tx, write_tx

# 证据包导入目标库覆盖：默认操作线上库；迁移/测试时可绑定到另一个库文件，
# 模拟"导入空实例"而不污染本进程的线上连接（线程/协程内显式生效）。
_bound_conn: contextvars.ContextVar = contextvars.ContextVar("evidence_db", default=None)


def _conn() -> sqlite3.Connection:
    return _bound_conn.get() or get_conn()


@contextmanager
def _write() -> Iterator[sqlite3.Connection]:
    bound = _bound_conn.get()
    if bound is not None:
        bound.execute("BEGIN IMMEDIATE")
        try:
            yield bound
            bound.commit()
        except Exception:
            bound.rollback()
            raise
    else:
        with write_tx() as c:
            yield c


@contextmanager
def bind_db(path: str, init_schema: bool = True) -> Iterator[sqlite3.Connection]:
    """把证据包读写绑定到另一个已初始化 schema 的库文件（导入空实例模拟）。"""
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    if init_schema:
        conn.executescript(dbmod._SCHEMA)
        conn.commit()
    token = _bound_conn.set(conn)
    try:
        yield conn
    finally:
        _bound_conn.reset(token)
        conn.close()

# 复用服务层异常分类（app 层据此映射 400/404/409）
from .services import Conflict, DomainError, NotFound  # noqa: F401

FORMAT = "promptgov-evidence-pack/1"
DEFAULT_SHARD_BYTES = 1024 * 1024  # 数据分片默认 1 MiB

# 证据闭包覆盖的全部表（计数与展示顺序）。
# 敏感隔离只携带**复核必需且不含原值/密文**的三类：不可变规则版本、每请求遮盖
# 映射、评估回放记录。guard_secrets（密文）/guard_credentials（令牌哈希）/
# guard_reviewer_grants/guard_reveals/guard_block_log 绝不入包——导入侧不获得
# 任何还原能力，也不夹带授权/凭据。
TABLES = (
    "families", "versions", "approvals", "testsets", "testcases",
    "eval_runs", "eval_cases", "requests", "rollouts",
    "stoploss_configs", "stoploss_windows", "stoploss_triggers",
    "feedback_receipts", "replays",
    "guard_rulesets", "guard_request_masks", "guard_eval_fixtures",
    "audit_log",
)
# 各表主键列
PK = {
    "families": "family_id", "versions": "version_id", "approvals": "approval_id",
    "testsets": "testset_id", "testcases": "case_id", "eval_runs": "run_id",
    "eval_cases": "id", "requests": "request_id", "rollouts": "rollout_id",
    "stoploss_configs": "rollout_id", "stoploss_windows": "window_id",
    "stoploss_triggers": "trigger_id", "feedback_receipts": "feedback_id",
    "replays": "replay_id", "guard_rulesets": "ruleset_id",
    "guard_request_masks": "request_id", "guard_eval_fixtures": "run_id",
    "audit_log": "id",
}
# 对象出边引用：表 -> (字段, 指向表)，空值/空字符串不产生引用。
# 这些是**结构边**：导出时是否把目标纳入包由范围闭包决定（见 _collect_scope）。
# 窄范围（version/requests）下，落在选择集合之外的结构边不展开集合，而是记入
# 清单的 external_refs（边界外部引用），验证侧据此区分"断链"与"范围边界"。
REF_FIELDS: dict[str, list[tuple[str, str]]] = {
    "families": [("active_version_id", "versions")],
    "versions": [("family_id", "families")],
    "approvals": [("version_id", "versions")],
    "testsets": [("family_id", "families")],
    "testcases": [("testset_id", "testsets")],
    "eval_runs": [("version_id", "versions"), ("testset_id", "testsets")],
    "eval_cases": [("run_id", "eval_runs"), ("case_id", "testcases")],
    "requests": [("version_id", "versions"), ("rollout_id", "rollouts")],
    "rollouts": [("family_id", "families"), ("candidate_version_id", "versions"),
                 ("base_version_id", "versions")],
    "stoploss_configs": [("rollout_id", "rollouts")],
    "stoploss_windows": [("rollout_id", "rollouts"), ("trigger_id", "stoploss_triggers")],
    "stoploss_triggers": [("window_id", "stoploss_windows"), ("rollout_id", "rollouts"),
                          ("candidate_version_id", "versions"),
                          ("base_version_id", "versions")],
    "feedback_receipts": [("rollout_id", "rollouts"), ("window_id", "stoploss_windows"),
                          ("request_id", "requests")],
    "replays": [("request_id", "requests")],
    # 敏感隔离（不含原值/密文）：规则版本属于族；遮盖映射属于请求、指向规则版本；
    # 评估回放记录属于评估运行、指向固定的规则版本（可能为 NULL）。
    "guard_rulesets": [("family_id", "families")],
    "guard_request_masks": [("request_id", "requests"), ("ruleset_id", "guard_rulesets")],
    "guard_eval_fixtures": [("run_id", "eval_runs"), ("ruleset_id", "guard_rulesets")],
    "audit_log": [],
}


class VerificationRejected(DomainError):
    """提交前校验未通过（HTTP 422）：包不会落库。"""


# audit_log.entity 取值 -> 闭包表名（审计动作的实体命名与表名单复数不同）
AUDIT_ENTITY_TABLE = {
    "family": "families", "version": "versions", "eval_run": "eval_runs",
    "testset": "testsets", "request": "requests", "replay": "replays",
    "rollout": "rollouts", "stoploss_window": "stoploss_windows",
    "stoploss_trigger": "stoploss_triggers", "approval": "approvals",
    # 隔离相关审计：实体在包内（request/规则版本）时由下方专门选择，避免把
    # 凭据/还原失败等不含包内结构边的审计整体夹带；这里不映射到表。
    "guard_ruleset": None, "guard_grant": None,
    "evidence_pack": None,
}


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _canonical(obj: Any) -> bytes:
    return core.canonical_json(obj).encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _line(kind: str, sha: str, payload: bytes) -> bytes:
    return _canonical({"kind": kind, "sha256": sha, "data": _b64(payload)}) + b"\n"


def _iter_lines(data: bytes) -> Iterator[bytes]:
    for line in data.split(b"\n"):
        if line:
            yield line


# ================================================================ 实例标识

def instance_id() -> str:
    """本实例的稳定标识（首次访问时生成并持久化，导入审计据此区分来源）。"""
    conn = _conn()
    row = conn.execute("SELECT value FROM app_meta WHERE key='instance_id'").fetchone()
    if row:
        return row["value"]
    iid = f"pginst-{uuid.uuid4().hex}"
    with _write() as c:
        c.execute("INSERT OR IGNORE INTO app_meta(key,value) VALUES ('instance_id',?)", (iid,))
    return _conn().execute(
        "SELECT value FROM app_meta WHERE key='instance_id'").fetchone()["value"]


# ================================================================ 导出：闭包收集

def _refs_of(table: str, row: dict) -> list[dict]:
    out = []
    for col, target in REF_FIELDS[table]:
        val = row.get(col)
        if val is not None and val != "":
            out.append({"table": target, "id": str(val)})
    return out


def _summary(table: str, row: dict, semvers: dict[str, str]) -> str:
    rid = str(row[PK[table]])
    if table == "families":
        active = row.get("active_version_id")
        tail = f" -> {semvers.get(active, active)}" if active else "（未发布）"
        return f"{row['name']} [{rid}]{tail}"
    if table == "versions":
        model = json.loads(row["model_params"]).get("_bound_model", "?")
        return f"{row['semver']} [{row['status']}] model={model} hash={row['content_hash'][:10]}"
    if table == "approvals":
        return f"{row['kind']}/{row['decision']} by {row['approver']}"
    if table == "testsets":
        return row["name"]
    if table == "testcases":
        return f"#{row['seq']} {row['name']}"
    if table == "eval_runs":
        return f"{row['model_id']} {row['status']} {row['passed']}/{row['total']}" \
               + ("（迟到证据）" if row.get("late") else "")
    if table == "eval_cases":
        return f"#{row['seq']} {row['name']} {'OK' if row['ok'] else 'FAIL'}"
    if table == "requests":
        return f"hit={semvers.get(row['version_id'], row['version_id'][:10])} " \
               f"in={row['input_digest'][:10]} out={row['output_digest'][:10]}" \
               + (f" rollout={row['rollout_id'][:12]}@gen{row['rollout_generation']}"
                  if row.get("rollout_id") else "")
    if table == "rollouts":
        return f"{semvers.get(row['candidate_version_id'], '?')} {row['status']} " \
               f"weight={row['weight']} gen={row['generation']}" \
               + ("（止损冻结）" if row.get("stoploss_tripped") else "")
    if table == "stoploss_configs":
        return f"window={row['window_seconds']}s min={row['min_sample']} " \
               f"limit={row['fail_ratio_limit']}"
    if table == "stoploss_windows":
        return f"seq={row['seq']} {row['status']}"
    if table == "stoploss_triggers":
        return f"{row['fail_count']}/{row['total_sample']}={row['fail_ratio']:.2f} " \
               f"candidate={semvers.get(row['candidate_version_id'], '?')}"
    if table == "feedback_receipts":
        return f"{rid} {row['outcome']} req={row['request_id'][:12]}"
    if table == "replays":
        return f"{row['mode']} {row['verdict']}"
    if table == "guard_rulesets":
        n_rules = len(json.loads(row["rules_json"]))
        return f"v{row['version']} [{row['status']}] {n_rules} rules hash={row['content_hash'][:10]}"
    if table == "guard_request_masks":
        toks = json.loads(row["tokens_json"])
        return (f"ruleset=v{row['ruleset_version']} tokens={len(toks)} "
                f"raw={row['raw_input_digest'][:10]}")
    if table == "guard_eval_fixtures":
        return (f"ruleset=v{row['ruleset_version'] if row['ruleset_version'] is not None else '-'} "
                f"masked={row['masked_total']} blocked={row['blocked_total']}")
    if table == "audit_log":
        return f"{row['action']} {row['entity']}/{row['entity_id']}"
    return rid


def _ids(clause_result) -> set[str]:
    return {str(r[0]) for r in clause_result}


# 子实体（反向）边：**仅 family 全量范围**使用——族/版本/批次等父行被纳入时
# 必须一并纳入的从属行。窄范围（version/requests）不得使用这些全族边，否则会
# 经 族→全部版本 / 版本→全部调用 / 批次→全部止损记录 把未勾选修订版及其请求、
# 灰度与风控记录夹带进来；窄范围走 _collect_scope 内显式的最小依赖展开。
CHILDREN: dict[str, list[tuple[str, str]]] = {
    "families": [("versions", "family_id"), ("testsets", "family_id"),
                 ("requests", "family_id"), ("rollouts", "family_id"),
                 ("guard_rulesets", "family_id")],
    "testsets": [("testcases", "testset_id")],
    "versions": [("approvals", "version_id"), ("eval_runs", "version_id"),
                 ("requests", "version_id")],
    "eval_runs": [("eval_cases", "run_id"), ("guard_eval_fixtures", "run_id")],
    "requests": [("replays", "request_id"), ("guard_request_masks", "request_id")],
    "rollouts": [("stoploss_configs", "rollout_id"),
                 ("stoploss_windows", "rollout_id"),
                 ("stoploss_triggers", "rollout_id"),
                 ("feedback_receipts", "rollout_id")],
    "stoploss_windows": [("feedback_receipts", "window_id")],
    "stoploss_triggers": [],
}


def _fetch_ids(c, table: str, col: str, ids: set[str]) -> set[str]:
    """取 col IN (ids) 的目标表主键集合（分块，空集安全）。"""
    out: set[str] = set()
    vals = list(ids)
    for i in range(0, len(vals), 400):
        chunk = vals[i:i + 400]
        if not chunk:
            continue
        ph = ",".join("?" * len(chunk))
        out |= _ids(c.execute(
            f"SELECT {PK[table]} FROM {table} WHERE {col} IN ({ph})", chunk).fetchall())
    return out


def _collect_family_closure(c, chosen: dict[str, set[str]]) -> None:
    """family 范围：沿出边（REF_FIELDS）+ 全量子实体边（CHILDREN）不动点展开，
    得到切点上一个完整的关联闭包。"""

    def add_children(parents: dict[str, set[str]]) -> None:
        for table, ids in parents.items():
            for child_t, col in CHILDREN.get(table, []):
                chosen[child_t] |= _fetch_ids(c, child_t, col, ids)

    for _ in range(16):
        before = sum(len(s) for s in chosen.values())
        add_children({t: s for t, s in chosen.items() if t in CHILDREN})
        for table, ids in list(chosen.items()):
            if not ids:
                continue
            vals = list(ids)
            for i in range(0, len(vals), 400):
                chunk = vals[i:i + 400]
                ph = ",".join("?" * len(chunk))
                for row in c.execute(
                        f"SELECT * FROM {table} WHERE {PK[table]} IN ({ph})",
                        chunk).fetchall():
                    for ref in _refs_of(table, dict(row)):
                        chosen[ref["table"]].add(ref["id"])
        if sum(len(s) for s in chosen.values()) == before:
            break

    # 止损触发快照会反向引用窗口，窗口 trigger_id 也可能指向触发：补一条显式边
    for t in list(chosen["stoploss_triggers"]):
        row = c.execute("SELECT window_id FROM stoploss_triggers WHERE trigger_id=?",
                        (t,)).fetchone()
        if row:
            chosen["stoploss_windows"].add(str(row["window_id"]))


def _audit_token(text: str, key: str) -> str | None:
    """从审计明细中取 ``key=<值>`` 的首个空白分隔 token（如 request=req_xxx）。"""
    m = re.search(rf"(?:^|\s){re.escape(key)}=(\S+)", text or "")
    return m.group(1) if m else None


def _select_audits(c, chosen: dict[str, set[str]], *, family_scope: bool,
                   rollout_ids: set[str]) -> None:
    """把与选择集合相关的审计行加入包。**只收与包内对象直接相关的审计**，
    审计本身绝不扩展选择集合（不沿明细文本里出现的任何 id 再拉对象）。

    - 实体即包内对象（version/eval_run/testset/request/replay/rollout/
      stoploss_window/stoploss_trigger）：纳入；
    - 回执审计（entity=feedback）：入账回执本身在包内，或被拒/重复尝试针对的
      调用在包内（family 范围保留旧规则：明细提到包内批次也纳入）；
    - family 范围：族实体审计（promote/rollback/create）随族纳入；
    - 窄范围：族实体审计一律排除——promote/rollback 明细含未勾选兄弟版本 id，
      纳入即等于夹带未勾选修订版的信息。
    """
    universe = {(t, i) for t, s in chosen.items() if t != "audit_log" for i in s}
    feedback_ids = chosen["feedback_receipts"]
    request_ids = chosen["requests"]
    ruleset_ids = chosen["guard_rulesets"]
    for a in c.execute("SELECT * FROM audit_log ORDER BY id").fetchall():
        a = dict(a)
        tbl = AUDIT_ENTITY_TABLE.get(a["entity"])
        eid = str(a["entity_id"])
        if tbl and (tbl, eid) in universe:
            if a["entity"] == "family" and not family_scope:
                continue
            chosen["audit_log"].add(str(a["id"]))
        elif a["entity"] == "feedback":
            if eid in feedback_ids:
                chosen["audit_log"].add(str(a["id"]))
            elif _audit_token(a["detail"], "request") in request_ids:
                chosen["audit_log"].add(str(a["id"]))
            elif family_scope and any(f"rollout={rid}" in a["detail"]
                                      for rid in rollout_ids):
                chosen["audit_log"].add(str(a["id"]))
        elif a["entity"] == "request":
            # 隔离阻断/重复阻断等以 request 为实体、且针对包内调用的审计
            # （明细绝不含原值，可安全入包）。
            if a["action"].startswith("guard.") and eid in request_ids:
                chosen["audit_log"].add(str(a["id"]))
        elif a["entity"] == "guard_ruleset" and family_scope and eid in ruleset_ids:
            # 规则版本变更审计只在族全量包携带（窄包仅做哈希复核）。
            chosen["audit_log"].add(str(a["id"]))


def _collect_version_scope(c, chosen: dict[str, set[str]], vid: str) -> None:
    """version 范围的**最小**依赖闭包（不经过族/批次全量子实体边）：

    勾选版本自身 → 所属族头（展示命名；不跟随活动指针）→ 该版本的审批与
    评估证据（run/cases）→ 评估实际使用的固定测试集及其用例（共享测试集按
    run.testset_id 整组纳入，用例不可拆分）→ **命中该版本**的调用及其历史
    重演 → 这些调用已入账的效果回执（回执的批次/窗口是边界外部引用）。

    不纳入：同族其他修订版及其审批/评估/调用、任何放量批次、未命中本版本的
    调用、止损配置/窗口/触发快照。
    """
    row = c.execute("SELECT family_id FROM versions WHERE version_id=?",
                    (vid,)).fetchone()
    family_ids = {str(row["family_id"])}
    chosen["families"] |= family_ids
    chosen["approvals"] |= _fetch_ids(c, "approvals", "version_id", {vid})
    run_ids = _fetch_ids(c, "eval_runs", "version_id", {vid})
    chosen["eval_runs"] |= run_ids
    # 评估证据依赖的固定测试集（共享测试集：随评估整组带其用例）
    testset_ids: set[str] = set()
    vals = list(run_ids)
    for i in range(0, len(vals), 400):
        chunk = vals[i:i + 400]
        ph = ",".join("?" * len(chunk))
        testset_ids |= _ids(c.execute(
            f"SELECT DISTINCT testset_id AS x FROM eval_runs WHERE run_id IN ({ph})",
            chunk).fetchall())
    chosen["testsets"] |= testset_ids
    for ts in testset_ids:
        chosen["testcases"] |= _fetch_ids(c, "testcases", "testset_id", {ts})
    for run in run_ids:
        chosen["eval_cases"] |= _fetch_ids(c, "eval_cases", "run_id", {run})
        chosen["guard_eval_fixtures"] |= _fetch_ids(
            c, "guard_eval_fixtures", "run_id", {run})
    # 评估固定的隔离规则版本（内容哈希复核必需；不含原值/密文）
    for fx_run in list(chosen["guard_eval_fixtures"]):
        row = c.execute("SELECT ruleset_id FROM guard_eval_fixtures WHERE run_id=?",
                        (fx_run,)).fetchone()
        if row and row["ruleset_id"]:
            chosen["guard_rulesets"].add(str(row["ruleset_id"]))
    # 仅命中**所选版本**的线上调用（不是族内全部调用）
    req_ids = _fetch_ids(c, "requests", "version_id", {vid})
    chosen["requests"] |= req_ids
    for rid in req_ids:
        chosen["replays"] |= _fetch_ids(c, "replays", "request_id", {rid})
        chosen["guard_request_masks"] |= _fetch_ids(
            c, "guard_request_masks", "request_id", {rid})
    for mid in list(chosen["guard_request_masks"]):
        row = c.execute("SELECT ruleset_id FROM guard_request_masks WHERE request_id=?",
                        (mid,)).fetchone()
        if row:
            chosen["guard_rulesets"].add(str(row["ruleset_id"]))
    # 仅这些调用已入账的回执（其 rollout/window 出边不展开，作为边界引用）
    chosen["feedback_receipts"] |= _fetch_ids(
        c, "feedback_receipts", "request_id", req_ids)


def _collect_requests_scope(c, chosen: dict[str, set[str]], rids: list[str]) -> None:
    """requests 范围的**最小**依赖闭包：所选调用 → 其历史重演 → 各调用实际
    命中构件（版本四要素，复查三元组/绑定模型必需）→ 版本所属族头（命名）→
    已入账回执。命中版本的审批/评估、放量批次、止损配置/窗口/触发均不纳入。"""
    req_ids = set(rids)
    chosen["requests"] |= req_ids
    for rid in req_ids:
        chosen["replays"] |= _fetch_ids(c, "replays", "request_id", {rid})
        chosen["guard_request_masks"] |= _fetch_ids(
            c, "guard_request_masks", "request_id", {rid})
    for mid in list(chosen["guard_request_masks"]):
        row = c.execute("SELECT ruleset_id FROM guard_request_masks WHERE request_id=?",
                        (mid,)).fetchone()
        if row:
            chosen["guard_rulesets"].add(str(row["ruleset_id"]))
    chosen["feedback_receipts"] |= _fetch_ids(
        c, "feedback_receipts", "request_id", req_ids)
    # 命中版本（出边）与族头：只取标识行，不展开版本的审批/评估/其它调用
    vals = list(req_ids)
    version_ids: set[str] = set()
    family_ids: set[str] = set()
    for i in range(0, len(vals), 400):
        chunk = vals[i:i + 400]
        ph = ",".join("?" * len(chunk))
        for row in c.execute(
                f"SELECT version_id, family_id FROM requests WHERE request_id IN ({ph})",
                chunk).fetchall():
            version_ids.add(str(row["version_id"]))
            family_ids.add(str(row["family_id"]))
    chosen["versions"] |= version_ids
    chosen["families"] |= family_ids


def _collect_scope(c, scope: dict) -> dict[str, set[str]]:
    """在快照连接上按范围取种子集合并展开，返回 table -> id 集合。

    范围语义（**选择集合即包内可见证据全集**）：

    - ``family``：切点上该族的完整关联闭包（出边 + 全量子实体边不动点），
      与历史行为一致；
    - ``version``：只含勾选修订版及其"打开所选评估、复查命中调用"所需的最小
      依赖（见 :func:`_collect_version_scope`）；
    - ``requests``：只含勾选调用及其复查最小依赖
      （见 :func:`_collect_requests_scope`）。

    窄范围下落在选择集合之外的结构边（族活动指针、调用/回执→放量批次、
    回执→风控窗口等）**不展开集合**，由打包阶段逐项记入清单 ``external_refs``；
    验证侧把它们识别为"范围边界外部引用"而非悬空引用。所有收集 SQL 都在本
    快照事务（WAL 同一 read mark）内执行，归档期间持续提交的写入不可见。
    """
    kind = scope.get("kind")
    chosen: dict[str, set[str]] = {t: set() for t in TABLES}

    def add(table: str, rid: Any):
        if rid is not None and rid != "":
            chosen[table].add(str(rid))

    family_scope = kind == "family"
    if kind == "family":
        fid = scope.get("family_id")
        if not c.execute("SELECT 1 FROM families WHERE family_id=?", (fid,)).fetchone():
            raise NotFound(f"模板族不存在: {fid}")
        add("families", fid)
        _collect_family_closure(c, chosen)
    elif kind == "version":
        vid = scope.get("version_id")
        row = c.execute("SELECT * FROM versions WHERE version_id=?", (vid,)).fetchone()
        if not row:
            raise NotFound(f"版本不存在: {vid}")
        add("versions", vid)
        _collect_version_scope(c, chosen, str(vid))
    elif kind == "requests":
        rids = scope.get("request_ids") or []
        if not rids:
            raise DomainError("调用范围必须提供非空 request_ids")
        for rid in rids:
            row = c.execute("SELECT * FROM requests WHERE request_id=?",
                            (rid,)).fetchone()
            if not row:
                raise NotFound(f"请求不存在: {rid}")
            add("requests", rid)
        _collect_requests_scope(c, chosen, [str(r) for r in rids])
    else:
        raise DomainError("scope.kind 必须是 family / version / requests")

    _select_audits(c, chosen, family_scope=family_scope,
                   rollout_ids=chosen["rollouts"])
    return chosen


def _load_rows(c, chosen: dict[str, set[str]]) -> dict[str, list[dict]]:
    rows: dict[str, list[dict]] = {}
    for table in TABLES:
        ids = sorted(chosen[table], key=lambda v: (not v.isdigit(), v))
        rows[table] = []
        for i in range(0, len(ids), 400):
            chunk = ids[i:i + 400]
            ph = ",".join("?" * len(chunk))
            rows[table].extend(dict(r) for r in c.execute(
                f"SELECT * FROM {table} WHERE {PK[table]} IN ({ph})", chunk).fetchall())
    return rows


def build_pack(scope: dict, actor: str = "api", shard_size_bytes: int | None = None,
               snapshot_callback: Callable[[dict], None] | None = None) -> dict:
    """导出证据包：稳定切点 + 闭包收集 + 内容寻址对象 + 清单/信封/分片。

    ``snapshot_callback(cutpoint)`` 在快照事务内、切点标定之后被调用——回调中
    其他线程/连接继续写入并提交，本事务后续读取也看不到这些行（WAL 读快照），
    供测试与外部登记使用。
    """
    shard_size = int(shard_size_bytes or DEFAULT_SHARD_BYTES)
    if shard_size < 256:
        raise DomainError("分片过小（≥256 字节）")
    pack_id = _uid("pack")
    with snapshot_tx() as c:
        cutpoint = dict(c.execute(
            "SELECT COALESCE(MAX(id),0) AS audit_max_id, datetime('now') AS db_time "
            "FROM audit_log").fetchone())
        cutpoint = {"audit_max_id": int(cutpoint["audit_max_id"]),
                    "db_time": cutpoint["db_time"]}
        if snapshot_callback:
            snapshot_callback(cutpoint)
        chosen = _collect_scope(c, scope)
        rows = _load_rows(c, chosen)

    semvers = {r["version_id"]: r["semver"] for r in rows["versions"]}
    chosen_keys = {(t, i) for t, ids in chosen.items() for i in ids}
    items: list[dict] = []
    for table in TABLES:
        for row in rows[table]:
            rec = _canonical(dict(row))
            refs = _refs_of(table, row)
            # 出边按是否落在选择集合内分流：包内引用必须随包可解析；落在集合外
            # 的结构边（活动指针指向未勾选版本、调用/回执→未纳入批次、回执→
            # 风控窗口等）是**范围边界外部引用**，逐项显式声明，不展开集合、
            # 不构成悬空引用。
            ext = [r for r in refs if (r["table"], r["id"]) not in chosen_keys]
            inside = [r for r in refs if (r["table"], r["id"]) in chosen_keys]
            items.append({
                "table": table, "id": str(row[PK[table]]),
                "object": core.sha256_hex(rec.decode("utf-8")),
                "size": len(rec), "summary": _summary(table, row, semvers),
                "refs": inside, "external_refs": ext,
            })
    items.sort(key=lambda it: (TABLES.index(it["table"]), it["id"]))
    counts = {t: len(rows[t]) for t in TABLES}

    exported_at = cutpoint["db_time"]
    source_iid = instance_id()
    manifest = {
        "format": FORMAT, "pack_id": pack_id, "scope": scope, "cutpoint": cutpoint,
        "source_instance_id": source_iid, "exported_at": exported_at,
        "items": items, "counts": counts,
    }
    m_bytes = _canonical(manifest)
    m_sha = core.sha256_hex(m_bytes.decode("utf-8"))
    payload = _line("manifest", m_sha, m_bytes)
    for it in items:
        row = next(r for r in rows[it["table"]] if str(r[PK[it["table"]]]) == it["id"])
        payload += _line("object", it["object"], _canonical(dict(row)))

    # 固定字节边界切数据分片；分片布局只进入信封（信封是传输元数据，
    # 清单只描述内容与切点，避免"清单含自身载荷分片"的循环依赖）。
    shards = [{"index": index, "sha256": _sha(payload[start:start + shard_size]),
               "start": start, "length": min(shard_size, len(payload) - start)}
              for index, start in enumerate(range(0, len(payload), shard_size), start=1)]
    archive_sha = _sha(payload)

    envelope = {
        "format": FORMAT, "pack_id": pack_id, "scope": scope, "cutpoint": cutpoint,
        "source_instance_id": source_iid, "exported_at": exported_at,
        "shard_size_bytes": shard_size, "shards": shards,
        "manifest_sha": m_sha, "archive_sha": archive_sha,
        "object_count": len(items), "byte_count": len(payload),
    }
    e_bytes = _canonical(envelope)
    e_sha = _sha(e_bytes)
    file_bytes = _line("envelope", e_sha, e_bytes) + payload

    with _write() as cx:
        cx.execute(
            """INSERT INTO evidence_packs(pack_id,status,outer_manifest_sha,manifest_sha,
               archive_sha,archive_blob,scope_json,cutpoint_json,source_instance_id,
               exported_at,shard_count,object_count,byte_count,counts_json)
               VALUES (?, 'exported', ?,?,?,?,?,?,?,?,?,?,?,?)""",
            (pack_id, e_sha, m_sha, archive_sha, sqlite_blob(file_bytes),
             json.dumps(scope, ensure_ascii=False), json.dumps(cutpoint, ensure_ascii=False),
             envelope["source_instance_id"], exported_at, len(shards), len(items),
             len(payload), json.dumps(counts, ensure_ascii=False)))
        _audit(cx, pack_id, actor, "pack.export",
               f"scope={json.dumps(scope, ensure_ascii=False)} cutpoint={exported_at} "
               f"objects={len(items)} shards={len(shards)} bytes={len(file_bytes)}")
    return get_pack(pack_id)


def sqlite_blob(b: bytes) -> bytes:
    """显式包装为 SQLite BLOB（避免被推断为 TEXT）。"""
    return sqlite3.Binary(b)


def _audit(c, pack_id: str, actor: str, action: str, detail: str = "") -> None:
    c.execute("INSERT INTO evidence_audit(pack_id,actor,action,detail) VALUES (?,?,?,?)",
              (pack_id, actor, action, detail))
    c.execute("INSERT INTO audit_log(actor,action,entity,entity_id,detail) "
              "VALUES (?,?, 'evidence_pack',?,?)", (actor, action, pack_id, detail))


# ================================================================ 校验

def _err(report: list[dict], code: str, message: str):
    report.append({"code": code, "message": message})


def verify_bytes(file_bytes: bytes) -> dict:
    """落库前完整校验一个归档，返回 {ok,errors,envelope,manifest,items,records}。

    检查链：信封自哈希 → 信封/清单身份一致 → 分片重切哈希 → 载荷哈希 →
    清单自哈希 → 逐对象内容寻址哈希 → 主键唯一/计数一致 → 全部出边引用
    可解析（无悬空引用）→ 语义不变量（模板四要素重哈希、证据计数/比率、
    止损归属、请求绑定模型、指针完整性）。
    """
    errors: list[dict] = []

    def parse_line(line: bytes, expect: str) -> dict | None:
        try:
            obj = json.loads(line.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            _err(errors, "line_malformed", f"{expect} 行不是合法 JSON：{exc}")
            return None
        if obj.get("kind") != expect:
            _err(errors, "line_kind", f"期望 {expect} 行，实际 {obj.get('kind')!r}")
            return None
        try:
            data = _unb64(obj.get("data", ""))
        except Exception as exc:  # noqa: BLE001
            _err(errors, "base64", f"{expect} 行 data 非法 base64：{exc}")
            return None
        if hashlib.sha256(data).hexdigest() != obj.get("sha256"):
            _err(errors, f"{expect}_sha_mismatch", f"{expect} 摘要与内容不符（内容被改）")
            return None
        return {"data": data, "sha": obj["sha256"]}

    lines = list(_iter_lines(file_bytes))
    if not lines:
        return {"ok": False, "errors": [{"code": "empty", "message": "空归档"}],
                "envelope": None, "manifest": None, "records": {}}
    env_l = parse_line(lines[0], "envelope")
    records: dict[tuple[str, str], dict] = {}
    envelope = manifest = None
    if env_l:
        try:
            envelope = json.loads(env_l["data"].decode("utf-8"))
            if _canonical(envelope) != env_l["data"]:
                _err(errors, "envelope_noncanonical", "信封不是规范化 JSON（摘要无法稳定复算）")
        except Exception as exc:  # noqa: BLE001
            _err(errors, "envelope_json", f"信封 JSON 损坏：{exc}")

    payload = file_bytes[len(lines[0]) + 1:]
    if envelope:
        if envelope.get("format") != FORMAT:
            _err(errors, "format", f"不支持的归档格式：{envelope.get('format')!r}")
        if hashlib.sha256(payload).hexdigest() != envelope.get("archive_sha"):
            _err(errors, "archive_sha_mismatch", "载荷整体摘要与信封不符（分片缺失/被改）")
        # 分片布局重切
        try:
            size = int(envelope["shard_size_bytes"])
            want = envelope["shards"]
            got_chunks = [payload[s:s + size] for s in range(0, len(payload), size)]
            if len(got_chunks) != len(want):
                _err(errors, "shard_count",
                     f"分片数不符：清单 {len(want)}，重切 {len(got_chunks)}（缺失分片）")
            for i, chunk in enumerate(got_chunks):
                if i >= len(want):
                    break
                d = want[i]
                if hashlib.sha256(chunk).hexdigest() != d.get("sha256") or \
                        d.get("length") != len(chunk) or d.get("start") != i * size:
                    _err(errors, "shard_sha_mismatch",
                                 f"分片 {d.get('index', i + 1)} 摘要/边界不符（对象缺失或被改）")
        except (KeyError, TypeError, ValueError) as exc:
            _err(errors, "shard_layout", f"信封分片布局损坏：{exc}")

    p_lines = list(_iter_lines(payload))
    m_sha = envelope.get("manifest_sha") if envelope else None
    if p_lines:
        man_l = parse_line(p_lines[0], "manifest")
        if man_l:
            if m_sha and man_l["sha"] != m_sha:
                _err(errors, "manifest_sha_mismatch", "清单哈希与信封记录不符")
            try:
                manifest = json.loads(man_l["data"].decode("utf-8"))
                if _canonical(manifest) != man_l["data"]:
                    _err(errors, "manifest_noncanonical", "清单不是规范化 JSON")
            except Exception as exc:  # noqa: BLE001
                _err(errors, "manifest_json", f"清单 JSON 损坏：{exc}")
    else:
        _err(errors, "manifest_missing", "载荷缺少清单行（对象缺失）")

    object_lines = p_lines[1:]
    items = manifest["items"] if manifest else []
    if len(object_lines) != len(items):
        _err(errors, "object_count",
             f"对象数不符：清单 {len(items)}，载荷 {len(object_lines)}（对象缺失或多余）")

    by_key: dict[tuple[str, str], dict] = {}
    seen_hashes: dict[str, tuple[str, str]] = {}
    for i, line in enumerate(object_lines):
        ol = parse_line(line, "object")
        if not ol or i >= len(items):
            continue
        it = items[i]
        if ol["sha"] != it["object"]:
            _err(errors, "object_sha_mismatch",
                 f"{it['table']}/{it['id']} 的对象摘要与清单不符（内容被改）")
        try:
            rec = json.loads(ol["data"].decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            _err(errors, "object_json", f"{it['table']}/{it['id']} 对象 JSON 损坏：{exc}")
            continue
        key = (it["table"], it["id"])
        if key in by_key:
            _err(errors, "duplicate_item", f"重复对象：{it['table']}/{it['id']}")
        if ol["sha"] in seen_hashes and seen_hashes[ol["sha"]] != key:
            _err(errors, "duplicate_object_hash",
                 f"同一对象哈希映射到不同主键：{seen_hashes[ol['sha']]} 与 {key}")
        by_key[key] = rec
        seen_hashes[ol["sha"]] = key
        # 逐项摘要要求记录可解析、主键一致
        if str(rec.get(PK.get(it["table"], ""))) != it["id"]:
            _err(errors, "primary_key_mismatch",
                 f"{it['table']} 对象主键与清单项不一致")

    if manifest and envelope:
        for fld in ("pack_id", "scope", "cutpoint", "source_instance_id", "exported_at"):
            if manifest.get(fld) != envelope.get(fld):
                _err(errors, "envelope_divergence",
                     f"信封与清单的 {fld} 不一致（信封被改）")
        counts = manifest.get("counts", {})
        for t in TABLES:
            n = sum(1 for k in by_key if k[0] == t)
            if int(counts.get(t, 0)) != n:
                _err(errors, "count_mismatch", f"计数不符：{t} 清单 {counts.get(t, 0)} 实际 {n}")

    # —— 引用闭包：内部引用不允许悬空；外部引用必须与清单声明一致 ——
    # 以**对象记录本身**重算出边（防止清单把内部引用谎报为外部引用以夹带/
    # 掩盖断链）：记录指向包内对象的边必须出现在 item.refs 且可解析；指向包外
    # 的边必须逐项出现在 item.external_refs（范围边界声明）。任何既不可解析、
    # 又未声明为边界的引用都是断链。
    item_by_key = {(it["table"], it["id"]): it for it in items}
    for (table, rid), rec in by_key.items():
        it = item_by_key.get((table, rid), {})
        declared_in = {(r["table"], r["id"]) for r in it.get("refs", [])}
        declared_ext = {(r["table"], r["id"]) for r in it.get("external_refs", [])}
        for ref in _refs_of(table, rec):
            key = (ref["table"], ref["id"])
            if key in by_key:
                if key not in declared_in:
                    _err(errors, "reference_misclassified",
                         f"{table}/{rid} 的包内引用 {ref['table']}/{ref['id']} "
                         f"未在清单 refs 中声明")
            elif key not in declared_ext:
                _err(errors, "dangling_reference",
                     f"{table}/{rid} 引用了包内不存在的 {ref['table']}/{ref['id']}"
                     f"（既非包内对象，也未在 external_refs 声明为范围边界）")
        # 清单不得把包内可解析的引用谎称为外部引用
        for key in declared_ext:
            if key in by_key:
                _err(errors, "external_ref_resolves_internally",
                     f"{table}/{rid} 声称的外部引用 {key[0]}/{key[1]} 实际在包内"
                     f"（范围声明与闭包不一致）")
        # 清单声明的内部引用必须真的是该记录的出边（防清单凭空加边）
        for key in declared_in:
            if key not in {(r["table"], r["id"]) for r in _refs_of(table, rec)}:
                _err(errors, "phantom_ref",
                     f"清单为 {table}/{rid} 声明了记录中不存在的引用 {key[0]}/{key[1]}")

    def rec_of(table: str, rid: Any) -> dict | None:
        return by_key.get((table, str(rid)))

    # —— 语义不变量 ——
    # 窄范围（version/requests）允许活动指针、批次、风控窗口等落在选择集合外，
    # 前提是对应出边已在清单 external_refs 中逐项声明（上面的闭包校验保证
    # "不可解析且未声明"一定报 dangling_reference）。
    def declared_external(table: str, rid: Any, target_table: str,
                          target_id: Any) -> bool:
        it = item_by_key.get((table, str(rid)))
        if not it:
            return False
        return any(r["table"] == target_table and r["id"] == str(target_id)
                   for r in it.get("external_refs", []))

    scope = manifest.get("scope") or {}
    scope_kind = scope.get("kind")
    for fid, f in ((k[1], r) for k, r in by_key.items() if k[0] == "families"):
        # 族全量包：活动指针必须在包内闭合；窄范围包：指针可指向未勾选修订版，
        # 但必须作为边界外部引用显式声明（不得悄悄断链，也不得拉入兄弟版本）。
        if f.get("active_version_id") and not rec_of("versions", f["active_version_id"]):
            if scope_kind == "family" or not declared_external(
                    "families", fid, "versions", f["active_version_id"]):
                _err(errors, "family_active_dangling",
                     f"族 {fid} 的线上指针 {f['active_version_id']} "
                     f"既不在包内也未声明为范围边界")
    for vid, v in ((k[1], r) for k, r in by_key.items() if k[0] == "versions"):
        try:
            re_hash = core.content_hash(v["system_instruction"],
                                        json.loads(v["variable_contract"]),
                                        json.loads(v["tool_permissions"]),
                                        json.loads(v["model_params"]))
            if re_hash != v["content_hash"]:
                _err(errors, "content_hash_mismatch",
                     f"版本 {vid} 四要素重哈希与 content_hash 不符（模板内容被改）")
        except Exception as exc:  # noqa: BLE001
            _err(errors, "version_fields", f"版本 {vid} 字段损坏：{exc}")
        if not rec_of("families", v.get("family_id")):
            _err(errors, "version_family_missing", f"版本 {vid} 缺少所属模板族")
    for run_id, run in ((k[1], r) for k, r in by_key.items() if k[0] == "eval_runs"):
        cases = [r for (t, _), r in by_key.items() if t == "eval_cases"
                 and str(r.get("run_id")) == run_id]
        if len(cases) != int(run.get("total", 0)):
            _err(errors, "eval_total_mismatch",
                 f"评估 {run_id} 登记 {run.get('total')} 用例，实际 {len(cases)}")
        passed = sum(int(c.get("ok", 0)) for c in cases)
        if passed != int(run.get("passed", -1)):
            _err(errors, "eval_passed_mismatch",
                 f"评估 {run_id} passed={run.get('passed')} 但逐用例合计 {passed}")
        rate = passed / len(cases) if cases else 0.0
        if cases and abs(float(run.get("pass_rate", -1)) - rate) > 1e-9:
            _err(errors, "eval_rate_mismatch", f"评估 {run_id} pass_rate 与逐用例不符")
        if not rec_of("versions", run.get("version_id")):
            _err(errors, "eval_version_missing", f"评估 {run_id} 缺少版本对象")
        # 评估固定测试集必须随包（共享测试集整组纳入）；窄范围不允许把测试集
        # 留作边界——逐用例证据与固定测试集是"打开所选评估"的最小依赖。
        if not rec_of("testsets", run.get("testset_id")):
            _err(errors, "eval_testset_missing",
                 f"评估 {run_id} 缺少固定测试集对象")
    for case_id, ec in ((k[1], r) for k, r in by_key.items() if k[0] == "eval_cases"):
        if not rec_of("testcases", ec.get("case_id")):
            _err(errors, "eval_case_testcase_missing",
                 f"评估用例 {case_id} 缺少固定测试集用例对象")
    for ro_id, ro in ((k[1], r) for k, r in by_key.items() if k[0] == "rollouts"):
        for fld in ("candidate_version_id", "base_version_id"):
            if not rec_of("versions", ro.get(fld)):
                _err(errors, "rollout_version_missing",
                     f"批次 {ro_id} 的 {fld} 对象缺失")
        if not rec_of("families", ro.get("family_id")):
            _err(errors, "rollout_family_missing", f"批次 {ro_id} 缺少模板族")
    for fb_id, fb in ((k[1], r) for k, r in by_key.items()
                      if k[0] == "feedback_receipts"):
        req = rec_of("requests", fb.get("request_id"))
        if not req:
            _err(errors, "receipt_request_missing", f"回执 {fb_id} 缺少调用对象")
        elif str(req.get("rollout_id") or "") != str(fb.get("rollout_id")):
            _err(errors, "receipt_rollout_mismatch",
                 f"回执 {fb_id} 的批次与调用固化批次不一致")
        # 窄范围只取回执行（复查调用所需的归属快照），批次/窗口可在边界外，
        # 但必须在 external_refs 声明；族全量包则必须随包闭合。
        if scope_kind == "family":
            if not rec_of("stoploss_windows", fb.get("window_id")):
                _err(errors, "receipt_window_missing", f"回执 {fb_id} 缺少统计窗口")
        else:
            if not rec_of("stoploss_windows", fb.get("window_id")) and not \
                    declared_external("feedback_receipts", fb_id,
                                      "stoploss_windows", fb.get("window_id")):
                _err(errors, "receipt_window_undeclared",
                     f"回执 {fb_id} 的窗口 {fb.get('window_id')} 不在包内且未声明边界")
            if not rec_of("rollouts", fb.get("rollout_id")) and not \
                    declared_external("feedback_receipts", fb_id,
                                      "rollouts", fb.get("rollout_id")):
                _err(errors, "receipt_rollout_undeclared",
                     f"回执 {fb_id} 的批次 {fb.get('rollout_id')} 不在包内且未声明边界")
    for req_id, req in ((k[1], r) for k, r in by_key.items() if k[0] == "requests"):
        v = rec_of("versions", req.get("version_id"))
        if v:
            bound = json.loads(v["model_params"]).get("_bound_model")
            if bound and req.get("model_id") != bound:
                _err(errors, "request_model_mismatch",
                     f"调用 {req_id} 模型与版本绑定模型不符")
        else:
            _err(errors, "request_version_missing",
                 f"调用 {req_id} 缺少命中版本对象（复查三元组无法重建）")
        if not rec_of("families", req.get("family_id")):
            _err(errors, "request_family_missing", f"调用 {req_id} 缺少模板族")
        # 命中放量批次可在范围边界外（窄范围不夹带灰度/风控记录），但必须声明。
        if req.get("rollout_id") and not rec_of("rollouts", req["rollout_id"]) and \
                not declared_external("requests", req_id, "rollouts",
                                      req["rollout_id"]):
            _err(errors, "request_rollout_undeclared",
                 f"调用 {req_id} 的批次 {req['rollout_id']} 不在包内且未声明边界")
    for trg_id, trg in ((k[1], r) for k, r in by_key.items()
                        if k[0] == "stoploss_triggers"):
        if not rec_of("stoploss_windows", trg.get("window_id")):
            _err(errors, "trigger_window_missing", f"触发快照 {trg_id} 缺少窗口")
        if not rec_of("rollouts", trg.get("rollout_id")):
            _err(errors, "trigger_rollout_missing", f"触发快照 {trg_id} 缺少批次")

    # —— 敏感内容隔离语义不变量 ——
    # 1) 规则版本内容哈希必须可由包内规则重算（规则不可变、可复核）；
    # 2) 请求/评估固定的规则版本必须在包内（不能指向被裁掉的规则版本）；
    # 3) 遮盖映射必须与其请求的规则版本一致、映射占位符在遮盖输入/提示内；
    # 4) 包内任何对象都不得含密文表/凭据/授权等禁止表（导入侧无还原能力）。
    for rs_id, rs in ((k[1], r) for k, r in by_key.items()
                      if k[0] == "guard_rulesets"):
        try:
            re_hash = guard.ruleset_hash(json.loads(rs["rules_json"]))
            if re_hash != rs.get("content_hash"):
                _err(errors, "guard_ruleset_hash_mismatch",
                     f"规则版本 {rs_id} 内容重哈希与 content_hash 不符（规则被改）")
        except Exception as exc:  # noqa: BLE001
            _err(errors, "guard_ruleset_fields", f"规则版本 {rs_id} 字段损坏：{exc}")
        if not rec_of("families", rs.get("family_id")):
            _err(errors, "guard_ruleset_family_missing",
                 f"规则版本 {rs_id} 缺少所属模板族")
    for mid, mk in ((k[1], r) for k, r in by_key.items()
                    if k[0] == "guard_request_masks"):
        req = rec_of("requests", mk.get("request_id"))
        rs = rec_of("guard_rulesets", mk.get("ruleset_id"))
        if not req:
            _err(errors, "guard_mask_request_missing",
                 f"遮盖映射 {mid} 缺少调用对象")
            continue
        if not rs:
            _err(errors, "guard_mask_ruleset_missing",
                 f"调用 {mk.get('request_id')} 的遮盖映射缺少规则版本对象（历史检查"
                 "无法重建固定版本）")
        if rs and (str(req.get("guard_ruleset_id") or "") != str(mk.get("ruleset_id"))
                   or str(req.get("guard_ruleset_hash") or "") != str(rs.get("content_hash"))):
            _err(errors, "guard_mask_version_drift",
                 f"调用 {mid} 固化的规则版本与遮盖映射不一致（映射被改写）")
        tokens = json.loads(mk.get("tokens_json", "[]"))
        masked_blob = str(req.get("inputs_json", "")) + str(req.get("rendered_prompt", ""))
        for t in tokens:
            tok = t.get("token", "")
            if tok and tok not in masked_blob:
                _err(errors, "guard_token_absent",
                     f"遮盖映射占位符 {tok} 未出现在调用的遮盖输入/渲染提示中")
            if "raw" in t:
                _err(errors, "guard_plaintext_in_mapping",
                     f"遮盖映射 {mid} 含 raw 原值字段（明文不得入包）")
    for fx_id, fx in ((k[1], r) for k, r in by_key.items()
                      if k[0] == "guard_eval_fixtures"):
        if not rec_of("eval_runs", fx.get("run_id")):
            _err(errors, "guard_fixture_run_missing",
                 f"评估隔离记录 {fx_id} 缺少评估运行")
        if fx.get("ruleset_id") and not rec_of("guard_rulesets", fx["ruleset_id"]):
            _err(errors, "guard_fixture_ruleset_missing",
                 f"评估 {fx_id} 固定的规则版本不在包内（历史检查无法重建）")
    # 禁止表绝不允许出现在包对象里（防篡改夹带密文/凭据/授权/还原审计/阻断日志）
    for forbidden in ("guard_secrets", "guard_credentials", "guard_reviewer_grants",
                      "guard_reveals", "guard_block_log"):
        present = [k[1] for k in by_key if k[0] == forbidden]
        if present:
            _err(errors, "guard_forbidden_table_leak",
                 f"证据包含有禁止表 {forbidden} 的对象（密文/凭据/授权不得导出）："
                 f"{present[:3]}")

    # —— 窄范围选择集合精确性（防夹带）——
    # version 范围：包内版本必须恰好是勾选版本；灰度批次与风控四表必须为空；
    # 包内调用必须全部命中勾选版本。requests 范围：包内调用必须恰好是勾选集合，
    # 批次与风控四表必须为空。族行只允许来自勾选/命中版本所属的族。
    if scope_kind == "version":
        want_v = str(scope.get("version_id"))
        got_versions = {k[1] for k in by_key if k[0] == "versions"}
        if got_versions != {want_v}:
            _err(errors, "scope_version_leak",
                 f"版本范围包夹带了未勾选版本：{got_versions - {want_v}}")
        for t in ("rollouts", "stoploss_configs", "stoploss_windows",
                  "stoploss_triggers"):
            extra = [k[1] for k in by_key if k[0] == t]
            if extra:
                _err(errors, "scope_gray_risk_leak",
                     f"版本范围包夹带了 {t}：{extra[:3]}")
        for rid, req in ((k[1], r) for k, r in by_key.items() if k[0] == "requests"):
            if str(req.get("version_id")) != want_v:
                _err(errors, "scope_request_version_leak",
                     f"版本范围包夹带了命中其他版本的调用 {rid}")
    elif scope_kind == "requests":
        want_reqs = {str(x) for x in (scope.get("request_ids") or [])}
        got_reqs = {k[1] for k in by_key if k[0] == "requests"}
        if got_reqs != want_reqs:
            _err(errors, "scope_requests_mismatch",
                 f"调用范围集合不符：多出 {got_reqs - want_reqs}，"
                 f"缺失 {want_reqs - got_reqs}")
        for t in ("rollouts", "stoploss_configs", "stoploss_windows",
                  "stoploss_triggers"):
            extra = [k[1] for k in by_key if k[0] == t]
            if extra:
                _err(errors, "scope_gray_risk_leak",
                     f"调用范围包夹带了 {t}：{extra[:3]}")

    return {"ok": not errors, "errors": errors, "envelope": envelope,
            "manifest": manifest, "items": items, "records": by_key}


# ================================================================ 包登记 / 查询

def _pack_row(pack_id: str):
    row = _conn().execute("SELECT * FROM evidence_packs WHERE pack_id=?",
                             (pack_id,)).fetchone()
    if not row:
        raise NotFound(f"证据包不存在: {pack_id}")
    return row


def get_pack(pack_id: str) -> dict:
    r = _pack_row(pack_id)
    d = dict(r)
    d["scope"] = json.loads(d.pop("scope_json"))
    d["cutpoint"] = json.loads(d.pop("cutpoint_json"))
    d["counts"] = json.loads(d.pop("counts_json"))
    d["audit"] = [dict(a) for a in _conn().execute(
        "SELECT * FROM evidence_audit WHERE pack_id=? ORDER BY id", (pack_id,)).fetchall()]
    return d


def list_packs(limit: int = 100) -> list[dict]:
    rows = _conn().execute(
        "SELECT pack_id,status,scope_json,source_instance_id,exported_at,imported_at,"
        "object_count,shard_count,byte_count,manifest_sha,outer_manifest_sha,created_at "
        "FROM evidence_packs ORDER BY created_at DESC, pack_id DESC LIMIT ?",
        (limit,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["scope"] = json.loads(d.pop("scope_json"))
        out.append(d)
    return out


def pack_file_bytes(pack_id: str) -> tuple[str, bytes]:
    r = _pack_row(pack_id)
    return r["pack_id"], bytes(r["archive_blob"])


def verify_stored_pack(pack_id: str, actor: str = "api") -> dict:
    """对已落库归档再校验（页面/API 的"校验状态"复核入口）。"""
    r = _pack_row(pack_id)
    report = verify_bytes(bytes(r["archive_blob"]))
    with _write() as c:
        _audit(c, pack_id, actor, "pack.verify",
               f"ok={report['ok']} errors={len(report['errors'])}")
    return {"pack_id": pack_id, "ok": report["ok"], "errors": report["errors"],
            "manifest_sha": r["manifest_sha"], "outer_manifest_sha": r["outer_manifest_sha"]}


# ================================================================ 导入：分片会话

def _load_session(c, import_id: str):
    row = c.execute("SELECT * FROM evidence_imports WHERE import_id=?",
                    (import_id,)).fetchone()
    if not row:
        raise NotFound(f"导入会话不存在: {import_id}")
    return row


def init_import(envelope_bytes: bytes, actor: str = "api") -> dict:
    """用归档信封（分片 0 原文）开启导入会话。

    - 包已在本实例且**同摘要**：直接返回原结果（幂等，同包再导入无副作用）；
    - 同 pack_id 但清单摘要不同：409 拒绝，且不写任何数据；
    - 否则建立 staging 会话，等待数据分片（同内容可建立多个并行会话）。
    """
    try:
        wrapper = json.loads(envelope_bytes.decode("utf-8").strip())
        data = _unb64(wrapper["data"])
    except Exception as exc:  # noqa: BLE001
        raise DomainError(f"信封不是合法的归档分片0：{exc}") from exc
    if wrapper.get("kind") != "envelope" or _sha(data) != wrapper.get("sha256"):
        raise DomainError("信封自校验失败（内容被改或不是分片0）")
    try:
        env = json.loads(data.decode("utf-8"))
        assert env["format"] == FORMAT
        n = len(env["shards"])
        assert n >= 1
        manifest_sha = env["manifest_sha"]
        pack_id = env["pack_id"]
    except Exception as exc:  # noqa: BLE001
        raise DomainError(f"信封字段不完整：{exc}") from exc

    with _write() as c:
        existing = c.execute("SELECT * FROM evidence_packs WHERE pack_id=?",
                             (pack_id,)).fetchone()
        if existing:
            if existing["manifest_sha"] == manifest_sha:
                return {"import_id": None, "pack_id": pack_id, "already": "committed",
                        "status": "imported", "shard_count": n, "received": list(range(1, n + 1))}
            raise Conflict(
                f"拒绝导入：pack_id={pack_id} 已存在但内容摘要不同"
                f"（已有 {existing['manifest_sha'][:12]}，本次 {manifest_sha[:12]}）")
        import_id = _uid("imp")
        c.execute(
            """INSERT INTO evidence_imports(import_id,pack_id,outer_manifest_sha,
               envelope_json,status,created_by,note)
               VALUES (?,?,?,?,'staging',?,?)""",
            (import_id, pack_id, wrapper["sha256"],
             json.dumps({"line_sha": wrapper["sha256"], "envelope": env},
                        ensure_ascii=False), actor, ""))
        _audit(c, pack_id, actor, "import.init",
               f"import={import_id} shards={n} source={env.get('source_instance_id')} "
               f"cutpoint={env.get('exported_at')}")
    return {"import_id": import_id, "pack_id": pack_id, "already": None,
            "status": "staging", "shard_count": n, "received": []}


def _session_env(row) -> dict:
    return json.loads(row["envelope_json"])["envelope"]


def get_import(import_id: str) -> dict:
    row = _load_session(_conn(), import_id)
    env = _session_env(row)
    received = {int(k): v for k, v in json.loads(row["received_shards_json"]).items()}
    return {"import_id": import_id, "pack_id": row["pack_id"], "status": row["status"],
            "note": row["note"], "result_pack_id": row["result_pack_id"],
            "shard_count": len(env["shards"]),
            "received": sorted(received), "missing": [d["index"] for d in env["shards"]
                                                      if d["index"] not in received],
            "created_at": row["created_at"], "committed_at": row["committed_at"]}


def list_imports(include_finished: bool = True) -> list[dict]:
    q = "SELECT * FROM evidence_imports"
    if not include_finished:
        q += " WHERE status='staging'"
    q += " ORDER BY created_at DESC"
    out = []
    for r in _conn().execute(q).fetchall():
        received_count = len(json.loads(r["received_shards_json"]))
        env = _session_env(r)
        d = {"import_id": r["import_id"], "pack_id": r["pack_id"], "status": r["status"],
             "note": r["note"], "result_pack_id": r["result_pack_id"],
             "has_result": r["result_pack_id"] is not None,
             "created_at": r["created_at"], "committed_at": r["committed_at"],
             "received_count": received_count,
             "shard_count": len(env["shards"])}
        out.append(d)
    return out


def put_import_shard(import_id: str, index: int, blob: bytes) -> dict:
    """上传一个数据分片（可乱序、可重试；摘要不符当场拒绝，暂存不变）。"""
    with _write() as c:
        row = _load_session(c, import_id)
        if row["status"] != "staging":
            raise Conflict(f"导入会话已 {row['status']}，不能再上传分片")
        env = _session_env(row)
        want = next((d for d in env["shards"] if int(d["index"]) == int(index)), None)
        if not want:
            raise DomainError(f"分片序号越界：{index}（共 {len(env['shards'])} 片）")
        digest = hashlib.sha256(blob).hexdigest()
        if digest != want["sha256"] or len(blob) != want["length"]:
            raise DomainError(f"分片 {index} 摘要/长度不符（内容被改或缺片）")
        received = json.loads(row["received_shards_json"])
        key = str(index)
        if key in received:
            if received[key]["sha"] == digest:
                pass  # 幂等重传
            else:
                raise Conflict(f"分片 {index} 已上传且摘要不同")
        else:
            received[key] = {"sha": digest, "blob_b64": _b64(blob)}
            c.execute("UPDATE evidence_imports SET received_shards_json=? WHERE import_id=?",
                      (json.dumps(received), import_id))
    return get_import(import_id)


def abort_import(import_id: str, actor: str = "api") -> dict:
    with _write() as c:
        row = _load_session(c, import_id)
        if row["status"] != "staging":
            raise Conflict(f"会话已 {row['status']}，无需放弃")
        c.execute("UPDATE evidence_imports SET status='aborted',note=? WHERE import_id=?",
                  ("人工放弃", import_id))
        _audit(c, row["pack_id"], actor, "import.abort", f"import={import_id}")
    return get_import(import_id)


def commit_import(import_id: str, actor: str = "api") -> dict:
    """组装全部分片 → 落库前校验 → 原子提交。

    缺片：会话保持 staging（可继续续传）。校验失败/同标识异内容：标记 failed，
    不插入 evidence_packs。并发提交同一包：单事务 + pack_id 主键，只有一方
    插入成功，另一方得到同摘要的原结果（幂等返回）。
    """
    with _write() as c:
        row = _load_session(c, import_id)
        if row["status"] == "committed":
            return {"pack_id": row["result_pack_id"], "already": "committed",
                    "report_ok": True, "errors": []}
        if row["status"] != "staging":
            raise Conflict(f"导入会话已 {row['status']}，不能提交")
        env = _session_env(row)
        received = json.loads(row["received_shards_json"])
        missing = [d["index"] for d in env["shards"] if str(d["index"]) not in received]
        if missing:
            raise Conflict(f"缺少分片 {missing}，请续传后再提交（会话已保留）")

        payload = b"".join(
            _unb64(received[str(d["index"])]["blob_b64"])
            for d in sorted(env["shards"], key=lambda x: x["index"]))
        e_line = _line("envelope", _sha(_canonical(env)), _canonical(env))
        # 校验在事务内计算，但拒绝动作必须在抛出异常前单独提交：否则外层的
        # 回滚会把会话 failed 标记一并撤销（失败路径也要留下审计）。
        reject_note = None
        reject_msg = None
        reject_kind = None
        if _sha(payload) != env["archive_sha"]:
            reject_note = "载荷整体摘要不符（分片被改/缺片）"
            reject_msg = "载荷整体摘要与信封不符"
            reject_kind = VerificationRejected
        else:
            report = verify_bytes(e_line + payload)
            if not report["ok"]:
                reject_note = "; ".join(f"{e['code']}" for e in report["errors"])[:400]
                reject_msg = ("校验未通过，导入已拒绝（未写入任何证据数据）：" +
                              "; ".join(f"{e['code']}:{e['message']}"
                                        for e in report["errors"][:5]))
                reject_kind = VerificationRejected
        if reject_note:
            _fail_session(c, row, actor, reject_note)
            c.commit()
            raise reject_kind(reject_msg)

        manifest = report["manifest"]
        pack_id, m_sha = env["pack_id"], env["manifest_sha"]
        existing = c.execute("SELECT * FROM evidence_packs WHERE pack_id=?",
                             (pack_id,)).fetchone()
        if existing:
            if existing["manifest_sha"] != m_sha:
                _fail_session(c, row, actor,
                              f"提交时发现同 pack_id 异内容包 {existing['manifest_sha'][:12]}")
                raise Conflict("拒绝导入：pack_id 相同但清单摘要不同（并发冲突包）")
            c.execute("UPDATE evidence_imports SET status='committed',committed_at="
                      "datetime('now'),result_pack_id=? WHERE import_id=?",
                      (pack_id, import_id))
            _audit(c, pack_id, actor, "import.commit.duplicate",
                   f"import={import_id} 同摘要并发/重复提交，返回原结果 {pack_id}")
            return {"pack_id": pack_id, "already": "committed",
                    "report_ok": True, "errors": []}

        outer_sha = hashlib.sha256(_canonical(env)).hexdigest()
        c.execute(
            """INSERT INTO evidence_packs(pack_id,status,outer_manifest_sha,manifest_sha,
               archive_sha,archive_blob,scope_json,cutpoint_json,source_instance_id,
               exported_at,shard_count,object_count,byte_count,counts_json,
               imported_at,import_actor)
               VALUES (?, 'imported', ?,?,?,?,?,?,?,?,?,?,?,?, datetime('now'), ?)""",
            (pack_id, outer_sha, m_sha, env["archive_sha"], sqlite_blob(e_line + payload),
             json.dumps(env["scope"], ensure_ascii=False),
             json.dumps(env["cutpoint"], ensure_ascii=False),
             env["source_instance_id"], env["exported_at"], len(env["shards"]),
             env["object_count"], env["byte_count"],
             json.dumps(manifest["counts"], ensure_ascii=False), actor))
        c.execute("UPDATE evidence_imports SET status='committed',committed_at="
                  "datetime('now'),result_pack_id=? WHERE import_id=?",
                  (pack_id, import_id))
        _audit(c, pack_id, actor, "import.commit",
               f"import={import_id} source={env['source_instance_id']} "
               f"cutpoint={env['exported_at']} objects={env['object_count']} "
               f"shards={len(env['shards'])}")
        return {"pack_id": pack_id, "already": None, "report_ok": True, "errors": []}


def _fail_session(c, row, actor: str, note: str) -> None:
    c.execute("UPDATE evidence_imports SET status='failed',note=? WHERE import_id=?",
              (note, row["import_id"]))
    _audit(c, row["pack_id"], actor, "import.reject",
           f"import={row['import_id']} {note}")


# ================================================================ 只读证据视图

class PackView:
    """归档的只读内存视图：导入证据页面完全经此读取，不触碰线上业务表。"""

    def __init__(self, pack_id: str):
        self.meta = get_pack(pack_id)
        report = verify_bytes(bytes(_pack_row(pack_id)["archive_blob"]))
        if not report["ok"]:
            raise DomainError(f"证据包 {pack_id} 校验失败，拒绝打开：" +
                              "; ".join(e["code"] for e in report["errors"]))
        self.envelope = report["envelope"]
        self.manifest = report["manifest"]
        self.records = report["records"]
        self.by_table: dict[str, list[dict]] = {t: [] for t in TABLES}
        for (t, _i), rec in self.records.items():
            self.by_table[t].append(rec)
        for t in self.by_table:
            self.by_table[t].sort(key=lambda r: str(r.get(PK[t])))

    def _get(self, table: str, rid: Any) -> dict | None:
        return self.records.get((table, str(rid)))

    def family(self) -> dict:
        fams = self.by_table["families"]
        scope = self.manifest["scope"]
        if scope.get("kind") == "family":
            f = self._get("families", scope.get("family_id"))
            if f:
                return f
        return fams[0]

    def versions(self, family_id: str | None = None) -> list[dict]:
        rows = self.by_table["versions"]
        if family_id:
            rows = [r for r in rows if r["family_id"] == family_id]
        return rows

    def eval_runs(self, version_id: str) -> list[dict]:
        return [r for r in self.by_table["eval_runs"] if r["version_id"] == version_id]

    def eval_run(self, run_id: str) -> dict | None:
        run = self._get("eval_runs", run_id)
        if not run:
            return None
        d = dict(run)
        d["cases"] = sorted((r for r in self.by_table["eval_cases"]
                             if str(r["run_id"]) == run_id), key=lambda r: r["seq"])
        return d

    def approvals(self, version_id: str) -> list[dict]:
        return [r for r in self.by_table["approvals"] if r["version_id"] == version_id]

    def requests(self, family_id: str | None = None, limit: int = 200) -> list[dict]:
        rows = self.by_table["requests"]
        if family_id:
            rows = [r for r in rows if r["family_id"] == family_id]
        rows = sorted(rows, key=lambda r: str(r.get("created_at")), reverse=True)
        return rows[:limit]

    def request(self, request_id: str) -> dict | None:
        return self._get("requests", request_id)

    def replays(self, request_id: str) -> list[dict]:
        return sorted((r for r in self.by_table["replays"]
                       if r["request_id"] == request_id),
                      key=lambda r: str(r.get("created_at")), reverse=True)

    def rollout(self, rollout_id: str) -> dict | None:
        return self._get("rollouts", rollout_id)

    def receipt(self, request_id: str) -> dict | None:
        for r in self.by_table["feedback_receipts"]:
            if r["request_id"] == request_id:
                return r
        return None

    # ------------------------------------------------------------ 敏感隔离（只读，无还原能力）
    def guard_ruleset(self, ruleset_id: str) -> dict | None:
        return self._get("guard_rulesets", ruleset_id)

    def guard_mask(self, request_id: str) -> dict | None:
        m = self._get("guard_request_masks", request_id)
        if not m:
            return None
        d = dict(m)
        d["tokens"] = json.loads(m.get("tokens_json", "[]"))
        d["actions"] = json.loads(m.get("actions_json", "{}"))
        d["output_actions"] = json.loads(m.get("output_actions_json", "[]"))
        return d

    def guard_fixture(self, run_id: str) -> dict | None:
        fx = self._get("guard_eval_fixtures", run_id)
        if not fx:
            return None
        d = dict(fx)
        d["cases"] = json.loads(fx.get("cases_json", "[]"))
        return d

    def guard_rulesets_for_family(self, family_id: str) -> list[dict]:
        return [r for r in self.by_table["guard_rulesets"]
                if r["family_id"] == family_id]

    def stoploss_overview(self, rollout_id: str) -> dict:
        ro = self.rollout(rollout_id)
        if not ro:
            raise NotFound(f"批次不在证据包内：{rollout_id}")
        cfg = self._get("stoploss_configs", rollout_id)
        windows = sorted((r for r in self.by_table["stoploss_windows"]
                          if r["rollout_id"] == rollout_id),
                         key=lambda r: -int(r["seq"]))
        req_by_id = {r["request_id"]: r for r in self.by_table["requests"]}
        ver_by_id = {r["version_id"]: r for r in self.by_table["versions"]}
        for w in windows:
            rcts = [r for r in self.by_table["feedback_receipts"]
                    if r["window_id"] == w["window_id"]]
            total, fails = len(rcts), sum(1 for r in rcts if r["outcome"] == "failure")
            w["total"] = total
            w["fails"] = fails
            w["fail_ratio"] = (fails / total) if total else 0.0
            trg = next((t for t in self.by_table["stoploss_triggers"]
                        if t["window_id"] == w["window_id"]), None)
            w["trigger_id"] = trg["trigger_id"] if trg else None
        triggers = []
        for t in sorted((r for r in self.by_table["stoploss_triggers"]
                         if r["rollout_id"] == rollout_id),
                        key=lambda r: str(r.get("created_at")), reverse=True):
            d = dict(t)
            try:
                d["snapshot"] = json.loads(t["snapshot_json"])
            except Exception:  # noqa: BLE001
                d["snapshot"] = {}
            triggers.append(d)
        receipts = []
        for fb in sorted((r for r in self.by_table["feedback_receipts"]
                         if r["rollout_id"] == rollout_id),
                        key=lambda r: str(r.get("created_at")), reverse=True):
            d = dict(fb)
            w = self._get("stoploss_windows", fb["window_id"])
            req = req_by_id.get(fb["request_id"], {})
            ver = ver_by_id.get(req.get("version_id"), {})
            d["window_seq"] = w["seq"] if w else None
            d["hit_semver"] = ver.get("semver", "?")
            d["routing_key"] = req.get("routing_key")
            d["hit_generation"] = req.get("rollout_generation")
            receipts.append(d)
        rejected = [dict(a) for a in sorted(
            (a for a in self.by_table["audit_log"]
             if a["action"] in ("feedback.reject", "feedback.duplicate")
             and f"rollout={rollout_id}" in str(a.get("detail", ""))),
            key=lambda a: -int(a["id"]))]
        return {
            "rollout": dict(ro), "config": dict(cfg) if cfg else None,
            "windows": [dict(w) for w in windows], "triggers": triggers,
            "receipts": receipts, "rejected": rejected,
            "active_window": next((w for w in windows if w["status"] == "active"), None),
        }
