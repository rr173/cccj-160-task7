"""敏感内容隔离（Guard）：规则引擎、密文保管、规则版本治理、短期还原凭据。

设计要点（对应需求不变量）：

- **规则按模板族配置且版本化**：每次配置生成不可变规则集 ``guard_rulesets``，
  族上唯一指针 ``families.active_guard_ruleset_id`` 决定**新**请求所用版本。
  线上请求、评估回放、证据包复核共用同一确定的规则版本（内容哈希可重算）。
- **每请求固定版本与遮盖映射**：请求在写锁事务内读取指针并把 ruleset id/
  version/hash 固化进 ``requests``；随后规则更新（新版本+翻指针）不改变任何
  在途/历史请求的遮盖结果。
- **替换后内容参与渲染**：扫描发生在契约校验/渲染/推理之前，遮盖后的输入进入
  模板与模型；输出侧再扫一遍，防止模型回显原值。
- **明文唯一存放处**：原值经确定性加密后只落在 ``guard_secrets``（密文），
  ``requests``/``eval_cases``/审计/证据包任何地方只有占位符与摘要。
- **还原凭据绑定请求、短期、单次**：凭据只存令牌哈希；还原在单写事务内校验
  授权（族授权未撤销）+有效期+未消费，行守卫消费，重复还原绝不再次暴露原值。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets as _secrets
import uuid
from typing import Any, Iterator

from . import core
from .db import get_conn, write_tx

# ---------------------------------------------------------------- 异常


class GuardError(Exception):
    """隔离模块基类。"""


class GuardBlocked(GuardError):
    """策略 = 拒绝：请求被阻断（HTTP 403）。不携带任何原值。"""

    def __init__(self, rule_id: str, rule_name: str, kind: str, fields: list[str],
                 ruleset_version: int, request_id: str):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.kind = kind
        self.fields = fields
        self.ruleset_version = ruleset_version
        self.request_id = request_id
        super().__init__(
            f"请求 {request_id} 命中敏感内容阻断规则 {rule_id}"
            f"（{rule_name or kind}，字段 {fields}，规则版本 v{ruleset_version}），"
            f"请求被拒绝且不进入模板渲染")


class GuardUnauthorized(GuardError):
    """未授权还原（无授权 / 授权已撤销 / 令牌错误；HTTP 403）。"""


class GuardExpired(GuardError):
    """还原凭据已过期（HTTP 403）。"""


class GuardReused(GuardError):
    """凭据已消费，重复还原不得再次暴露原值（HTTP 409）。"""


class GuardConflict(GuardError):
    """并发冲突 / 状态不允许（规则指针、授权 CAS；HTTP 409）。"""


# ---------------------------------------------------------------- 规则引擎

VALID_KINDS = ("regex", "keyword")
VALID_ACTIONS = ("mask", "block")
_TOKEN_OPEN = "⟦"
_TOKEN_CLOSE = "⟧"
OUTPUT_MASK = "⟦REDACTED⟧"


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def validate_rule(rule: Any) -> dict:
    """校验并规范化单条规则，返回规范化后的 dict。非法即 ValueError。"""
    if not isinstance(rule, dict):
        raise ValueError("每条规则必须是对象")
    rid = str(rule.get("id", "")).strip()
    if not rid or not re.fullmatch(r"[\w.\-]+", rid):
        raise ValueError("规则 id 不能为空且只能含字母数字 . _ -")
    kind = str(rule.get("kind", "")).strip()
    if kind not in VALID_KINDS:
        raise ValueError(f"规则 {rid} 的 kind 必须是 {VALID_KINDS}")
    action = str(rule.get("action", "")).strip()
    if action not in VALID_ACTIONS:
        raise ValueError(f"规则 {rid} 的 action 必须是 {VALID_ACTIONS}")
    pattern = rule.get("pattern", "")
    if not isinstance(pattern, str) or not pattern:
        raise ValueError(f"规则 {rid} 的 pattern 必须是非空字符串")
    if kind == "regex":
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"规则 {rid} 的正则非法: {exc}") from exc
    fields = rule.get("fields", ["*"])
    if isinstance(fields, str):
        fields = [fields]
    if not isinstance(fields, list) or not fields or not all(
            isinstance(f, str) and f for f in fields):
        raise ValueError(f"规则 {rid} 的 fields 必须是非空字符串数组")
    token = str(rule.get("token", "")).strip()
    if action == "mask" and not token:
        raise ValueError(f"规则 {rid} 是替换策略，必须提供占位名 token")
    return {"id": rid, "kind": kind, "action": action, "pattern": pattern,
            "fields": list(fields), "token": token,
            "name": str(rule.get("name", "")).strip()}


def compile_ruleset(rules: list[dict]) -> list[dict]:
    """校验规则集（重复 id 拒绝），返回规范化规则数组。"""
    norm = [validate_rule(r) for r in rules]
    ids = [r["id"] for r in norm]
    if len(set(ids)) != len(ids):
        raise ValueError("规则 id 不能重复")
    return norm


def ruleset_hash(rules: list[dict]) -> str:
    """规则内容哈希：规范化规则数组的 SHA-256（版本身份，复核/证据重算）。"""
    return core.sha256_hex(core.canonical_json(sorted(rules, key=lambda r: r["id"])))


def _field_applies(rule_fields: list[str], path: str) -> bool:
    """字段作用域：'*' 匹配所有；否则匹配点路径前缀（a 命中 a 与 a.b）。"""
    if "*" in rule_fields:
        return True
    top = path.split(".", 1)[0]
    return path in rule_fields or top in rule_fields


def _iter_string_leaves(obj: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """遍历输入中的字符串叶子，产出 (点路径, 字符串值)。

    列表元素的路径形如 ``items.0.text``（索引段），字段作用域按顶层变量名
    生效（契约变量都是顶层标量/对象，列表内容随其父变量一起受控）。
    """
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            child = f"{path}.{k}" if path else str(k)
            yield from _iter_string_leaves(v, child)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            child = f"{path}.{i}" if path else str(i)
            yield from _iter_string_leaves(v, child)


def _rule_matches(rule: dict, text: str) -> list[tuple[int, int]]:
    if rule["kind"] == "regex":
        return [(m.start(), m.end()) for m in re.finditer(rule["pattern"], text)]
    pat = rule["pattern"]
    out, start = [], 0
    while True:
        i = text.find(pat, start)
        if i < 0:
            return out
        out.append((i, i + len(pat)))
        start = i + len(pat)


def _merge_intervals(spans: list[tuple[str, int, int]]) -> list[tuple[str, int, int]]:
    """合并重叠区间：同一位置多条规则命中时按规则数组顺序优先（先到先占）。"""
    occupied: list[tuple[int, int]] = []
    merged: list[tuple[str, int, int]] = []
    for rid, s, e in sorted(spans, key=lambda x: (x[1], x[2])):
        if any(s < oe and e > os_ for os_, oe in occupied):
            continue  # 与已占位区间重叠：跳过
        occupied.append((s, e))
        merged.append((rid, s, e))
    return merged


def scan_inputs(rules: list[dict], inputs: dict) -> dict:
    """对原始输入执行隔离扫描（纯函数）。

    返回::

        {blocked: None|{rule_id,name,kind,fields,matches},
         masked_inputs: dict,        # 遮盖后的输入（无阻断时有效）
         tokens: [{token,rule_id,kind,field,path}],
         rules_hit: [rule_id...], masked_count}

    阻断优先：任一 block 规则在其作用域内命中即阻断，不产出遮盖结果。
    替换区间重叠时按规则顺序先到先占，保证输出确定。
    """
    leaves = list(_iter_string_leaves(inputs))
    # 1) 阻断扫描（先于一切替换）
    for rule in rules:
        if rule["action"] != "block":
            continue
        hits: list[str] = []
        n = 0
        for path, text in leaves:
            if _field_applies(rule["fields"], path) and _rule_matches(rule, text):
                hits.append(path)
                n += len(_rule_matches(rule, text))
        if hits:
            return {"blocked": {"rule_id": rule["id"], "name": rule["name"],
                                "kind": rule["kind"], "fields": sorted(set(hits)),
                                "match_count": n},
                    "masked_inputs": None, "tokens": [], "rules_hit": [rule["id"]],
                    "masked_count": 0}
    # 2) 替换扫描
    by_path_spans: dict[str, list[tuple[str, int, int]]] = {}
    rule_by_id = {r["id"]: r for r in rules}
    for rule in rules:
        if rule["action"] != "mask":
            continue
        for path, text in leaves:
            if not _field_applies(rule["fields"], path):
                continue
            for s, e in _rule_matches(rule, text):
                by_path_spans.setdefault(path, []).append((rule["id"], s, e))

    token_records: list[dict] = []
    counters: dict[str, int] = {}
    rules_hit: set[str] = set()

    def apply(obj: Any, path: str = "") -> Any:
        if isinstance(obj, str):
            spans = by_path_spans.get(path)
            if not spans:
                return obj
            chosen = _merge_intervals(spans)
            rules_hit.update(rid for rid, _, _ in chosen)
            by_rule: dict[str, list[tuple[int, int]]] = {}
            for rid, s, e in chosen:
                by_rule.setdefault(rid, []).append((s, e))
            # 每条规则各自编号占位符：重建文本时按位置合并替换
            pieces, last = [], 0
            all_spans = sorted(((s, e, rid) for rid, sp in by_rule.items()
                                for s, e in sp), key=lambda x: x[0])
            for s, e, rid in all_spans:
                r = rule_by_id[rid]
                pieces.append(obj[last:s])
                n = counters.get(r["token"], 0) + 1
                counters[r["token"]] = n
                t = f"{_TOKEN_OPEN}{r['token']}#{n:03d}{_TOKEN_CLOSE}"
                pieces.append(t)
                token_records.append({"token": t, "rule_id": rid, "kind": r["kind"],
                                      "field": path.split(".", 1)[0], "path": path,
                                      "raw": obj[s:e]})
                last = e
            pieces.append(obj[last:])
            return "".join(pieces)
        if isinstance(obj, dict):
            return {k: apply(v, f"{path}.{k}" if path else str(k)) for k, v in obj.items()}
        if isinstance(obj, list):
            return [apply(v, f"{path}.{i}" if path else str(i)) for i, v in enumerate(obj)]
        return obj

    masked = apply(inputs)
    return {"blocked": None, "masked_inputs": masked, "tokens": token_records,
            "rules_hit": sorted(rules_hit), "masked_count": len(token_records)}


def scan_output(rules: list[dict], output_text: str) -> tuple[str, int]:
    """输出侧扫描：所有命中（含 block 规则）统一替换为固定遮盖标记，防止回显。

    返回 (遮盖后输出, 命中数)。block 规则只阻断请求，不会走到输出；这里对
    mask 规则做输出遮盖（对全量输出文本生效，字段作用域不适用）。
    """
    spans: list[tuple[int, int]] = []
    for rule in rules:
        if rule["action"] != "mask":
            continue
        spans.extend(_rule_matches(rule, output_text))
    merged = [(s, e) for _, s, e in _merge_intervals(
        ("__out__", s, e) for s, e in spans)]
    if not merged:
        return output_text, 0
    pieces, last, n = [], 0, 0
    for s, e in sorted(merged):
        pieces.append(output_text[last:s])
        pieces.append(OUTPUT_MASK)
        last = e
        n += 1
    pieces.append(output_text[last:])
    return "".join(pieces), n


def output_contains_match(rules: list[dict], text: str) -> list[str]:
    """泄漏检查：文本中是否仍含任一 mask 规则可命中的原值模式。"""
    return [r["id"] for r in rules if r["action"] == "mask" and _rule_matches(r, text)]


# ---------------------------------------------------------------- 加密（HMAC-SHA256 CTR + 认证标签）


def _hmac(key: bytes, *parts: bytes) -> bytes:
    m = hmac.new(key, b"", hashlib.sha256)
    for p in parts:
        m.update(p)
    return m.digest()


def _keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        block = hmac.new(key, nonce + counter.to_bytes(8, "big"),
                         hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:n])


def _master_key() -> tuple[str, bytes]:
    """取主密钥与密钥标识。

    优先环境变量 ``PROMPTGOV_GUARD_KEY``（运维注入，不落库）；未配置时从实例
    元数据 ``app_meta.guard_key`` 取持久随机密钥（首用生成）。key_id = 密钥
    SHA-256 前 12 位，随密文保存以支持未来轮换。
    """
    env = os.environ.get("PROMPTGOV_GUARD_KEY")
    if env:
        kb = hashlib.sha256(env.encode("utf-8")).digest()
        return "env-" + hashlib.sha256(kb).hexdigest()[:10], kb
    conn = get_conn()
    row = conn.execute("SELECT value FROM app_meta WHERE key='guard_key'").fetchone()
    if row:
        return "inst-" + hashlib.sha256(row["value"].encode()).hexdigest()[:10], \
            hashlib.sha256(row["value"].encode()).digest()
    raw = _secrets.token_hex(32)
    with write_tx() as c:
        c.execute("INSERT OR IGNORE INTO app_meta(key,value) VALUES ('guard_key',?)",
                  (raw,))
    row = get_conn().execute(
        "SELECT value FROM app_meta WHERE key='guard_key'").fetchone()
    kb = hashlib.sha256(row["value"].encode()).digest()
    return "inst-" + hashlib.sha256(row["value"].encode()).hexdigest()[:10], kb


def encrypt_value(plaintext: str) -> bytes:
    """加密单个原值 → ⟨v1|key_id|iv|ct|tag⟩。IV 随机；标签覆盖 key_id/iv/密文。"""
    key_id, key = _master_key()
    iv = _secrets.token_bytes(16)
    data = plaintext.encode("utf-8")
    ks = _keystream(key, iv, len(data))
    ct = bytes(a ^ b for a, b in zip(data, ks))
    tag = _hmac(key, b"guard-v1", key_id.encode(), iv, ct)
    blob = json.dumps({"v": 1, "kid": key_id, "iv": iv.hex(),
                       "ct": ct.hex(), "tag": tag.hex()},
                      sort_keys=True, separators=(",", ":")).encode()
    return blob


def decrypt_value(blob: bytes) -> str:
    """解密 :func:`encrypt_value` 产物；标签不符即抛错（密文被改）。"""
    obj = json.loads(blob.decode())
    iv = bytes.fromhex(obj["iv"])
    ct = bytes.fromhex(obj["ct"])
    tag = bytes.fromhex(obj["tag"])
    # 当前实例密钥验证（导入包不含密文，故历史密文始终由原实例解开）
    key_id, key = _master_key()
    expected = _hmac(key, b"guard-v1", obj["kid"].encode(), iv, ct)
    if not hmac.compare_digest(expected, tag):
        raise GuardError("密文认证失败（密钥不匹配或密文被改），拒绝还原")
    ks = _keystream(key, iv, len(ct))
    data = bytes(a ^ b for a, b in zip(ct, ks))
    return data.decode("utf-8")


def new_token() -> tuple[str, str]:
    """生成还原凭据明文令牌与其存储哈希。明文只在签发响应里出现一次。"""
    plain = _secrets.token_urlsafe(24)
    return plain, hashlib.sha256(plain.encode()).hexdigest()


# ============================================================ 规则版本治理

class GuardDomain(GuardError):
    """400 级隔离配置错误。"""


def _audit(c, actor: str, action: str, entity: str, eid: str, detail: str = ""):
    c.execute("INSERT INTO audit_log(actor,action,entity,entity_id,detail) "
              "VALUES (?,?,?,?,?)", (actor, action, entity, eid, detail))


def _family(c, family_id: str):
    row = c.execute("SELECT * FROM families WHERE family_id=?", (family_id,)).fetchone()
    if not row:
        raise GuardDomain(f"模板族不存在: {family_id}")
    return row


def active_ruleset(c, family_id: str) -> dict | None:
    """族上当前生效的不可变规则集（按指针取行）；未配置返回 None。"""
    f = _family(c, family_id)
    if not f["active_guard_ruleset_id"]:
        return None
    row = c.execute("SELECT * FROM guard_rulesets WHERE ruleset_id=?",
                    (f["active_guard_ruleset_id"],)).fetchone()
    return dict(row) if row else None


def create_ruleset(family_id: str, rules: list[dict], actor: str,
                   note: str = "", activate: bool = False) -> dict:
    """创建一个不可变规则版本（草稿或直接生效）。

    规则内容完全相同（哈希重复）的版本拒绝创建——规则更新必须确实改变规则；
    族内版本号单调递增。``activate=True`` 在同一写事务内翻转族指针（原子生效，
    旧版本置 superseded）。
    """
    norm = compile_ruleset(rules)  # 非法规则抛 ValueError
    chash = ruleset_hash(norm)
    ruleset_id = _uid("grs")
    with write_tx() as c:
        _family(c, family_id)
        dup = c.execute(
            "SELECT 1 FROM guard_rulesets WHERE family_id=? AND content_hash=?",
            (family_id, chash)).fetchone()
        if dup:
            raise GuardDomain("规则内容与某已有版本完全相同（哈希重复），未产生新版本")
        ver = c.execute("SELECT COALESCE(MAX(version),0)+1 AS v FROM guard_rulesets "
                        "WHERE family_id=?", (family_id,)).fetchone()["v"]
        status = "active" if activate else "draft"
        c.execute(
            """INSERT INTO guard_rulesets(ruleset_id,family_id,version,rules_json,
               content_hash,status,note,created_by,activated_at)
               VALUES (?,?,?,?,?,?,?,?,""" + ("datetime('now')" if activate else "NULL") + ")",
            (ruleset_id, family_id, ver,
             json.dumps(norm, ensure_ascii=False, sort_keys=True), chash, status,
             note, actor))
        if activate:
            c.execute("UPDATE guard_rulesets SET status='superseded' WHERE family_id=? "
                      "AND status='active' AND ruleset_id<>?", (family_id, ruleset_id))
            c.execute("UPDATE families SET active_guard_ruleset_id=?, updated_at="
                      "datetime('now') WHERE family_id=?", (ruleset_id, family_id))
        _audit(c, actor, "guard.ruleset.create", "guard_ruleset", ruleset_id,
               f"family={family_id} version={ver} rules={len(norm)} "
               f"hash={chash[:12]} activate={int(activate)}")
    return get_ruleset(ruleset_id)


def activate_ruleset(ruleset_id: str, actor: str,
                     expected_active_ruleset_id: str | None = None) -> dict:
    """把一个草稿规则版本翻为族上唯一生效版本（原子，旧版本 superseded）。

    可选 expected_active_ruleset_id 做 CAS：两位管理员并发更新时，后到者基于
    过期指针操作得到 409，避免静默覆盖。规则指针的翻转不影响任何已固化版本的
    在途/历史请求（它们按 requests 内的 ruleset 版本复核）。
    """
    with write_tx() as c:
        row = c.execute("SELECT * FROM guard_rulesets WHERE ruleset_id=?",
                        (ruleset_id,)).fetchone()
        if not row:
            raise GuardDomain(f"规则版本不存在: {ruleset_id}")
        if row["status"] not in ("draft", "active"):
            raise GuardDomain(f"规则版本状态为 {row['status']}，不能生效（仅草稿可生效）")
        fam = _family(c, row["family_id"])
        if expected_active_ruleset_id is not None and \
                fam["active_guard_ruleset_id"] != expected_active_ruleset_id:
            raise GuardConflict(
                "并发冲突：规则指针已被其他更新改变（CAS 失败），请刷新后重试")
        old = fam["active_guard_ruleset_id"]
        c.execute("UPDATE guard_rulesets SET status='superseded' WHERE family_id=? "
                  "AND status='active'", (row["family_id"],))
        c.execute("UPDATE guard_rulesets SET status='active', activated_at="
                  "datetime('now') WHERE ruleset_id=?", (ruleset_id,))
        c.execute("UPDATE families SET active_guard_ruleset_id=?, updated_at="
                  "datetime('now') WHERE family_id=?",
                  (ruleset_id, row["family_id"]))
        _audit(c, actor, "guard.ruleset.activate", "guard_ruleset", ruleset_id,
               f"family={row['family_id']} version={row['version']} "
               f"prev={old or 'none'} hash={row['content_hash'][:12]}")
    return get_ruleset(ruleset_id)


def get_ruleset(ruleset_id: str) -> dict:
    row = get_conn().execute("SELECT * FROM guard_rulesets WHERE ruleset_id=?",
                             (ruleset_id,)).fetchone()
    if not row:
        raise GuardDomain(f"规则版本不存在: {ruleset_id}")
    d = dict(row)
    d["rules"] = json.loads(d.pop("rules_json"))
    return d


def list_rulesets(family_id: str) -> list[dict]:
    rows = get_conn().execute(
        "SELECT * FROM guard_rulesets WHERE family_id=? ORDER BY version DESC",
        (family_id,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["rules"] = json.loads(d.pop("rules_json"))
        out.append(d)
    return out


def preview(family_id: str, inputs: dict, ruleset_id: str | None = None) -> dict:
    """隔离预览（不落任何数据、不写审计）：按指定版本或缺省当前生效版本扫描。"""
    conn = get_conn()
    if ruleset_id:
        rs = conn.execute("SELECT * FROM guard_rulesets WHERE ruleset_id=?",
                          (ruleset_id,)).fetchone()
        if not rs:
            raise GuardDomain(f"规则版本不存在: {ruleset_id}")
        rs = dict(rs)
    else:
        rs = active_ruleset(conn, family_id)
        if rs is None:
            return {"configured": False, "ruleset_version": None,
                    "blocked": None, "masked_inputs": inputs, "tokens": [],
                    "masked_count": 0}
    rules = json.loads(rs["rules_json"])
    res = scan_inputs(rules, inputs)
    return {"configured": True, "ruleset_id": rs["ruleset_id"],
            "ruleset_version": rs["version"], "ruleset_hash": rs["content_hash"],
            **res}


# ------------------------------------------------------------ 复核人授权

def grant_reviewer(family_id: str, reviewer: str, actor: str, reason: str = "") -> dict:
    """授权一名复核人为该模板族签发还原凭据。幂等：存在未撤销授权则返回原行。"""
    reviewer = reviewer.strip()
    if not reviewer:
        raise GuardDomain("复核人标识不能为空")
    with write_tx() as c:
        _family(c, family_id)
        existing = c.execute(
            "SELECT * FROM guard_reviewer_grants WHERE family_id=? AND reviewer=? "
            "AND revoked_at IS NULL", (family_id, reviewer)).fetchone()
        if existing:
            gid = existing["grant_id"]
        else:
            gid = _uid("grg")
            c.execute(
                """INSERT INTO guard_reviewer_grants(grant_id,family_id,reviewer,
                   granted_by,reason) VALUES (?,?,?,?,?)""",
                (gid, family_id, reviewer, actor, reason))
            _audit(c, actor, "guard.grant", "guard_grant", gid,
                   f"family={family_id} reviewer={reviewer}")
    return get_grant(gid)


def revoke_reviewer(grant_id: str, expected_version: int, actor: str,
                    reason: str = "") -> dict:
    """撤销复核授权（expected_version CAS）。撤销后该复核人不能再签发/使用新凭据，
    已签发但未使用的凭据在还原时也按授权已撤销拒绝。"""
    with write_tx() as c:
        row = c.execute("SELECT * FROM guard_reviewer_grants WHERE grant_id=?",
                        (grant_id,)).fetchone()
        if not row:
            raise GuardDomain(f"复核授权不存在: {grant_id}")
        if row["revoked_at"]:
            raise GuardConflict(f"授权 {grant_id} 已被撤销")
        cur = c.execute(
            "UPDATE guard_reviewer_grants SET revoked_at=datetime('now'), revoked_by=?, "
            "reason=?, revoke_version=revoke_version+1 WHERE grant_id=? AND "
            "revoke_version=? AND revoked_at IS NULL",
            (actor, reason, grant_id, int(expected_version)))
        if cur.rowcount != 1:
            raise GuardConflict("并发冲突：授权版本号已变化（CAS 失败），请刷新后重试")
        _audit(c, actor, "guard.grant.revoke", "guard_grant", grant_id,
               f"family={row['family_id']} reviewer={row['reviewer']}")
    return get_grant(grant_id)


def get_grant(grant_id: str) -> dict:
    row = get_conn().execute("SELECT * FROM guard_reviewer_grants WHERE grant_id=?",
                             (grant_id,)).fetchone()
    if not row:
        raise GuardDomain(f"复核授权不存在: {grant_id}")
    return dict(row)


def list_grants(family_id: str | None = None) -> list[dict]:
    q = "SELECT * FROM guard_reviewer_grants"
    args: tuple = ()
    if family_id:
        q += " WHERE family_id=?"
        args = (family_id,)
    return [dict(r) for r in get_conn().execute(
        q + " ORDER BY created_at DESC", args).fetchall()]


def _active_grant(c, family_id: str, reviewer: str):
    return c.execute(
        "SELECT * FROM guard_reviewer_grants WHERE family_id=? AND reviewer=? "
        "AND revoked_at IS NULL", (family_id, reviewer)).fetchone()


# ------------------------------------------------------------ 还原凭据（短期、单次、绑定请求）

DEFAULT_TTL_SECONDS = 300


def issue_credential(request_id: str, reviewer: str, actor: str,
                     ttl_seconds: int | None = None) -> dict:
    """为某个被隔离请求签发短期还原凭据。

    - 复核人必须持有该请求所属模板族的**未撤销**授权；
    - 凭据绑定单个 request_id，不可跨请求使用；
    - 同一复核人对同一请求同时只允许一张未消费且未过期的凭据（防凭据堆积）；
    - 明文令牌只在本响应出现一次，库里只存 SHA-256。
    """
    reviewer = reviewer.strip()
    ttl = int(ttl_seconds or DEFAULT_TTL_SECONDS)
    if ttl <= 0 or ttl > 3600:
        raise GuardDomain("凭据有效期必须是 1~3600 秒")
    with write_tx() as c:
        req = c.execute("SELECT * FROM requests WHERE request_id=?",
                        (request_id,)).fetchone()
        if not req:
            raise GuardDomain(f"请求不存在: {request_id}")
        mask = c.execute("SELECT 1 FROM guard_request_masks WHERE request_id=?",
                         (request_id,)).fetchone()
        if not mask:
            raise GuardDomain("该请求没有遮盖映射（未启用隔离或未发生遮盖），无需还原")
        if not c.execute("SELECT 1 FROM guard_secrets WHERE request_id=?",
                         (request_id,)).fetchone():
            raise GuardDomain("该请求没有可还原的密文值")
        grant = _active_grant(c, req["family_id"], reviewer)
        if not grant:
            _reveal_audit(c, request_id, "", reviewer, "denied_unauthorized",
                          f"family={req['family_id']} 签发阶段：复核人无有效授权")
            raise GuardUnauthorized(
                f"复核人 {reviewer} 未获模板族 {req['family_id']} 的还原授权"
                "（或授权已撤销），拒绝签发凭据")
        live = c.execute(
            "SELECT credential_id FROM guard_credentials WHERE request_id=? AND reviewer=? "
            "AND status='issued' AND expires_at>datetime('now')",
            (request_id, reviewer)).fetchone()
        if live:
            raise GuardReused(
                "该复核人对此请求已有一张未消费且有效的凭据，请先使用或等待其过期，"
                "不能重复签发")
        plain, tok_hash = new_token()
        cid = _uid("grc")
        c.execute(
            """INSERT INTO guard_credentials(credential_id,request_id,family_id,reviewer,
               grant_id,token_hash,ttl_seconds,expires_at)
               VALUES (?,?,?,?,?,?,?, datetime('now', ?))""",
            (cid, request_id, req["family_id"], reviewer, grant["grant_id"],
             tok_hash, ttl, f"+{ttl} seconds"))
        _reveal_audit(c, request_id, cid, reviewer, "issued",
                      f"family={req['family_id']} ttl={ttl}s grant={grant['grant_id']}")
        row = c.execute("SELECT issued_at,expires_at FROM guard_credentials "
                        "WHERE credential_id=?", (cid,)).fetchone()
    # 明文令牌仅此一次随响应返回
    return {"credential_id": cid, "request_id": request_id, "reviewer": reviewer,
            "token": plain, "ttl_seconds": ttl, "issued_at": row["issued_at"],
            "expires_at": row["expires_at"]}


def _reveal_audit(c, request_id: str, cid: str, reviewer: str, result: str,
                  detail: str = ""):
    c.execute(
        "INSERT INTO guard_reveals(request_id,credential_id,reviewer,result,detail) "
        "VALUES (?,?,?,?,?)", (request_id, cid, reviewer, result, detail))


class _RevealDeny(Exception):
    """还原被拒的内部信号：携带要抛出的业务异常与审计信息。

    审计必须在事务回滚**之后**单独写入，否则会随回滚一起丢失（拒绝不得改变
    凭据/密文状态，但要留下逐次尝试记录）。
    """

    def __init__(self, exc: GuardError, request_id: str, cid: str, reviewer: str,
                 result: str, detail: str):
        self.exc = exc
        self.audit = (request_id, cid, reviewer, result, detail)
        super().__init__(str(exc))


def reveal(request_id: str, token: str, actor: str = "api") -> dict:
    """用短期凭据单次还原原值。全部判定在单个写锁事务内，凭据行守卫消费。

    失败一律不返回任何原值，且每次尝试都留 guard_reveals 审计：
    - 令牌不存在/不属于该请求：denied_token / denied_unauthorized（403）；
    - 授权已撤销：denied_unauthorized（403，凭据作废）；
    - 已过期：denied_expired（403）；
    - 已消费（重复还原）：denied_reused（409），绝不再次暴露原值。
    成功：行守卫把凭据置 consumed 后才解密，并发的第二次还原必走 reused。
    """
    token = (token or "").strip()
    if not token:
        raise GuardUnauthorized("缺少还原令牌")
    tok_hash = hashlib.sha256(token.encode()).hexdigest()
    payload = None
    try:
      with write_tx() as c:
        cred = c.execute("SELECT * FROM guard_credentials WHERE token_hash=?",
                         (tok_hash,)).fetchone()
        if not cred:
            raise _RevealDeny(GuardUnauthorized("还原令牌无效"), request_id, "", "",
                             "denied_token", f"令牌哈希 {tok_hash[:12]} 不存在")
        if cred["request_id"] != request_id:
            raise _RevealDeny(
                GuardUnauthorized("还原令牌与请求不匹配（凭据绑定单个请求）"),
                request_id, cred["credential_id"], cred["reviewer"],
                "denied_unauthorized", f"令牌绑定另一请求 {cred['request_id']}")
        if cred["status"] == "consumed":
            raise _RevealDeny(
                GuardReused("该还原凭据已消费（单次有效），重复还原不得再次暴露原值"),
                request_id, cred["credential_id"], cred["reviewer"], "denied_reused",
                f"credential={cred['credential_id']} consumed_at={cred['consumed_at']}")
        # 授权可在签发后被撤销：还原时按业务时刻重新确认
        grant = _active_grant(c, cred["family_id"], cred["reviewer"])
        if not grant:
            raise _RevealDeny(
                GuardUnauthorized("复核授权已被撤销，凭据已作废"),
                request_id, cred["credential_id"], cred["reviewer"],
                "denied_unauthorized", "复核授权已撤销/不存在，凭据作废")
        now = c.execute("SELECT datetime('now') AS t").fetchone()["t"]
        if now >= cred["expires_at"]:
            raise _RevealDeny(
                GuardExpired(f"还原凭据已于 {cred['expires_at']} 过期（单次短期凭据）"),
                request_id, cred["credential_id"], cred["reviewer"], "denied_expired",
                f"expires_at={cred['expires_at']} now={now}")
        # 行守卫消费：只有仍 issued 且未过期的行能被更新，并发只一胜
        cur = c.execute(
            "UPDATE guard_credentials SET status='consumed', consumed_at=datetime('now') "
            "WHERE credential_id=? AND status='issued' AND "
            "datetime('now')<expires_at", (cred["credential_id"],))
        if cur.rowcount != 1:
            raise _RevealDeny(
                GuardReused("凭据已被并发消费，本次还原不暴露原值"),
                request_id, cred["credential_id"], cred["reviewer"], "denied_reused",
                "消费行守卫失败（并发单次竞争）")

        mask = c.execute("SELECT tokens_json FROM guard_request_masks WHERE request_id=?",
                         (request_id,)).fetchone()
        tokens = json.loads(mask["tokens_json"]) if mask else []
        secrets = c.execute("SELECT token,ciphertext FROM guard_secrets WHERE request_id=?",
                            (request_id,)).fetchall()
        sec_by_token = {r["token"]: r["ciphertext"] for r in secrets}
        values = []
        raw_map = {}
        for t in tokens:
            blob = sec_by_token.get(t["token"])
            if blob is None:
                continue
            value = decrypt_value(bytes(blob))
            raw_map[t["token"]] = value
            values.append({"token": t["token"], "rule_id": t["rule_id"],
                           "field": t["field"], "path": t["path"], "value": value})
        # 用库里的遮盖输入逐占位符还原，重建原始输入（不落库，仅本次返回）
        req = c.execute("SELECT inputs_json FROM requests WHERE request_id=?",
                        (request_id,)).fetchone()
        raw_inputs = json.loads(req["inputs_json"])

        def restore(obj):
            if isinstance(obj, str):
                if obj in raw_map:
                    return raw_map[obj]
                # 占位符可能内嵌在更长文本中：逐 token 做字符串内插替换
                if any(tok in obj for tok in raw_map):
                    out = obj
                    for tok, val in raw_map.items():
                        out = out.replace(tok, val)
                    return out
                return obj
            if isinstance(obj, dict):
                return {k: restore(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [restore(v) for v in obj]
            return obj

        raw_inputs = restore(raw_inputs)
        _reveal_audit(c, request_id, cred["credential_id"], cred["reviewer"],
                      "revealed", f"family={cred['family_id']} values={len(values)} "
                                  f"credential={cred['credential_id']}")
        payload = {"request_id": request_id, "reviewer": cred["reviewer"],
                   "credential_id": cred["credential_id"], "consumed_at": now,
                   "values": values, "raw_inputs": raw_inputs}
    except _RevealDeny as deny:
        with write_tx() as ac:
            _reveal_audit(ac, *deny.audit)
        raise deny.exc
    return payload


def request_guard_view(request_id: str) -> dict | None:
    """请求复查页：固化的规则版本、遮盖映射（无原值）、密文计数、还原审计。"""
    req = get_conn().execute(
        "SELECT guard_ruleset_id,guard_ruleset_version,guard_ruleset_hash,guard_status,"
        "raw_input_digest FROM requests WHERE request_id=?", (request_id,)).fetchone()
    if not req:
        raise GuardDomain(f"请求不存在: {request_id}")
    if not req["guard_ruleset_id"]:
        return None
    d = {"ruleset_id": req["guard_ruleset_id"],
         "ruleset_version": req["guard_ruleset_version"],
         "ruleset_hash": req["guard_ruleset_hash"],
         "status": req["guard_status"], "raw_input_digest": req["raw_input_digest"]}
    mask = get_conn().execute("SELECT * FROM guard_request_masks WHERE request_id=?",
                              (request_id,)).fetchone()
    if mask:
        d["tokens"] = json.loads(mask["tokens_json"])
        d["actions"] = json.loads(mask["actions_json"])
        d["output_actions"] = json.loads(mask["output_actions_json"])
    else:
        d["tokens"], d["actions"], d["output_actions"] = [], {"masked": 0}, []
    d["secret_count"] = get_conn().execute(
        "SELECT COUNT(*) c FROM guard_secrets WHERE request_id=?",
        (request_id,)).fetchone()["c"]
    d["credentials"] = [dict(r) for r in get_conn().execute(
        "SELECT credential_id,reviewer,status,ttl_seconds,issued_at,expires_at,"
        "consumed_at FROM guard_credentials WHERE request_id=? ORDER BY issued_at DESC",
        (request_id,)).fetchall()]
    d["reveals"] = [dict(r) for r in get_conn().execute(
        "SELECT id,credential_id,reviewer,result,detail,created_at FROM guard_reveals "
        "WHERE request_id=? ORDER BY id DESC", (request_id,)).fetchall()]
    return d


def list_block_log(family_id: str | None = None, limit: int = 100) -> list[dict]:
    q = "SELECT bl.* FROM guard_block_log bl"
    args: tuple = ()
    if family_id:
        q += " WHERE bl.family_id=?"
        args = (family_id,)
    q += " ORDER BY bl.id DESC LIMIT ?"
    args = args + (limit,)
    return [dict(r) for r in get_conn().execute(q, args).fetchall()]


# ============================================================ 服务层共用辅助

def storable_tokens(tokens: list[dict]) -> list[dict]:
    """把扫描内存记录（含 raw 原值）转换为落库映射（剥离 raw，明文绝不入库）。"""
    return [{k: t[k] for k in ("token", "rule_id", "kind", "field", "path")}
            for t in tokens]


def persist_secrets(c, request_id: str, tokens: list[dict]) -> None:
    """在调用方写事务内把每个命中原值加密写入 guard_secrets（唯一密文存放处）。"""
    for t in tokens:
        c.execute(
            "INSERT INTO guard_secrets(request_id,token,ciphertext) VALUES (?,?,?)",
            (request_id, t["token"], encrypt_value(t["raw"])))


def log_block(c, *, request_id: str, family_id: str, rs: dict, blocked: dict,
              raw_input_digest: str, actor: str) -> None:
    """在调用方写事务内记录阻断（只含规则标识/字段/计数，绝无原值）。

    同一 request_id+原始输入摘要唯一：重复阻断请求命中既有行，不重复插入。
    """
    c.execute(
        """INSERT INTO guard_block_log(request_id,family_id,ruleset_id,ruleset_version,
           ruleset_hash,raw_input_digest,rule_id,rule_name,kind,fields_json,
           match_count,actor)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(request_id,raw_input_digest) DO NOTHING""",
        (request_id, family_id, rs["ruleset_id"], rs["version"], rs["content_hash"],
         raw_input_digest, blocked["rule_id"], blocked.get("name", ""), blocked["kind"],
         json.dumps(blocked["fields"], ensure_ascii=False), blocked.get("match_count", 1),
         actor))


def find_block_log(request_id: str, raw_input_digest: str | None = None) -> dict | None:
    if raw_input_digest:
        r = get_conn().execute(
            "SELECT * FROM guard_block_log WHERE request_id=? AND raw_input_digest=?",
            (request_id, raw_input_digest)).fetchone()
    else:
        r = get_conn().execute(
            "SELECT * FROM guard_block_log WHERE request_id=? ORDER BY id DESC LIMIT 1",
            (request_id,)).fetchone()
    d = dict(r) if r else None
    if d:
        d["fields"] = json.loads(d.pop("fields_json"))
    return d


