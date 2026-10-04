"""敏感内容隔离核心：规则规范化、确定性识别/替换、密文封装。

纯函数部分（不碰数据库）保证：
- 同一规则版本 + 同一输入永远得到同一遮盖结果与同一遮盖映射（重复推理幂等、
  评估回放/证据包复核可逐字节重现）；
- 明文只存在于进程内存中；落库的只有遮盖后内容与**密文**条目；
- 还原凭据本身只以 SHA-256 哈希存储，明文短期凭据只在创建响应里出现一次。

零第三方依赖：演示加密用 sha256 派生密钥流做 XOR（标准库 hashlib/base64），
生产环境可把 :func:`seal`/:func:`open_entry` 换成 KMS 信封加密，存储格式与
上层接口不变。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from typing import Any

from . import core

# 允许的动作
ACTIONS = ("redact", "deny")
# 可识别的匹配方式（演示实现：字面量子串；结构对更多类型留口）
MATCH_KINDS = ("literal",)
# field=* 表示对契约内任意字符串变量值生效
ANY_FIELD = "*"

DENY_OUTPUT = json.dumps(
    {"answer": "请求包含被策略禁止的敏感内容，已被在线隔离策略拒绝（deny）。",
     "blocked": True, "label": "blocked", "score": 0,
     "_provenance": {"masked": True, "action": "deny"}},
    ensure_ascii=False, sort_keys=True)


class MaskRuleError(ValueError):
    """规则配置错误（400）。"""


def normalize_rules(rules: list[dict]) -> list[dict]:
    """校验并规范化管理员提交的规则集，返回排序后的不可变列表。

    规则形如::

        {"rule_id": "phone", "field": "customer_text", "match": "literal",
         "pattern": "13800001111", "replacement": "[手机号]"}

    - rule_id 同版本内唯一且非空；field 为契约变量名或 ``*``（任意字符串变量）；
    - pattern 必须非空（演示仅支持字面量子串识别）；
    - replacement 可空（缺省为 ``[<rule_id>]`` 形式的遮盖标记）。
    """
    if not isinstance(rules, list) or not rules:
        raise MaskRuleError("规则集必须是非空数组（至少一条规则；暂时无需隔离请勿启用）")
    out: list[dict] = []
    seen: set[str] = set()
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            raise MaskRuleError(f"第 {i + 1} 条规则不是对象")
        rid = str(r.get("rule_id", "")).strip()
        if not rid:
            raise MaskRuleError(f"第 {i + 1} 条规则缺少 rule_id")
        if rid in seen:
            raise MaskRuleError(f"rule_id 重复: {rid}")
        seen.add(rid)
        field = str(r.get("field", "")).strip() or ANY_FIELD
        match = str(r.get("match", "literal")).strip()
        if match not in MATCH_KINDS:
            raise MaskRuleError(f"规则 {rid} 的 match 仅支持 {MATCH_KINDS}，收到 {match!r}")
        pattern = r.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise MaskRuleError(f"规则 {rid} 的 pattern 必须是非空字符串")
        replacement = str(r.get("replacement", "") or "")
        out.append({"rule_id": rid, "field": field, "match": match,
                    "pattern": pattern,
                    "replacement": replacement or f"[{rid}]"})
    out.sort(key=lambda r: r["rule_id"])
    return out


def rules_fingerprint(action: str, rules: list[dict]) -> str:
    """动作+规则集的规范化指纹（版本内容寻址；重复配置幂等识别）。"""
    return core.sha256_hex(core.canonical_json({"action": action, "rules": rules}))


# ---------------------------------------------------------------- 识别 / 替换

def _iter_string_fields(inputs: dict, contract: dict):
    """产出 (field_name, value)：优先精确字段规则，其次 * 规则。

    只处理契约声明的字符串变量（网关投影之后的输入），与模板渲染口径一致。
    """
    for name, value in inputs.items():
        if isinstance(value, str):
            yield name, value


def _scan_value(text: str, patterns: list[tuple[str, str, str]]) -> list[tuple[int, int, str, str]]:
    """在单个字符串里找全部非重叠命中，按起始位置/长度排序。

    返回 (start, end, rule_id, replacement)；重叠时起点更早、模式更长者优先，
    保证同一文本的遮盖结果确定、与扫描顺序无关。
    """
    hits: list[tuple[int, int, str, str]] = []
    for rule_id, pattern, replacement in patterns:
        start = 0
        while True:
            idx = text.find(pattern, start)
            if idx < 0:
                break
            hits.append((idx, idx + len(pattern), rule_id, replacement))
            start = idx + len(pattern)
    # 起点升序、更长的模式优先；同起点同长度按 rule_id 定序
    hits.sort(key=lambda h: (h[0], -(h[1] - h[0]), h[2]))
    chosen: list[tuple[int, int, str, str]] = []
    for h in hits:
        if chosen and h[0] < chosen[-1][1]:
            continue  # 与已选片段重叠，跳过（确定性去重）
        chosen.append(h)
    return chosen


def apply_rules(action: str, rules: list[dict], inputs: dict) -> dict:
    """对**投影后**的输入执行识别与替换（纯函数）。

    返回::

        {"action": "redact"|"deny", "matched": bool,
         "masked_inputs": {...},        # 替换后参与模板渲染的输入
         "findings": [{"field","rule_id","value","replacement","token"}]}

    - deny：只要有任意命中即 matched=True，masked_inputs 保持原样（不会进入渲染）；
    - redact：命中值替换为遮盖标记；同一请求内同一 (field, 原值) 复用同一 token，
      遮盖结果对重复推理保持逐字节一致。findings 里的 value 是明文，仅用于当场
      密封入库，调用方不得把它写进审计/日志。
    """
    by_field: dict[str, list[dict]] = {}
    wildcard: list[dict] = []
    for r in rules:
        (wildcard if r["field"] == ANY_FIELD else by_field.setdefault(r["field"], [])).append(r)

    findings: list[dict] = []
    masked_inputs = dict(inputs)
    # (field, 原值) -> token：同值同标，确定性
    token_map: dict[tuple[str, str], str] = {}
    matched = False
    for name, value in _iter_string_fields(inputs, {}):
        applicable = by_field.get(name, []) + wildcard
        if not applicable:
            continue
        patterns = [(r["rule_id"], r["pattern"], r["replacement"]) for r in applicable]
        spans = _scan_value(value, patterns)
        if not spans:
            continue
        matched = True
        if action == "deny":
            for s, e, rid, _ in spans:
                findings.append({"field": name, "rule_id": rid, "value": value[s:e],
                                 "replacement": "", "token": ""})
            continue
        # redact：从后往前替换，避免位移
        new_value = value
        for s, e, rid, replacement in reversed(spans):
            original = value[s:e]
            key = (name, original)
            token = token_map.get(key)
            if token is None:
                token = f"⟨mask:{len(token_map) + 1:03d}:{rid}⟩"
                token_map[key] = token
            label = replacement if replacement == f"[{rid}]" else replacement
            # replacement 若就是默认 [rid]，附加稳定 token 让同值可对齐
            visible = f"{label}{token}" if label.startswith("[") else f"{label}{token}"
            new_value = new_value[:s] + visible + new_value[e:]
            findings.append({"field": name, "rule_id": rid, "value": original,
                             "replacement": visible, "token": token})
        masked_inputs[name] = new_value
    return {"action": action, "matched": matched, "masked_inputs": masked_inputs,
            "findings": findings}


# ---------------------------------------------------------------- 密文封装

_SERVER_SECRET_SALT = "promptgov-mask-v1"


def _keystream(secret_context: str, n: int) -> bytes:
    """由 sha256 链式派生 n 字节密钥流（确定性、零依赖）。"""
    out = b""
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(
            f"{_SERVER_SECRET_SALT}|{secret_context}|{counter}".encode("utf-8")).digest()
        counter += 1
    return out[:n]


def seal(rule_version_id: str, request_id: str, token: str, plaintext: str) -> str:
    """把单个命中明文密封为 base64 密文。

    密钥流绑定 (规则版本, 请求, token)：密文离开本行上下文无法用同一流程解出，
    且不同请求/不同条目的密文不可互换（证据包导出后没有服务器侧还原入口）。
    """
    data = plaintext.encode("utf-8")
    ctx = f"{rule_version_id}|{request_id}|{token}"
    stream = _keystream(ctx, len(data))
    ct = bytes(b ^ k for b, k in zip(data, stream))
    return base64.b64encode(ct).decode("ascii")


def open_entry(rule_version_id: str, request_id: str, token: str, ct_b64: str) -> str:
    """还原单条密文（仅在凭据消费成功的事务内调用）。"""
    ct = base64.b64decode(ct_b64.encode("ascii"))
    ctx = f"{rule_version_id}|{request_id}|{token}"
    stream = _keystream(ctx, len(ct))
    return bytes(b ^ k for b, k in zip(ct, stream)).decode("utf-8")


def new_reveal_secret() -> str:
    """生成一次性短期还原凭据明文（只在创建响应中返回这一次）。"""
    return "mrv_" + secrets.token_urlsafe(24)


def hash_token(secret: str) -> str:
    """凭据明文的落库形式：SHA-256（不可逆；校验用 hmac.compare_digest）。"""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def tokens_equal(presented: str, stored_sha: str) -> bool:
    return hmac.compare_digest(hash_token(presented), stored_sha)


def sealed_entries(rule_version_id: str, request_id: str,
                   findings: list[dict]) -> list[dict]:
    """把 apply_rules 的当场 findings 密封为可落库条目（不含可识别明文）。"""
    entries = []
    for f in findings:
        if not f.get("token"):
            continue
        entries.append({
            "token": f["token"], "field": f["field"], "rule_id": f["rule_id"],
            "replacement": f["replacement"],
            "ct": seal(rule_version_id, request_id, f["token"], f["value"]),
        })
    entries.sort(key=lambda e: (e["field"], e["token"]))
    return entries
