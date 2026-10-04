"""敏感内容隔离服务层。

- 规则按模板族**版本化不可变**配置（draft/active/retired），发布新版本在单
  ``BEGIN IMMEDIATE`` 事务内翻转族上唯一指针；正在处理的在途请求已在路由事务内
  固定旧版本，规则更新只影响其后的新请求，绝不能改写历史（见 :func:`pin_active`
  与 services.invoke 的二次落库——落库时**不重读**指针）。
- 线上请求、评估回放、证据包复核共用同一套版本化规则；替换后的输入才进入模板
  渲染与模型，阻断请求不接触模型。
- 原值只以密文（:func:`promptgov.masking.seal`）落在 ``mask_hits``；审计明细与
- 证据包导出永不包含明文（只记 rule_id/字段/token/计数）。
- 还原凭据绑定 (请求, 复核人)、短期有效（半开区间）、**单次消费**：消费用行守卫
  UPDATE 原子完成，重复/并发还原只有一次能拿到原值。
"""
from __future__ import annotations

import json
from typing import Any

from . import core, masking
from . import services as _svc
from .errors import Conflict, DomainError, NotFound
from .db import audit, get_conn, write_tx

DEFAULT_TTL_SECONDS = 600
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 3600


def _uid(prefix: str) -> str:
    return _svc._uid(prefix)


def _loads(s):
    return json.loads(s)


def db_now(c=None) -> str:
    return _svc.db_now(c)


class _RollbackAndAudit(Exception):
    """内部信号：凭据判定失败 -> 回滚业务事务，并在事务外独立补一条拒绝审计。

    失败审计不能与判定同事务（回滚会把审计一起撤销）；由
    :func:`consume_reveal_token` 捕获后在独立事务补记，再向调用方抛原业务异常。
    """

    def __init__(self, actor, token_id, request_id, code, exc_cls, msg):
        super().__init__(msg)
        self.actor = actor
        self.token_id = token_id
        self.request_id = request_id
        self.code = code
        self.exc_cls = exc_cls
        self.msg = msg


# ================================================================ 规则版本

def _rule_row(rule_version_id: str):
    row = get_conn().execute(
        "SELECT * FROM mask_rule_versions WHERE rule_version_id=?",
        (rule_version_id,)).fetchone()
    if not row:
        raise NotFound(f"隔离规则版本不存在: {rule_version_id}")
    return row


def _rule_view(row) -> dict:
    d = dict(row)
    d["rules"] = _loads(d["rules_json"])
    return d


def get_rule_version(rule_version_id: str) -> dict:
    return _rule_view(_rule_row(rule_version_id))


def active_rule_version(conn, family_id: str) -> dict | None:
    """族当前生效的规则版本（调用方应在写锁事务内读取以固定在途请求）。"""
    f = conn.execute("SELECT mask_active_version_id FROM families WHERE family_id=?",
                     (family_id,)).fetchone()
    if not f:
        raise NotFound(f"模板族不存在: {family_id}")
    rid = f["mask_active_version_id"]
    if not rid:
        return None
    row = conn.execute("SELECT * FROM mask_rule_versions WHERE rule_version_id=?",
                       (rid,)).fetchone()
    return _rule_view(row) if row else None


def pin_active(conn, family_id: str) -> dict | None:
    """在请求/评估的**路由事务内**固定规则版本快照。

    返回的 dict 被后续渲染/落库全程复用；落库事务不得重新读取族指针——规则在
    推理期间更新时，本请求仍按固定版本完成与复查（"规则更新不改写在途请求"）。
    """
    return active_rule_version(conn, family_id)


def list_rule_versions(family_id: str) -> list[dict]:
    if not get_conn().execute("SELECT 1 FROM families WHERE family_id=?",
                             (family_id,)).fetchone():
        raise NotFound(f"模板族不存在: {family_id}")
    rows = get_conn().execute(
        "SELECT * FROM mask_rule_versions WHERE family_id=? ORDER BY version_no DESC",
        (family_id,)).fetchall()
    out = [_rule_view(r) for r in rows]
    active_id = get_conn().execute(
        "SELECT mask_active_version_id FROM families WHERE family_id=?",
        (family_id,)).fetchone()["mask_active_version_id"]
    for d in out:
        d["is_active"] = d["rule_version_id"] == active_id
    return out


def create_rule_version(family_id: str, action: str, rules: list[dict], actor: str,
                        note: str = "", activate: bool = True) -> dict:
    """创建（并默认立即发布）一条新的不可变隔离规则版本。

    - action=redact：命中值替换为遮盖标记后参与模板渲染；
    - action=deny：任意命中即拒绝，请求不接触模型；
    - 与当前生效版本指纹完全相同的配置拒绝重复发版（幂等保护）。
    发布在同一写事务内翻转 families.mask_active_version_id 并把旧版本置 retired。
    """
    action = str(action or "redact").strip()
    if action not in masking.ACTIONS:
        raise DomainError(f"策略动作必须是 {masking.ACTIONS}")
    norm = masking.normalize_rules(rules)
    fingerprint = masking.rules_fingerprint(action, norm)

    with write_tx() as c:
        fam = c.execute("SELECT * FROM families WHERE family_id=?",
                        (family_id,)).fetchone()
        if not fam:
            raise NotFound(f"模板族不存在: {family_id}")
        if fam["mask_active_version_id"]:
            cur = c.execute("SELECT * FROM mask_rule_versions WHERE rule_version_id=?",
                            (fam["mask_active_version_id"],)).fetchone()
            if cur and cur["rules_hash"] == fingerprint:
                raise Conflict("规则与动作与当前生效版本完全相同（指纹一致），"
                               "未产生新版本；确需重发请先修改规则")
        nxt = int(c.execute(
            "SELECT COALESCE(MAX(version_no),0)+1 AS n FROM mask_rule_versions "
            "WHERE family_id=?", (family_id,)).fetchone()["n"])
        rule_version_id = _uid("mrv")
        status = "active" if activate else "draft"
        c.execute(
            """INSERT INTO mask_rule_versions(rule_version_id,family_id,version_no,status,
               action,rules_json,rules_hash,note,created_by,activated_at)
               VALUES (?,?,?,?,?,?,?,?,?, CASE WHEN ?='active' THEN datetime('now') END)""",
            (rule_version_id, family_id, nxt, status, action,
             json.dumps(norm, ensure_ascii=False, sort_keys=True), fingerprint,
             note, actor, status))
        if activate:
            c.execute(
                "UPDATE mask_rule_versions SET status='retired', retired_at=datetime('now') "
                "WHERE family_id=? AND status='active' AND rule_version_id<>?",
                (family_id, rule_version_id))
            c.execute("UPDATE families SET mask_active_version_id=?, updated_at=datetime('now') "
                      "WHERE family_id=?", (rule_version_id, family_id))
        audit(actor, "mask.rule.create", "mask_rule", rule_version_id,
              f"family={family_id} v{nxt} action={action} rules={len(norm)} "
              f"activate={int(bool(activate))} ids={[r['rule_id'] for r in norm]}")
    return get_rule_version(rule_version_id)


def activate_rule_version(rule_version_id: str, actor: str) -> dict:
    """把已存在的规则版本切为当前生效（旧 active 置 retired），单事务翻唯一指针。

    只影响之后的新请求；已经固定旧版本的在途/历史请求不被改写。
    """
    with write_tx() as c:
        r = c.execute("SELECT * FROM mask_rule_versions WHERE rule_version_id=?",
                      (rule_version_id,)).fetchone()
        if not r:
            raise NotFound(f"隔离规则版本不存在: {rule_version_id}")
        fam = c.execute("SELECT mask_active_version_id FROM families WHERE family_id=?",
                        (r["family_id"],)).fetchone()
        if fam["mask_active_version_id"] == rule_version_id:
            raise Conflict("该规则版本已是当前生效版本")
        c.execute("UPDATE mask_rule_versions SET status='retired', "
                  "retired_at=datetime('now') WHERE family_id=? AND status='active'",
                  (r["family_id"],))
        c.execute("UPDATE mask_rule_versions SET status='active', retired_at=NULL, "
                  "activated_at=COALESCE(activated_at, datetime('now')) "
                  "WHERE rule_version_id=?", (rule_version_id,))
        c.execute("UPDATE families SET mask_active_version_id=?, updated_at=datetime('now') "
                  "WHERE family_id=?", (rule_version_id, r["family_id"]))
        audit(actor, "mask.rule.activate", "mask_rule", rule_version_id,
              f"family={r['family_id']} v{r['version_no']} action={r['action']}")
    return get_rule_version(rule_version_id)


# ================================================================ 预览

def preview(family_id: str, action: str, rules: list[dict], inputs: dict,
            version_id: str | None = None, actor: str = "api") -> dict:
    """隔离预览：对管理员提供的样本输入当场跑识别/替换，**不落任何数据**。

    响应中的 findings 含原值片段（仅回显给正在配置规则的管理员），但只存在于
    本次 HTTP 响应；审计只记录规则 id/命中数，绝不记录样本值。可选 version_id
    时用该版本模板渲染"替换后参与渲染"的提示预览。
    """
    action = str(action or "redact").strip()
    if action not in masking.ACTIONS:
        raise DomainError(f"策略动作必须是 {masking.ACTIONS}")
    norm = masking.normalize_rules(rules)
    if not isinstance(inputs, dict):
        raise DomainError("预览输入必须是 JSON 对象")
    result = masking.apply_rules(action, norm, inputs)
    rendered = None
    render_error = None
    if version_id:
        from .services import _version_row
        v = _version_row(version_id)
        if v["family_id"] != family_id:
            raise DomainError("预览版本不属于该模板族")
        contract = _loads(v["variable_contract"])
        try:
            rendered = core.render_prompt(v["system_instruction"], contract,
                                          result["masked_inputs"])
        except Exception as exc:  # noqa: BLE001
            render_error = str(exc)
    findings = [{"field": f["field"], "rule_id": f["rule_id"], "value": f["value"],
                 "replacement": f["replacement"], "token": f["token"]}
                for f in result["findings"]]
    audit(actor, "mask.preview", "family", family_id,
          f"action={action} rules={[r['rule_id'] for r in norm]} "
          f"matched={int(result['matched'])} hits={len(findings)} "
          f"fields={sorted({f['field'] for f in findings})}")
    return {
        "action": action, "matched": result["matched"],
        "would_block": bool(action == "deny" and result["matched"]),
        "masked_inputs": result["masked_inputs"], "findings": findings,
        "rendered_prompt": rendered, "render_error": render_error,
    }


# ================================================================ 复核人名册

def add_reviewer(family_id: str, reviewer: str, actor: str, note: str = "") -> dict:
    reviewer = str(reviewer or "").strip()
    if not reviewer:
        raise DomainError("复核人标识不能为空")
    with write_tx() as c:
        if not c.execute("SELECT 1 FROM families WHERE family_id=?",
                         (family_id,)).fetchone():
            raise NotFound(f"模板族不存在: {family_id}")
        c.execute(
            """INSERT INTO mask_reviewers(family_id,reviewer,note,created_by)
               VALUES (?,?,?,?)
               ON CONFLICT(family_id,reviewer) DO UPDATE SET active=1, note=excluded.note""",
            (family_id, reviewer, note, actor))
        audit(actor, "mask.reviewer.add", "mask_reviewer", reviewer,
              f"family={family_id} note={note}")
    return {"family_id": family_id, "reviewer": reviewer, "active": True}


def remove_reviewer(family_id: str, reviewer: str, actor: str) -> dict:
    with write_tx() as c:
        cur = c.execute(
            "UPDATE mask_reviewers SET active=0 WHERE family_id=? AND reviewer=? AND active=1",
            (family_id, reviewer)).rowcount
        if not cur:
            raise NotFound(f"复核人 {reviewer} 不在模板族 {family_id} 的授权名册中")
        audit(actor, "mask.reviewer.remove", "mask_reviewer", reviewer,
              f"family={family_id}")
    return {"family_id": family_id, "reviewer": reviewer, "active": False}


def list_reviewers(family_id: str, active_only: bool = False) -> list[dict]:
    q = "SELECT * FROM mask_reviewers WHERE family_id=?"
    if active_only:
        q += " AND active=1"
    return [dict(r) for r in get_conn().execute(
        q + " ORDER BY reviewer", (family_id,)).fetchall()]


def _require_reviewer(c, family_id: str, reviewer: str) -> None:
    row = c.execute(
        "SELECT 1 FROM mask_reviewers WHERE family_id=? AND reviewer=? AND active=1",
        (family_id, reviewer)).fetchone()
    if not row:
        raise DomainError(f"复核人 {reviewer!r} 未获模板族 {family_id} 的原值还原授权")


# ================================================================ 请求侧隔离

def isolate(rule: dict | None, projected_inputs: dict, request_id: str) -> dict:
    """对**投影后**输入执行固定版本的隔离（纯计算，不写库）。

    返回 effective（参与渲染的输入）、entries（可落库密文条目）、matched/deny。
    阻断策略也先生成一份遮盖版输入用于落库（数据库不留明文），但渲染/推理被跳过。
    """
    if not rule:
        return {"rule": None, "matched": False, "deny": False,
                "effective": projected_inputs, "entries": []}
    red = masking.apply_rules("redact", rule["rules"], projected_inputs)
    entries = masking.sealed_entries(rule["rule_version_id"], request_id, red["findings"])
    deny = bool(rule["action"] == "deny" and red["matched"])
    return {"rule": rule, "matched": red["matched"], "deny": deny,
            "effective": red["masked_inputs"] if red["matched"] else projected_inputs,
            "storage_inputs": red["masked_inputs"], "entries": entries}


def persist_hit(c, request_id: str, family_id: str, iso: dict) -> None:
    """在请求落库的同一写事务内写入逐请求遮盖映射（只含密文）。"""
    rule = iso["rule"]
    if not rule or not iso["matched"]:
        return
    action = "deny" if iso["deny"] else "redact"
    entries = iso["entries"]
    c.execute(
        """INSERT INTO mask_hits(request_id,family_id,rule_version_id,rule_version_no,
           action,token_count,entries_json,masked_digest)
           VALUES (?,?,?,?,?,?,?,?)""",
        (request_id, family_id, rule["rule_version_id"], rule["version_no"], action,
         len(entries), json.dumps(entries, ensure_ascii=False, sort_keys=True),
         core.digest_inputs(iso["storage_inputs"])))


def request_mask_view(request_id: str) -> dict | None:
    """调用复核页：该请求固定的规则版本 + 遮盖映射（密文不回解）+ 还原凭据状态。"""
    hit = get_conn().execute("SELECT * FROM mask_hits WHERE request_id=?",
                             (request_id,)).fetchone()
    req = get_conn().execute(
        "SELECT mask_rule_version_no, mask_rule_version_id, mask_action FROM requests "
        "WHERE request_id=?", (request_id,)).fetchone()
    if not req:
        raise NotFound(f"请求不存在: {request_id}")
    if not req["mask_rule_version_id"]:
        return None
    rule = get_conn().execute("SELECT * FROM mask_rule_versions WHERE rule_version_id=?",
                              (req["mask_rule_version_id"],)).fetchone()
    entries = []
    if hit:
        entries = [{"token": e["token"], "field": e["field"], "rule_id": e["rule_id"],
                    "replacement": e["replacement"]}
                   for e in _loads(hit["entries_json"])]
    tokens = get_conn().execute(
        "SELECT token_id,reviewer,status,expires_at,consumed_at,consumed_by,created_at "
        "FROM mask_reveal_tokens WHERE request_id=? ORDER BY created_at DESC",
        (request_id,)).fetchall()
    return {
        "pinned": True,
        "rule_version_id": req["mask_rule_version_id"],
        "rule_version_no": req["mask_rule_version_no"],
        "rule_version_in_pack": bool(rule),
        "action": req["mask_action"] or ("redact" if hit else ""),
        "matched": bool(hit),
        "hit_action": hit["action"] if hit else "",
        "rules_hash": rule["rules_hash"] if rule else None,
        "rules": _loads(rule["rules_json"]) if rule else [],
        "entries": entries,
        "token_count": len(entries),
        "tokens": [dict(t) for t in tokens],
    }


# ================================================================ 短期还原凭据

def issue_reveal_token(request_id: str, reviewer: str, actor: str,
                       ttl_seconds: int | None = None) -> dict:
    """为单个请求签发绑定复核人的一次性短期还原凭据。

    明文 token 只在本响应出现一次；库里只存 SHA-256。复核人必须在该族授权名册
    （active）内，且请求必须存在密文遮盖映射。
    """
    reviewer = str(reviewer or "").strip()
    ttl = int(ttl_seconds or DEFAULT_TTL_SECONDS)
    if not (MIN_TTL_SECONDS <= ttl <= MAX_TTL_SECONDS):
        raise DomainError(f"凭据有效期必须在 {MIN_TTL_SECONDS}~{MAX_TTL_SECONDS} 秒之间")
    with write_tx() as c:
        req = c.execute("SELECT * FROM requests WHERE request_id=?",
                        (request_id,)).fetchone()
        if not req:
            raise NotFound(f"请求不存在: {request_id}")
        _require_reviewer(c, req["family_id"], reviewer)
        hit = c.execute("SELECT token_count FROM mask_hits WHERE request_id=?",
                        (request_id,)).fetchone()
        if not hit or int(hit["token_count"]) == 0:
            raise Conflict("该请求没有可还原的遮盖内容（未命中替换规则或为无隔离旧请求）")
        now = db_now(c)
        expires = c.execute("SELECT datetime(?, ?) AS t",
                            (now, f"+{ttl} seconds")).fetchone()["t"]
        secret = masking.new_reveal_secret()
        token_id = _uid("tok")
        c.execute(
            """INSERT INTO mask_reveal_tokens(token_id,request_id,family_id,reviewer,
               token_sha,status,ttl_seconds,expires_at)
               VALUES (?,?,?,?,?, 'issued',?,?)""",
            (token_id, request_id, req["family_id"], reviewer,
             masking.hash_token(secret), ttl, expires))
        audit(reviewer, "mask.reveal.issue", "mask_token", token_id,
              f"request={request_id} family={req['family_id']} ttl={ttl}s "
              f"entries={hit['token_count']} expires={expires}")
    return {"token_id": token_id, "token": secret, "request_id": request_id,
            "reviewer": reviewer, "expires_at": expires, "ttl_seconds": ttl,
            "entries": int(hit["token_count"])}


def consume_reveal_token(request_id: str, secret: str, reviewer: str,
                         actor: str | None = None) -> dict:
    """消费凭据还原原值。绑定请求+复核人、半开有效期、**单次消费**。

    任何失败（凭据不存在/绑定别的请求/复核人不符/过期/已消费/已撤销）都**先
    独立提交一条拒绝审计**再抛错——失败审计绝不能随业务事务一起回滚；成功路径
    用行守卫 UPDATE 保证并发与重复提交恰好一次，成功审计与消费同事务提交。
    """
    reviewer = str(reviewer or "").strip()
    actor = actor or reviewer
    secret = str(secret or "")
    if not secret or not reviewer:
        raise DomainError("必须提供还原凭据与复核人标识")
    # 第一阶段：写锁事务内做全部判定与一次性消费；失败原因通过信号带出事务，
    # 在事务回滚后用独立事务补审计（保证拒绝留痕）。
    result: dict = {}
    try:
        with write_tx() as c:
            req = c.execute("SELECT family_id FROM requests WHERE request_id=?",
                            (request_id,)).fetchone()
            if not req:
                raise NotFound(f"请求不存在: {request_id}")
            row = c.execute("SELECT * FROM mask_reveal_tokens WHERE token_sha=?",
                            (masking.hash_token(secret),)).fetchone()
            denied = None
            if not row:
                denied = ("bad_token", DomainError,
                          "还原凭据无效（不暴露该凭据是否存在）")
            elif row["request_id"] != request_id:
                denied = ("wrong_request", DomainError, "凭据绑定的是其他请求，拒绝还原")
            elif row["reviewer"] != reviewer:
                denied = (f"wrong_reviewer presented={reviewer}", DomainError,
                          "复核人与凭据绑定身份不一致，拒绝还原")
            elif row["status"] == "consumed":
                denied = (f"reuse consumed_at={row['consumed_at']} by={row['consumed_by']}",
                          Conflict,
                          "该凭据已消费：一次性凭据不可重复使用，原值不会再次暴露")
            elif row["status"] == "revoked":
                denied = ("revoked", Conflict, "该凭据已被管理员撤销")
            else:
                now = db_now(c)
                if now >= row["expires_at"]:  # 半开区间：恰好到期即失效
                    denied = (f"expired now={now} expires={row['expires_at']}", Conflict,
                              f"凭据已过期（{row['expires_at']}），请重新申请")
            if denied:
                code, exc_cls, msg = denied
                raise _RollbackAndAudit(
                    actor, row["token_id"] if row else "-", request_id, code, exc_cls, msg)
            # 单次消费行守卫：并发/重复提交恰好一次成功
            cur = c.execute(
                "UPDATE mask_reveal_tokens SET status='consumed', consumed_at=datetime('now'), "
                "consumed_by=? WHERE token_id=? AND status='issued' AND consumed_at IS NULL",
                (reviewer, row["token_id"]))
            if cur.rowcount != 1:
                raise _RollbackAndAudit(
                    actor, row["token_id"], request_id, "race_consumed", Conflict,
                    "并发冲突：凭据已被另一请求消费，本次未暴露原值")
            hit = c.execute("SELECT * FROM mask_hits WHERE request_id=?",
                            (request_id,)).fetchone()
            entries_enc = _loads(hit["entries_json"])
            values = []
            for e in entries_enc:
                values.append({"field": e["field"], "rule_id": e["rule_id"],
                               "token": e["token"], "replacement": e["replacement"],
                               "value": masking.open_entry(hit["rule_version_id"], request_id,
                                                          e["token"], e["ct"])})
            values.sort(key=lambda x: (x["field"], x["token"]))
            c.execute(
                "INSERT INTO audit_log(actor,action,entity,entity_id,detail) VALUES (?,?,?,?,?)",
                (reviewer, "mask.reveal.consume", "mask_token", row["token_id"],
                 f"request={request_id} family={req['family_id']} entries={len(values)} "
                 f"fields={sorted({v['field'] for v in values})} "
                 f"rules={sorted({v['rule_id'] for v in values})}"))
            result = {"request_id": request_id, "reviewer": reviewer,
                      "token_id": row["token_id"], "consumed_at": db_now(c),
                      "values": values}
    except _RollbackAndAudit as sig:
        # 业务事务已回滚；独立提交拒绝审计（绝不与判定同事务以免被一起撤销）。
        audit(actor, "mask.reveal.deny", "mask_token", sig.token_id,
              f"request={sig.request_id} reason={sig.code}")
        raise sig.exc_cls(sig.msg) from None
    return result


def revoke_reveal_token(token_id: str, actor: str) -> dict:
    with write_tx() as c:
        row = c.execute("SELECT * FROM mask_reveal_tokens WHERE token_id=?",
                        (token_id,)).fetchone()
        if not row:
            raise NotFound(f"还原凭据不存在: {token_id}")
        if row["status"] != "issued":
            raise Conflict(f"凭据已 {row['status']}，无需撤销")
        c.execute("UPDATE mask_reveal_tokens SET status='revoked' WHERE token_id=?",
                  (token_id,))
        audit(actor, "mask.reveal.revoke", "mask_token", token_id,
              f"request={row['request_id']} reviewer={row['reviewer']}")
    return {"token_id": token_id, "status": "revoked"}


def list_reveal_tokens(request_id: str) -> list[dict]:
    return [dict(r) for r in get_conn().execute(
        "SELECT token_id,request_id,reviewer,status,ttl_seconds,expires_at,created_at,"
        "consumed_at,consumed_by FROM mask_reveal_tokens WHERE request_id=? "
        "ORDER BY created_at DESC", (request_id,)).fetchall()]


# ================================================================ 逐请求审计

def request_audit(request_id: str) -> list[dict]:
    """逐请求审计：以该请求为实体的审计 + 明细中引用该请求的隔离/凭据审计。

    注意：凭据还原明细只含字段/规则 id/计数，不含任何原值；本接口同样不回解
    密文。
    """
    rows = get_conn().execute(
        """SELECT * FROM audit_log
           WHERE (entity='request' AND entity_id=?)
              OR (entity IN ('mask_token','mask_hit') AND detail LIKE ?)
           ORDER BY id DESC LIMIT 200""",
        (request_id, f"%request={request_id}%")).fetchall()
    return [dict(r) for r in rows]


def pinned_rule_for_request(req: dict) -> dict | None:
    """重演/包内复查：按请求固化的规则版本 id 取回版本（找不到=旧请求或边界）。"""
    rid = req.get("mask_rule_version_id") if isinstance(req, dict) else None
    if not rid:
        return None
    row = get_conn().execute("SELECT * FROM mask_rule_versions WHERE rule_version_id=?",
                             (rid,)).fetchone()
    return _rule_view(row) if row else None
