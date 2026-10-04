"""服务层：模板版本治理、评估证据、审批（有效期/主动撤销）、原子发布/回滚、线上调用、重演。"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta
from typing import Any

from . import config, core, guard, llm
from .db import audit, get_conn, write_tx


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _loads(s: str) -> Any:
    return json.loads(s)


# UTC 时刻统一存 'YYYY-MM-DD HH:MM:SS'（与 SQLite datetime('now') 同格式，
# 可直接做字典序比较/datetime 修饰符运算）。
_TIME_FMT = "%Y-%m-%d %H:%M:%S"
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?$")


def parse_ts(value: str | None) -> str | None:
    """解析/规范化外部传入的时刻：接受 ``YYYY-MM-DD HH:MM:SS``、
    ``YYYY-MM-DDTHH:MM`` 与 ``YYYY-MM-DDTHH:MM:SS``，输出 SQLite 同构规范串。"""
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    if not _TS_RE.match(s):
        raise DomainError("时刻格式必须是 'YYYY-MM-DD HH:MM:SS'（可省略秒或用 T 分隔）")
    try:
        has_date_sep = "T" in s
        has_seconds = s.count(":") == 2
        if has_date_sep:
            fmt = "%Y-%m-%dT%H:%M:%S" if has_seconds else "%Y-%m-%dT%H:%M"
        else:
            fmt = _TIME_FMT if has_seconds else "%Y-%m-%d %H:%M"
        return datetime.strptime(s, fmt).strftime(_TIME_FMT)
    except ValueError as exc:
        raise DomainError(f"非法时刻 {value!r}：{exc}") from exc


def db_now(c=None) -> str:
    c = c or get_conn()
    return c.execute("SELECT datetime('now') AS t").fetchone()["t"]


def shift_ts(ts: str, seconds: int) -> str:
    """规范时刻加减秒（测试构造边界时刻用）。"""
    return (datetime.strptime(ts, _TIME_FMT) + timedelta(seconds=seconds)).strftime(_TIME_FMT)


def _fmt_remaining(seconds: int) -> str:
    seconds = int(seconds)
    if seconds <= 0:
        return "0s"
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    if s or not parts:
        parts.append(f"{s}s")
    return " ".join(parts)


def _version_row(version_id: str):
    row = get_conn().execute("SELECT * FROM versions WHERE version_id=?", (version_id,)).fetchone()
    if not row:
        raise NotFound(f"版本不存在: {version_id}")
    return row


def _family_row(family_id: str):
    row = get_conn().execute("SELECT * FROM families WHERE family_id=?", (family_id,)).fetchone()
    if not row:
        raise NotFound(f"模板族不存在: {family_id}")
    return row


class DomainError(Exception):
    """400 级业务错误。"""


class NotFound(DomainError):
    """404。"""


class Conflict(DomainError):
    """409：并发冲突 / 状态不允许。"""


# ================================================================ 模板族 / 版本

def create_family(family_id: str, name: str, description: str, actor: str) -> dict:
    with write_tx() as c:
        exists = c.execute("SELECT 1 FROM families WHERE family_id=?", (family_id,)).fetchone()
        if exists:
            raise Conflict(f"模板族已存在: {family_id}")
        c.execute("INSERT INTO families(family_id,name,description) VALUES (?,?,?)",
                  (family_id, name, description))
        audit(actor, "family.create", "family", family_id, name)
    return get_family(family_id)


def get_family(family_id: str) -> dict:
    f = _family_row(family_id)
    return dict(f)


def list_families() -> list[dict]:
    return [dict(r) for r in get_conn().execute(
        "SELECT * FROM families ORDER BY family_id").fetchall()]


def list_versions(family_id: str) -> list[dict]:
    _family_row(family_id)
    rows = get_conn().execute(
        "SELECT * FROM versions WHERE family_id=? ORDER BY created_at, semver",
        (family_id,)).fetchall()
    active = _family_row(family_id)["active_version_id"]
    out = []
    for r in rows:
        d = dict(r)
        d["is_active"] = (r["version_id"] == active)
        out.append(d)
    return out


def create_version(family_id: str, semver: str, system_instruction: str,
                   variable_contract: dict, tool_permissions: list, model_params: dict,
                   model_id: str, actor: str) -> dict:
    """创建不可变草稿版本。

    模型标识写入 model_params._bound_model 并纳入内容指纹：模型是版本四要素绑定的
    一部分，换模型即产生不同版本/不同哈希。证据与线上都绑定该模型。
    """
    _family_row(family_id)
    llm.get_model(model_id)  # 必须是已注册模型
    bound_params = dict(model_params)
    bound_params["_bound_model"] = model_id
    chash = core.content_hash(system_instruction, variable_contract,
                              tool_permissions, bound_params)
    dup = get_conn().execute(
        "SELECT 1 FROM versions WHERE family_id=? AND content_hash=?",
        (family_id, chash)).fetchone()
    if dup:
        raise Conflict("已存在四要素完全相同的版本（内容哈希重复），无需重复发布")

    prev = get_conn().execute(
        "SELECT variable_contract, tool_permissions FROM versions "
        "WHERE family_id=? ORDER BY created_at DESC LIMIT 1", (family_id,)).fetchone()
    contract_change = core.classify_contract_change(
        _loads(prev["variable_contract"]) if prev else None, variable_contract)

    # 尚未首发时没有线上基线，首个版本的工具集合不视为"权限扩大"。
    active_id = _family_row(family_id)["active_version_id"]
    baseline_tools = None
    if active_id:
        baseline_tools = _loads(_version_row(active_id)["tool_permissions"])
    expanded = int(core.permission_grew(baseline_tools, tool_permissions))

    version_id = _uid("ver")
    with write_tx() as c:
        c.execute(
            """INSERT INTO versions(version_id,family_id,semver,status,system_instruction,
               variable_contract,tool_permissions,model_params,content_hash,
               contract_change,permission_expanded,created_by)
               VALUES (?,?,?, 'draft',?,?,?,?,?,?,?,?)""",
            (version_id, family_id, semver, system_instruction,
             json.dumps(variable_contract, ensure_ascii=False),
             json.dumps(sorted(tool_permissions)),
             json.dumps(bound_params, sort_keys=True, ensure_ascii=False),
             chash, contract_change, expanded, actor))
        c.execute("UPDATE families SET updated_at=datetime('now') WHERE family_id=?",
                  (family_id,))
        audit(actor, "version.create", "version", version_id,
              f"{family_id}@{semver} contract={contract_change} tool_expanded={expanded} "
              f"model={model_id}")
    return get_version(version_id)


def get_version(version_id: str) -> dict:
    r = _version_row(version_id)
    d = dict(r)
    f = _family_row(r["family_id"])
    d["is_active"] = r["version_id"] == f["active_version_id"]
    return d


def abandon_version(version_id: str, actor: str) -> dict:
    v = _version_row(version_id)
    if v["status"] in ("active", "superseded"):
        raise Conflict("线上/历史线上版本不可废弃")
    with write_tx() as c:
        c.execute("UPDATE versions SET status='abandoned' WHERE version_id=? AND status NOT IN "
                  "('active','superseded')", (version_id,))
        audit(actor, "version.abandon", "version", version_id, v["status"])
    return get_version(version_id)


# ================================================================ 测试集 / 评估

def create_testset(family_id: str, name: str, cases: list[dict], actor: str) -> str:
    _family_row(family_id)
    testset_id = _uid("ts")
    with write_tx() as c:
        c.execute("INSERT INTO testsets(testset_id,family_id,name) VALUES (?,?,?)",
                  (testset_id, family_id, name))
        for i, case in enumerate(cases):
            c.execute(
                "INSERT INTO testcases(case_id,testset_id,seq,name,inputs,expect) "
                "VALUES (?,?,?,?,?,?)",
                (_uid("tc"), testset_id, i, case["name"],
                 json.dumps(case["inputs"], ensure_ascii=False),
                 json.dumps(case["expect"], ensure_ascii=False)))
        audit(actor, "testset.create", "testset", testset_id, f"{family_id} {len(cases)} cases")
    return testset_id


def get_testset_for_family(family_id: str):
    return get_conn().execute(
        "SELECT * FROM testsets WHERE family_id=? ORDER BY created_at LIMIT 1",
        (family_id,)).fetchone()


def list_eval_runs(version_id: str | None = None) -> list[dict]:
    if version_id:
        rows = get_conn().execute(
            "SELECT * FROM eval_runs WHERE version_id=? ORDER BY created_at", (version_id,))
    else:
        rows = get_conn().execute("SELECT * FROM eval_runs ORDER BY created_at DESC")
    return [dict(r) for r in rows.fetchall()]


def get_eval_run(run_id: str) -> dict:
    row = get_conn().execute("SELECT * FROM eval_runs WHERE run_id=?", (run_id,)).fetchone()
    if not row:
        raise NotFound(f"评估运行不存在: {run_id}")
    d = dict(row)
    d["cases"] = [dict(r) for r in get_conn().execute(
        "SELECT * FROM eval_cases WHERE run_id=? ORDER BY seq", (run_id,)).fetchall()]
    return d


def start_evaluation(version_id: str, actor: str) -> str:
    """在固定测试集上生成评估证据。证据绑定 (版本内容哈希, 版本绑定模型)。

    返回 run_id。证据完成前不改变发布资格；支持"迟到"——后补评估也会落证据，
    但发布时会校验证据是否仍对应本次内容与模型。
    """
    v = _version_row(version_id)
    if v["status"] == "abandoned":
        raise Conflict("已废弃版本不可评估")
    testset = get_testset_for_family(v["family_id"])
    if not testset:
        raise DomainError("该模板族尚无固定测试集，无法生成评估证据")
    use_model = _version_bound_model(v, get_conn())
    llm.get_model(use_model)

    run_id = _uid("run")
    cases = get_conn().execute(
        "SELECT * FROM testcases WHERE testset_id=? ORDER BY seq",
        (testset["testset_id"],)).fetchall()

    with write_tx() as c:
        # 评估回放与线上请求共用同一规则来源：评估开始瞬间族上生效的隔离规则
        # 版本被固定到 eval_run；评估进行期间规则更新不改变本次评估，历史证据
        # 永远按本版本复核（与请求固定 ruleset 同理）。
        grs_row = None
        fam = c.execute("SELECT active_guard_ruleset_id FROM families WHERE family_id=?",
                        (v["family_id"],)).fetchone()
        if fam["active_guard_ruleset_id"]:
            grs_row = c.execute("SELECT * FROM guard_rulesets WHERE ruleset_id=?",
                                (fam["active_guard_ruleset_id"],)).fetchone()
        c.execute(
            """INSERT INTO eval_runs(run_id,version_id,testset_id,model_id,status,total,
               guard_ruleset_id,guard_ruleset_version,guard_ruleset_hash)
               VALUES (?,?,?,?, 'running', ?,?,?,?)""",
            (run_id, version_id, testset["testset_id"], use_model, len(cases),
             grs_row["ruleset_id"] if grs_row else None,
             grs_row["version"] if grs_row else None,
             grs_row["content_hash"] if grs_row else ""))
        c.execute("UPDATE versions SET status='evaluating' WHERE version_id=? "
                  "AND status IN ('draft','failed_eval','evaluated')", (version_id,))
        audit(actor, "eval.start", "eval_run", run_id,
              f"version={version_id} model={use_model} cases={len(cases)}"
              + (f" guard={grs_row['ruleset_id']}@v{grs_row['version']}"
                 if grs_row else " guard=none"))
    return run_id


def _infer_model(v) -> str:
    # 模型始终取版本绑定模型（model_params._bound_model）。
    return _version_bound_model(v, get_conn())


def run_evaluation(run_id: str, actor: str = "evaluator") -> dict:
    """执行评估（确定性，逐用例渲染->推理->断言），写入不可变证据。"""
    run = get_conn().execute("SELECT * FROM eval_runs WHERE run_id=?", (run_id,)).fetchone()
    if not run:
        raise NotFound(run_id)
    if run["status"] != "running":
        raise Conflict("该评估已完成，证据不可变")
    v = _version_row(run["version_id"])
    contract = _loads(v["variable_contract"])
    params = _loads(v["model_params"])

    # 评估固定的隔离规则版本（start 时固化）：无则不隔离
    eval_rules = None
    if run["guard_ruleset_id"]:
        grs_row = get_conn().execute("SELECT * FROM guard_rulesets WHERE ruleset_id=?",
                                     (run["guard_ruleset_id"],)).fetchone()
        eval_rules = _loads(grs_row["rules_json"]) if grs_row else None

    cases = get_conn().execute(
        "SELECT * FROM testcases WHERE testset_id=? ORDER BY seq",
        (run["testset_id"],)).fetchall()
    passed = 0
    detail_rows = []
    guard_case_stats = []
    g_masked_total = g_blocked_total = 0
    for case in cases:
        raw_inputs = _loads(case["inputs"])
        inputs = core.project_inputs(raw_inputs, contract)
        inp_digest = core.digest_inputs(inputs)
        c_masked = c_blocked = c_outmasked = 0
        if eval_rules:
            scan = guard.scan_inputs(eval_rules, inputs)
            if scan["blocked"]:
                # 阻断用例：不渲染原指令、不调用模型，记录确定性的阻断提示作为
                # 渲染提示与输出（无原值），断言必不通过，证据可复现。
                c_blocked = scan["blocked"].get("match_count", 1)
                g_blocked_total += 1
                guard_case_stats.append({"seq": case["seq"], "name": case["name"],
                                         "masked": 0, "blocked": c_blocked,
                                         "output_masked": 0,
                                         "rule_id": scan["blocked"]["rule_id"]})
                block_prompt = (
                    f"[GUARD BLOCKED] 用例输入在评估固定规则版本 "
                    f"v{run['guard_ruleset_version']} 命中阻断规则 "
                    f"{scan['blocked']['rule_id']}（字段 "
                    f"{scan['blocked']['fields']}），请求被拒绝，未进行模板渲染与推理。")
                block_output = json.dumps(
                    {"blocked": True, "rule_id": scan["blocked"]["rule_id"],
                     "ruleset_version": run["guard_ruleset_version"]},
                    ensure_ascii=False, sort_keys=True)
                detail_rows.append((case["case_id"], case["seq"], case["name"], inp_digest,
                                    block_prompt, block_output,
                                    core.digest_output(block_output), 0,
                                    "敏感内容阻断，未进入推理"))
                continue
            inputs = scan["masked_inputs"]
            c_masked = len(scan["tokens"])
            g_masked_total += c_masked
        prompt = core.render_prompt(v["system_instruction"], contract, inputs)
        output = llm.generate(run["model_id"], v["content_hash"], prompt, inputs, params)
        if eval_rules:
            output, c_outmasked = guard.scan_output(eval_rules, output)
        ok, detail = llm.assert_expect(output, _loads(case["expect"]))
        passed += int(ok)
        guard_case_stats.append({"seq": case["seq"], "name": case["name"],
                                 "masked": c_masked, "blocked": 0,
                                 "output_masked": c_outmasked})
        detail_rows.append((case["case_id"], case["seq"], case["name"], inp_digest,
                            prompt, output, core.digest_output(output), int(ok), detail))
    total = len(cases)
    rate = passed / total if total else 0.0
    status = "passed" if rate + 1e-9 >= config.PASS_THRESHOLD else "failed"

    with write_tx() as c:
        for row in detail_rows:
            c.execute(
                """INSERT INTO eval_cases(case_id,seq,name,input_digest,rendered_prompt,
                   output,output_digest,ok,detail,run_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], run_id))
        c.execute(
            """UPDATE eval_runs SET status=?, pass_rate=?, passed=?, finished_at=datetime('now')
               WHERE run_id=? AND status='running'""",
            (status, rate, passed, run_id))
        # 迟到标记：证据回来时版本已不是候选（已发布其他版本/废弃）
        cur = c.execute("SELECT status FROM versions WHERE version_id=?",
                        (v["version_id"],)).fetchone()["status"]
        late = cur in ("active", "superseded", "abandoned")
        if late:
            c.execute("UPDATE eval_runs SET late=1 WHERE run_id=?", (run_id,))
        # 仅在仍是候选版本时回写评估态；历史版本保留其既有生命周期状态
        if cur not in ("active", "superseded", "abandoned", "approved"):
            c.execute("UPDATE versions SET status=?, pass_rate=? WHERE version_id=?",
                      ("evaluated" if status == "passed" else "failed_eval", rate,
                       v["version_id"]))
        elif cur == "approved":
            c.execute("UPDATE versions SET pass_rate=? WHERE version_id=?",
                      (rate, v["version_id"]))
        # 隔离回放记录：逐用例遮盖/阻断统计（不含原值）；即使族上未配置规则也
        # 写一行（ruleset_id 为 NULL），表示"本次评估在无隔离下进行"这一确定事实。
        c.execute(
            """INSERT INTO guard_eval_fixtures(run_id,ruleset_id,ruleset_version,
               ruleset_hash,cases_json,masked_total,blocked_total)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(run_id) DO NOTHING""",
            (run_id, run["guard_ruleset_id"], run["guard_ruleset_version"],
             run["guard_ruleset_hash"] or "",
             json.dumps(guard_case_stats, ensure_ascii=False),
             g_masked_total, g_blocked_total))
        audit(actor, "eval.finish", "eval_run", run_id,
              f"{status} {passed}/{total} rate={rate:.2f} late={int(late)}"
              + (f" guard_masked={g_masked_total} guard_blocked={g_blocked_total}"
                 if run["guard_ruleset_id"] else ""))
    return get_eval_run(run_id)


# ================================================================ 审批（有效期 / 主动撤销）

def approve(version_id: str, kind: str, approver: str, decision: str,
            reason: str, granted_tools: list | None = None,
            valid_from: str | None = None, valid_until: str | None = None) -> dict:
    """审批。kind=release 发布审批；kind=tool_expansion 权限扩大专项审批。

    工具权限相对线上扩大时，必须持有一张覆盖该扩大集合的 tool_expansion 审批。
    审批人可对 tool_expansion 授权设置有效期（半开区间
    [valid_from, valid_until)，两界均空=永久授权，兼容旧审批语义）：
    - 业务时刻早于 valid_from：授权尚未生效；
    - 业务时刻 ≥ valid_until：授权恰好/已经失效；
    - 主动撤销见 :func:`revoke_approval`（revoke_version CAS）。
    granted_tools 可显式给出本次授权覆盖的工具子集（缺省=候选的全部工具），
    只覆盖部分工具的授权过不了门禁。
    """
    v = _version_row(version_id)
    if kind not in ("release", "tool_expansion"):
        raise DomainError("审批类型必须是 release 或 tool_expansion")
    if decision not in ("approved", "rejected"):
        raise DomainError("decision 必须是 approved/rejected")
    vf = parse_ts(valid_from)
    vu = parse_ts(valid_until)
    if vf and vu and not (vf < vu):
        raise DomainError("生效时刻必须严格早于失效时刻（半开区间 [生效, 失效)）")
    tools = list(granted_tools) if granted_tools is not None else _loads(v["tool_permissions"])
    approval_id = _uid("appr")
    with write_tx() as c:
        c.execute(
            """INSERT INTO approvals(approval_id,version_id,kind,decision,approver,reason,
               granted_tools,valid_from,valid_until) VALUES (?,?,?,?,?,?,?,?,?)""",
            (approval_id, version_id, kind, decision, approver, reason,
             json.dumps(tools, ensure_ascii=False), vf, vu))
        if kind == "release" and decision == "approved":
            c.execute("UPDATE versions SET status='approved' WHERE version_id=? "
                      "AND status NOT IN ('active','superseded','abandoned')", (version_id,))
        window = "永久" if (vf is None and vu is None) else f"{vf or '即刻'} ~ {vu or '永久'}"
        audit(approver, f"approval.{kind}.{decision}", "approval", approval_id,
              f"version={version_id} {reason} tools={tools} window=[{window}]")
    return get_approval(approval_id)


def approval_view(row, now: str | None = None) -> dict:
    """审批行 + 按当前（或指定）时刻计算的有效状态/剩余时间。

    state: approved（生效中）/ pending（尚未生效）/ expired（恰好/已经失效）/
           revoked（已主动撤销）/ rejected（未通过）/ permanent（永久授权，生效中）。
    撤销与到期叠加时以 revoked 为准（历史事实优先）。
    """
    d = dict(row)
    if d["decision"] != "approved":
        d["state"] = "rejected"
    elif d["revoked_at"]:
        d["state"] = "revoked"
    elif d["valid_from"] is None and d["valid_until"] is None:
        d["state"] = "permanent"
    else:
        t = now or db_now()
        if d["valid_from"] and t < d["valid_from"]:
            d["state"] = "pending"
        elif d["valid_until"] and t >= d["valid_until"]:
            d["state"] = "expired"
        else:
            d["state"] = "approved"
    d["is_active"] = d["state"] in ("approved", "permanent")
    d["is_permanent"] = d["valid_from"] is None and d["valid_until"] is None
    t = now or db_now()
    if d["state"] == "approved" and d["valid_until"]:
        d["remaining_seconds"] = int(
            (datetime.strptime(d["valid_until"], _TIME_FMT)
             - datetime.strptime(t, _TIME_FMT)).total_seconds())
        d["remaining_human"] = _fmt_remaining(d["remaining_seconds"])
    else:
        d["remaining_seconds"] = None
        d["remaining_human"] = ""
    if d["state"] == "pending" and d["valid_from"]:
        d["wait_seconds"] = int(
            (datetime.strptime(d["valid_from"], _TIME_FMT)
             - datetime.strptime(t, _TIME_FMT)).total_seconds())
        d["wait_human"] = _fmt_remaining(d["wait_seconds"])
    else:
        d["wait_seconds"] = None
        d["wait_human"] = ""
    d["can_revoke"] = (d["decision"] == "approved" and d["state"] in
                       ("approved", "permanent", "pending"))
    return d


def get_approval(approval_id: str) -> dict:
    r = get_conn().execute("SELECT * FROM approvals WHERE approval_id=?",
                           (approval_id,)).fetchone()
    if not r:
        raise NotFound(approval_id)
    return approval_view(r)


def list_approvals(version_id: str | None = None) -> list[dict]:
    if version_id:
        rows = get_conn().execute("SELECT * FROM approvals WHERE version_id=? ORDER BY created_at",
                                  (version_id,))
    else:
        rows = get_conn().execute("SELECT * FROM approvals ORDER BY created_at DESC")
    now = db_now()
    return [approval_view(r, now) for r in rows.fetchall()]


def revoke_approval(approval_id: str, expected_version: int, actor: str,
                    reason: str = "") -> dict:
    """主动撤销一张生效中/待生效的 tool_expansion 授权。

    以 ``expected_version`` 做乐观并发控制（CAS）：审批人基于某一版本号操作，
    并发撤销只有一方成功，rowcount≠1 即 409，审批与业务状态均不变。撤销后
    建批/命中/一步发布三处门禁当场失效（在同一写锁下按业务时刻重查）；
    撤销不改变已固化授权快照的历史调用结论。需要恢复请重新审批（新记录）。
    """
    expected_version = int(expected_version)
    with write_tx() as c:
        r = c.execute("SELECT * FROM approvals WHERE approval_id=?",
                      (approval_id,)).fetchone()
        if not r:
            raise NotFound(f"审批不存在: {approval_id}")
        if r["kind"] != "tool_expansion":
            raise DomainError("仅 tool_expansion（工具扩权）授权支持有效期与主动撤销；"
                              "release 审批保留旧语义")
        if r["decision"] != "approved":
            raise DomainError("未通过的审批无需撤销")
        if r["revoked_at"]:
            raise Conflict(f"审批 {approval_id} 已被 {r['revoked_by']} 撤销（版本"
                           f"{r['revoke_version']}）；如需恢复请重新审批")
        state = approval_view(r)["state"]
        if state not in ("approved", "permanent", "pending"):
            raise Conflict(f"审批当前状态为 {state}，不可撤销（已自然失效）")
        cur = c.execute(
            "UPDATE approvals SET revoked_at=datetime('now'), revoked_by=?, revoke_reason=?, "
            "revoke_version=revoke_version+1 WHERE approval_id=? AND revoke_version=? "
            "AND revoked_at IS NULL",
            (actor, reason, approval_id, expected_version))
        if cur.rowcount != 1:
            latest = c.execute("SELECT revoke_version, revoked_by FROM approvals "
                               "WHERE approval_id=?", (approval_id,)).fetchone()
            raise Conflict("并发冲突：审批版本号已变化（CAS 失败，"
                           f"当前版本 {latest['revoke_version']}，"
                           f"撤销人 {latest['revoked_by']}），请刷新后重试")
        audit(actor, "approval.tool_expansion.revoke", "approval", approval_id,
              f"version={r['version_id']} expected_version={expected_version} "
              f"reason={reason} tools={_loads(r['granted_tools'])}")
    return get_approval(approval_id)


def _latest_release_approval(c, version_id: str):
    return c.execute(
        "SELECT * FROM approvals WHERE version_id=? AND kind='release' AND decision='approved' "
        "ORDER BY created_at DESC LIMIT 1", (version_id,)).fetchone()


def _covering_expansion_rows(c, version_id: str, required_tools: list) -> list:
    """覆盖所需工具集合的全部 approved tool_expansion 原始审批行（未按时刻过滤）。"""
    need = set(required_tools)
    rows = c.execute(
        "SELECT * FROM approvals WHERE version_id=? AND kind='tool_expansion' "
        "AND decision='approved'", (version_id,)).fetchall()
    return [r for r in rows if need <= set(_loads(r["granted_tools"]))]


def _active_expansion_approval(c, version_id: str, required_tools: list, at: str):
    """业务时刻 ``at`` 仍有效（未撤销、在 [from, until) 内）且覆盖全部所需工具
    的授权；永久授权（valid_from/valid_until 均 NULL）持续兼容。无则返回 None。"""
    for r in _covering_expansion_rows(c, version_id, required_tools):
        if r["revoked_at"]:
            continue
        if r["valid_from"] and at < r["valid_from"]:
            continue
        if r["valid_until"] and at >= r["valid_until"]:
            continue
        return r
    return None


def expansion_gate_detail(c, version_id: str, base_tools: list | None,
                          cand_tools: list, at: str | None = None) -> dict:
    """候选扩权门禁在业务时刻 ``at`` 的复查明细（建批/命中/一步发布共用）。

    返回 {expands, required_tools, covered_by, active, covering_rows}；
    门禁通过 = (not expands) 或 active 非空。
    """
    at = at or db_now(c)
    expands = core.permission_grew(base_tools, cand_tools)
    added = sorted(set(cand_tools) - set(base_tools or []))
    rows = _covering_expansion_rows(c, version_id, cand_tools) if expands else []
    active = _active_expansion_approval(c, version_id, cand_tools, at) if expands else None
    return {"expands": expands, "added_tools": added, "required_tools": sorted(cand_tools),
            "covering": [approval_view(r, at) for r in rows], "active":
            approval_view(active, at) if active else None, "checked_at": at}


def _require_active_expansion(c, version_id: str, base_tools: list, cand_tools: list,
                              at: str, where: str) -> dict:
    """门禁：扩权候选在业务时刻 at 必须存在覆盖**全部候选工具**的有效授权。

    任一校验失败（尚未生效 / 恰好到期 / 已撤销 / 只覆盖部分工具）都抛 Conflict，
    由调用方在写事务内触发回滚——线上指针与放量状态均不改变。返回授权快照。
    """
    gate = expansion_gate_detail(c, version_id, base_tools, cand_tools, at)
    if not gate["expands"]:
        return {"required": False}
    active = gate["active"]
    if active is not None:
        return {"required": True, "approval": active}
    added = gate["added_tools"]
    if gate["covering"]:
        states = "，".join(f"{a['approval_id']}={a['state']}" for a in gate["covering"])
        raise Conflict(
            f"候选新增工具 {added} 的专项授权当前不满足门禁（{where}，业务时刻 {at}）："
            f"存在覆盖授权但状态为 {states}；授权必须在业务时刻处于生效中且覆盖候选"
            f"的全部工具；线上指针与放量状态未改变")
    raise Conflict(
        f"候选新增可调用工具 {added}，但不存在覆盖候选全部工具 {sorted(cand_tools)} 的"
        f"tool_expansion 授权（{where}，业务时刻 {at}）：部分覆盖不算就位；"
        f"线上指针与放量状态未改变")


# ================================================================ 发布 / 回滚（原子）

def _promotion_checks(c, family_id: str, version_id: str, expected_active: str | None):
    family = c.execute("SELECT * FROM families WHERE family_id=?", (family_id,)).fetchone()
    v = c.execute("SELECT * FROM versions WHERE version_id=?", (version_id,)).fetchone()
    if not v:
        raise NotFound(version_id)
    if v["family_id"] != family_id:
        raise DomainError("版本不属于该模板族")
    if family["active_version_id"] != expected_active:
        raise Conflict("并发冲突：线上指针在操作期间已变化（CAS 失败），请刷新后重试")

    if v["status"] in ("abandoned",):
        raise Conflict("已废弃版本不可发布")

    # 1) 必须有通过的、内容与模型都对得上的评估证据
    run = c.execute(
        "SELECT * FROM eval_runs WHERE version_id=? AND status='passed' "
        "ORDER BY finished_at DESC LIMIT 1", (version_id,)).fetchone()
    if not run:
        raise Conflict("缺少通过的评估证据，禁止发布（先在固定测试集上评估）")
    if run["model_id"] != _version_bound_model(v, c):
        raise Conflict("评估证据所用模型与版本绑定模型不一致：模型变化需用绑定模型重新评估")
    if run["pass_rate"] + 1e-9 < config.PASS_THRESHOLD:
        raise Conflict("评估通过率未达发布门槛")
    # 证据必须针对当前不可变版本内容：版本内容不可变，run 通过 version_id 绑定；
    if not c.execute("SELECT 1 FROM eval_runs WHERE run_id=? AND version_id=?",
                     (run["run_id"], version_id)).fetchone():
        raise Conflict("评估证据与版本不匹配")

    # 2) 必须有通过的发布审批（回滚到曾经上线版本时仍校验，保证全程可审计）
    if not _latest_release_approval(c, version_id):
        raise Conflict("缺少通过的发布审批")

    # 3) 权限扩大必须有专项审批。首发（线上无版本）不算"扩大"；之后以版本创建时
    #    相对线上基线计算的 permission_expanded 为准，并在发布当下再复核一次：
    #    授权必须此刻仍有效（未到期/未撤销）且覆盖候选的全部新增工具。
    cur_active = family["active_version_id"]
    baseline = None
    if cur_active:
        baseline = _loads(c.execute(
            "SELECT tool_permissions FROM versions WHERE version_id=?",
            (cur_active,)).fetchone()["tool_permissions"])
    expands = core.permission_grew(baseline, _loads(v["tool_permissions"]))
    if expands:
        _require_active_expansion(
            c, version_id, baseline, _loads(v["tool_permissions"]),
            db_now(c), where="一步发布（promote）")
    return family, v, run, baseline or []


def _version_bound_model(v, c) -> str:
    # 模型标识记录在 versions.model_params._bound_model（创建时写入）
    return _loads(v["model_params"]).get("_bound_model", "langfang-3-64k")


def promote(family_id: str, version_id: str, actor: str,
            expected_active: str | None = None) -> dict:
    """热发布（热更新）：单事务内翻转唯一线上指针。

    使用 expected_active 做 CAS：并发的回滚/发布会互相失败，杜绝"线上看到半个版本"。
    """
    f = _family_row(family_id)
    if expected_active is None:
        expected_active = f["active_version_id"]
    with write_tx() as c:
        family, v, run, baseline = _promotion_checks(c, family_id, version_id, expected_active)
        old_active = family["active_version_id"]
        cur = c.execute("SELECT active_version_id FROM families WHERE family_id=?",
                        (family_id,)).fetchone()
        if cur["active_version_id"] != expected_active:
            raise Conflict("并发冲突：线上指针已被其他发布/回滚改变")
        # 翻转指针 + 状态迁移，全部在同一事务
        c.execute("UPDATE families SET active_version_id=?, updated_at=datetime('now') "
                  "WHERE family_id=?", (version_id, family_id))
        c.execute("UPDATE versions SET status='active', promoted_at=datetime('now') "
                  "WHERE version_id=?", (version_id,))
        if old_active and old_active != version_id:
            c.execute("UPDATE versions SET status='superseded' WHERE version_id=?",
                      (old_active,))
        added, removed = core.diff_tools(baseline, _loads(v["tool_permissions"]))
        audit(actor, "version.promote", "family", family_id,
              f"{old_active} -> {version_id} (eval={run['run_id'][:12]}, "
              f"tools +{added} -{removed}, contract={v['contract_change']})")
    return get_family(family_id)


def rollback(family_id: str, target_version_id: str, actor: str,
             expected_active: str | None = None) -> dict:
    """并发回滚：回到一个完整的历史版本。

    回滚目标必须曾是完整线上版本（active/superseded）或至少通过校验；
    其工具权限是历史快照，相对当前只会收窄或持平，故不需要重新审批，
    但仍要求该版本当年存在发布审批记录（保证可复核）。CAS 防并发覆盖。
    """
    f = _family_row(family_id)
    if expected_active is None:
        expected_active = f["active_version_id"]
    with write_tx() as c:
        family = c.execute("SELECT * FROM families WHERE family_id=?", (family_id,)).fetchone()
        target = c.execute("SELECT * FROM versions WHERE version_id=?",
                           (target_version_id,)).fetchone()
        if not target:
            raise NotFound(target_version_id)
        if family["active_version_id"] != expected_active:
            raise Conflict("并发冲突：线上指针已变化，回滚中止（CAS 失败）")
        if target["status"] not in ("active", "superseded"):
            raise Conflict("只能回滚到曾完整上线的版本（保证是一个完整版本）")
        # 回滚不得引入新权限（历史快照相对当前只收窄/持平）
        cur_tools = _loads(c.execute(
            "SELECT tool_permissions FROM versions WHERE version_id=?",
            (family["active_version_id"],)).fetchone()["tool_permissions"])
        if core.permission_grew(cur_tools, _loads(target["tool_permissions"])):
            raise Conflict("目标版本工具权限大于当前，属于扩大而非回滚，须走发布审批")
        old = family["active_version_id"]
        c.execute("UPDATE families SET active_version_id=?, updated_at=datetime('now') "
                  "WHERE family_id=?", (target_version_id, family_id))
        c.execute("UPDATE versions SET status='active', promoted_at=datetime('now') "
                  "WHERE version_id=?", (target_version_id,))
        c.execute("UPDATE versions SET status='superseded' WHERE version_id=? AND version_id<>?",
                  (old, target_version_id))
        audit(actor, "version.rollback", "family", family_id,
              f"{old} -> {target_version_id}（历史完整版本，权限未扩大，免新审批）")
    return get_family(family_id)


# ================================================================ 分批放量

ROLLOUT_OPEN = ("ramping", "frozen")   # 进行中（未终结）的批次状态


def _rollout_row(rollout_id: str):
    row = get_conn().execute("SELECT * FROM rollouts WHERE rollout_id=?",
                             (rollout_id,)).fetchone()
    if not row:
        raise NotFound(f"放量批次不存在: {rollout_id}")
    return row


def get_rollout(rollout_id: str) -> dict:
    return dict(_rollout_row(rollout_id))


def list_rollouts(family_id: str) -> list[dict]:
    _family_row(family_id)
    return [dict(r) for r in get_conn().execute(
        "SELECT * FROM rollouts WHERE family_id=? ORDER BY created_at DESC, rollout_id",
        (family_id,)).fetchall()]


def current_rollout(family_id: str) -> dict | None:
    """进行中的批次（ramping/frozen），无则 None。"""
    row = get_conn().execute(
        "SELECT * FROM rollouts WHERE family_id=? AND status IN ('ramping','frozen') "
        "ORDER BY created_at DESC LIMIT 1", (family_id,)).fetchone()
    return dict(row) if row else None


def list_rollout_candidates(family_id: str) -> list[dict]:
    """可建立放量批次的已审核构件：非线上/历史线上/废弃，且持有通过的 release 审批。"""
    _family_row(family_id)
    rows = get_conn().execute(
        "SELECT * FROM versions WHERE family_id=? "
        "AND status NOT IN ('active','superseded','abandoned') "
        "ORDER BY created_at DESC", (family_id,)).fetchall()
    conn = get_conn()
    return [get_version(r["version_id"]) for r in rows
            if _latest_release_approval(conn, r["version_id"])]


def create_rollout(family_id: str, candidate_version_id: str, weight: int,
                   actor: str) -> dict:
    """为已审核构件建立带权重的放量批次。

    门禁（与发布同标准，全部在单事务内校验）：
    1. 模板族已有线上版本（无当前构件则无从对照分流）；
    2. 候选构件有通过的评估证据（模型一致、通过率达标）与 approved 的 release 审批；
    3. 候选相对线上新增可调用工具时，必须已存在覆盖该工具集的 tool_expansion
       专项授权——保证首个请求命中候选之前授权已就位；
    4. 同族无其他进行中批次。
    """
    if not (0 <= int(weight) <= 100):
        raise DomainError("权重必须是 0~100 的整数（候选流量百分比）")
    weight = int(weight)
    f = _family_row(family_id)
    if not f["active_version_id"]:
        raise Conflict("该模板族尚未发布线上版本，无法建立放量批次（缺少当前构件作对照）")
    v = _version_row(candidate_version_id)
    if v["family_id"] != family_id:
        raise DomainError("候选构件不属于该模板族")
    if candidate_version_id == f["active_version_id"]:
        raise DomainError("候选构件不能就是当前线上版本（无需放量）")
    if v["status"] in ("abandoned", "superseded", "active"):
        raise Conflict(f"候选构件状态为 {v['status']}，不可作为放量候选")

    rollout_id = _uid("ro")
    with write_tx() as c:
        if c.execute("SELECT 1 FROM rollouts WHERE family_id=? AND status IN ('ramping','frozen')",
                     (family_id,)).fetchone():
            raise Conflict("已存在进行中的放量批次：请先完成或撤销，再建立新批次")
        run = c.execute(
            "SELECT * FROM eval_runs WHERE version_id=? AND status='passed' "
            "ORDER BY finished_at DESC LIMIT 1", (candidate_version_id,)).fetchone()
        if not run:
            raise Conflict("候选构件缺少通过的评估证据，禁止放量")
        if run["model_id"] != _version_bound_model(v, c):
            raise Conflict("候选构件评估证据所用模型与绑定模型不一致")
        if run["pass_rate"] + 1e-9 < config.PASS_THRESHOLD:
            raise Conflict("候选构件评估通过率未达门槛")
        if not _latest_release_approval(c, candidate_version_id):
            raise Conflict("候选构件缺少通过的发布审批（仅已审核构件可建立放量批次）")
        base_tools = _loads(c.execute(
            "SELECT tool_permissions FROM versions WHERE version_id=?",
            (f["active_version_id"],)).fetchone()["tool_permissions"])
        cand_tools = _loads(v["tool_permissions"])
        at = db_now(c)
        _require_active_expansion(c, candidate_version_id, base_tools, cand_tools, at,
                                  where="创建放量批次")
        c.execute(
            """INSERT INTO rollouts(rollout_id,family_id,candidate_version_id,
               base_version_id,weight,status,generation,created_by)
               VALUES (?,?,?,?,?, 'ramping', 1, ?)""",
            (rollout_id, family_id, candidate_version_id, f["active_version_id"],
             weight, actor))
        audit(actor, "rollout.create", "rollout", rollout_id,
              f"family={family_id} candidate={candidate_version_id} "
              f"base={f['active_version_id']} weight={weight}%")
    return get_rollout(rollout_id)


def _cas_transition(c, rollout_id: str, expected_generation: int,
                    set_clause: str, params: tuple, from_status: tuple) -> None:
    """批次状态切换的唯一出口：代次 CAS + 状态前置，全部在调用方的写事务内。

    rowcount != 1 即并发冲突（代次已变）或状态已迁移，抛 409；事务回滚，
    已生效的路由表（weight/status/generation）保持原样。
    """
    placeholders = ",".join(f"'{s}'" for s in from_status)
    cur = c.execute(
        f"UPDATE rollouts SET {set_clause}, generation=generation+1, "
        f"updated_at=datetime('now') WHERE rollout_id=? AND generation=? "
        f"AND status IN ({placeholders})",
        (*params, rollout_id, expected_generation))
    if cur.rowcount != 1:
        raise Conflict("并发冲突：批次代次已变化或批次已终结（CAS 失败），请刷新后重试")


def ramp_rollout(rollout_id: str, new_weight: int, expected_generation: int,
                 actor: str) -> dict:
    """升档：提高候选分流权重。权重单调递增，既走候选的 key 不会掉回。"""
    new_weight = int(new_weight)
    if not (0 < new_weight <= 100):
        raise DomainError("升档权重必须是 1~100 的整数")
    with write_tx() as c:
        r = c.execute("SELECT * FROM rollouts WHERE rollout_id=?", (rollout_id,)).fetchone()
        if not r:
            raise NotFound(f"放量批次不存在: {rollout_id}")
        # 代次核对先于输入校验：并发升档的输家读到的是赢家已提交的新状态，
        # 必须判为 409 并发冲突而非 400 输入错误
        if r["generation"] != expected_generation:
            raise Conflict("并发冲突：批次代次已变化（CAS 失败），请刷新后重试")
        if r["status"] != "ramping":
            raise Conflict(f"批次当前状态为 {r['status']}，仅放量中（ramping）可升档")
        if new_weight <= r["weight"]:
            raise DomainError(f"升档权重必须大于当前权重 {r['weight']}%")
        _cas_transition(c, rollout_id, expected_generation, "weight=?",
                        (new_weight,), ("ramping",))
        audit(actor, "rollout.ramp", "rollout", rollout_id,
              f"weight {r['weight']}% -> {new_weight}% (gen {expected_generation})")
    return get_rollout(rollout_id)


def freeze_rollout(rollout_id: str, expected_generation: int, actor: str) -> dict:
    """冻结：暂停放量，期间所有新调用（含本应命中候选的 key）都走当前构件。"""
    with write_tx() as c:
        r = c.execute("SELECT * FROM rollouts WHERE rollout_id=?", (rollout_id,)).fetchone()
        if not r:
            raise NotFound(f"放量批次不存在: {rollout_id}")
        if r["status"] != "ramping":
            raise Conflict(f"批次当前状态为 {r['status']}，仅放量中可冻结")
        _cas_transition(c, rollout_id, expected_generation, "status='frozen'",
                        (), ("ramping",))
        audit(actor, "rollout.freeze", "rollout", rollout_id,
              f"weight={r['weight']}% 冻结，新调用全部走当前构件")
    return get_rollout(rollout_id)


def resume_rollout(rollout_id: str, expected_generation: int, actor: str) -> dict:
    """恢复：冻结批次回到放量态，权重不变（同 key 路由决定与冻结前一致）。

    自动止损触发的冻结不能走普通恢复：必须走人工恢复（recover_rollout），
    后者会开启新代次并重置统计窗口，同时保留旧窗口供复核。
    """
    with write_tx() as c:
        r = c.execute("SELECT * FROM rollouts WHERE rollout_id=?", (rollout_id,)).fetchone()
        if not r:
            raise NotFound(f"放量批次不存在: {rollout_id}")
        if r["status"] != "frozen":
            raise Conflict(f"批次当前状态为 {r['status']}，仅已冻结批次可恢复")
        if r["stoploss_tripped"]:
            raise Conflict(
                "该冻结由自动止损触发，不能直接恢复：请使用人工恢复（recover）——"
                "恢复会开启新代次并重置统计窗口，旧窗口保留复核")
        _cas_transition(c, rollout_id, expected_generation, "status='ramping'",
                        (), ("frozen",))
        audit(actor, "rollout.resume", "rollout", rollout_id,
              f"恢复放量 weight={r['weight']}%")
    return get_rollout(rollout_id)


def complete_rollout(rollout_id: str, expected_generation: int, actor: str) -> dict:
    """完成：候选构件转正——单事务内翻转线上指针并终结批次。

    要求线上指针仍等于批次基线（期间未被一步切换接口改动），否则冲突且
    路由表不变。完成后全部流量自然落到新线上版本。
    """
    with write_tx() as c:
        r = c.execute("SELECT * FROM rollouts WHERE rollout_id=?", (rollout_id,)).fetchone()
        if not r:
            raise NotFound(f"放量批次不存在: {rollout_id}")
        if r["status"] not in ROLLOUT_OPEN:
            raise Conflict("批次已终结，不可完成")
        family = c.execute("SELECT * FROM families WHERE family_id=?",
                           (r["family_id"],)).fetchone()
        if family["active_version_id"] != r["base_version_id"]:
            raise Conflict("线上指针已偏离批次基线（期间发生了一步切换），批次不能完成；"
                           "请撤销该批次后重新评估")
        # 完成即翻线上指针：按业务时刻（此刻）重新确认扩权授权仍有效且覆盖候选
        # 全部工具——授权在建批后到期/被撤销/只覆盖部分工具时，完成必须失败，
        # 批次状态与线上指针都不变。
        base_tools = _loads(c.execute(
            "SELECT tool_permissions FROM versions WHERE version_id=?",
            (r["base_version_id"],)).fetchone()["tool_permissions"])
        cand_row = c.execute("SELECT * FROM versions WHERE version_id=?",
                             (r["candidate_version_id"],)).fetchone()
        _require_active_expansion(c, r["candidate_version_id"], base_tools,
                                  _loads(cand_row["tool_permissions"]), db_now(c),
                                  where="放量完成转正（complete）")
        _cas_transition(c, rollout_id, expected_generation,
                        "status='completed', weight=100", (), ROLLOUT_OPEN)
        c.execute("UPDATE families SET active_version_id=?, updated_at=datetime('now') "
                  "WHERE family_id=?", (r["candidate_version_id"], r["family_id"]))
        c.execute("UPDATE versions SET status='active', promoted_at=datetime('now') "
                  "WHERE version_id=?", (r["candidate_version_id"],))
        c.execute("UPDATE versions SET status='superseded' WHERE version_id=?",
                  (r["base_version_id"],))
        _close_active_window(c, rollout_id, reason="rollout_completed")
        audit(actor, "rollout.complete", "rollout", rollout_id,
              f"候选转正 {r['base_version_id']} -> {r['candidate_version_id']}")
    return get_rollout(rollout_id)


def cancel_rollout(rollout_id: str, expected_generation: int, actor: str) -> dict:
    """撤销：终结批次，流量全部回归当前构件（线上指针从未移动，天然回归）。"""
    with write_tx() as c:
        r = c.execute("SELECT * FROM rollouts WHERE rollout_id=?", (rollout_id,)).fetchone()
        if not r:
            raise NotFound(f"放量批次不存在: {rollout_id}")
        if r["status"] not in ROLLOUT_OPEN:
            raise Conflict("批次已终结，不可撤销")
        _cas_transition(c, rollout_id, expected_generation,
                        "status='cancelled'", (), ROLLOUT_OPEN)
        _close_active_window(c, rollout_id, reason="rollout_cancelled")
        audit(actor, "rollout.cancel", "rollout", rollout_id,
              f"撤销放量，流量回归当前构件 {r['base_version_id']}")
    return get_rollout(rollout_id)


# ================================================================ 自动止损

FEEDBACK_OUTCOMES = ("success", "failure")


class _ConcurrentTrip(Exception):
    """本事务的冻结行守卫失败：批次已被并发越界回执抢先冻结。内部信号，触发整单重试，
    重试会在最新状态下走到 stoploss_tripped 的只审计分支。"""


def _semver(c, version_id: str) -> str:
    row = c.execute("SELECT semver FROM versions WHERE version_id=?",
                    (version_id,)).fetchone()
    return row["semver"] if row else ""


def _close_active_window(c, rollout_id: str, reason: str) -> None:
    """关闭仍 active 的统计窗口（tripped 窗口保留其触发状态，不动）。

    批次完成/撤销时调用；与批次状态切换在同一写事务内。
    """
    cur = c.execute(
        "UPDATE stoploss_windows SET status='closed', closed_at=datetime('now') "
        "WHERE rollout_id=? AND status='active'", (rollout_id,))
    if cur.rowcount:
        audit("system", "stoploss.window_closed", "stoploss_window", rollout_id, reason)


# ---------------------------------------------------------------- 配置

def configure_stoploss(rollout_id: str, window_seconds: int, min_sample: int,
                       fail_ratio_limit: float, actor: str) -> dict:
    """设置/更新试投的止损配置：观察窗口、最小样本量、失败占比上限。

    统计窗口一旦开启（已有入账回执），当前窗口的判定门槛冻结为开窗时的配置快照；
    为避免窗口中途移动门槛，此时拒绝改配——请先人工恢复重置窗口后再调整。
    """
    window_seconds = int(window_seconds)
    min_sample = int(min_sample)
    fail_ratio_limit = float(fail_ratio_limit)
    if window_seconds <= 0:
        raise DomainError("观察窗口必须是正整数秒")
    if min_sample < 1:
        raise DomainError("最小样本量必须 ≥ 1")
    if not (0.0 <= fail_ratio_limit <= 1.0):
        raise DomainError("失败占比上限必须在 [0, 1] 之间（0 = 任何失败都越界）")
    with write_tx() as c:
        r = c.execute("SELECT * FROM rollouts WHERE rollout_id=?", (rollout_id,)).fetchone()
        if not r:
            raise NotFound(f"放量批次不存在: {rollout_id}")
        if r["status"] not in ROLLOUT_OPEN:
            raise Conflict(f"批次已终结（{r['status']}），不能再配置止损")
        w = c.execute("SELECT * FROM stoploss_windows WHERE rollout_id=? AND status='active'",
                      (rollout_id,)).fetchone()
        if w and c.execute(
                "SELECT 1 FROM feedback_receipts WHERE window_id=? LIMIT 1",
                (w["window_id"],)).fetchone():
            raise Conflict(
                "当前统计窗口已有入账回执，门槛已冻结；请先人工恢复（recover）开启新窗口后再改配")
        exists = c.execute("SELECT 1 FROM stoploss_configs WHERE rollout_id=?",
                           (rollout_id,)).fetchone()
        if exists:
            c.execute(
                """UPDATE stoploss_configs SET window_seconds=?, min_sample=?,
                   fail_ratio_limit=?, created_by=?, updated_at=datetime('now')
                   WHERE rollout_id=?""",
                (window_seconds, min_sample, fail_ratio_limit, actor, rollout_id))
            action = "stoploss.config_update"
        else:
            c.execute(
                """INSERT INTO stoploss_configs(rollout_id,window_seconds,min_sample,
                   fail_ratio_limit,created_by) VALUES (?,?,?,?,?)""",
                (rollout_id, window_seconds, min_sample, fail_ratio_limit, actor))
            action = "stoploss.config_set"
        audit(actor, action, "rollout", rollout_id,
              f"window={window_seconds}s min_sample={min_sample} "
              f"fail_ratio_limit={fail_ratio_limit:.2f}")
    return get_stoploss_config(rollout_id)


def get_stoploss_config(rollout_id: str) -> dict | None:
    row = get_conn().execute("SELECT * FROM stoploss_configs WHERE rollout_id=?",
                             (rollout_id,)).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------- 窗口 / 统计

def list_windows(rollout_id: str) -> list[dict]:
    return [dict(r) for r in get_conn().execute(
        "SELECT * FROM stoploss_windows WHERE rollout_id=? ORDER BY seq DESC",
        (rollout_id,)).fetchall()]


def _get_or_open_window(c, rollout_id: str, config_row) -> dict:
    """取当前 active 窗口；不存在则按当前配置开窗（seq 在批次内递增）。"""
    w = c.execute(
        "SELECT * FROM stoploss_windows WHERE rollout_id=? AND status='active'",
        (rollout_id,)).fetchone()
    if w:
        return dict(w)
    last = c.execute("SELECT COALESCE(MAX(seq),0) AS m FROM stoploss_windows WHERE rollout_id=?",
                     (rollout_id,)).fetchone()["m"]
    window_id = _uid("win")
    c.execute(
        """INSERT INTO stoploss_windows(window_id,rollout_id,seq,status,window_seconds,
           min_sample,fail_ratio_limit) VALUES (?,?,?, 'active',?,?,?)""",
        (window_id, rollout_id, last + 1, config_row["window_seconds"],
         config_row["min_sample"], config_row["fail_ratio_limit"]))
    audit("system", "stoploss.window_open", "stoploss_window", window_id,
          f"rollout={rollout_id} seq={last + 1} window={config_row['window_seconds']}s "
          f"min_sample={config_row['min_sample']} limit={config_row['fail_ratio_limit']:.2f}")
    return dict(c.execute("SELECT * FROM stoploss_windows WHERE window_id=?",
                          (window_id,)).fetchone())


def _window_stats(c, window_row: dict, at_request_created_at: str) -> dict:
    """滚动窗口统计：仅统计请求产生时间在 [t-window_seconds, t] 内的入账回执。

    以刚入账回执复制的 requests.created_at 为右端点，故"迟到回执"按其真实产生
    时刻落入窗口参与计数；窗口前的旧回执自然被排除，不会改变当前判定。
    """
    row = c.execute(
        """SELECT COUNT(*) AS total,
                  COALESCE(SUM(CASE WHEN outcome='failure' THEN 1 ELSE 0 END),0) AS fails
           FROM feedback_receipts
           WHERE window_id=? AND request_created_at <= ?
             AND request_created_at >= datetime(?, ?)""",
        (window_row["window_id"], at_request_created_at, at_request_created_at,
         f"-{int(window_row['window_seconds'])} seconds")).fetchone()
    total, fails = int(row["total"]), int(row["fails"])
    return {"total": total, "fails": fails,
            "fail_ratio": (fails / total) if total else 0.0}


def window_stats(rollout_id: str, window_id: str) -> dict:
    """历史页用：以当前时刻为右端点的滚动窗口统计。"""
    conn = get_conn()
    w = conn.execute("SELECT * FROM stoploss_windows WHERE window_id=?",
                     (window_id,)).fetchone()
    if not w:
        raise NotFound(f"统计窗口不存在: {window_id}")
    return _window_stats(conn, dict(w), _db_now(conn))


def _db_now(c) -> str:
    return c.execute("SELECT datetime('now') AS t").fetchone()["t"]


# ---------------------------------------------------------------- 回执入账 / 触发

def report_feedback(rollout_id: str, feedback_id: str, request_id: str,
                    outcome: str, actor: str) -> dict:
    """报告一次生产推理效果回执，并在同一事务内完成自动止损判定。

    入账前置（任一不满足则只写审计记录、不触发任何状态变化，HTTP 仍返回 200）：
    1. request 存在且真实由该试投产生（requests.rollout_id 一致）；
    2. 请求实际命中候选构件（version_id == 候选），基线/无关请求不入账；
    3. 命中时批次代次 == 当前批次代次，旧代次（冻结/升档/止损前）只留审计；
    4. 回执在配置的滚动观察窗口内（按请求产生时间），迟到回执只留审计；
    5. 批次当前为 ramping（含自动止损冻结/完成/撤销均不再入账）；
    6. 已配置止损参数。

    硬冲突（409）：同一 feedback_id 重复回执；同一 request_id 重复入账。
    触发：窗口内样本 ≥ min_sample 且 fail/total 严格大于 fail_ratio_limit 时，
    在同一事务内冻结批次、新流量回落基线（路由层看到 frozen 即走基线）、保存快照。
    """
    feedback_id = str(feedback_id).strip()
    request_id = str(request_id).strip()
    if not feedback_id or not request_id:
        raise DomainError("feedback_id 与 request_id 不能为空")
    if outcome not in FEEDBACK_OUTCOMES:
        raise DomainError("outcome 必须是 success 或 failure")

    def _attempt():
        with write_tx() as c:
            # 幂等键优先：同一 feedback_id 全局只能入账一次。先于 request/rollout
            # 查找，保证调用方拿同一 feedback_id 重试时始终得到一致的 409，且不改状态。
            prev = c.execute("SELECT request_id,outcome,rollout_id FROM feedback_receipts "
                             "WHERE feedback_id=?", (feedback_id,)).fetchone()
            if prev:
                audit(actor, "feedback.duplicate", "feedback", feedback_id,
                      f"rollout={rollout_id} request={request_id} 已对 "
                      f"rollout={prev['rollout_id']} request={prev['request_id']} "
                      f"outcome={prev['outcome']} 入账，重复回执拒绝")
                raise Conflict(f"feedback_id={feedback_id} 已入账（对应 request="
                               f"{prev['request_id']}），同一回执只能入账一次")
            req = c.execute("SELECT * FROM requests WHERE request_id=?",
                            (request_id,)).fetchone()
            if not req:
                raise NotFound(f"请求不存在: {request_id}")
            r = c.execute("SELECT * FROM rollouts WHERE rollout_id=?",
                          (rollout_id,)).fetchone()
            if not r:
                raise NotFound(f"放量批次不存在: {rollout_id}")

            def reject(reason: str, detail: str):
                audit(actor, "feedback.reject", "feedback", feedback_id,
                      f"rollout={rollout_id} request={request_id} outcome={outcome} "
                      f"reason={reason} {detail}".strip())
                return {"feedback_id": feedback_id, "rollout_id": rollout_id,
                        "request_id": request_id, "outcome": outcome, "credited": False,
                        "reject_reason": reason, "tripped": False}

            # 1) 回执必须对应该试投真实产生的请求
            if not req["rollout_id"]:
                return reject("unrelated_request",
                              f"请求未参与任何放量（hit={req['version_id']}）")
            if req["rollout_id"] != rollout_id:
                return reject("unrelated_request",
                              f"请求属于另一批次 {req['rollout_id']}")
            # 同一 request_id 在同一批次只能入账一次（紧跟归属校验之后：即便批次随后
            # 冻结/升代，重复报告同一条试投请求仍应得到 409，而不是被当成旧代次回执）
            dup_req = c.execute(
                "SELECT feedback_id FROM feedback_receipts WHERE request_id=?",
                (request_id,)).fetchone()
            if dup_req:
                audit(actor, "feedback.duplicate", "feedback", feedback_id,
                      f"rollout={rollout_id} request={request_id} 已有入账回执 "
                      f"{dup_req['feedback_id']}，一条请求只能报告一次")
                raise Conflict(f"request_id={request_id} 已有入账回执 "
                               f"{dup_req['feedback_id']}，一条请求只能报告一次")
            # 2) 必须命中候选构件（冻结期产生的调用命中基线，仅审计）
            if req["version_id"] != r["candidate_version_id"]:
                # 批次已被自动止损冻结时，冻结期基线请求给出更明确的原因
                if r["status"] == "frozen" and r["stoploss_tripped"]:
                    return reject("stoploss_tripped",
                                  f"批次已自动止损冻结，请求命中基线 {req['version_id']}")
                return reject("hit_baseline",
                              f"请求命中基线构件 {req['version_id']}，非候选")
            # 候选命中但批次已不在放量：冻结（含止损）/完成/撤销后的候选命中理论上不会
            # 新增（路由层已回落），仍明确记录，绝不触发状态变化
            if r["status"] != "ramping":
                if r["stoploss_tripped"]:
                    return reject("stoploss_tripped", f"批次已自动止损冻结（{r['status']}）")
                return reject("rollout_not_ramping", f"批次当前状态 {r['status']}")
            # 3) 旧代次只留审计（状态仍为 ramping，但请求是旧代次产生的）
            if req["rollout_generation"] != r["generation"]:
                return reject("stale_generation",
                              f"请求命中代次 {req['rollout_generation']}，"
                              f"当前代次 {r['generation']}")
            # 6) 止损配置必须就位
            cfg = c.execute("SELECT * FROM stoploss_configs WHERE rollout_id=?",
                            (rollout_id,)).fetchone()
            if not cfg:
                return reject("stoploss_not_configured", "批次尚未配置止损参数")
            # 4) 观察窗口（惰性开窗前先判迟到：开窗不改变时间判定）
            now = _db_now(c)
            req_at = req["created_at"]
            age = c.execute(
                "SELECT CAST((julianday(?) - julianday(?)) * 86400 AS INTEGER) AS age",
                (now, req_at)).fetchone()["age"]
            if age is None or age < 0 or age > int(cfg["window_seconds"]):
                return reject("late_receipt",
                              f"请求产生于 {req_at}，超出观察窗口 {cfg['window_seconds']}s")

            window = _get_or_open_window(c, rollout_id, cfg)
            c.execute(
                """INSERT INTO feedback_receipts(feedback_id,rollout_id,window_id,request_id,
                   outcome,request_created_at,actor)
                   VALUES (?,?,?,?,?,?,?)""",
                (feedback_id, rollout_id, window["window_id"], request_id, outcome,
                 req_at, actor))

            stats = _window_stats(c, window, req_at)
            over_limit = stats["fail_ratio"] > float(window["fail_ratio_limit"]) + 1e-12
            reached_sample = stats["total"] >= int(window["min_sample"])
            tripped, trigger_id = False, None
            if reached_sample and over_limit:
                # —— 单事务自动止损：冻结批次 + 流量回落基线（frozen 语义）+ 快照。
                # 行守卫 rowcount=0 说明批次恰在本事务期间被另一越界回执冻结：
                # 本回执不得入账/触发，整单回滚后重试，在最新状态下走只审计分支。
                cur = c.execute(
                    "UPDATE rollouts SET status='frozen', stoploss_tripped=1, "
                    "generation=generation+1, updated_at=datetime('now') "
                    "WHERE rollout_id=? AND status='ramping'", (rollout_id,))
                if cur.rowcount != 1:
                    raise _ConcurrentTrip()
                trigger_id = _uid("trg")
                snapshot = {
                    "rollout_id": rollout_id,
                    "frozen_generation_before": r["generation"],
                    "frozen_generation_after": r["generation"] + 1,
                    "candidate_version_id": r["candidate_version_id"],
                    "candidate_semver": _semver(c, r["candidate_version_id"]),
                    "base_version_id": r["base_version_id"],
                    "base_semver": _semver(c, r["base_version_id"]),
                    "family_id": r["family_id"], "weight": r["weight"],
                    "window_seconds": window["window_seconds"],
                    "min_sample": window["min_sample"],
                    "fail_ratio_limit": window["fail_ratio_limit"],
                    "stats": stats, "trigger_request_id": request_id,
                    "trigger_feedback_id": feedback_id,
                    "traffic_action": "frozen: 新流量（含本应命中候选的 key）全部回落基线",
                }
                c.execute(
                    """INSERT INTO stoploss_triggers(trigger_id,window_id,rollout_id,
                       rollout_generation,candidate_version_id,candidate_semver,
                       base_version_id,base_semver,weight,total_sample,fail_count,
                       fail_ratio,trigger_feedback_id,snapshot_json)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (trigger_id, window["window_id"], rollout_id, r["generation"],
                     r["candidate_version_id"], snapshot["candidate_semver"],
                     r["base_version_id"], snapshot["base_semver"], r["weight"],
                     stats["total"], stats["fails"], stats["fail_ratio"],
                     feedback_id, json.dumps(snapshot, ensure_ascii=False, sort_keys=True)))
                c.execute(
                    "UPDATE stoploss_windows SET status='tripped', closed_at=datetime('now'), "
                    "trigger_id=? WHERE window_id=?", (trigger_id, window["window_id"]))
                audit(actor, "stoploss.trip", "rollout", rollout_id,
                      f"trigger={trigger_id} window={window['window_id']} "
                      f"sample={stats['total']} fail={stats['fails']} "
                      f"ratio={stats['fail_ratio']:.2f} > {window['fail_ratio_limit']:.2f}；"
                      f"单事务冻结批次，新流量回落基线 {r['base_version_id']}，"
                      f"代次 {r['generation']} -> {r['generation'] + 1}")
                tripped = True
            audit(actor, "feedback.credited", "feedback", feedback_id,
                  f"rollout={rollout_id} window={window['window_id']} request={request_id} "
                  f"outcome={outcome}" + (" TRIP" if tripped else ""))
            return {"feedback_id": feedback_id, "rollout_id": rollout_id,
                    "request_id": request_id, "outcome": outcome, "credited": True,
                    "reject_reason": None,
                    "window_id": window["window_id"], "window_seq": window["seq"],
                    "stats": stats,
                    "threshold": {"min_sample": window["min_sample"],
                                  "fail_ratio_limit": window["fail_ratio_limit"],
                                  "reached_sample": reached_sample, "over_limit": over_limit},
                    "tripped": tripped, "trigger_id": trigger_id}

    # 写锁串行下仍可能出现"读过 ramping 后赢家先提交冻结"的交错；最多重试一次，
    # 重试在最新已提交状态下重新判定（重复/旧代次/已冻结均有确定性归宿）。
    try:
        return _attempt()
    except _ConcurrentTrip:
        return _attempt()


# ---------------------------------------------------------------- 人工恢复

def recover_rollout(rollout_id: str, expected_generation: int, actor: str) -> dict:
    """人工恢复自动止损：开启新代次并重置统计窗口。

    - 仅可对自动止损冻结（frozen + stoploss_tripped）的批次执行；
    - 单事务：CAS 回 ramping（代次 +1）、清除止损标记、关闭已触发窗口、
      按当前配置开窗（seq+1，统计清零）；
    - 旧窗口（tripped）、触发快照、历史回执与请求全部保留，可继续复核；
    - 权重不变，恢复后按稳定散列分流（冻结前同 key 的决定与桶号一致）。
    """
    with write_tx() as c:
        r = c.execute("SELECT * FROM rollouts WHERE rollout_id=?", (rollout_id,)).fetchone()
        if not r:
            raise NotFound(f"放量批次不存在: {rollout_id}")
        if r["status"] != "frozen" or not r["stoploss_tripped"]:
            raise Conflict("只能对自动止损触发的冻结批次做人工恢复（普通冻结请用 resume）")
        if r["generation"] != expected_generation:
            raise Conflict("并发冲突：批次代次已变化（CAS 失败），请刷新后重试")
        cur = c.execute(
            "UPDATE rollouts SET status='ramping', stoploss_tripped=0, "
            "generation=generation+1, updated_at=datetime('now') "
            "WHERE rollout_id=? AND status='frozen' AND stoploss_tripped=1 AND generation=?",
            (rollout_id, expected_generation))
        if cur.rowcount != 1:
            raise Conflict("并发冲突：批次状态已变化，人工恢复中止（CAS 失败）")
        old_w = c.execute(
            "SELECT * FROM stoploss_windows WHERE rollout_id=? AND status='tripped' "
            "ORDER BY seq DESC LIMIT 1", (rollout_id,)).fetchone()
        old_seq = old_w["seq"] if old_w else 0
        cfg = c.execute("SELECT * FROM stoploss_configs WHERE rollout_id=?",
                        (rollout_id,)).fetchone()
        if not cfg:
            raise Conflict("批次缺少止损配置，无法重置统计窗口（请先重新配置）")
        new_window_id = _uid("win")
        c.execute(
            """INSERT INTO stoploss_windows(window_id,rollout_id,seq,status,window_seconds,
               min_sample,fail_ratio_limit,started_at)
               VALUES (?,?,?, 'active',?,?,?, datetime('now'))""",
            (new_window_id, rollout_id, old_seq + 1, cfg["window_seconds"],
             cfg["min_sample"], cfg["fail_ratio_limit"]))
        audit(actor, "stoploss.recover", "rollout", rollout_id,
              f"人工恢复：新代次 {expected_generation} -> {expected_generation + 1}，"
              f"新窗口 {new_window_id} seq={old_seq + 1} 统计重置（窗口 {cfg['window_seconds']}s/"
              f"min_sample={cfg['min_sample']}/limit={cfg['fail_ratio_limit']:.2f}），"
              f"旧窗口与历史请求保留复核")
    return get_rollout(rollout_id)


# ---------------------------------------------------------------- 触发 / 回执查询

def list_triggers(rollout_id: str | None = None) -> list[dict]:
    q = "SELECT * FROM stoploss_triggers"
    args: tuple = ()
    if rollout_id:
        q += " WHERE rollout_id=?"
        args = (rollout_id,)
    q += " ORDER BY created_at DESC"
    out = []
    for r in get_conn().execute(q, args).fetchall():
        d = dict(r)
        d["snapshot"] = _loads(d.pop("snapshot_json"))
        out.append(d)
    return out


def get_trigger(trigger_id: str) -> dict:
    r = get_conn().execute("SELECT * FROM stoploss_triggers WHERE trigger_id=?",
                           (trigger_id,)).fetchone()
    if not r:
        raise NotFound(f"触发快照不存在: {trigger_id}")
    d = dict(r)
    d["snapshot"] = _loads(d.pop("snapshot_json"))
    return d


def list_receipts(rollout_id: str | None = None, window_id: str | None = None,
                  limit: int = 200) -> list[dict]:
    q = ("SELECT fb.*, w.seq AS window_seq, ver.semver AS hit_semver, "
         "req.routing_key AS routing_key, req.rollout_generation AS hit_generation "
         "FROM feedback_receipts fb "
         "JOIN stoploss_windows w ON w.window_id=fb.window_id "
         "JOIN requests req ON req.request_id=fb.request_id "
         "JOIN versions ver ON ver.version_id=req.version_id")
    clauses, args = [], []
    if rollout_id:
        clauses.append("fb.rollout_id=?"); args.append(rollout_id)
    if window_id:
        clauses.append("fb.window_id=?"); args.append(window_id)
    if clauses:
        q += " WHERE " + " AND ".join(clauses)
    q += " ORDER BY fb.created_at DESC LIMIT ?"
    args.append(limit)
    return [dict(r) for r in get_conn().execute(q, tuple(args)).fetchall()]


def get_receipt(feedback_id: str) -> dict:
    r = get_conn().execute(
        "SELECT * FROM feedback_receipts WHERE feedback_id=?",
        (feedback_id,)).fetchone()
    if not r:
        raise NotFound(f"回执不存在: {feedback_id}")
    return dict(r)


def get_request_receipt(request_id: str) -> dict | None:
    r = get_conn().execute(
        "SELECT * FROM feedback_receipts WHERE request_id=?",
        (request_id,)).fetchone()
    return dict(r) if r else None


def list_rejected_feedback(rollout_id: str, limit: int = 200) -> list[dict]:
    """审计流中该批次被拒/重复的回执尝试（旧代次、迟到、无关请求等）。"""
    rows = get_conn().execute(
        "SELECT * FROM audit_log WHERE action IN ('feedback.reject','feedback.duplicate') "
        "AND detail LIKE ? ORDER BY id DESC LIMIT ?",
        (f"%{rollout_id}%", limit)).fetchall()
    return [dict(r) for r in rows]


def stoploss_overview(rollout_id: str) -> dict:
    """历史页面聚合：批次、配置、窗口（含统计）、触发快照、入账与被拒回执。"""
    ro = get_rollout(rollout_id)
    cfg = get_stoploss_config(rollout_id)
    windows = list_windows(rollout_id)
    conn = get_conn()
    for w in windows:
        stats_row = conn.execute(
            """SELECT COUNT(*) AS total,
                      COALESCE(SUM(CASE WHEN outcome='failure' THEN 1 ELSE 0 END),0) AS fails
               FROM feedback_receipts WHERE window_id=?""", (w["window_id"],)).fetchone()
        w["total"] = int(stats_row["total"])
        w["fails"] = int(stats_row["fails"])
        w["fail_ratio"] = (w["fails"] / w["total"]) if w["total"] else 0.0
        trg = conn.execute("SELECT trigger_id FROM stoploss_triggers WHERE window_id=?",
                           (w["window_id"],)).fetchone()
        w["trigger_id"] = trg["trigger_id"] if trg else None
    return {
        "rollout": ro, "config": cfg, "windows": windows,
        "triggers": list_triggers(rollout_id),
        "receipts": list_receipts(rollout_id=rollout_id),
        "rejected": list_rejected_feedback(rollout_id),
        "active_window": next((w for w in windows if w["status"] == "active"), None),
    }


# ================================================================ 线上调用

def invoke(family_id: str, inputs: dict, actor: str, request_id: str | None = None,
           routing_key: str | None = None) -> dict:
    """线上推理：敏感隔离 → 路由决策 → 精确三元组固化。

    处理顺序（隔离不可绕过）：
    1. 写锁事务内解析路由（命中构件/批次/授权快照），并读取族上**当前**隔离
       规则版本指针；同时用客户端 request_id 做幂等检查。
    2. 契约校验/投影后，对**原始**输入按固定规则版本扫描：block 命中即拒绝
       （不渲染、不推理，写 guard_block_log 后抛 GuardBlocked）；mask 命中则
       替换，遮盖后的输入参与模板渲染与模型推理；输出再扫一次防回显。
    3. 落库事务内再次确认扩权授权，并把规则版本 id/version/hash、原始输入摘要、
       遮盖映射（无原值）与密文（guard_secrets）固化。

    规则更新（新版本+翻族指针）发生在本请求解析之后时，本请求仍使用已固定的
    ruleset——规则更新不能改写在途请求。同一 request_id 的重复请求返回同一
    遮盖结果（不重新推理、不暴露原值）。
    """
    routing_key = (routing_key or "").strip() or None
    rid = (request_id or "").strip() or _uid("req")

    # --- 事务 1（立即取锁）：路由解析 + 规则版本固定 + 幂等检查 ---
    authz_snapshot = {"required": False}
    with write_tx() as c:
        family = c.execute("SELECT * FROM families WHERE family_id=?", (family_id,)).fetchone()
        if not family:
            raise NotFound(f"模板族不存在: {family_id}")
        active_id = family["active_version_id"]
        if not active_id:
            raise Conflict("该模板族尚未发布任何版本，拒绝线上流量")

        # 幂等：同一 request_id 视为同一业务请求。重复推理必须返回同一遮盖结果；
        # 原始输入摘要不同则明确拒绝（同一业务标识不允许改换内容重放）。
        prior = c.execute("SELECT * FROM requests WHERE request_id=?", (rid,)).fetchone()
        prior_block = None
        if not prior:
            prior_block = c.execute(
                "SELECT * FROM guard_block_log WHERE request_id=? ORDER BY id DESC LIMIT 1",
                (rid,)).fetchone()

        hit_version_id = active_id
        hit_rollout_id = None
        hit_generation = None
        rollout = c.execute(
            "SELECT * FROM rollouts WHERE family_id=? AND status IN ('ramping','frozen') "
            "ORDER BY created_at DESC LIMIT 1", (family_id,)).fetchone()
        if rollout and routing_key and rollout["status"] == "ramping":
            bucket = core.stable_bucket(rollout["rollout_id"], routing_key)
            if bucket < rollout["weight"]:
                cand = c.execute("SELECT * FROM versions WHERE version_id=?",
                                 (rollout["candidate_version_id"],)).fetchone()
                base = c.execute("SELECT * FROM versions WHERE version_id=?",
                                 (active_id,)).fetchone()
                base_tools, cand_tools = (_loads(base["tool_permissions"]),
                                          _loads(cand["tool_permissions"]))
                at = db_now(c)
                gate = _require_active_expansion(
                    c, cand["version_id"], base_tools, cand_tools, at,
                    where="候选实时命中")
                if gate["required"]:
                    a = gate["approval"]
                    authz_snapshot = {
                        "required": True, "checked_at": at,
                        "approval_id": a["approval_id"], "kind": a["kind"],
                        "decision": a["decision"], "approver": a["approver"],
                        "granted_tools": _loads(a["granted_tools"]),
                        "candidate_tools": cand_tools,
                        "added_tools": sorted(set(cand_tools) - set(base_tools)),
                        "valid_from": a["valid_from"], "valid_until": a["valid_until"],
                        "is_permanent": bool(a["is_permanent"]),
                        "revoke_version": a["revoke_version"],
                        "revoked_at": a["revoked_at"],
                        "state_at_check": a["state"],
                    }
                hit_version_id = cand["version_id"]
                hit_rollout_id = rollout["rollout_id"]
                hit_generation = rollout["generation"]
        elif rollout and rollout["status"] == "frozen":
            hit_rollout_id = rollout["rollout_id"]
            hit_generation = rollout["generation"]
        v = c.execute("SELECT * FROM versions WHERE version_id=?", (hit_version_id,)).fetchone()
        contract = _loads(v["variable_contract"])
        params = _loads(v["model_params"])
        model_id = params.get("_bound_model")
        if not model_id:
            raise DomainError("命中版本缺少绑定模型标识（数据异常）")

        # 固定本请求所用的敏感隔离规则版本（随后翻指针不影响本请求）
        grs = None
        if family["active_guard_ruleset_id"]:
            grs_row = c.execute("SELECT * FROM guard_rulesets WHERE ruleset_id=?",
                                (family["active_guard_ruleset_id"],)).fetchone()
            grs = ({"ruleset_id": grs_row["ruleset_id"], "version": grs_row["version"],
                    "content_hash": grs_row["content_hash"],
                    "rules": _loads(grs_row["rules_json"])} if grs_row else None)

    errors = core.validate_against_contract(inputs, contract)
    if errors:
        raise DomainError("输入违反变量契约: " + "; ".join(errors))
    effective_raw = core.project_inputs(inputs, contract)
    raw_digest = core.digest_inputs(effective_raw)

    # 幂等归宿 1：重复的成功请求——返回同一（遮盖）结果，绝不重新推理/再暴露原值
    if prior:
        if prior["raw_input_digest"] and prior["raw_input_digest"] != raw_digest:
            raise Conflict(
                f"request_id={rid} 已存在但输入摘要不同：同一业务请求标识不允许改换"
                "内容重放；如需新结果请使用新 request_id")
        return _idempotent_response(prior)
    # 幂等归宿 2：重复的阻断请求——给出同一确定的拒绝结论（不携带原值）
    if prior_block:
        pb = dict(prior_block)
        audit(actor, "guard.block.duplicate", "request", rid,
              f"family={family_id} ruleset=v{pb['ruleset_version']} "
              f"rule={pb['rule_id']} 重复阻断请求，返回同一拒绝结论")
        raise guard.GuardBlocked(pb["rule_id"], pb["rule_name"], pb["kind"],
                                 _loads(pb["fields_json"]), pb["ruleset_version"], rid)

    # --- 敏感隔离扫描（规则版本已固定；替换后内容参与渲染）---
    guard_status = "none"
    scan = None
    effective = effective_raw
    if grs:
        scan = guard.scan_inputs(grs["rules"], effective_raw)
        if scan["blocked"]:
            with write_tx() as c:
                # 并发的同 request_id 阻断：行可能已被另一线程写入，重读给出同一结论
                raced = c.execute(
                    "SELECT * FROM guard_block_log WHERE request_id=? ORDER BY id DESC LIMIT 1",
                    (rid,)).fetchone()
                if raced:
                    rb = dict(raced)
                    audit(actor, "guard.block.duplicate", "request", rid,
                          f"family={family_id} ruleset=v{rb['ruleset_version']} "
                          f"rule={rb['rule_id']} 并发重复阻断")
                else:
                    guard.log_block(c, request_id=rid, family_id=family_id, rs=grs,
                                    blocked=scan["blocked"], raw_input_digest=raw_digest,
                                    actor=actor)
                    audit(actor, "guard.block", "request", rid,
                          f"family={family_id} ruleset={grs['ruleset_id']}@v{grs['version']} "
                          f"rule={scan['blocked']['rule_id']} "
                          f"fields={scan['blocked']['fields']} "
                          f"count={scan['blocked']['match_count']} raw={raw_digest[:12]}")
            raise guard.GuardBlocked(scan["blocked"]["rule_id"], scan["blocked"]["name"],
                                     scan["blocked"]["kind"], scan["blocked"]["fields"],
                                     grs["version"], rid)
        effective = scan["masked_inputs"]
        guard_status = "masked" if scan["tokens"] else "clean"

    prompt = core.render_prompt(v["system_instruction"], contract,
                                effective if grs else inputs)
    output = llm.generate(model_id, v["content_hash"], prompt, effective, params)

    # 输出侧遮盖：模型若回显任一被替换原值，输出中再次命中同一模式即遮盖，
    # 保证导出/返回/落库的输出不含明文。
    output_masked_count = 0
    output_actions: list[dict] = []
    if grs:
        masked_output, output_masked_count = guard.scan_output(grs["rules"], output)
        if output_masked_count:
            output_actions.append({"stage": "output", "masked": output_masked_count})
            output = masked_output

    inp_digest = core.digest_inputs(effective)
    out_digest = core.digest_output(output)
    params_json = json.dumps(params, sort_keys=True, ensure_ascii=False)
    params_fp = core.params_fingerprint(params)

    with write_tx() as c:
        # 插入前在同一写锁事务内按"请求落库时刻"再确认一次授权（路由决策与本行
        # 写入之间隔着一次推理，期间授权可能恰好到期/被撤销）；任一失败本行不写，
        # 线上指针与放量状态也不变。最终快照以本次复核为准固化。
        if hit_rollout_id and authz_snapshot.get("required"):
            ro2 = c.execute("SELECT * FROM rollouts WHERE rollout_id=?",
                            (hit_rollout_id,)).fetchone()
            cand2 = c.execute("SELECT * FROM versions WHERE version_id=?",
                              (hit_version_id,)).fetchone()
            base2 = c.execute("SELECT * FROM versions WHERE version_id=?",
                              (ro2["base_version_id"],)).fetchone()
            base_tools2, cand_tools2 = (_loads(base2["tool_permissions"]),
                                        _loads(cand2["tool_permissions"]))
            at2 = db_now(c)
            gate2 = _require_active_expansion(
                c, hit_version_id, base_tools2, cand_tools2, at2,
                where="候选实时命中（落库复核）")
            a = gate2["approval"]
            authz_snapshot = {
                "required": True, "checked_at": at2,
                "approval_id": a["approval_id"], "kind": a["kind"],
                "decision": a["decision"], "approver": a["approver"],
                "granted_tools": _loads(a["granted_tools"]),
                "candidate_tools": cand_tools2,
                "added_tools": sorted(set(cand_tools2) - set(base_tools2)),
                "valid_from": a["valid_from"], "valid_until": a["valid_until"],
                "is_permanent": bool(a["is_permanent"]),
                "revoke_version": a["revoke_version"],
                "revoked_at": a["revoked_at"],
                "state_at_check": a["state"],
            }
        snapshot_json = json.dumps(authz_snapshot, ensure_ascii=False, sort_keys=True)
        grs_id = grs["ruleset_id"] if grs else None
        grs_ver = grs["version"] if grs else None
        grs_hash = grs["content_hash"] if grs else ""
        c.execute(
            """INSERT INTO requests(request_id,family_id,version_id,model_id,input_digest,
               inputs_json,rendered_prompt,output_digest,output,template_hash_at_call,
               routing_key,rollout_id,rollout_generation,params_json,params_fingerprint,
               authz_snapshot_json,guard_ruleset_id,guard_ruleset_version,
               guard_ruleset_hash,raw_input_digest,guard_status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (rid, family_id, hit_version_id, model_id, inp_digest,
             json.dumps(effective, ensure_ascii=False, sort_keys=True), prompt,
             out_digest, output, v["content_hash"], routing_key, hit_rollout_id,
             hit_generation, params_json, params_fp, snapshot_json,
             grs_id, grs_ver, grs_hash, raw_digest, guard_status))
        if grs and scan and scan["tokens"]:
            tokens = scan["tokens"]
            guard.persist_secrets(c, rid, tokens)
            actions = {"masked": len(tokens),
                       "rules_hit": scan["rules_hit"],
                       "rule_ids": sorted({t["rule_id"] for t in tokens})}
            c.execute(
                """INSERT INTO guard_request_masks(request_id,ruleset_id,ruleset_version,
                   ruleset_hash,raw_input_digest,tokens_json,actions_json,
                   output_actions_json) VALUES (?,?,?,?,?,?,?,?)""",
                (rid, grs["ruleset_id"], grs["version"], grs["content_hash"], raw_digest,
                 json.dumps(guard.storable_tokens(tokens), ensure_ascii=False),
                 json.dumps(actions, ensure_ascii=False, sort_keys=True),
                 json.dumps(output_actions, ensure_ascii=False)))
        audit(actor, "invoke", "request", rid,
              f"family={family_id} version={hit_version_id} model={model_id} "
              f"input={inp_digest[:12]} output={out_digest[:12]}"
              + (f" rollout={hit_rollout_id}@gen{hit_generation} key={routing_key}"
                 if hit_rollout_id else "")
              + (" authz=" + authz_snapshot.get("approval_id", "none")
                 if authz_snapshot.get("required") else "")
              + (f" guard=v{grs['version']} {guard_status} masked="
                 f"{len(scan['tokens']) if scan else 0}" if grs else ""))
    return {
        "request_id": rid, "family_id": family_id, "version_id": hit_version_id,
        "model_id": model_id, "input_digest": inp_digest, "template_hash": v["content_hash"],
        "output_digest": out_digest, "rendered_prompt": prompt, "output": _loads(output),
        "routing_key": routing_key, "rollout_id": hit_rollout_id,
        "rollout_generation": hit_generation, "params_fingerprint": params_fp,
        "authz_snapshot": authz_snapshot,
        "guard": {"ruleset_id": grs_id, "ruleset_version": grs_ver,
                  "ruleset_hash": grs_hash, "status": guard_status,
                  "masked": len(scan["tokens"]) if grs and scan else 0,
                  "output_masked": output_masked_count,
                  "redacted": True if (grs and scan and scan["tokens"]) else False},
        "idempotent": False,
    }


def _idempotent_response(row) -> dict:
    """重复请求：从已落库（遮盖后）记录重建同一响应，绝不重新推理或暴露原值。"""
    d = dict(row)
    gv = guard.request_guard_view(d["request_id"])
    return {
        "request_id": d["request_id"], "family_id": d["family_id"],
        "version_id": d["version_id"], "model_id": d["model_id"],
        "input_digest": d["input_digest"], "template_hash": d["template_hash_at_call"],
        "output_digest": d["output_digest"], "rendered_prompt": d["rendered_prompt"],
        "output": _loads(d["output"]),
        "routing_key": d["routing_key"], "rollout_id": d["rollout_id"],
        "rollout_generation": d["rollout_generation"],
        "params_fingerprint": d["params_fingerprint"],
        "authz_snapshot": (_loads(d["authz_snapshot_json"])
                           if d["authz_snapshot_json"] else {"required": False}),
        "guard": ({"ruleset_id": gv["ruleset_id"], "ruleset_version": gv["ruleset_version"],
                   "ruleset_hash": gv["ruleset_hash"], "status": gv["status"],
                   "masked": len(gv.get("tokens", [])),
                   "output_masked": sum(a.get("masked", 0)
                                        for a in gv.get("output_actions", [])),
                   "redacted": True} if gv else None),
        "idempotent": True,
    }


def get_request(request_id: str) -> dict:
    r = get_conn().execute("SELECT * FROM requests WHERE request_id=?",
                           (request_id,)).fetchone()
    if not r:
        raise NotFound(f"请求不存在: {request_id}")
    d = dict(r)
    d["authz_snapshot"] = _loads(d["authz_snapshot_json"]) if d["authz_snapshot_json"] else None
    return d


def request_authz_view(request_id: str) -> dict | None:
    """调用复查页用：命中时固化的授权快照 + 该审批当前状态对照。

    历史结论只按快照复查（随后到期/撤销不改写）；当前状态仅作展示对照。
    返回 None 表示该命中未走扩权复核（基线/未扩大候选/旧调用）。
    """
    r = get_conn().execute("SELECT authz_snapshot_json FROM requests WHERE request_id=?",
                           (request_id,)).fetchone()
    if not r or not r["authz_snapshot_json"]:
        return None
    snap = _loads(r["authz_snapshot_json"])
    if not snap.get("required"):
        return snap
    cur_row = get_conn().execute(
        "SELECT * FROM approvals WHERE approval_id=?",
        (snap["approval_id"],)).fetchone()
    snap["current"] = approval_view(cur_row) if cur_row else None
    return snap


# ================================================================ 重演

def replay(request_id: str, actor: str, override_version_id: str | None = None,
           override_model_id: str | None = None, override_inputs: dict | None = None,
           inject_drift: bool = False) -> dict:
    """按原元数据复核，并可做单轴反事实重演以归因。

    - exact：原版本/模型/输入重放，比对输出摘要；
    - 反事实：仅改 input|model|template 之一，定位差异来源；
    - inject_drift：模拟后端非确定性（三元组不变但输出漂移）。
    """
    req = get_request(request_id)
    orig_v = _version_row(req["version_id"])
    use_version_id = override_version_id or req["version_id"]
    use_model_id = override_model_id or req["model_id"]
    v = _version_row(use_version_id)
    llm.get_model(use_model_id)

    orig_inputs = _loads(req["inputs_json"])
    use_inputs = override_inputs if override_inputs is not None else orig_inputs
    contract = _loads(v["variable_contract"])
    # 复核原命中构件时，优先使用调用记录固化的推理配置（权重/批次变化不影响复查）；
    # 反事实换版本时取目标版本快照。老数据无 params_json 则回退版本快照。
    frozen_params = req.get("params_json") or ""
    if use_version_id == req["version_id"] and frozen_params:
        params = _loads(frozen_params)
    else:
        params = _loads(v["model_params"])

    errors = core.validate_against_contract(use_inputs, contract)
    if errors:
        raise DomainError("重演输入违反目标版本变量契约: " + "; ".join(errors))
    effective = core.project_inputs(use_inputs, contract)
    prompt = core.render_prompt(v["system_instruction"], contract, use_inputs)
    output = llm.generate(use_model_id, v["content_hash"], prompt, effective, params)
    if inject_drift:
        # 模拟同三元组下的运行时漂移（真实模型温度/后端差异）
        import uuid as _u
        output = json.dumps({**_loads(output), "_drift": _u.uuid4().hex[:8]},
                            ensure_ascii=False, sort_keys=True)

    new_in_digest = core.digest_inputs(effective)
    new_out_digest = core.digest_output(output)
    same_template = v["content_hash"] == req["template_hash_at_call"]
    same_model = use_model_id == req["model_id"]
    same_input = new_in_digest == req["input_digest"]
    same_output = new_out_digest == req["output_digest"]

    changed_axes = []
    if not same_template:
        changed_axes.append("template")
    if not same_model:
        changed_axes.append("model")
    if not same_input:
        changed_axes.append("input")
    mode = "exact" if not changed_axes and not override_version_id and \
        not override_model_id and override_inputs is None else "counterfactual"

    if same_template and same_model and same_input and same_output:
        verdict = "reproduced"
    elif same_template and same_model and same_input and not same_output:
        verdict = "output_drift"
    elif len(changed_axes) == 1:
        verdict = f"{changed_axes[0]}_changed"
    else:
        verdict = "mixed_changes:" + "+".join(changed_axes) if changed_axes else "output_drift"

    replay_id = _uid("rpl")
    with write_tx() as c:
        c.execute(
            """INSERT INTO replays(replay_id,request_id,mode,changed_axis,ov_version_id,
               ov_model_id,ov_input_digest,verdict,same_template,same_model,same_input,
               same_output,replay_output_digest,replay_output)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (replay_id, request_id, mode, ",".join(changed_axes) or "none",
             override_version_id, use_model_id if override_model_id else None,
             new_in_digest if override_inputs is not None else None, verdict,
             int(same_template), int(same_model), int(same_input), int(same_output),
             new_out_digest, output))
        audit(actor, "replay", "replay", replay_id,
              f"request={request_id} mode={mode} axes={changed_axes} verdict={verdict}")
    return {
        "replay_id": replay_id, "request_id": request_id, "mode": mode, "verdict": verdict,
        "changed_axes": changed_axes,
        "original": {
            "version_id": req["version_id"], "model_id": req["model_id"],
            "input_digest": req["input_digest"], "output_digest": req["output_digest"],
            "template_hash": req["template_hash_at_call"],
            "output": _loads(req["output"]),
        },
        "replayed": {
            "version_id": use_version_id, "model_id": use_model_id,
            "input_digest": new_in_digest, "output_digest": new_out_digest,
            "template_hash": v["content_hash"],
            "rendered_prompt": prompt, "output": _loads(output),
        },
        "axes": {"template": same_template, "model": same_model,
                 "input": same_input, "output": same_output},
    }


def list_replays(request_id: str | None = None) -> list[dict]:
    q = "SELECT * FROM replays"
    args: tuple = ()
    if request_id:
        q += " WHERE request_id=?"
        args = (request_id,)
    q += " ORDER BY created_at DESC"
    return [dict(r) for r in get_conn().execute(q, args).fetchall()]


def list_requests(family_id: str | None = None, limit: int = 50) -> list[dict]:
    q = "SELECT * FROM requests"
    args: tuple = ()
    if family_id:
        q += " WHERE family_id=?"
        args = (family_id,)
    q += " ORDER BY created_at DESC LIMIT ?"
    args = args + (limit,)
    return [dict(r) for r in get_conn().execute(q, args).fetchall()]


def audit_log(limit: int = 100) -> list[dict]:
    return [dict(r) for r in get_conn().execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]
