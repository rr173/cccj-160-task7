"""HTTP 入口：JSON API + 评估页面 + 重演报告（仅依赖标准库）。"""
from __future__ import annotations

import json
import re
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

from . import config, evidence, guard, llm, services
from .db import audit, get_conn, init_db
from .jinja_compat import render_text

TPL_DIR = Path(__file__).resolve().parent / "templates"

_CSS = """
:root{--bg:#0f1420;--panel:#171e2e;--line:#27324a;--ink:#e6ebf5;--mut:#93a0b8;
--ok:#2fbf71;--bad:#ef5b5b;--warn:#e8a838;--acc:#4f8cff;--chip:#22304a}
*{box-sizing:border-box}body{margin:0;font:14px/1.55 -apple-system,Segoe UI,Roboto,
'Helvetica Neue',Arial,'PingFang SC','Microsoft YaHei',sans-serif;background:var(--bg);
color:var(--ink)}a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
header{padding:14px 22px;border-bottom:1px solid var(--line);display:flex;gap:18px;
align-items:center;background:#121826}header .brand{font-weight:700;font-size:16px}
header nav a{color:var(--mut);margin-right:14px}header nav a.on,header nav a:hover{color:var(--ink)}
.wrap{max-width:1180px;margin:22px auto;padding:0 20px}
.grid{display:grid;gap:16px}.g2{grid-template-columns:1fr 1fr}.g3{grid-template-columns:1fr 1fr 1fr}
@media(max-width:900px){.g2,.g3{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
.card h2{margin:0 0 12px;font-size:15px}.card h3{margin:18px 0 8px;font-size:13px;color:var(--mut);
text-transform:uppercase;letter-spacing:.06em}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:8px 10px;
border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mut);font-weight:600}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.small{font-size:12px;color:var(--mut)}.chip{display:inline-block;padding:2px 9px;border-radius:999px;
background:var(--chip);font-size:12px;border:1px solid var(--line)}
.badge{display:inline-block;padding:2px 9px;border-radius:6px;font-size:12px;font-weight:600}
.b-active{background:rgba(47,191,113,.15);color:var(--ok);border:1px solid rgba(47,191,113,.4)}
.b-draft{background:#2a3346;color:var(--mut)}.b-approved{background:rgba(79,140,255,.15);
color:var(--acc);border:1px solid rgba(79,140,255,.4)}.b-evaluating{background:rgba(232,168,56,.15);
color:var(--warn)}.b-evaluated{background:rgba(47,191,113,.12);color:var(--ok)}
.b-failed_eval,.b-rejected,.b-abandoned{background:rgba(239,91,91,.13);color:var(--bad)}
.b-superseded{background:#232c3f;color:#8a97ae}
.b-ramping{background:rgba(232,168,56,.15);color:var(--warn);border:1px solid rgba(232,168,56,.4)}
.b-frozen{background:rgba(79,140,255,.15);color:var(--acc);border:1px solid rgba(79,140,255,.4)}
.b-completed{background:rgba(47,191,113,.15);color:var(--ok);border:1px solid rgba(47,191,113,.4)}
.b-cancelled{background:#232c3f;color:#8a97ae}
.b-permanent{background:rgba(47,191,113,.15);color:var(--ok);border:1px solid rgba(47,191,113,.4)}
.b-pending{background:rgba(232,168,56,.15);color:var(--warn);border:1px solid rgba(232,168,56,.4)}
.b-expired{background:#2a3346;color:var(--mut);border:1px solid var(--line)}
.b-revoked{background:rgba(239,91,91,.13);color:var(--bad);border:1px solid rgba(239,91,91,.4)}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.mut{color:var(--mut)}
input,select,textarea{width:100%;background:#0f1624;border:1px solid var(--line);color:var(--ink);
border-radius:8px;padding:8px 10px;font:inherit;font-family:ui-monospace,Menlo,monospace;font-size:12.5px}
textarea{min-height:90px;resize:vertical}label{display:block;margin:10px 0 4px;font-size:12.5px;
color:var(--mut)}
button,.btn{display:inline-block;background:var(--acc);color:#fff;border:0;border-radius:8px;
padding:7px 14px;font:inherit;font-weight:600;cursor:pointer}button.ghost,.btn.ghost{background:#26304a;
color:var(--ink);border:1px solid var(--line)}button.danger{background:#5a2a2a}
button:disabled{opacity:.45;cursor:not-allowed}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
pre{background:#0d1320;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;
font-size:12px;max-height:340px}
.kv{display:grid;grid-template-columns:130px 1fr;gap:4px 12px;font-size:13px}.kv div:nth-child(odd){color:var(--mut)}
.flash{background:rgba(239,91,91,.12);border:1px solid rgba(239,91,91,.4);color:#ffb4b4;padding:10px 14px;
border-radius:8px;margin-bottom:14px}.note{background:rgba(79,140,255,.08);border:1px solid
rgba(79,140,255,.3);padding:10px 14px;border-radius:8px;margin-bottom:14px;font-size:13px}
.axis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:12px 0}
.axis div{background:#0d1320;border:1px solid var(--line);border-radius:8px;padding:10px;text-align:center}
"""


def render_template(name: str, ctx: dict) -> str:
    tpl = (TPL_DIR / name).read_text(encoding="utf-8")
    return render_text(tpl, ctx)


def page(title: str, content_name: str, ctx: dict) -> str:
    ctx.setdefault("flash", "")
    ctx["css"] = _CSS
    content = render_template(content_name, ctx)
    return render_template("layout.html", {"title": title, "css": _CSS, "content": content})


def _json_body(handler) -> dict:
    length = int(handler.headers.get("Content-Length") or 0)
    raw = handler.rfile.read(length) if length else b"{}"
    try:
        data = json.loads(raw.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        # 兼容普通表单
        data = {k: v[0] for k, v in parse_qs(raw.decode("utf-8")).items()}
    if not isinstance(data, dict):
        raise services.DomainError("请求体必须是 JSON 对象")
    return data


def _form(handler) -> dict:
    length = int(handler.headers.get("Content-Length") or 0)
    raw = handler.rfile.read(length).decode("utf-8") if length else ""
    return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}


def _jloads_field(form: dict, key: str, default):
    raw = form.get(key, "")
    if not str(raw).strip():
        return default
    return json.loads(raw)


def _short(h: str, n=12) -> str:
    return (h or "")[:n]


def _ver_context(v: dict) -> dict:
    return {
        "version_id": v["version_id"], "semver": v["semver"], "status": v["status"],
        "is_active": v["is_active"], "content_hash": v["content_hash"],
        "short_hash": _short(v["content_hash"]),
        "contract_change": v["contract_change"], "permission_expanded": v["permission_expanded"],
        "pass_rate": v["pass_rate"], "created_at": v["created_at"],
        "model_id": json.loads(v["model_params"]).get("_bound_model", ""),
        "tools": json.loads(v["tool_permissions"]),
        "contract": json.loads(v["variable_contract"]),
    }


def _authz_card(authz: dict | None) -> dict:
    """调用复查页：命中时固化的授权快照 + 当前状态对照（模板可直取）。"""
    if not authz:
        return {"exists": False}
    if not authz.get("required"):
        return {"exists": True, "required": False}
    cur = authz.get("current")
    window = "永久" if authz.get("is_permanent") else \
        f"{authz.get('valid_from') or '即刻'} ~ {authz.get('valid_until') or '永久'}"
    return {
        "exists": True, "required": True,
        "approval_id": authz["approval_id"], "approver": authz["approver"],
        "granted_tools": authz["granted_tools"], "candidate_tools": authz["candidate_tools"],
        "added_tools": authz["added_tools"], "checked_at": authz["checked_at"],
        "window_text": window, "is_permanent": bool(authz.get("is_permanent")),
        "state_at_check": authz["state_at_check"],
        "revoke_version": authz["revoke_version"],
        "current_exists": bool(cur),
        "current_state": cur["state"] if cur else "deleted",
        "current_changed": bool(cur and cur["state"] != authz["state_at_check"]),
        "current_remaining": cur["remaining_human"] if cur else "",
    }


def _scope_from_body(b: dict) -> dict:
    kind = (b.get("scope_kind") or b.get("kind") or "family").strip()
    if kind == "family":
        if not b.get("family_id"):
            raise services.DomainError("模板族范围必须提供 family_id")
        return {"kind": "family", "family_id": b["family_id"].strip()}
    if kind == "version":
        if not b.get("version_id"):
            raise services.DomainError("版本范围必须提供 version_id")
        return {"kind": "version", "version_id": b["version_id"].strip()}
    if kind in ("requests", "calls"):
        raw = b.get("request_ids") or []
        if isinstance(raw, str):
            raw = [s.strip() for s in raw.split(",") if s.strip()]
        if not raw:
            raise services.DomainError("调用范围必须提供 request_ids")
        return {"kind": "requests", "request_ids": [str(s).strip() for s in raw]}
    raise services.DomainError("scope kind 必须是 family / version / requests")


def _pack_summary(p: dict) -> dict:
    """证据包对外/页面共用的可 JSON 化摘要。"""
    if "archive_blob" in p:
        p = {k: v for k, v in p.items() if k != "archive_blob"}
    return p


def _scope_label(scope: dict) -> str:
    if scope.get("kind") == "family":
        return f"模板族 {scope.get('family_id')}"
    if scope.get("kind") == "version":
        return f"版本 {scope.get('version_id')}"
    return f"调用范围（{len(scope.get('request_ids', []))} 个调用）"


class Handler(BaseHTTPRequestHandler):
    server_version = "PromptGov/1.0"

    def log_message(self, fmt, *args):  # 安静日志
        pass

    # ------------------------------------------------------------ 工具
    def _send(self, code: int, body: bytes, ctype: str, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False, indent=2).encode(),
                   "application/json; charset=utf-8")

    def _html(self, html_text: str, code=200):
        self._send(code, html_text.encode("utf-8"), "text/html; charset=utf-8")

    def _redirect(self, location: str):
        self._send(HTTPStatus.SEE_OTHER, b"", "text/plain", {"Location": location})

    def _err(self, exc: Exception):
        if isinstance(exc, evidence.VerificationRejected):
            code = 422
        elif isinstance(exc, (guard.GuardUnauthorized, guard.GuardExpired)):
            code = 403
        elif isinstance(exc, guard.GuardBlocked):
            code = 403
        elif isinstance(exc, (guard.GuardReused, guard.GuardConflict)):
            code = 409
        elif isinstance(exc, guard.GuardDomain):
            code = 400
        elif isinstance(exc, services.NotFound):
            code = 404
        elif isinstance(exc, services.Conflict):
            code = 409
        elif isinstance(exc, services.DomainError):
            code = 400
        else:
            code = 500
            traceback.print_exc()
        body = {"error": type(exc).__name__, "message": str(exc)}
        if isinstance(exc, guard.GuardBlocked):
            body["blocked"] = {"rule_id": exc.rule_id, "kind": exc.kind,
                               "fields": exc.fields,
                               "ruleset_version": exc.ruleset_version}
        self._json(body, code)

    # ------------------------------------------------------------ 路由
    def do_GET(self):  # noqa: N802
        try:
            self._route("GET")
        except Exception as exc:  # noqa: BLE001
            if getattr(self, "_is_page", False):
                if isinstance(exc, services.NotFound):
                    code = 404
                elif isinstance(exc, (services.Conflict, services.DomainError)):
                    code = 400
                else:
                    code = 500
                self._html(page("出错", "error.html", {"message": str(exc),
                                                       "kind": type(exc).__name__}), code)
            else:
                self._err(exc)

    def do_POST(self):  # noqa: N802
        try:
            self._route("POST")
        except Exception as exc:  # noqa: BLE001
            if getattr(self, "_is_page", False):
                # 阻断/凭据类异常已经自行渲染页面（issue/reveal）；其余表单动作
                # 回到来源页提示（Guard 异常同样以错误信息展示，不泄露原值）。
                referer = self.headers.get("Referer", "/")
                self._redirect(referer.split("?")[0] + "?err=" + quote(str(exc)[:200]))
            else:
                self._err(exc)

    def do_PUT(self):  # noqa: N802
        try:
            self._route("PUT")
        except Exception as exc:  # noqa: BLE001
            self._err(exc)

    def _route(self, method: str):
        self._is_page = False
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        q = parse_qs(parsed.query)
        p = path

        # ------------------------------------------------ 页面
        if method == "GET" and p == "/":
            return self._page_dashboard(q)
        m = re.fullmatch(r"/families/([\w.-]+)", p)
        if method == "GET" and m:
            return self._page_family(m.group(1), q)
        m = re.fullmatch(r"/families/([\w.-]+)/guard", p)
        if method == "GET" and m:
            return self._page_family_guard(m.group(1), q)
        if method == "GET" and p == "/guard/audit":
            return self._page_guard_audit(q)
        m = re.fullmatch(r"/versions/([\w.-]+)/eval", p)
        if method == "GET" and m:
            return self._page_eval(m.group(1), q)
        if method == "GET" and p == "/approvals":
            return self._page_approvals(q, None)
        m = re.fullmatch(r"/requests/([\w.-]+)/replay", p)
        if method == "GET" and m:
            return self._page_replay(m.group(1), q)
        m = re.fullmatch(r"/families/([\w.-]+)/rollout", p)
        if method == "GET" and m:
            return self._page_rollout(m.group(1), q)
        m = re.fullmatch(r"/rollouts/([\w.-]+)/stoploss", p)
        if method == "GET" and m:
            return self._page_stoploss(m.group(1), q)
        # ------------------------------------------------ 证据包页面
        if method == "GET" and p == "/evidence":
            return self._page_evidence(q)
        if method == "GET" and p == "/evidence/export":
            return self._page_evidence_export(q)
        m = re.fullmatch(r"/evidence/packs/([\w.-]+)", p)
        if method == "GET" and m:
            return self._page_pack_detail(m.group(1), q)
        m = re.fullmatch(r"/evidence/packs/([\w.-]+)/versions/([\w.-]+)/eval", p)
        if method == "GET" and m:
            return self._page_pack_eval(m.group(1), m.group(2), q)
        m = re.fullmatch(r"/evidence/packs/([\w.-]+)/requests/([\w.-]+)/replay", p)
        if method == "GET" and m:
            return self._page_pack_replay(m.group(1), m.group(2), q)
        m = re.fullmatch(r"/evidence/packs/([\w.-]+)/rollouts/([\w.-]+)/stoploss", p)
        if method == "GET" and m:
            return self._page_pack_stoploss(m.group(1), m.group(2), q)

        # ------------------------------------------------ UI 表单动作
        if method == "POST" and re.fullmatch(r"/ui/families/[\w.-]+/versions", p):
            return self._ui_create_version(p.split("/")[3])
        if method == "POST" and re.fullmatch(r"/ui/versions/[\w.-]+/eval-start", p):
            return self._ui_eval_start(p.split("/")[3])
        if method == "POST" and re.fullmatch(r"/ui/eval-runs/[\w.-]+/run", p):
            return self._ui_eval_run(p.split("/")[3])
        if method == "POST" and re.fullmatch(r"/ui/versions/[\w.-]+/approve", p):
            return self._ui_approve(p.split("/")[3])
        if method == "POST" and re.fullmatch(r"/ui/approvals/[\w.-]+/revoke", p):
            return self._ui_revoke_approval(p.split("/")[3])
        if method == "POST" and re.fullmatch(r"/ui/families/[\w.-]+/(promote|rollback)", p):
            fid = p.split("/")[3]
            return self._ui_promote_rollback(fid, p.split("/")[-1])
        if method == "POST" and re.fullmatch(r"/ui/families/[\w.-]+/invoke", p):
            return self._ui_invoke(p.split("/")[3])
        if method == "POST" and re.fullmatch(r"/ui/families/[\w.-]+/rollouts", p):
            return self._ui_create_rollout(p.split("/")[3])
        if method == "POST" and \
                re.fullmatch(r"/ui/rollouts/[\w.-]+/(ramp|freeze|resume|complete|cancel)", p):
            return self._ui_rollout_action(p.split("/")[3], p.split("/")[-1])
        if method == "POST" and \
                re.fullmatch(r"/ui/rollouts/[\w.-]+/stoploss/config", p):
            return self._ui_stoploss_config(p.split("/")[3])
        if method == "POST" and \
                re.fullmatch(r"/ui/rollouts/[\w.-]+/stoploss/recover", p):
            return self._ui_stoploss_recover(p.split("/")[3])
        if method == "POST" and \
                re.fullmatch(r"/ui/rollouts/[\w.-]+/feedback", p):
            return self._ui_feedback(p.split("/")[3])
        if method == "POST" and \
                re.fullmatch(r"/ui/requests/[\w.-]+/feedback", p):
            return self._ui_feedback(p.split("/")[3])
        if method == "POST" and re.fullmatch(r"/ui/requests/[\w.-]+/replay", p):
            return self._ui_replay(p.split("/")[3])
        if method == "POST" and p == "/ui/families":
            return self._ui_create_family()
        if method == "POST" and p == "/ui/evidence/exports":
            return self._ui_export_pack()
        if method == "POST" and re.fullmatch(r"/ui/evidence/imports/[\w.-]+/commit", p):
            return self._ui_commit_import(p.split("/")[-2])
        if method == "POST" and re.fullmatch(r"/ui/evidence/imports/[\w.-]+/abort", p):
            return self._ui_abort_import(p.split("/")[-2])

        # ------------------------------------------------ Guard UI 表单动作
        if method == "POST" and re.fullmatch(r"/ui/families/[\w.-]+/guard/rulesets", p):
            return self._ui_guard_create_ruleset(p.split("/")[3])
        if method == "POST" and re.fullmatch(r"/ui/guard/rulesets/[\w.-]+/activate", p):
            return self._ui_guard_activate(p.split("/")[-2])
        if method == "POST" and re.fullmatch(r"/ui/families/[\w.-]+/guard/preview", p):
            return self._ui_guard_preview(p.split("/")[3])
        if method == "POST" and re.fullmatch(r"/ui/families/[\w.-]+/guard/grants", p):
            return self._ui_guard_grant(p.split("/")[3])
        if method == "POST" and re.fullmatch(r"/ui/guard/grants/[\w.-]+/revoke", p):
            return self._ui_guard_revoke_grant(p.split("/")[-2])
        if method == "POST" and re.fullmatch(r"/ui/requests/[\w.-]+/reveal-credential", p):
            return self._ui_guard_issue(p.split("/")[-2])
        if method == "POST" and re.fullmatch(r"/ui/requests/[\w.-]+/reveal", p):
            return self._ui_guard_reveal(p.split("/")[-2])

        # ------------------------------------------------ JSON API
        if method == "GET" and p == "/api/models":
            return self._json(llm.list_models())
        if method == "GET" and p == "/api/families":
            return self._json(services.list_families())
        if method == "POST" and p == "/api/families":
            b = _json_body(self)
            return self._json(services.create_family(
                b["family_id"], b["name"], b.get("description", ""), b.get("actor", "api")), 201)
        if method == "GET" and p == "/api/audit":
            return self._json(services.audit_log(int(q.get("limit", ["100"])[0])))

        m = re.fullmatch(r"/api/families/([\w.-]+)", p)
        if method == "GET" and m:
            return self._json(services.get_family(m.group(1)))
        m = re.fullmatch(r"/api/families/([\w.-]+)/versions", p)
        if m:
            fid = m.group(1)
            if method == "GET":
                return self._json(services.list_versions(fid))
            b = _json_body(self)
            v = services.create_version(
                fid, b["semver"], b["system_instruction"], b["variable_contract"],
                b.get("tool_permissions", []), b.get("model_params", {}),
                b["model_id"], b.get("actor", "api"))
            return self._json(v, 201)
        m = re.fullmatch(r"/api/families/([\w.-]+)/invoke", p)
        if method == "POST" and m:
            b = _json_body(self)
            return self._json(services.invoke(m.group(1), b["inputs"],
                                              b.get("actor", "api"),
                                              b.get("request_id"),
                                              b.get("routing_key")), 201)
        m = re.fullmatch(r"/api/families/([\w.-]+)/rollouts", p)
        if m:
            fid = m.group(1)
            if method == "GET":
                return self._json(services.list_rollouts(fid))
            b = _json_body(self)
            return self._json(services.create_rollout(
                fid, b["candidate_version_id"], int(b.get("weight", 10)),
                b.get("actor", "api")), 201)
        m = re.fullmatch(r"/api/families/([\w.-]+)/(promote|rollback)", p)
        if method == "POST" and m:
            b = _json_body(self)
            fid, action = m.group(1), m.group(2)
            if action == "promote":
                res = services.promote(fid, b["version_id"], b.get("actor", "api"),
                                       b.get("expected_active"))
            else:
                res = services.rollback(fid, b["target_version_id"], b.get("actor", "api"),
                                        b.get("expected_active"))
            return self._json(res)

        m = re.fullmatch(r"/api/versions/([\w.-]+)", p)
        if method == "GET" and m:
            return self._json(services.get_version(m.group(1)))
        m = re.fullmatch(r"/api/versions/[\w.-]+/eval/start", p)
        if method == "POST" and m:
            vid = p.split("/")[3]
            run_id = services.start_evaluation(vid, "api")
            return self._json({"run_id": run_id}, 202)
        m = re.fullmatch(r"/api/eval-runs/([\w.-]+)/run", p)
        if method == "POST" and m:
            return self._json(services.run_evaluation(m.group(1), "api"))
        m = re.fullmatch(r"/api/versions/([\w.-]+)/eval-runs", p)
        if method == "GET" and m:
            return self._json(services.list_eval_runs(m.group(1)))
        m = re.fullmatch(r"/api/versions/([\w.-]+)/approve", p)
        if method == "POST" and m:
            b = _json_body(self)
            return self._json(services.approve(
                m.group(1), b["kind"], b.get("approver", "api"),
                b.get("decision", "approved"), b.get("reason", ""),
                b.get("granted_tools"), b.get("valid_from"),
                b.get("valid_until")), 201)
        m = re.fullmatch(r"/api/approvals/([\w.-]+)/revoke", p)
        if method == "POST" and m:
            b = _json_body(self)
            if b.get("expected_version") is None:
                raise services.DomainError(
                    "必须提供 expected_version（审批版本号）做并发控制")
            return self._json(services.revoke_approval(
                m.group(1), int(b["expected_version"]), b.get("actor", "api"),
                b.get("reason", "")))
        m = re.fullmatch(r"/api/approvals/([\w.-]+)", p)
        if method == "GET" and m:
            return self._json(services.get_approval(m.group(1)))
        if method == "GET" and p == "/api/approvals":
            return self._json(services.list_approvals(q.get("version", [None])[0]))
        m = re.fullmatch(r"/api/eval-runs/([\w.-]+)", p)
        if method == "GET" and m:
            return self._json(services.get_eval_run(m.group(1)))
        m = re.fullmatch(r"/api/rollouts/([\w.-]+)", p)
        if method == "GET" and m:
            return self._json(services.get_rollout(m.group(1)))
        m = re.fullmatch(r"/api/rollouts/([\w.-]+)/(ramp|freeze|resume|complete|cancel)", p)
        if method == "POST" and m:
            b = _json_body(self)
            rid, action = m.group(1), m.group(2)
            gen = b.get("expected_generation")
            if gen is None:
                raise services.DomainError("必须提供 expected_generation 做原子冲突控制")
            actor = b.get("actor", "api")
            if action == "ramp":
                if "weight" not in b:
                    raise services.DomainError("升档必须提供 weight")
                res = services.ramp_rollout(rid, int(b["weight"]), int(gen), actor)
            elif action == "freeze":
                res = services.freeze_rollout(rid, int(gen), actor)
            elif action == "resume":
                res = services.resume_rollout(rid, int(gen), actor)
            elif action == "complete":
                res = services.complete_rollout(rid, int(gen), actor)
            else:
                res = services.cancel_rollout(rid, int(gen), actor)
            return self._json(res)
        # -------- 自动止损：配置 / 回执 / 恢复 / 历史
        m = re.fullmatch(r"/api/rollouts/([\w.-]+)/stoploss/config", p)
        if m and method == "POST":
            b = _json_body(self)
            for key in ("window_seconds", "min_sample", "fail_ratio_limit"):
                if key not in b:
                    raise services.DomainError(f"止损配置缺少字段: {key}")
            res = services.configure_stoploss(
                m.group(1), int(b["window_seconds"]), int(b["min_sample"]),
                float(b["fail_ratio_limit"]), b.get("actor", "api"))
            return self._json(res, 200)
        if method == "GET" and m:
            res = services.get_stoploss_config(m.group(1))
            if res is None:
                self._json({"error": "NotFound", "message": "该批次尚未配置止损"}, 404)
            else:
                return self._json(res)
        m = re.fullmatch(r"/api/rollouts/([\w.-]+)/stoploss", p)
        if method == "GET" and m:
            return self._json(services.stoploss_overview(m.group(1)))
        m = re.fullmatch(r"/api/rollouts/([\w.-]+)/feedback", p)
        if method == "POST" and m:
            b = _json_body(self)
            for key in ("feedback_id", "request_id", "outcome"):
                if not b.get(key):
                    raise services.DomainError(f"回执缺少字段: {key}")
            res = services.report_feedback(
                m.group(1), str(b["feedback_id"]), str(b["request_id"]),
                b["outcome"], b.get("actor", "api"))
            return self._json(res, 201 if res.get("credited") else 200)
        m = re.fullmatch(r"/api/rollouts/([\w.-]+)/recover", p)
        if method == "POST" and m:
            b = _json_body(self)
            if b.get("expected_generation") is None:
                raise services.DomainError("必须提供 expected_generation 做原子冲突控制")
            res = services.recover_rollout(m.group(1), int(b["expected_generation"]),
                                           b.get("actor", "api"))
            return self._json(res)
        m = re.fullmatch(r"/api/stoploss/triggers/([\w.-]+)", p)
        if method == "GET" and m:
            return self._json(services.get_trigger(m.group(1)))
        if method == "GET" and p == "/api/stoploss/triggers":
            return self._json(services.list_triggers(q.get("rollout", [None])[0]))
        if method == "GET" and p == "/api/feedback":
            return self._json(services.list_receipts(
                rollout_id=q.get("rollout", [None])[0],
                window_id=q.get("window", [None])[0]))
        m = re.fullmatch(r"/api/feedback/([\w.-]+)", p)
        if method == "GET" and m:
            return self._json(services.get_receipt(m.group(1)))
        m = re.fullmatch(r"/api/requests/([\w.-]+)", p)
        if method == "GET" and m:
            return self._json(services.get_request(m.group(1)))
        m = re.fullmatch(r"/api/requests/([\w.-]+)/replays", p)
        if method == "GET" and m:
            return self._json(services.list_replays(m.group(1)))
        m = re.fullmatch(r"/api/requests/([\w.-]+)/replay", p)
        if method == "POST" and m:
            b = _json_body(self)
            return self._json(services.replay(
                m.group(1), b.get("actor", "api"), b.get("override_version_id"),
                b.get("override_model_id"), b.get("override_inputs"),
                bool(b.get("inject_drift", False))), 201)
        if method == "GET" and p == "/api/requests":
            return self._json(services.list_requests(q.get("family", [None])[0]))

        # ------------------------------------------------ 敏感内容隔离（Guard）JSON API
        m = re.fullmatch(r"/api/families/([\w.-]+)/guard/rulesets", p)
        if method == "GET" and m:
            return self._json(guard.list_rulesets(m.group(1)))
        if method == "POST" and m:
            b = _json_body(self)
            try:
                res = guard.create_ruleset(
                    m.group(1), b.get("rules", []), b.get("actor", "api"),
                    b.get("note", ""), bool(b.get("activate", False)))
            except ValueError as exc:
                raise services.DomainError(f"规则非法：{exc}") from exc
            return self._json(res, 201)
        m = re.fullmatch(r"/api/guard/rulesets/([\w.-]+)/activate", p)
        if method == "POST" and m:
            b = _json_body(self)
            return self._json(guard.activate_ruleset(
                m.group(1), b.get("actor", "api"),
                b.get("expected_active_ruleset_id")))
        m = re.fullmatch(r"/api/guard/rulesets/([\w.-]+)", p)
        if method == "GET" and m:
            return self._json(guard.get_ruleset(m.group(1)))
        m = re.fullmatch(r"/api/families/([\w.-]+)/guard/preview", p)
        if method == "POST" and m:
            b = _json_body(self)
            try:
                return self._json(guard.preview(
                    m.group(1), b["inputs"], b.get("ruleset_id")))
            except ValueError as exc:
                raise services.DomainError(str(exc)) from exc
        m = re.fullmatch(r"/api/families/([\w.-]+)/guard/grants", p)
        if m:
            if method == "GET":
                return self._json(guard.list_grants(m.group(1)))
            b = _json_body(self)
            return self._json(guard.grant_reviewer(
                m.group(1), b["reviewer"], b.get("actor", "api"),
                b.get("reason", "")), 201)
        if method == "GET" and p == "/api/guard/grants":
            return self._json(guard.list_grants(None))
        m = re.fullmatch(r"/api/guard/grants/([\w.-]+)/revoke", p)
        if method == "POST" and m:
            b = _json_body(self)
            if b.get("expected_version") is None:
                raise services.DomainError("必须提供 expected_version 做并发控制")
            return self._json(guard.revoke_reviewer(
                m.group(1), int(b["expected_version"]), b.get("actor", "api"),
                b.get("reason", "")))
        m = re.fullmatch(r"/api/requests/([\w.-]+)/guard", p)
        if method == "GET" and m:
            return self._json(guard.request_guard_view(m.group(1)))
        m = re.fullmatch(r"/api/requests/([\w.-]+)/reveal-credential", p)
        if method == "POST" and m:
            b = _json_body(self)
            return self._json(guard.issue_credential(
                m.group(1), b["reviewer"], b.get("actor", "api"),
                int(b["ttl_seconds"]) if b.get("ttl_seconds") else None), 201)
        m = re.fullmatch(r"/api/requests/([\w.-]+)/reveal", p)
        if method == "POST" and m:
            b = _json_body(self)
            if not b.get("token"):
                raise guard.GuardUnauthorized("缺少还原令牌")
            return self._json(guard.reveal(
                m.group(1), b["token"], b.get("actor", "api")), 200)
        if method == "GET" and p == "/api/guard/blocks":
            return self._json(guard.list_block_log(q.get("family", [None])[0]))

        # ------------------------------------------------ 证据包 JSON API
        return self._route_evidence(method, p, q)

    def _route_evidence(self, method: str, p: str, q: dict):
        # 导出
        if method == "POST" and p == "/api/evidence/exports":
            b = _json_body(self)
            scope = _scope_from_body(b)
            pack = evidence.build_pack(
                scope, b.get("actor", "api"),
                int(b["shard_size_bytes"]) if b.get("shard_size_bytes") else None)
            return self._json(_pack_summary(pack), 201)
        if method == "GET" and p == "/api/evidence/packs":
            return self._json(evidence.list_packs(int(q.get("limit", ["100"])[0])))
        m = re.fullmatch(r"/api/evidence/packs/([\w.-]+)", p)
        if method == "GET" and m:
            return self._json(_pack_summary(evidence.get_pack(m.group(1))))
        m = re.fullmatch(r"/api/evidence/packs/([\w.-]+)/manifest", p)
        if method == "GET" and m:
            view = evidence.PackView(m.group(1))
            return self._json(view.manifest)
        m = re.fullmatch(r"/api/evidence/packs/([\w.-]+)/verify", p)
        if method == "POST" and m:
            b = _json_body(self)
            return self._json(evidence.verify_stored_pack(
                m.group(1), b.get("actor", "api")))
        m = re.fullmatch(r"/api/evidence/packs/([\w.-]+)/download", p)
        if method == "GET" and m:
            pid, blob = evidence.pack_file_bytes(m.group(1))
            return self._send(200, blob, "application/x-promptgov-evidence",
                              {"Content-Disposition":
                               f'attachment; filename="{pid}.pgpack"'})
        m = re.fullmatch(r"/api/evidence/packs/([\w.-]+)/(eval-runs|requests|rollouts|audit)", p)
        if method == "GET" and m:
            view = evidence.PackView(m.group(1))
            kind = m.group(2)
            if kind == "eval-runs":
                vid = q.get("version", [None])[0]
                return self._json(view.eval_runs(vid) if vid else view.by_table["eval_runs"])
            if kind == "requests":
                return self._json(view.requests(q.get("family", [None])[0]))
            if kind == "rollouts":
                return self._json(view.by_table["rollouts"])
            return self._json(view.by_table["audit_log"])

        # 导入：初始化 / 分片上传 / 状态 / 提交 / 放弃
        if method == "POST" and p == "/api/evidence/imports":
            ctype = self.headers.get("Content-Type", "")
            if "application/json" in ctype:
                b = _json_body(self)
                env_text = b.get("envelope_line", "")
                actor = b.get("actor", "api")
            else:
                env_text = self._read_raw().decode("utf-8")
                actor = "api"
            return self._json(evidence.init_import(env_text.encode("utf-8"), actor), 201)
        if method == "GET" and p == "/api/evidence/imports":
            return self._json(evidence.list_imports())
        m = re.fullmatch(r"/api/evidence/imports/([\w.-]+)", p)
        if method == "GET" and m:
            return self._json(evidence.get_import(m.group(1)))
        m = re.fullmatch(r"/api/evidence/imports/([\w.-]+)/shards/(\d+)", p)
        if method == "PUT" and m:
            blob = self._read_raw()
            expect = self.headers.get("X-SHA256")
            import hashlib as _hl
            if expect and _hl.sha256(blob).hexdigest() != expect:
                raise services.DomainError("分片内容与 X-SHA256 不符（上传层校验拒绝）")
            return self._json(evidence.put_import_shard(
                m.group(1), int(m.group(2)), blob))
        m = re.fullmatch(r"/api/evidence/imports/([\w.-]+)/commit", p)
        if method == "POST" and m:
            b = _json_body(self)
            return self._json(evidence.commit_import(
                m.group(1), b.get("actor", "api")))
        m = re.fullmatch(r"/api/evidence/imports/([\w.-]+)/abort", p)
        if method == "POST" and m:
            b = _json_body(self)
            return self._json(evidence.abort_import(
                m.group(1), b.get("actor", "api")))

        self._json({"error": "NotFound", "message": f"无此路由: {method} {p}"}, 404)

    def _read_raw(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    # ============================================================ 页面渲染
    def _flash(self, q) -> str:
        return unquote(q.get("err", [""])[0])

    def _page_dashboard(self, q):
        self._is_page = True
        families = services.list_families()
        rows = []
        for f in families:
            versions = services.list_versions(f["family_id"])
            active = next((v for v in versions if v["is_active"]), None)
            ro = services.current_rollout(f["family_id"])
            if ro:
                cand = next((v for v in versions
                             if v["version_id"] == ro["candidate_version_id"]), None)
                ro = {**ro, "candidate_semver": cand["semver"] if cand else "?",
                      "is_tripped": bool(ro["stoploss_tripped"]) and ro["status"] == "frozen"}
            rows.append({"family_id": f["family_id"], "name": f["name"],
                         "description": f["description"],
                         "active": _ver_context(active) if active else None,
                         "rollout": ro,
                         "n_versions": len(versions)})
        ctx = {"families": rows, "models": llm.list_models(),
               "flash": self._flash(q), "audit": services.audit_log(12)}
        self._html(page("模板治理 · 总览", "dashboard.html", ctx))

    def _page_family(self, fid, q):
        self._is_page = True
        family = services.get_family(fid)
        versions = [_ver_context(v) for v in services.list_versions(fid)]
        versions.sort(key=lambda v: v["created_at"], reverse=True)
        active = next((v for v in versions if v["is_active"]), None)
        # 视图层预算操作标志（受限模板表达式不支持 and/!= 等复合布尔）
        for v in versions:
            v["can_promote"] = (not v["is_active"] and
                                v["status"] in ("evaluated", "approved", "failed_eval"))
            v["can_rollback"] = (v["status"] == "superseded")
            v["active_id_or_empty"] = active["version_id"] if active else ""
        # 新建版本默认值：从当前线上版本预填
        defaults = {"semver": "", "system_instruction": "", "contract": "{}",
                    "tools": "", "params": json.dumps(
                        {"temperature": 0.2, "top_p": 0.9, "max_tokens": 1024},
                        ensure_ascii=False, indent=2)}
        if active:
            av = services.get_version(active["version_id"])
            defaults.update({
                "semver": _bump(active["semver"]),
                "system_instruction": av["system_instruction"],
                "contract": json.dumps(json.loads(av["variable_contract"]),
                                       ensure_ascii=False, indent=2),
                "tools": ", ".join(json.loads(av["tool_permissions"])),
                "params": json.dumps({k: val for k, val in json.loads(av["model_params"]).items()
                                      if not k.startswith("_")}, ensure_ascii=False, indent=2),
            })
        testset = services.get_testset_for_family(fid)
        case_count = 0
        if testset:
            case_count = get_conn().execute(
                "SELECT COUNT(*) c FROM testcases WHERE testset_id=?",
                (testset["testset_id"],)).fetchone()["c"]
        requests = services.list_requests(fid, limit=8)
        req_rows = [{"request_id": r["request_id"], "version_id": r["version_id"],
                     "model_id": r["model_id"], "input_digest": _short(r["input_digest"]),
                     "output_digest": _short(r["output_digest"]),
                     "routing_key": r["routing_key"] or "",
                     "rollout_generation": r["rollout_generation"],
                     "created_at": r["created_at"]} for r in requests]
        rollout = services.current_rollout(fid)
        ctx = {"family": family, "versions": versions, "active": active,
               "defaults": defaults, "models": llm.list_models(),
               "testset_name": testset["name"] if testset else "（无）",
               "case_count": case_count, "requests": req_rows,
               "rollout": rollout,
               "flash": self._flash(q)}
        self._html(page(f"{family['name']} · 版本", "family.html", ctx))

    def _page_approvals(self, q, only_version):
        self._is_page = True
        only_version = only_version or q.get("version", [None])[0]
        rows = services.list_approvals(only_version)
        conn = get_conn()
        items = []
        for a in rows:
            vr = conn.execute(
                "SELECT v.semver,v.family_id,f.name AS family_name FROM versions v "
                "JOIN families f ON f.family_id=v.family_id WHERE v.version_id=?",
                (a["version_id"],)).fetchone()
            d = dict(a)
            d["semver"] = vr["semver"] if vr else "?"
            d["family_id"] = vr["family_id"] if vr else "?"
            d["family_name"] = vr["family_name"] if vr else "?"
            d["granted_tool_list"] = json.loads(a["granted_tools"])
            window = "永久" if a["is_permanent"] else \
                f"{a['valid_from'] or '即刻'} ~ {a['valid_until'] or '永久'}"
            d["window_text"] = window
            items.append(d)
        ctx = {"approvals": items, "only_version": only_version or "",
               "now": services.db_now(), "flash": self._flash(q)}
        self._html(page("工具扩权审批 · 有效期与撤销", "approvals.html", ctx))

    def _page_eval(self, vid, q):
        self._is_page = True
        v = services.get_version(vid)
        family = services.get_family(v["family_id"])
        runs = services.list_eval_runs(vid)
        runs.sort(key=lambda r: r["created_at"], reverse=True)
        run_rows = []
        cases = []
        selected_id = q.get("run", [None])[0]
        for r in runs:
            run_rows.append({"run_id": r["run_id"], "status": r["status"],
                             "model_id": r["model_id"], "pass_rate": r["pass_rate"],
                             "passed": r["passed"], "total": r["total"],
                             "late": r["late"], "created_at": r["created_at"],
                             "guard_version": r.get("guard_ruleset_version"),
                             "selected": r["run_id"] == selected_id})

        def _fixture_view(run_id):
            row = get_conn().execute("SELECT * FROM guard_eval_fixtures WHERE run_id=?",
                                     (run_id,)).fetchone()
            if not row:
                return None
            by_seq = {x["seq"]: x for x in json.loads(row["cases_json"])}
            return {"version": row["ruleset_version"], "masked": row["masked_total"],
                    "blocked": row["blocked_total"], "by_seq": by_seq,
                    "configured": row["ruleset_id"] is not None}

        def _case_rows(detail, fx):
            out = []
            for c in detail["cases"]:
                g = (fx["by_seq"].get(c["seq"], {}) or {}) if fx else {}
                out.append({"name": c["name"], "ok": c["ok"], "detail": c["detail"],
                            "input_digest": _short(c["input_digest"]),
                            "output_digest": _short(c["output_digest"]),
                            "rendered_prompt": c["rendered_prompt"], "output": c["output"],
                            "seq": c["seq"],
                            "gmasked": g.get("masked", 0), "gblocked": g.get("blocked", 0)})
            return out

        if selected_id:
            detail = services.get_eval_run(selected_id)
            fixture = _fixture_view(selected_id)
            cases = _case_rows(detail, fixture)
            cur_run = detail
        elif runs:
            rid0 = runs[0]["run_id"]
            detail = services.get_eval_run(rid0)
            fixture = _fixture_view(rid0)
            cases = _case_rows(detail, fixture)
            cur_run = detail
        else:
            cur_run = None
            fixture = None
        approvals = services.list_approvals(vid)
        vc = _ver_context(v)
        ctx = {"v": vc, "family": family, "runs": run_rows, "cases": cases,
               "fixture": fixture,
               "cur_run": cur_run, "approvals": approvals,
               "threshold": config.PASS_THRESHOLD, "flash": self._flash(q)}
        self._html(page(f"评估 · {v['semver']}", "eval.html", ctx))

    def _page_rollout(self, fid, q):
        self._is_page = True
        family = services.get_family(fid)
        versions = {v["version_id"]: _ver_context(v)
                    for v in services.list_versions(fid)}
        rollouts = services.list_rollouts(fid)

        def enrich(r):
            cand = versions.get(r["candidate_version_id"])
            base = versions.get(r["base_version_id"])
            d = dict(r)
            d["candidate_semver"] = cand["semver"] if cand else "?"
            d["base_semver"] = base["semver"] if base else "?"
            d["open"] = r["status"] in ("ramping", "frozen")
            d["is_ramping"] = r["status"] == "ramping"
            d["is_frozen"] = r["status"] == "frozen"
            d["is_tripped"] = bool(r["stoploss_tripped"]) and r["status"] == "frozen"
            d["next_weight"] = min(100, r["weight"] + 10)
            d["stoploss_cfg"] = services.get_stoploss_config(r["rollout_id"])
            return d

        rows = [enrich(r) for r in rollouts]
        current = next((r for r in rows if r["open"]), None)

        active_ver = next((v for v in versions.values() if v["is_active"]), None)
        base_tools = json.loads(services.get_version(
            active_ver["version_id"])["tool_permissions"]) if active_ver else []
        conn = get_conn()

        def gate_view(version_id: str) -> dict:
            cand_row = conn.execute("SELECT * FROM versions WHERE version_id=?",
                                    (version_id,)).fetchone()
            g = services.expansion_gate_detail(conn, version_id, base_tools,
                                               json.loads(cand_row["tool_permissions"]))
            if not g["expands"]:
                return {"expands": False, "blocked": False, "text": "权限未扩大，无需专项授权"}
            active = g["active"]
            if active:
                tail = "永久" if active["is_permanent"] else \
                    (f"剩余 {active['remaining_human']}"
                     if active["state"] == "approved" else "")
                return {"expands": True, "blocked": False,
                        "text": f"新增 {g['added_tools']}：授权生效中（{tail}）",
                        "approval_id": active["approval_id"]}
            if g["covering"]:
                st = "，".join(a["state"] for a in g["covering"])
                return {"expands": True, "blocked": True,
                        "text": f"新增 {g['added_tools']}：已有授权但当前 {st}"
                                f"（建批/命中/转正会被拦截）"}
            return {"expands": True, "blocked": True,
                    "text": f"新增 {g['added_tools']}：无覆盖全部候选工具的专项授权"}

        candidates = [{"version_id": v["version_id"], "semver": v["semver"],
                       "status": v["status"], "short_hash": _short(v["content_hash"]),
                       "model_id": json.loads(v["model_params"]).get("_bound_model", ""),
                       "gate": gate_view(v["version_id"])}
                      for v in services.list_rollout_candidates(fid)]
        requests = services.list_requests(fid, limit=10)
        req_rows = [{"request_id": r["request_id"], "version_id": r["version_id"],
                     "routing_key": r["routing_key"] or "",
                     "rollout_generation": r["rollout_generation"],
                     "hit_candidate": bool(current) and
                     r["rollout_id"] == current["rollout_id"],
                     "created_at": r["created_at"]} for r in requests]
        ctx = {"family": family, "current": current, "rollouts": rows,
               "candidates": candidates, "requests": req_rows,
               "flash": self._flash(q)}
        self._html(page(f"{family['name']} · 放量批次", "rollout.html", ctx))

    def _page_stoploss(self, rid, q):
        self._is_page = True
        ov = services.stoploss_overview(rid)
        ro, cfg = ov["rollout"], ov["config"]
        versions = {v["version_id"]: _ver_context(v)
                    for v in services.list_versions(ro["family_id"])}
        family = services.get_family(ro["family_id"])

        def pct(x) -> str:
            return f"{float(x) * 100:.0f}%"

        cand = versions.get(ro["candidate_version_id"])
        base = versions.get(ro["base_version_id"])
        ro_view = {
            "rollout_id": rid, "status": ro["status"], "weight": ro["weight"],
            "generation": ro["generation"],
            "is_tripped": bool(ro["stoploss_tripped"]) and ro["status"] == "frozen",
            "is_ramping": ro["status"] == "ramping",
            "candidate_version_id": ro["candidate_version_id"],
            "base_version_id": ro["base_version_id"],
            "candidate_semver": cand["semver"] if cand else "?",
            "base_semver": base["semver"] if base else "?",
        }
        cfg_view = ({"window_seconds": cfg["window_seconds"], "min_sample": cfg["min_sample"],
                     "fail_ratio_limit": f"{cfg['fail_ratio_limit']:.2f}"}
                    if cfg else {"window_seconds": 3600, "min_sample": 20,
                                 "fail_ratio_limit": "0.20"})
        active = None
        if ov["active_window"]:
            w = ov["active_window"]
            active = {"window_id": w["window_id"], "seq": w["seq"],
                      "started_at": w["started_at"], "window_seconds": w["window_seconds"],
                      "min_sample": w["min_sample"], "total": w["total"], "fails": w["fails"],
                      "fail_pct": pct(w["fail_ratio"]), "limit_pct": pct(w["fail_ratio_limit"]),
                      "at_or_over_sample": w["total"] >= w["min_sample"],
                      "over_limit": w["fail_ratio"] > w["fail_ratio_limit"] + 1e-12}
        active_has_receipts = bool(active and active["total"] > 0)
        windows = [{"seq": w["seq"], "status": w["status"],
                    "window_seconds": w["window_seconds"], "min_sample": w["min_sample"],
                    "total": w["total"], "fails": w["fails"], "fail_pct": pct(w["fail_ratio"]),
                    "limit_pct": pct(w["fail_ratio_limit"]), "started_at": w["started_at"]}
                   for w in ov["windows"]]
        triggers = [{"trigger_id": t["trigger_id"], "created_at": t["created_at"],
                     "window_id": t["window_id"], "rollout_generation": t["rollout_generation"],
                     "candidate_semver": t["candidate_semver"], "base_semver": t["base_semver"],
                     "weight": t["weight"], "total_sample": t["total_sample"],
                     "fail_count": t["fail_count"], "fail_pct": pct(t["fail_ratio"]),
                     "trigger_feedback_id": t["trigger_feedback_id"]}
                    for t in ov["triggers"]]
        receipts = [{"feedback_id": r["feedback_id"], "outcome": r["outcome"],
                     "request_id": r["request_id"], "window_seq": r["window_seq"],
                     "hit_semver": r["hit_semver"], "routing_key": r["routing_key"] or "",
                     "hit_generation": r["hit_generation"],
                     "request_created_at": r["request_created_at"]}
                    for r in ov["receipts"]]
        rejected = [{"created_at": r["created_at"], "entity_id": r["entity_id"],
                     "detail": r["detail"], "action": r["action"]}
                    for r in ov["rejected"]]
        ctx = {"family": family, "ro": ro_view, "cfg": cfg_view, "active": active,
               "active_has_receipts": active_has_receipts, "windows": windows,
               "triggers": triggers, "receipts": receipts, "rejected": rejected,
               "flash": self._flash(q)}
        self._html(page(f"自动止损 · {ro_view['candidate_semver']}", "stoploss.html", ctx))

    # ============================================================ 敏感隔离页面
    def _guard_card(self, rid) -> dict:
        """调用复查页隔离卡片：固定规则版本、遮盖映射、密文数、凭据/还原审计。"""
        gv = guard.request_guard_view(rid)
        if not gv:
            return {"exists": False}
        creds = []
        for cd in gv.get("credentials", []):
            creds.append({"credential_id": cd["credential_id"], "reviewer": cd["reviewer"],
                          "status": cd["status"], "ttl_seconds": cd["ttl_seconds"],
                          "issued_at": cd["issued_at"], "expires_at": cd["expires_at"],
                          "consumed_at": cd["consumed_at"] or ""})
        reveals = [{"reviewer": r["reviewer"] or "（未识别）", "result": r["result"],
                    "created_at": r["created_at"], "detail": r["detail"]}
                   for r in gv.get("reveals", [])]
        return {
            "exists": True, "ruleset_id": gv["ruleset_id"],
            "ruleset_version": gv["ruleset_version"],
            "ruleset_hash": gv["ruleset_hash"], "short_hash": _short(gv["ruleset_hash"]),
            "status": gv["status"], "raw_input_digest": gv["raw_input_digest"],
            "secret_count": gv["secret_count"],
            "tokens": [{"token": t["token"], "rule_id": t["rule_id"],
                        "field": t["field"], "path": t["path"]}
                       for t in gv.get("tokens", [])],
            "masked": gv["actions"].get("masked", 0),
            "output_masked": sum(a.get("masked", 0)
                                 for a in gv.get("output_actions", [])),
            "credentials": creds, "reveals": reveals,
            "has_tokens": bool(gv.get("tokens")),
        }

    def _page_family_guard(self, fid, q):
        self._is_page = True
        family = services.get_family(fid)
        rulesets = guard.list_rulesets(fid)
        active_id = family.get("active_guard_ruleset_id")
        rs_rows = []
        for r in rulesets:
            rules = []
            for ru in r["rules"]:
                rules.append({"id": ru["id"], "kind": ru["kind"], "action": ru["action"],
                              "name": ru["name"], "pattern": ru["pattern"],
                              "fields": ", ".join(ru["fields"]),
                              "token": ru["token"], "is_block": ru["action"] == "block",
                              "is_mask": ru["action"] == "mask"})
            rs_rows.append({"ruleset_id": r["ruleset_id"], "version": r["version"],
                            "status": r["status"], "note": r["note"],
                            "is_active": r["ruleset_id"] == active_id,
                            "short_hash": _short(r["content_hash"]),
                            "rule_count": len(rules), "rules": rules,
                            "created_by": r["created_by"], "created_at": r["created_at"],
                            "activated_at": r["activated_at"] or "",
                            "can_activate": r["status"] == "draft"})
        active = next((r for r in rs_rows if r["is_active"]), None)
        grants = []
        for g in guard.list_grants(fid):
            grants.append({"grant_id": g["grant_id"], "reviewer": g["reviewer"],
                           "granted_by": g["granted_by"], "reason": g["reason"],
                           "revoke_version": g["revoke_version"],
                           "revoked": bool(g["revoked_at"]),
                           "revoked_at": g["revoked_at"] or "",
                           "revoked_by": g["revoked_by"]})
        # 预览结果（?preview=1 时由表单提交后重定向带结果较复杂；这里用同页 POST 渲染）
        preview = None
        if q.get("preview_result"):
            try:
                preview = json.loads(q["preview_result"][0])
            except Exception:  # noqa: BLE001
                preview = None
        blocked = [{"request_id": b["request_id"], "rule_id": b["rule_id"],
                    "version": b["ruleset_version"], "kind": b["kind"],
                    "fields": ", ".join(json.loads(b["fields_json"])),
                    "created_at": b["created_at"]}
                   for b in guard.list_block_log(fid, limit=10)]
        default_rules = json.dumps([
            {"id": "phone", "kind": "regex", "action": "mask",
             "pattern": r"1[3-9]\d{9}", "fields": ["*"], "token": "PHONE",
             "name": "手机号"},
            {"id": "forbid_leak", "kind": "keyword", "action": "block",
             "pattern": "内部机密", "fields": ["*"], "token": "",
             "name": "禁止泄露词"},
        ], ensure_ascii=False, indent=2)
        ctx = {"family": family, "rulesets": rs_rows, "active": active,
               "grants": grants, "preview": preview, "blocked": blocked,
               "default_rules": default_rules,
               "has_active": bool(active), "flash": self._flash(q)}
        self._html(page(f"敏感内容隔离 · {family['name']}", "guard.html", ctx))

    def _page_guard_audit(self, q):
        self._is_page = True
        conn = get_conn()
        # 逐请求隔离审计流：规则版本变更、阻断、签发/还原/失败（全部不含原值）
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE action LIKE 'guard.%' "
            "OR action='invoke' ORDER BY id DESC LIMIT 200").fetchall()
        items = []
        for a in rows:
            if a["action"].startswith("guard.") or "guard=" in a["detail"] \
                    or "guard" in a["detail"]:
                items.append({"id": a["id"], "actor": a["actor"], "action": a["action"],
                              "entity": a["entity"], "entity_id": a["entity_id"],
                              "detail": a["detail"], "created_at": a["created_at"],
                              "is_guard": a["action"].startswith("guard.")})
        # 凭据/还原尝试明细（只含结论，不含令牌/原值）
        reveals = [dict(r) for r in conn.execute(
            "SELECT g.id,g.request_id,g.credential_id,g.reviewer,g.result,g.detail,"
            "g.created_at FROM guard_reveals g ORDER BY g.id DESC LIMIT 100").fetchall()]
        blocks = [{"request_id": b["request_id"], "family_id": b["family_id"],
                   "rule_id": b["rule_id"], "version": b["ruleset_version"],
                   "fields": ", ".join(json.loads(b["fields_json"])),
                   "created_at": b["created_at"]}
                  for b in guard.list_block_log(None, limit=50)]
        ctx = {"items": items[:120], "reveals": reveals, "blocks": blocks,
               "flash": self._flash(q)}
        self._html(page("敏感隔离 · 逐请求审计", "guard_audit.html", ctx))

    def _page_replay(self, rid, q):
        self._is_page = True
        req = services.get_request(rid)
        versions = [_ver_context(x) for x in services.list_versions(req["family_id"])]
        family = services.get_family(req["family_id"])
        replays = services.list_replays(rid)
        rpl_rows = [{"replay_id": r["replay_id"], "mode": r["mode"], "verdict": r["verdict"],
                     "changed_axis": r["changed_axis"], "same_template": r["same_template"],
                     "same_model": r["same_model"], "same_input": r["same_input"],
                     "same_output": r["same_output"], "created_at": r["created_at"]}
                    for r in replays]
        latest = services.replay  # noop ref
        rollout = None
        if req.get("rollout_id"):
            try:
                rollout = services.get_rollout(req["rollout_id"])
            except services.NotFound:
                rollout = None
        receipt = services.get_request_receipt(rid)
        authz = services.request_authz_view(rid)
        guard_card = self._guard_card(rid)
        is_candidate_hit = bool(
            rollout and req["version_id"] == rollout["candidate_version_id"])
        same_generation = bool(
            rollout and req["rollout_generation"] == rollout["generation"])
        stoploss_cfg = services.get_stoploss_config(req["rollout_id"]) if req.get("rollout_id") else None
        feedback_card = {
            "rollout_id": req.get("rollout_id") or "",
            "is_candidate_hit": is_candidate_hit,
            "same_generation": same_generation,
            "rollout_status": rollout["status"] if rollout else "",
            "rollout_tripped": bool(rollout and rollout["stoploss_tripped"]),
            "hit_generation": req.get("rollout_generation"),
            "current_generation": rollout["generation"] if rollout else None,
            "configured": bool(stoploss_cfg),
            "feedback_id": receipt["feedback_id"] if receipt else "",
            "outcome": receipt["outcome"] if receipt else "",
            "credited_at": receipt["created_at"] if receipt else "",
            "window_id": receipt["window_id"] if receipt else "",
            "can_report": bool(rollout and not receipt and
                               rollout["status"] == "ramping" and stoploss_cfg),
        }
        ctx = {"req": {"request_id": rid, "family_id": req["family_id"],
                       "family_name": family["name"], "version_id": req["version_id"],
                       "model_id": req["model_id"],
                       "input_digest": req["input_digest"],
                       "output_digest": req["output_digest"],
                       "template_hash": req["template_hash_at_call"],
                       "short_template_hash": _short(req["template_hash_at_call"]),
                       "inputs_json": json.dumps(json.loads(req["inputs_json"]),
                                                 ensure_ascii=False, indent=2),
                       "output": req["output"],
                       "rendered_prompt": req["rendered_prompt"],
                       "routing_key": req.get("routing_key") or "",
                       "rollout_id": req.get("rollout_id") or "",
                       "rollout_generation": req.get("rollout_generation"),
                       "params_fingerprint": req.get("params_fingerprint") or "",
                       "params_json": json.dumps(json.loads(req["params_json"]),
                                                 ensure_ascii=False, indent=2)
                       if req.get("params_json") else "",
                       "created_at": req["created_at"]},
               "rollout": rollout,
               "feedback": feedback_card,
               "authz": _authz_card(authz),
               "guardcard": guard_card,
               "versions": versions, "models": llm.list_models(),
               "replays": rpl_rows, "result": None, "flash": self._flash(q)}
        # 若带 ?rpl= 则展示该报告详情
        rpl_id = q.get("rpl", [None])[0]
        if rpl_id:
            row = get_conn().execute("SELECT * FROM replays WHERE replay_id=?",
                                     (rpl_id,)).fetchone()
            if row:
                ctx["result"] = {
                    "verdict": row["verdict"], "mode": row["mode"],
                    "changed_axis": row["changed_axis"],
                    "same_template": row["same_template"], "same_model": row["same_model"],
                    "same_input": row["same_input"], "same_output": row["same_output"],
                    "replay_output": row["replay_output"]}
        self._html(page("重演报告", "replay.html", ctx))

    # ============================================================ 证据包页面
    def _page_evidence(self, q):
        self._is_page = True
        packs = []
        for p in evidence.list_packs(200):
            d = dict(p)
            d["scope_label"] = _scope_label(d["scope"])
            d["short_manifest"] = _short(d["manifest_sha"])
            d["short_outer"] = _short(d["outer_manifest_sha"])
            packs.append(d)
        imports = evidence.list_imports()
        ctx = {"packs": packs, "imports": imports[:30],
               "families": services.list_families(),
               "flash": self._flash(q)}
        self._html(page("证据包 · 迁移归档", "evidence.html", ctx))

    def _page_evidence_export(self, q):
        self._is_page = True
        kind = q.get("kind", ["family"])[0]
        fid = q.get("family_id", [""])[0]
        vid = q.get("version_id", [""])[0]
        calls = q.get("request_ids", [""])[0]
        ctx = {"families": services.list_families(), "kind": kind,
               "family_id": fid, "version_id": vid, "request_ids": calls,
               "flash": self._flash(q)}
        self._html(page("导出证据包", "evidence_export.html", ctx))

    def _pack_view_ctx(self, pid):
        view = evidence.PackView(pid)
        meta = evidence.get_pack(pid)
        return view, meta

    def _page_pack_detail(self, pid, q):
        self._is_page = True
        view, meta = self._pack_view_ctx(pid)
        fam = view.family()
        semvers = {v["version_id"]: v["semver"] for v in view.by_table["versions"]}
        # 清单逐项摘要（按表分组）
        groups = []
        for t in evidence.TABLES:
            its = [it for it in view.manifest["items"] if it["table"] == t]
            if its:
                groups.append({"table": t, "count": len(its),
                               "items": [{"id": it["id"], "summary": it["summary"],
                                          "object": _short(it["object"]),
                                          "size": it["size"]} for it in its]})
        versions = []
        for v in view.by_table["versions"]:
            d = _ver_context({**v, "is_active": v["version_id"] == fam["active_version_id"]})
            d["n_eval"] = len(view.eval_runs(v["version_id"]))
            versions.append(d)
        rollouts = []
        for r in view.by_table["rollouts"]:
            rollouts.append({
                "rollout_id": r["rollout_id"], "status": r["status"],
                "weight": r["weight"], "generation": r["generation"],
                "candidate_semver": semvers.get(r["candidate_version_id"], "?"),
                "base_semver": semvers.get(r["base_version_id"], "?"),
                "is_tripped": bool(r["stoploss_tripped"]) and r["status"] == "frozen"})
        triggers = []
        for t in view.by_table["stoploss_triggers"]:
            triggers.append({"trigger_id": t["trigger_id"], "created_at": t["created_at"],
                             "candidate_semver": semvers.get(t["candidate_version_id"], "?"),
                             "total_sample": t["total_sample"], "fail_count": t["fail_count"],
                             "rollout_id": t["rollout_id"]})
        requests = []
        for r in view.requests(fam["family_id"], limit=20):
            requests.append({"request_id": r["request_id"],
                             "semver": semvers.get(r["version_id"], "?"),
                             "model_id": r["model_id"],
                             "rollout_id": r.get("rollout_id") or "",
                             "created_at": r["created_at"]})
        ctx = {
            "pid": pid, "meta": meta, "family": fam, "scope_label": _scope_label(meta["scope"]),
            "groups": groups, "versions": versions, "rollouts": rollouts,
            "triggers": triggers, "requests": requests,
            "short_manifest": _short(meta["manifest_sha"]),
            "short_outer": _short(meta["outer_manifest_sha"]),
            "short_archive": _short(meta["archive_sha"]),
            "count_rows": [{"table": t, "n": n} for t, n in meta["counts"].items() if n],
            "counts": meta["counts"], "flash": self._flash(q)}
        self._html(page(f"证据包 {_short(pid, 8)}", "pack_detail.html", ctx))

    def _page_pack_eval(self, pid, vid, q):
        self._is_page = True
        view, meta = self._pack_view_ctx(pid)
        v = view._get("versions", vid)
        if not v:
            raise services.NotFound(f"版本不在证据包内：{vid}")
        family = view._get("families", v["family_id"])
        vc = _ver_context({**v, "is_active": v["version_id"] == family["active_version_id"]})
        runs = sorted(view.eval_runs(vid), key=lambda r: str(r["created_at"]), reverse=True)
        selected_id = q.get("run", [None])[0] or (runs[0]["run_id"] if runs else None)
        cur = view.eval_run(selected_id) if selected_id else None
        cases = [{"seq": c["seq"], "name": c["name"], "ok": c["ok"], "detail": c["detail"],
                  "input_digest": c["input_digest"], "output_digest": c["output_digest"],
                  "rendered_prompt": c["rendered_prompt"], "output": c["output"]}
                 for c in (cur["cases"] if cur else [])]
        fixture = view.guard_fixture(selected_id) if selected_id else None
        if fixture:
            by_seq = {x["seq"]: x for x in fixture["cases"]}
            for c in cases:
                fx = by_seq.get(c["seq"])
                c["masked"] = fx["masked"] if fx else 0
                c["blocked"] = fx["blocked"] if fx else 0
                c["output_masked"] = fx["output_masked"] if fx else 0
        run_rows = [{"run_id": r["run_id"], "status": r["status"], "model_id": r["model_id"],
                     "pass_rate": r["pass_rate"], "passed": r["passed"], "total": r["total"],
                     "late": r["late"], "created_at": r["created_at"],
                     "guard_version": r.get("guard_ruleset_version"),
                     "selected": r["run_id"] == selected_id} for r in runs]
        ctx = {"pid": pid, "v": vc, "family": family, "runs": run_rows,
               "cur_run": cur, "cases": cases, "threshold": config.PASS_THRESHOLD,
               "fixture": ({"version": fixture["ruleset_version"],
                            "masked": fixture["masked_total"],
                            "blocked": fixture["blocked_total"],
                            "ruleset_in_pack": bool(
                                view.guard_ruleset(fixture["ruleset_id"]))
                            if fixture["ruleset_id"] else False}
                           if fixture else None),
               "approvals": [services.approval_view(a) for a in view.approvals(vid)],
               "flash": self._flash(q)}
        self._html(page(f"包内评估 · {vc['semver']}", "pack_eval.html", ctx))

    def _page_pack_replay(self, pid, rid, q):
        self._is_page = True
        view, meta = self._pack_view_ctx(pid)
        req = view.request(rid)
        if not req:
            raise services.NotFound(f"调用不在证据包内：{rid}")
        family = view._get("families", req["family_id"])
        rollout = view.rollout(req["rollout_id"]) if req.get("rollout_id") else None
        receipt = view.receipt(rid)
        authz_pack = None
        snap_raw = req.get("authz_snapshot_json") or ""
        if snap_raw:
            snap = json.loads(snap_raw)
            if snap.get("required"):
                cur = view._get("approvals", snap["approval_id"])
                authz_pack = {
                    "required": True,
                    "approval_id": snap["approval_id"], "approver": snap.get("approver", ""),
                    "checked_at": snap.get("checked_at", ""),
                    "granted_tools": snap.get("granted_tools", []),
                    "candidate_tools": snap.get("candidate_tools", []),
                    "added_tools": snap.get("added_tools", []),
                    "is_permanent": bool(snap.get("is_permanent")),
                    "state_at_check": snap.get("state_at_check", ""),
                    "revoke_version": snap.get("revoke_version", ""),
                    "window_text": "永久" if snap.get("is_permanent") else
                    f"{snap.get('valid_from') or '即刻'} ~ {snap.get('valid_until') or '永久'}",
                    "current_state": (services.approval_view(
                        cur, now=meta["cutpoint"]["db_time"])["state"]
                        if cur else "not_in_pack"),
                    "current_exists": bool(cur),
                }
            else:
                authz_pack = {"required": False}
        semvers = {x["version_id"]: x["semver"] for x in view.by_table["versions"]}
        # 包内敏感隔离视图（只读；密文/凭据不入包，故无还原入口）
        gmask = view.guard_mask(rid)
        guard_pack = None
        if gmask:
            grs = view.guard_ruleset(gmask["ruleset_id"])
            guard_pack = {
                "exists": True, "status": req.get("guard_status", ""),
                "ruleset_version": gmask["ruleset_version"],
                "ruleset_id": gmask["ruleset_id"],
                "ruleset_in_pack": bool(grs),
                "short_hash": _short(gmask["ruleset_hash"]),
                "raw_input_digest": gmask["raw_input_digest"],
                "masked": gmask["actions"].get("masked", 0),
                "output_masked": sum(a.get("masked", 0)
                                     for a in gmask.get("output_actions", [])),
                "tokens": [{"token": t["token"], "rule_id": t["rule_id"],
                            "field": t["field"], "path": t["path"]}
                           for t in gmask["tokens"]],
                "has_tokens": bool(gmask["tokens"]),
                "rules": grs["rules"] if grs else [],
                "hash_ok": bool(grs and grs["content_hash"] == gmask["ruleset_hash"])}
        rpl_rows = [{"replay_id": r["replay_id"], "mode": r["mode"], "verdict": r["verdict"],
                     "changed_axis": r["changed_axis"], "same_template": r["same_template"],
                     "same_model": r["same_model"], "same_input": r["same_input"],
                     "same_output": r["same_output"], "created_at": r["created_at"]}
                    for r in view.replays(rid)]
        ctx = {
            "pid": pid, "family": family, "rollout": rollout,
            "req": {"request_id": rid, "family_id": req["family_id"],
                    "family_name": family["name"], "version_id": req["version_id"],
                    "semver": semvers.get(req["version_id"], "?"),
                    "model_id": req["model_id"], "input_digest": req["input_digest"],
                    "output_digest": req["output_digest"],
                    "template_hash": req["template_hash_at_call"],
                    "short_template_hash": _short(req["template_hash_at_call"]),
                    "inputs_json": json.dumps(json.loads(req["inputs_json"]),
                                              ensure_ascii=False, indent=2),
                    "output": req["output"], "rendered_prompt": req["rendered_prompt"],
                    "routing_key": req.get("routing_key") or "",
                    "rollout_id": req.get("rollout_id") or "",
                    "rollout_generation": req.get("rollout_generation"),
                    "params_fingerprint": req.get("params_fingerprint") or "",
                    "params_json": json.dumps(json.loads(req["params_json"]),
                                              ensure_ascii=False, indent=2)
                    if req.get("params_json") else "",
                    "created_at": req["created_at"]},
            "has_receipt": bool(receipt), "receipt": receipt,
            "authz": authz_pack,
            "guardpack": guard_pack,
            "replays": rpl_rows, "flash": self._flash(q)}
        self._html(page("包内调用复查", "pack_replay.html", ctx))

    def _page_pack_stoploss(self, pid, ro_id, q):
        self._is_page = True
        view, meta = self._pack_view_ctx(pid)
        ov = view.stoploss_overview(ro_id)
        ro, cfg = ov["rollout"], ov["config"]
        versions = {v["version_id"]: _ver_context(
            {**v, "is_active": False}) for v in view.by_table["versions"]}

        def pct(x):
            return f"{float(x) * 100:.0f}%"

        ro_view = {"rollout_id": ro_id, "status": ro["status"], "weight": ro["weight"],
                   "generation": ro["generation"],
                   "is_tripped": bool(ro["stoploss_tripped"]) and ro["status"] == "frozen",
                   "candidate_version_id": ro["candidate_version_id"],
                   "base_version_id": ro["base_version_id"],
                   "candidate_semver": versions.get(ro["candidate_version_id"],
                                                    {"semver": "?"})["semver"],
                   "base_semver": versions.get(ro["base_version_id"], {"semver": "?"})["semver"]}
        windows = [{"seq": w["seq"], "status": w["status"],
                    "window_seconds": w["window_seconds"], "min_sample": w["min_sample"],
                    "total": w["total"], "fails": w["fails"],
                    "fail_pct": pct(w["fail_ratio"]),
                    "limit_pct": pct(w["fail_ratio_limit"]),
                    "started_at": w["started_at"]} for w in ov["windows"]]
        triggers = [{"trigger_id": t["trigger_id"], "created_at": t["created_at"],
                     "rollout_generation": t["rollout_generation"],
                     "candidate_semver": versions.get(t["candidate_version_id"],
                                                      {"semver": "?"})["semver"],
                     "base_semver": versions.get(t["base_version_id"],
                                                 {"semver": "?"})["semver"],
                     "weight": t["weight"], "total_sample": t["total_sample"],
                     "fail_count": t["fail_count"], "fail_pct": pct(t["fail_ratio"]),
                     "trigger_feedback_id": t["trigger_feedback_id"]}
                    for t in ov["triggers"]]
        receipts = [{"feedback_id": r["feedback_id"], "outcome": r["outcome"],
                     "request_id": r["request_id"], "window_seq": r["window_seq"],
                     "hit_semver": r["hit_semver"], "routing_key": r["routing_key"] or "",
                     "hit_generation": r["hit_generation"],
                     "request_created_at": r["request_created_at"]}
                    for r in ov["receipts"]]
        rejected = [{"created_at": r["created_at"], "entity_id": r["entity_id"],
                     "detail": r["detail"], "action": r["action"]}
                    for r in ov["rejected"]]
        cfg_view = ({"window_seconds": cfg["window_seconds"], "min_sample": cfg["min_sample"],
                     "fail_ratio_limit": f"{cfg['fail_ratio_limit']:.2f}"}
                    if cfg else None)
        ctx = {"pid": pid, "ro": ro_view, "cfg": cfg_view, "windows": windows,
               "triggers": triggers, "receipts": receipts, "rejected": rejected,
               "flash": self._flash(q)}
        self._html(page("包内止损历史", "pack_stoploss.html", ctx))

    # ============================================================ UI 动作
    def _ui_create_family(self):
        self._is_page = True
        f = _form(self)
        services.create_family(f["family_id"].strip(), f["name"].strip(),
                               f.get("description", ""), f.get("actor", "web") or "web")
        self._redirect(f"/families/{f['family_id'].strip()}")

    def _ui_create_version(self, fid):
        self._is_page = True
        f = _form(self)
        contract = _jloads_field(f, "variable_contract", {})
        tools = [t.strip() for t in f.get("tool_permissions", "").split(",") if t.strip()]
        params = _jloads_field(f, "model_params", {})
        v = services.create_version(
            fid, f["semver"].strip(), f["system_instruction"], contract, tools, params,
            f["model_id"], f.get("actor", "web") or "web")
        self._redirect(f"/versions/{v['version_id']}/eval")

    def _ui_eval_start(self, vid):
        self._is_page = True
        f = _form(self)
        run_id = services.start_evaluation(vid, f.get("actor", "web") or "web")
        self._redirect(f"/versions/{vid}/eval?run={run_id}")

    def _ui_eval_run(self, run_id):
        self._is_page = True
        f = _form(self)
        run = services.run_evaluation(run_id, f.get("actor", "web") or "web")
        self._redirect(f"/versions/{run['version_id']}/eval?run={run_id}")

    def _ui_approve(self, vid):
        self._is_page = True
        f = _form(self)
        granted = None
        if f.get("granted_tools", "").strip():
            granted = [t.strip() for t in f["granted_tools"].split(",") if t.strip()]
        services.approve(vid, f["kind"], f.get("approver", "web") or "web",
                         f.get("decision", "approved"), f.get("reason", ""),
                         granted_tools=granted,
                         valid_from=(f.get("valid_from", "").strip() or None),
                         valid_until=(f.get("valid_until", "").strip() or None))
        self._redirect(f"/versions/{vid}/eval")

    def _ui_revoke_approval(self, approval_id):
        self._is_page = True
        f = _form(self)
        services.revoke_approval(approval_id, int(f["expected_version"]),
                                 f.get("actor", "web") or "web", f.get("reason", ""))
        back = f.get("back", "/approvals")
        self._redirect(back)

    def _ui_promote_rollback(self, fid, action):
        self._is_page = True
        f = _form(self)
        expected = f.get("expected_active") or None
        if action == "promote":
            services.promote(fid, f["version_id"], f.get("actor", "web") or "web", expected)
        else:
            services.rollback(fid, f["target_version_id"], f.get("actor", "web") or "web",
                              expected)
        self._redirect(f"/families/{fid}")

    def _ui_invoke(self, fid):
        self._is_page = True
        f = _form(self)
        inputs = _jloads_field(f, "inputs_json", {})
        res = services.invoke(fid, inputs, f.get("actor", "web") or "web",
                              routing_key=f.get("routing_key") or None)
        self._redirect(f"/requests/{res['request_id']}/replay")

    def _ui_create_rollout(self, fid):
        self._is_page = True
        f = _form(self)
        services.create_rollout(fid, f["candidate_version_id"],
                             int(f.get("weight") or 10), f.get("actor", "web") or "web")
        self._redirect(f"/families/{fid}/rollout")

    def _ui_rollout_action(self, rid, action):
        self._is_page = True
        f = _form(self)
        gen = int(f["expected_generation"])
        actor = f.get("actor", "web") or "web"
        if action == "ramp":
            ro = services.ramp_rollout(rid, int(f["weight"]), gen, actor)
        elif action == "freeze":
            ro = services.freeze_rollout(rid, gen, actor)
        elif action == "resume":
            ro = services.resume_rollout(rid, gen, actor)
        elif action == "complete":
            ro = services.complete_rollout(rid, gen, actor)
        else:
            ro = services.cancel_rollout(rid, gen, actor)
        self._redirect(f"/families/{ro['family_id']}/rollout")

    def _ui_stoploss_config(self, rid):
        self._is_page = True
        f = _form(self)
        services.configure_stoploss(
            rid, int(f["window_seconds"]), int(f["min_sample"]),
            float(f["fail_ratio_limit"]), f.get("actor", "web") or "web")
        self._redirect(f"/rollouts/{rid}/stoploss")

    def _ui_stoploss_recover(self, rid):
        self._is_page = True
        f = _form(self)
        services.recover_rollout(rid, int(f["expected_generation"]),
                                 f.get("actor", "web") or "web")
        self._redirect(f"/rollouts/{rid}/stoploss")

    def _ui_feedback(self, rollout_id):
        self._is_page = True
        f = _form(self)
        request_id = f["request_id"]
        try:
            res = services.report_feedback(
                rollout_id, f["feedback_id"].strip(), request_id, f["outcome"],
                f.get("actor", "web") or "web")
        except services.Conflict as exc:
            # 重复回执（feedback_id/request_id 已入账）：回到调用详情页提示
            self._redirect(f"/requests/{request_id}/replay?err=" + quote(str(exc)[:200]))
            return
        if not res.get("credited"):
            self._redirect(f"/requests/{request_id}/replay?err=" + quote(
                f"回执未入账（{res['reject_reason']}）：仅保留审计记录，未触发状态变化"))
        elif res.get("tripped"):
            self._redirect(f"/rollouts/{rollout_id}/stoploss?err=" + quote(
                f"回执已入账并触发自动止损：样本 {res['stats']['total']}，"
                f"失败 {res['stats']['fails']}，批次已冻结、流量回落基线"))
        else:
            self._redirect(f"/requests/{request_id}/replay")

    def _ui_replay(self, rid):
        self._is_page = True
        f = _form(self)
        ov_version = f.get("override_version_id") or None
        ov_model = f.get("override_model_id") or None
        override_inputs = None
        if f.get("change_inputs") == "1":
            override_inputs = _jloads_field(f, "inputs_json", {})
        inject = f.get("inject_drift") == "on"
        res = services.replay(rid, f.get("actor", "web") or "web",
                              ov_version, ov_model, override_inputs, inject)
        self._redirect(f"/requests/{rid}/replay?rpl={res['replay_id']}")

    def _ui_export_pack(self):
        self._is_page = True
        f = _form(self)
        scope = _scope_from_body({
            "scope_kind": f.get("scope_kind", "family"),
            "family_id": f.get("family_id", ""),
            "version_id": f.get("version_id", ""),
            "request_ids": f.get("request_ids", ""),
        })
        shard = int(f["shard_size_bytes"]) if f.get("shard_size_bytes") else None
        pack = evidence.build_pack(scope, f.get("actor", "web") or "web", shard)
        self._redirect(f"/evidence/packs/{pack['pack_id']}")

    def _ui_commit_import(self, import_id):
        self._is_page = True
        f = _form(self)
        evidence.commit_import(import_id, f.get("actor", "web") or "web")
        self._redirect("/evidence")

    def _ui_abort_import(self, import_id):
        self._is_page = True
        f = _form(self)
        evidence.abort_import(import_id, f.get("actor", "web") or "web")
        self._redirect("/evidence")

    # ============================================================ Guard UI 动作
    def _ui_guard_create_ruleset(self, fid):
        self._is_page = True
        f = _form(self)
        try:
            rules = json.loads(f.get("rules", "[]"))
            rs = guard.create_ruleset(
                fid, rules, f.get("actor", "web") or "web", f.get("note", ""),
                activate=(f.get("activate") == "1"))
        except ValueError as exc:
            self._redirect(f"/families/{fid}/guard?err=" + quote(f"规则非法：{exc}"))
            return
        self._redirect(f"/families/{fid}/guard")

    def _ui_guard_activate(self, ruleset_id):
        self._is_page = True
        f = _form(self)
        expected = f.get("expected_active_ruleset_id") or None
        rs = guard.activate_ruleset(ruleset_id, f.get("actor", "web") or "web", expected)
        self._redirect(f"/families/{rs['family_id']}/guard")

    def _ui_guard_preview(self, fid):
        self._is_page = True
        f = _form(self)
        inputs = _jloads_field(f, "inputs_json", {})
        rules = f.get("rules", "").strip()
        try:
            if rules:
                # 用表单里尚未保存的规则做预览：创建为草稿（不生效）再预览
                rs = guard.create_ruleset(
                    fid, json.loads(rules), f.get("actor", "web") or "web",
                    "隔离预览草稿", activate=False)
                pv = guard.preview(fid, inputs, rs["ruleset_id"])
            else:
                pv = guard.preview(fid, inputs, None)
        except (ValueError, guard.GuardError) as exc:
            self._redirect(f"/families/{fid}/guard?err=" + quote(str(exc)[:200]))
            return
        payload = json.dumps(pv, ensure_ascii=False)
        self._redirect(f"/families/{fid}/guard?preview_result=" + quote(payload))

    def _ui_guard_grant(self, fid):
        self._is_page = True
        f = _form(self)
        guard.grant_reviewer(fid, f["reviewer"].strip(), f.get("actor", "web") or "web",
                             f.get("reason", ""))
        self._redirect(f"/families/{fid}/guard")

    def _ui_guard_revoke_grant(self, grant_id):
        self._is_page = True
        f = _form(self)
        g = guard.revoke_reviewer(grant_id, int(f["expected_version"]),
                                  f.get("actor", "web") or "web", f.get("reason", ""))
        self._redirect(f"/families/{g['family_id']}/guard")

    def _ui_guard_issue(self, rid):
        self._is_page = True
        f = _form(self)
        try:
            res = guard.issue_credential(
                rid, f["reviewer"].strip(), f.get("actor", "web") or "web",
                int(f["ttl_seconds"]) if f.get("ttl_seconds", "").strip() else None)
        except (guard.GuardError, ValueError) as exc:
            self._redirect(f"/requests/{rid}/replay?err=" + quote(str(exc)[:200]))
            return
        # 明文令牌仅此一次展示；落到一次性提示页
        ctx = {"rid": rid, "token": res["token"], "credential_id": res["credential_id"],
               "reviewer": res["reviewer"], "expires_at": res["expires_at"],
               "ttl": res["ttl_seconds"]}
        self._html(page("还原凭据（仅此一次显示）", "guard_credential.html", ctx))

    def _ui_guard_reveal(self, rid):
        self._is_page = True
        f = _form(self)
        try:
            res = guard.reveal(rid, f.get("token", ""), f.get("actor", "web") or "web")
        except (guard.GuardError, ValueError) as exc:
            self._redirect(f"/requests/{rid}/replay?err=" + quote(str(exc)[:200]))
            return
        values = [{"token": v["token"], "rule_id": v["rule_id"], "field": v["field"],
                   "path": v["path"], "value": v["value"]} for v in res["values"]]
        ctx = {"rid": rid, "reviewer": res["reviewer"],
               "credential_id": res["credential_id"], "consumed_at": res["consumed_at"],
               "values": values,
               "raw_inputs": json.dumps(res["raw_inputs"], ensure_ascii=False, indent=2)}
        self._html(page("原值还原结果（凭据已消费）", "guard_reveal.html", ctx))



def _bump(semver: str) -> str:
    parts = (semver.split(".") + ["0", "0", "0"])[:3]
    try:
        parts[2] = str(int(parts[2]) + 1)
    except ValueError:
        return ""
    return ".".join(parts)


def build_server() -> ThreadingHTTPServer:
    init_db()
    if config.SEED:
        from . import seed  # 延迟导入
        seed.run()
    return ThreadingHTTPServer((config.HOST, config.PORT), Handler)


def main():
    httpd = build_server()
    print(f"PromptGov 服务已启动: http://{config.HOST}:{config.PORT}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
