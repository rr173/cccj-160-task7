"""极小、受限的 Jinja 风格渲染器（仅支持模板所需子集）。

支持：
  {{ var }}  {{ user.name }}  {{ items[0] }}  {{ x | default("v") }}
  {% if cond %}...{% elif %}...{% else %}...{% endif %}
  {% for x in items %}...{% endfor %}（含 loop.index）
不提供任意 Python 求值/属性访问，杜绝模板注入。
"""
from __future__ import annotations

import html
import re
from typing import Any

_TOKEN_RE = re.compile(r"(\{\{.*?\}\}|\{%.*?%\})", re.S)


class _Undefined:
    def __str__(self) -> str:
        return ""


UNDEFINED = _Undefined()


def _split_pipe(expr: str) -> list[str]:
    parts, depth, cur = [], 0, ""
    for ch in expr:
        if ch in "[(":
            depth += 1
        elif ch in "])":
            depth -= 1
        if ch == "|" and depth == 0:
            parts.append(cur.strip()); cur = ""
        else:
            cur += ch
    parts.append(cur.strip())
    return parts


def _resolve_atom(token: str, ctx: dict) -> Any:
    token = token.strip()
    if token in ("true", "True"):
        return True
    if token in ("false", "False"):
        return False
    if token in ("none", "null", "None"):
        return None
    if (token.startswith('"') and token.endswith('"')) or \
       (token.startswith("'") and token.endswith("'")):
        return token[1:-1]
    if re.fullmatch(r"-?\d+", token):
        return int(token)
    if re.fullmatch(r"-?\d+\.\d+", token):
        return float(token)
    parts = re.findall(r"[^.\[\]]+", token)
    if not parts:
        return UNDEFINED
    cur: Any = ctx.get(parts[0], UNDEFINED)
    for key in parts[1:]:
        if cur is UNDEFINED or cur is None:
            return UNDEFINED
        if isinstance(cur, dict):
            cur = cur.get(key, UNDEFINED)
        elif isinstance(cur, list) and key.isdigit():
            i = int(key)
            cur = cur[i] if 0 <= i < len(cur) else UNDEFINED
        else:
            cur = getattr(cur, key, UNDEFINED)
    return cur


_FILTERS = {
    "upper": lambda v: str(v).upper(),
    "lower": lambda v: str(v).lower(),
    "strip": lambda v: str(v).strip(),
    "title": lambda v: str(v).title(),
    "length": lambda v: len(v),
    "trim": lambda v: str(v).strip(),
    "e": lambda v: html.escape(str(v)),
    "escape": lambda v: html.escape(str(v)),
    "tojson": lambda v: __import__("json").dumps(v, ensure_ascii=False),
    "default": lambda v, d="": d if (v is UNDEFINED or v is None) else v,
}


_CMP_RE = re.compile(r"^(.+?)\s*(==|!=)\s*(.+)$", re.S)


def _eval_cond(expr: str, ctx: dict) -> bool:
    """条件求值：支持 == / != 比较，否则按真值判断。"""
    expr = expr.strip()
    m = _CMP_RE.match(expr)
    if m:
        left = _eval_expr(m.group(1).strip(), ctx)
        right = _eval_expr(m.group(3).strip(), ctx)
        equal = left == right
        return equal if m.group(2) == "==" else not equal
    return _truthy(_eval_expr(expr, ctx))


def _eval_expr(expr: str, ctx: dict) -> Any:
    expr = expr.strip()
    # 受限的 Python 三元：EXPR if COND else EXPR（不支持在分支里再嵌套三元）
    m = re.match(r"^(.+?)\s+if\s+(.+?)\s+else\s+(.+)$", expr, re.S)
    if m and "|" not in expr:
        then_part, cond_part, else_part = m.group(1), m.group(2), m.group(3)
        branch = then_part if _truthy(_eval_expr(cond_part, ctx)) else else_part
        return _eval_expr(branch.strip(), ctx)
    pieces = _split_pipe(expr)
    cur = _resolve_atom(pieces[0], ctx)
    for fexpr in pieces[1:]:
        m = re.match(r"(\w+)(?:\((.*)\))?$", fexpr.strip())
        if not m:
            raise ValueError(f"未知过滤器写法: {fexpr}")
        fname, argstr = m.group(1), m.group(2)
        if fname not in _FILTERS:
            raise ValueError(f"未知过滤器: {fname}")
        if argstr is None:
            cur = _FILTERS[fname](cur)
        else:
            arg = _resolve_atom(argstr.strip(), ctx)
            cur = _FILTERS[fname](cur, arg)
    return cur


def _truthy(v: Any) -> bool:
    return v is not UNDEFINED and v is not False and v is not None and v != "" and v != 0


def _tokens(template: str):
    return _TOKEN_RE.split(template)


def render_text(template: str, ctx: dict) -> str:
    """渲染入口：切分为节点后递归处理 if/for/表达式。"""
    parts = _tokens(template)
    nodes, _ = _parse(parts, 0, len(parts), terminators=())
    return _render(nodes, dict(ctx))


def _parse(parts: list[str], i: int, end: int, terminators: tuple[str, ...]):
    nodes: list[tuple] = []
    while i < end:
        part = parts[i]
        if part.startswith("{%"):
            stmt = part[2:-2].strip()
            if any(stmt.startswith(t.rstrip()) for t in terminators) or stmt in terminators:
                return nodes, i
            if stmt.startswith("if "):
                cond_expr = stmt[3:].strip()
                branches = []
                i += 1
                body, i = _parse(parts, i, end, ("elif ", "else", "endif"))
                branches.append((cond_expr, body))
                while parts[i].startswith("{%") and parts[i][2:-2].strip().startswith("elif "):
                    ce = parts[i][2:-2].strip()[5:].strip()
                    i += 1
                    body, i = _parse(parts, i, end, ("elif ", "else", "endif"))
                    branches.append((ce, body))
                if parts[i].startswith("{%") and parts[i][2:-2].strip() == "else":
                    i += 1
                    elsebody, i = _parse(parts, i, end, ("endif",))
                    branches.append((None, elsebody))
                term = parts[i][2:-2].strip()
                assert term == "endif", f"缺少 endif，遇到 {term}"
                i += 1
                nodes.append(("if", branches))
            elif stmt.startswith("for "):
                m = re.match(r"for\s+(\w+)\s+in\s+(.+)", stmt)
                if not m:
                    raise ValueError(f"非法 for: {stmt}")
                i += 1
                body, i = _parse(parts, i, end, ("endfor",))
                term = parts[i][2:-2].strip()
                assert term == "endfor"
                i += 1
                nodes.append(("for", m.group(1), m.group(2), body))
            else:
                raise ValueError(f"不支持的语句: {stmt}")
        elif part.startswith("{{"):
            nodes.append(("out", part[2:-2].strip()))
            i += 1
        else:
            nodes.append(("text", part))
            i += 1
    return nodes, i


def _render(nodes: list[tuple], ctx: dict) -> str:
    out: list[str] = []
    for node in nodes:
        kind = node[0]
        if kind == "text":
            out.append(node[1])
        elif kind == "out":
            val = _eval_expr(node[1], ctx)
            out.append("" if val is UNDEFINED else str(val))
        elif kind == "if":
            for cond_expr, body in node[1]:
                if cond_expr is None or _eval_cond(cond_expr, ctx):
                    out.append(_render(body, ctx))
                    break
        elif kind == "for":
            _, var, iter_expr, body = node
            iterable = _eval_expr(iter_expr, ctx) or []
            for idx, item in enumerate(iterable, start=1):
                sub = dict(ctx)
                sub[var] = item
                sub["loop"] = {"index": idx}
                out.append(_render(body, sub))
    return "".join(out)
