"""领域核心：内容指纹、变量契约、工具权限、模板渲染。

这些纯函数保证：
- 同一逻辑模板永远得到同一 content_hash（重演时判定"模板是否变化"的依据）；
- 旧请求只依赖版本快照，不依赖当前线上指针；
- 渲染使用受限环境，变量缺失/类型错误在发布前与调用时一致暴露。
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from .jinja_compat import render_text  # 极小自带渲染器，零依赖


CANONICAL_KWARGS = {"sort_keys": True, "ensure_ascii": False, "separators": (",", ":")}


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, **CANONICAL_KWARGS)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def content_hash(system_instruction: str, variable_contract: dict,
                 tool_permissions: list, model_params: dict) -> str:
    """模板四要素的精确指纹。任何字节级差异都会改变哈希。"""
    payload = canonical_json({
        "system_instruction": system_instruction,
        "variable_contract": variable_contract,
        "tool_permissions": sorted(tool_permissions),
        "model_params": model_params,
    })
    return sha256_hex(payload)


def digest_inputs(inputs: dict) -> str:
    """输入摘要：规范化 JSON 后取 SHA-256。重演区分输入变化即对比此值。"""
    return sha256_hex(canonical_json(inputs))


def digest_output(output: str) -> str:
    return sha256_hex(output)


def params_fingerprint(model_params: dict) -> str:
    """推理配置指纹：规范化 JSON 的 SHA-256。调用记录固化此值供复查比对。"""
    return sha256_hex(canonical_json(model_params))


# ---------------------------------------------------------------- 放量路由

def stable_bucket(rollout_id: str, routing_key: str) -> int:
    """分批放量的稳定散列：同一 (rollout_id, routing_key) 永远落在同一桶 [0,100)。

    桶号不依赖权重与批次代次：权重只作为阈值（bucket < weight 走候选），因此
    代次不变时同一 key 的路由决定绝不漂移；升档（权重单调增大）时既已走候选的
    key 也不会掉回当前构件。
    """
    h = sha256_hex(f"rollout|{rollout_id}|{routing_key}")
    return int(h[:8], 16) % 100


# ---------------------------------------------------------------- 变量契约

_PRIMITIVES = {"string": str, "integer": int, "number": (int, float),
               "boolean": bool, "object": dict, "array": list}


def validate_against_contract(inputs: dict, contract: dict,
                              strict_undeclared: bool = False) -> list[str]:
    """按契约校验输入，返回错误信息列表（空列表=通过）。

    契约形如 {"topic": {"type": "string", "required": true}, ...}

    - 必填缺失、类型错误：始终硬失败；
    - 契约未声明变量：默认作为"前向兼容多余字段"忽略（评估网关投影后调用），
      以保证固定测试集可跨越"新增可选变量"的兼容版本运行；strict_undeclared=True
      时（严格网关模式）视为违约。
    """
    errors: list[str] = []
    declared = set(contract.keys())
    for name, spec in contract.items():
        if spec.get("required", True) and name not in inputs:
            errors.append(f"缺少必填变量: {name}")
    for key, value in inputs.items():
        if key not in declared:
            if strict_undeclared:
                errors.append(f"存在契约未声明变量: {key}")
            continue
        want = contract[key].get("type", "string")
        py = _PRIMITIVES.get(want)
        if py and not isinstance(value, py):
            errors.append(f"变量 {key} 类型应为 {want}，实际 {type(value).__name__}")
    return errors


def project_inputs(inputs: dict, contract: dict) -> dict:
    """网关投影：仅保留当前版本契约声明的字段（多余字段不进入提示）。"""
    return {k: v for k, v in inputs.items() if k in contract}


def classify_contract_change(old: dict | None, new: dict) -> str:
    """契约升级分级：none / compatible / breaking。

    - breaking：删除变量、新增必填变量、既有变量类型改变；
    - compatible：仅新增可选变量；
    """
    if not old:
        return "none"
    old_names, new_names = set(old), set(new)
    if old_names - new_names:
        return "breaking"
    for name in old_names & new_names:
        if old[name].get("type") != new[name].get("type"):
            return "breaking"
        if not old[name].get("required", True) and new[name].get("required", True):
            return "breaking"  # 可选变必填
    added = new_names - old_names
    for name in added:
        if new[name].get("required", True):
            return "breaking"
    return "compatible" if added else "none"


# ---------------------------------------------------------------- 工具权限

def permission_grew(before: list[str] | None, after: list[str]) -> bool:
    """权限集合是否扩大（出现新增工具即扩大）。

    before=None 表示"尚无线上基线"（尚未首发），不构成扩大；
    before=[] 表示存在线上版本但其权限为空，此时新增工具算扩大。
    """
    if before is None:
        return False
    return bool(set(after) - set(before))


def diff_tools(before: list[str], after: list[str]) -> tuple[list[str], list[str]]:
    return sorted(set(after) - set(before)), sorted(set(before) - set(after))


# ---------------------------------------------------------------- 渲染

class TemplateRenderError(ValueError):
    pass


def render_prompt(system_instruction: str, variable_contract: dict, inputs: dict) -> str:
    """渲染系统指令。输入先过契约校验，再投影到声明字段；渲染器为受限表达式子集。"""
    errors = validate_against_contract(inputs, variable_contract)
    if errors:
        raise TemplateRenderError("; ".join(errors))
    safe_inputs = project_inputs(inputs, variable_contract)
    try:
        return render_text(system_instruction, safe_inputs)
    except Exception as exc:  # noqa: BLE001 - 统一成领域错误
        raise TemplateRenderError(f"模板渲染失败: {exc}") from exc
