"""模型注册表与可重演的"假"大模型提供方。

生产环境这里会接真实推理网关；本服务内建确定性提供方，使整个治理/重演链路
离线可跑且结果稳定可断言。其输出同时依赖：
  model_id        —— 模型变化 => 输出摘要变化
  template hash   —— 模板变化 => 输出摘要变化
  input digest    —— 输入变化 => 输出摘要变化
因此重演时可干净地分离 input/model/template 三条变化轴。

每个模型有可复现的"行为指纹"（分类阈值等），不同模型对同一输入可给出不同结果。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .core import digest_inputs


@dataclass(frozen=True)
class ModelInfo:
    model_id: str
    vendor: str
    label: str
    seed: int
    capability: float            # 决定该模型在测试集上的表现（0~1）
    params_schema: dict = field(default_factory=lambda: {
        "temperature": "number", "top_p": "number", "max_tokens": "integer"})


# 内建模型：一个稳健的正式模型、一个能力较弱的候选模型（用于演示模型变化）
MODELS: dict[str, ModelInfo] = {
    "langfang-3-64k": ModelInfo("langfang-3-64k", "langfang", "LangFang 3 · 64K", 101, 0.95),
    "langfang-3-mini": ModelInfo("langfang-3-mini", "langfang", "LangFang 3 · Mini", 202, 0.55),
}


def list_models() -> list[dict]:
    return [{"model_id": m.model_id, "vendor": m.vendor, "label": m.label,
             "capability": m.capability} for m in MODELS.values()]


def get_model(model_id: str) -> ModelInfo:
    if model_id not in MODELS:
        raise KeyError(f"未注册的模型标识: {model_id}（线上请求必须绑定已注册模型）")
    return MODELS[model_id]


def _rng(model: ModelInfo, template_hash: str, input_digest: str, salt: str = "") -> int:
    h = hashlib.sha256(
        f"{model.model_id}|{model.seed}|{template_hash}|{input_digest}|{salt}".encode()
    ).hexdigest()
    return int(h[:12], 16)


_POS = ["满意", "点赞", "棒", "推荐", "解决", "耐心", "高兴", "开心", "感谢",
        "great", "happy", "positive", "love", "good"]
_NEG = ["差", "生气", "投诉", "退款", "失望", "慢", "糟糕", "烂",
        "bad", "angry", "terrible", "hate", "awful"]


def _true_sentiment(text: str) -> str:
    blob = text.lower()
    pos = sum(w in blob for w in _POS)
    neg = sum(w in blob for w in _NEG)
    if pos > neg:
        return "positive"
    if neg > pos:
        return "negative"
    return "neutral"


def generate(model_id: str, template_hash: str, rendered_prompt: str,
             inputs: dict, model_params: dict) -> str:
    """确定性"生成"。返回结构化 JSON 文本，便于评估断言与人工复核。

    同一 (model_id, template_hash, input_digest, params) 永远产出同一输出。
    输出同时受三者影响：
      - 输入决定真实极性（input 变 => 判定/摘要变）；
      - 模型 capability 决定确定性"翻转率"（model 变 => 判定可能变）；
      - 模板哈希进入随机盐，并在指令偏向时轻微影响判断（template 变 => 摘要变）。
    """
    model = get_model(model_id)
    inp_digest = digest_inputs(inputs)
    params_note = json.dumps(model_params, sort_keys=True, ensure_ascii=False)
    r = _rng(model, template_hash, inp_digest, params_note)

    blob = json.dumps(inputs, ensure_ascii=False, sort_keys=True)
    customer = str(inputs.get("customer_text", blob))
    truth = _true_sentiment(customer)
    label = truth
    # 能力越弱，越可能把极性判错（完全由三元组确定性决定）
    flip_pct = round((1.0 - model.capability) * 100)
    if (r % 100) < flip_pct:
        label = {"positive": "negative", "negative": "positive",
                 "neutral": "negative"}[truth]
    # 指令明显带偏向时（如"一律判定"），模板会强制改变判断
    if "一律判定" in rendered_prompt or "所有反馈" in rendered_prompt:
        forced = "negative" if "negative" in rendered_prompt else "positive"
        label = forced
    score = 55 + (r % 45) if label == truth else max(5, 40 - (r % 35))
    score = max(0, min(100, score))

    answer = (
        f"answer:{model.label}: 已按当前模板与参数处理 {len(blob)} 字输入；"
        f"判定={label}; 置信度={score}。"
    )
    result = {
        "answer": answer,
        "label": label,
        "score": score,
        "_provenance": {
            "model_id": model.model_id,
            "template_hash": template_hash[:12],
            "input_digest": inp_digest[:12],
        },
    }
    return json.dumps(result, ensure_ascii=False, sort_keys=True)


# ---------------------------------------------------------------- 评估断言

def _parse_output(raw: str) -> dict:
    try:
        return json.loads(raw)
    except Exception:
        return {"answer": raw}


def assert_expect(raw_output: str, expect: dict) -> tuple[bool, str]:
    """对单条用例的期望做判定。expect 形如：

    {"assert": "contains", "value": "positive"}
    {"assert": "json_field", "field": "label", "equals": "positive"}
    {"assert": "json_field", "field": "score", "min": 80}
    """
    kind = expect.get("assert", "contains")
    if kind == "contains":
        ok = str(expect["value"]) in raw_output
        return ok, ("包含" if ok else f"未包含") + f" {expect['value']!r}"
    if kind == "equals":
        ok = raw_output.strip() == str(expect["value"])
        return ok, "完全相等" if ok else "与期望值不等"
    data = _parse_output(raw_output)
    if kind == "json_field":
        field_ = expect["field"]
        if field_ not in data:
            return False, f"输出缺少字段 {field_}"
        val = data[field_]
        if "equals" in expect and val != expect["equals"]:
            return False, f"{field_}={val!r} ≠ {expect['equals']!r}"
        if "min" in expect and not isinstance(val, (int, float)) or \
           ("min" in expect and val < expect["min"]):
            return False, f"{field_}={val} 低于 {expect['min']}"
        if "max" in expect and val > expect["max"]:
            return False, f"{field_}={val} 高于 {expect['max']}"
        return True, f"{field_}={val} 满足约束"
    return False, f"未知断言类型 {kind}"
