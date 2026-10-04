"""幂等演示种子：一个模板族 + 固定测试集 + 覆盖治理全链路的版本与流量。"""
from __future__ import annotations

import json

from . import guard, services
from .db import get_conn

FAMILY = "support-router"

CONTRACT_V1 = {
    "customer_text": {"type": "string", "required": True},
    "lang": {"type": "string", "required": False},
}
CONTRACT_V2 = {
    "customer_text": {"type": "string", "required": True},
    "lang": {"type": "string", "required": False},
    "channel": {"type": "string", "required": False},   # 新增可选变量：兼容升级
}
PARAMS = {"temperature": 0.2, "top_p": 0.9, "max_tokens": 1024}

INSTRUCTION_V1 = """你是客服分流助手。仅依据客户文本输出结构化判断。
客户原话：{{ customer_text }}
{% if lang %}语言：{{ lang }}{% endif %}
请给出 label 与 score。"""

INSTRUCTION_V2 = """你是客服分流助手（v2 增强版）。综合渠道信息做判断。
渠道：{{ channel | default("web") }}
客户原话：{{ customer_text }}
{% if lang %}语言：{{ lang }}{% endif %}
优先识别 positive 反馈。请给出 label 与 score。"""

INSTRUCTION_V3 = INSTRUCTION_V2  # v3 仅扩大工具权限，模板内容相同，演示权限门禁

TEST_CASES = [
    {"name": "满意-中文", "inputs": {"customer_text": "非常满意，解决很快，点赞", "lang": "zh",
                                    "channel": "app"},
     "expect": {"assert": "json_field", "field": "label", "equals": "positive"}},
    {"name": "满意-英文", "inputs": {"customer_text": "Great support, very happy", "lang": "en",
                                    "channel": "web"},
     "expect": {"assert": "json_field", "field": "label", "equals": "positive"}},
    {"name": "高置信", "inputs": {"customer_text": "太棒了，强烈推荐给朋友", "lang": "zh",
                                 "channel": "app"},
     "expect": {"assert": "json_field", "field": "score", "min": 60}},
    {"name": "包含正向词", "inputs": {"customer_text": "positive experience overall",
                                    "lang": "en", "channel": "web"},
     "expect": {"assert": "json_field", "field": "label", "equals": "positive"}},
]

# 演示用输入
ONLINE_INPUTS = {"customer_text": "客服非常耐心，问题一次解决", "lang": "zh", "channel": "app"}


def run() -> None:
    conn = get_conn()
    if conn.execute("SELECT 1 FROM families WHERE family_id=?", (FAMILY,)).fetchone():
        return
    actor = "seed"
    services.create_family(FAMILY, "客服分流模板", "把客户反馈分流为 positive/neutral/negative",
                           actor)
    services.create_testset(FAMILY, "固定回归测试集 v1（不可变）", TEST_CASES, actor)

    # v1：评估 -> 发布审批 -> 发布为线上版本
    v1 = services.create_version(FAMILY, "1.0.0", INSTRUCTION_V1, CONTRACT_V1,
                                 ["ticket.read", "kb.search"], PARAMS,
                                 "langfang-3-64k", actor)
    run1 = services.start_evaluation(v1["version_id"], actor)
    services.run_evaluation(run1, actor)
    services.approve(v1["version_id"], "release", "ops-lead", "approved",
                     "首发：评估全绿，权限最小", )
    services.promote(FAMILY, v1["version_id"], actor)
    # 产生一条线上请求，供后续重演
    services.invoke(FAMILY, ONLINE_INPUTS, actor)

    # v2：契约兼容升级 + 指令增强（权限不变），评估通过并审批，但暂不发布（候选）
    v2 = services.create_version(FAMILY, "1.1.0", INSTRUCTION_V2, CONTRACT_V2,
                                 ["ticket.read", "kb.search"], PARAMS,
                                 "langfang-3-64k", actor)
    run2 = services.start_evaluation(v2["version_id"], actor)
    services.run_evaluation(run2, actor)
    services.approve(v2["version_id"], "release", "ops-lead", "approved",
                     "兼容新增 channel 变量，评估通过")

    # v3：工具权限扩大版本（新增 refund.execute），演示"必须重新审批"
    v3 = services.create_version(FAMILY, "1.2.0", INSTRUCTION_V2, CONTRACT_V2,
                                 ["ticket.read", "kb.search", "refund.execute"], PARAMS,
                                 "langfang-3-64k", actor)
    run3 = services.start_evaluation(v3["version_id"], actor)
    services.run_evaluation(run3, actor)
    services.approve(v3["version_id"], "release", "ops-lead", "approved",
                     "发布审批通过（注意：权限扩大仍需专项审批）")
    # v3 曾有一张 tool_expansion 专项授权，但已过期（演示有效期门禁：过期授权
    # 不满足建批/命中/转正）；审批页可看到 expired 状态，重新审批即可恢复。
    now = services.db_now()
    services.approve(
        v3["version_id"], "tool_expansion", "sec-oncall", "approved",
        "退款工具扩权（限时灰度窗口，已过期）",
        valid_from=services.shift_ts(now, -7 * 86400),
        valid_until=services.shift_ts(now, -3600))

    # v4：能力较弱模型的草稿，评估可能不达标，演示模型差异/失败证据
    v4 = services.create_version(FAMILY, "1.3.0", INSTRUCTION_V2, CONTRACT_V2,
                                 ["ticket.read", "kb.search"], PARAMS,
                                 "langfang-3-mini", actor)
    run4 = services.start_evaluation(v4["version_id"], actor)
    services.run_evaluation(run4, actor)

    # 分批放量演示：v2（已审核、权限未扩大）建立 20% 权重批次；
    # 两笔带 routing_key 的线上调用，固化命中构件/批次代次/参数指纹
    ro = services.create_rollout(FAMILY, v2["version_id"], 20, actor)
    services.invoke(FAMILY, ONLINE_INPUTS, actor, routing_key="user-10086")
    services.invoke(FAMILY, ONLINE_INPUTS, actor, routing_key="user-20431")

    # 自动止损演示：1 小时滚动窗口、最小样本 10、失败占比上限 30%；
    # 灌入若干命中候选的请求，报告 8 成功 / 2 失败（样本 10 达门槛，20% 未越界，
    # 批次仍在放量、统计窗口 live）。回执去重与拒绝场景见测试与止损历史页。
    from . import core
    services.configure_stoploss(ro["rollout_id"], 3600, 10, 0.30, actor)
    hit_keys = []
    i = 0
    while len(hit_keys) < 10:
        key = f"trial-user-{i}"
        if core.stable_bucket(ro["rollout_id"], key) < ro["weight"]:
            hit_keys.append(key)
        i += 1
    demo_reqs = []
    for idx, key in enumerate(hit_keys):
        res = services.invoke(FAMILY, ONLINE_INPUTS, actor,
                              request_id=f"seed-demo-req-{idx:02d}", routing_key=key)
        demo_reqs.append(res)
    for idx, res in enumerate(demo_reqs):
        outcome = "failure" if idx < 2 else "success"
        services.report_feedback(ro["rollout_id"], f"seed-demo-fb-{idx:02d}",
                                 res["request_id"], outcome, actor)

    # 敏感内容隔离演示：v1 规则版本——手机号/邮箱替换、“内部机密”关键词阻断；
    # 授权一名复核人可签发短期还原凭据。随后再造一条含手机号的线上请求，
    # 请求复查页可看到固定规则版本、遮盖映射与还原入口。
    guard_rules_v1 = [
        {"id": "phone", "kind": "regex", "action": "mask",
         "pattern": r"1[3-9]\d{9}", "fields": ["*"], "token": "PHONE",
         "name": "手机号"},
        {"id": "email", "kind": "regex", "action": "mask",
         "pattern": r"[\w.+-]+@[\w-]+\.[\w.-]+", "fields": ["*"], "token": "EMAIL",
         "name": "邮箱"},
        {"id": "internal_secret", "kind": "keyword", "action": "block",
         "pattern": "内部机密", "fields": ["*"], "token": "",
         "name": "禁止外泄内部机密"},
    ]
    guard.create_ruleset(FAMILY, guard_rules_v1, actor,
                         "v1：手机号/邮箱替换，内部机密阻断", activate=True)
    guard.grant_reviewer(FAMILY, "auditor-li", actor, "客服质检复核人，可短期还原")
    services.invoke(FAMILY,
                    {"customer_text": "回电请打 13812345678，或发邮件 a.b@example.com",
                     "lang": "zh", "channel": "app"}, actor,
                    request_id="seed-guard-masked-01")

    conn.commit()
    print("[seed] 演示数据就绪：family=%s 线上=v1，候选 v2（20%% 放量中，止损 3600s/"
          "n≥10/失败≤30%%，已入账 8 成功 2 失败）、v3（需工具权限审批）、"
          "v4（弱模型证据）；敏感隔离 v1（手机/邮箱替换、机密阻断，"
          "复核人 auditor-li）" % FAMILY)
