"""自动止损（生产推理效果回执）端到端验证（标准库 unittest，离线可跑）。

覆盖需求场景：
- 重复回执：同一 feedback_id / 同一 request_id 只能入账一次（409，无状态变化）
- 回执归属：仅真实由该试投产生且命中候选构件的请求入账；基线命中、其他批次、
  无批次请求一律只留审计
- 旧代次：冻结/升档/止损前产生的命中回执只留审计，不触发状态变化
- 阈值临界：未达最小样本不触发；达到样本但失败占比 == 上限不触发；严格越界才触发
- 并发触发：多线程同时提交越界回执，状态只变化一次（frozen + 单快照 + 单次代次+1）
- 触发事务：冻结与快照/窗口翻转/统计在单事务；新流量（含本应命中候选的 key）回落基线
- 迟到回执：超出观察窗口的回执只留审计
- 人工恢复：开启新代次、重置统计窗口；旧窗口/快照/回执/请求复核能力保留
- JSON API 与页面冒烟
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.request
import uuid

_TMP = tempfile.mkdtemp(prefix="promptgov-stoploss-test-")
os.environ["PROMPTGOV_DATA"] = _TMP
os.environ["PROMPTGOV_SEED"] = "0"
os.environ["PROMPTGOV_PORT"] = "0"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from promptgov import core, db, services  # noqa: E402
from promptgov.db import get_conn  # noqa: E402

db.init_db()

CONTRACT = {
    "customer_text": {"type": "string", "required": True},
    "lang": {"type": "string", "required": False},
}
PARAMS = {"temperature": 0.2, "top_p": 0.9, "max_tokens": 1024}
INSTRUCTION_V1 = "你是客服分流助手。客户原话：{{ customer_text }} 请给出 label 与 score。"
INSTRUCTION_V2 = "你是客服分流助手（v2）。客户原话：{{ customer_text }} 优先识别 positive。"
INPUTS = {"customer_text": "客服非常耐心，问题一次解决", "lang": "zh"}
TEST_CASES = [
    {"name": "满意", "inputs": {"customer_text": "非常满意，点赞", "lang": "zh"},
     "expect": {"assert": "json_field", "field": "label", "equals": "positive"}},
]


def _uid() -> str:
    return uuid.uuid4().hex[:8]


def make_family_with_candidate(weight: int = 100):
    """建族：v1 上线、v2 已审核；建放量批次（默认 100% 便于制造候选命中）。"""
    fid = f"f-{_uid()}"
    services.create_family(fid, f"族{fid}", "", "test")
    services.create_testset(fid, "固定测试集", TEST_CASES, "test")
    v1 = services.create_version(fid, "1.0.0", INSTRUCTION_V1, CONTRACT,
                                 ["ticket.read"], PARAMS, "langfang-3-64k", "test")
    services.run_evaluation(services.start_evaluation(v1["version_id"], "test"), "test")
    services.approve(v1["version_id"], "release", "ops", "approved", "首发")
    services.promote(fid, v1["version_id"], "test")
    v2 = services.create_version(fid, "1.1.0", INSTRUCTION_V2, CONTRACT,
                                 ["ticket.read"], PARAMS, "langfang-3-64k", "test")
    services.run_evaluation(services.start_evaluation(v2["version_id"], "test"), "test")
    services.approve(v2["version_id"], "release", "ops", "approved", "候选")
    ro = services.create_rollout(fid, v2["version_id"], weight, "test")
    return fid, v1["version_id"], v2["version_id"], ro


def setup_stoploss(ro, window_seconds=3600, min_sample=10, fail_ratio_limit=0.4):
    return services.configure_stoploss(ro["rollout_id"], window_seconds, min_sample,
                                       fail_ratio_limit, "test")


def candidate_request(fid, label, key=None):
    """产生一条命中候选的请求；request_id 全局唯一，返回完整响应（含 request_id）。"""
    rid = f"req-{label}-{_uid()}"
    return services.invoke(fid, INPUTS, "test", request_id=rid,
                           routing_key=key if key is not None else f"key-{rid}")


def plain_request(fid, label):
    """不携带 routing_key 的普通调用（不参与分流）。"""
    rid = f"req-{label}-{_uid()}"
    return services.invoke(fid, INPUTS, "test", request_id=rid)


def backdate(request_id: str, modifier: str) -> None:
    """直接改 requests.created_at，确定性模拟迟到请求（SQLite datetime 修饰符）。"""
    conn = get_conn()
    conn.execute("UPDATE requests SET created_at=datetime('now',?) WHERE request_id=?",
                 (modifier, request_id))
    conn.commit()


def audit_actions(rollout_id: str) -> list[str]:
    return [a["action"] for a in services.list_rejected_feedback(rollout_id)]


class StoplossConfigTest(unittest.TestCase):

    def test_config_validation(self):
        _, _, _, ro = make_family_with_candidate()
        for kwargs in (dict(window_seconds=0, min_sample=10, fail_ratio_limit=0.4),
                       dict(window_seconds=60, min_sample=0, fail_ratio_limit=0.4),
                       dict(window_seconds=60, min_sample=10, fail_ratio_limit=-0.1),
                       dict(window_seconds=60, min_sample=10, fail_ratio_limit=1.5)):
            with self.assertRaises(services.DomainError):
                services.configure_stoploss(ro["rollout_id"], actor="test", **kwargs)

    def test_config_frozen_after_first_receipt(self):
        fid, v1, v2, ro = make_family_with_candidate()
        rid = ro["rollout_id"]
        setup_stoploss(ro)
        q = candidate_request(fid, "q1")
        services.report_feedback(rid, f"fb-{_uid()}", q["request_id"], "success", "test")
        # 窗口已有入账回执：改配被拒（门槛冻结）
        with self.assertRaises(services.Conflict):
            services.configure_stoploss(rid, 7200, 20, 0.1, "test")
        cfg = services.get_stoploss_config(rid)
        self.assertEqual((cfg["window_seconds"], cfg["min_sample"]), (3600, 10))

    def test_config_rejected_on_finished_rollout(self):
        fid, v1, v2, ro = make_family_with_candidate()
        services.cancel_rollout(ro["rollout_id"], ro["generation"], "test")
        with self.assertRaises(services.Conflict):
            setup_stoploss(ro)


class FeedbackEligibilityTest(unittest.TestCase):

    def test_only_real_candidate_hit_requests_are_credited(self):
        fid, v1, v2, ro = make_family_with_candidate(weight=100)
        rid = ro["rollout_id"]
        setup_stoploss(ro)
        cand = candidate_request(fid, "cand")
        self.assertEqual(cand["version_id"], v2)
        res = services.report_feedback(rid, f"fb-{_uid()}", cand["request_id"],
                                       "success", "test")
        self.assertTrue(res["credited"])

        # 冻结期产生的调用命中基线，应识别为本批次的 hit_baseline（仅审计）
        ro = services.freeze_rollout(rid, services.get_rollout(rid)["generation"], "test")
        base_req = services.invoke(fid, INPUTS, "test",
                                   request_id=f"req-base-{_uid()}", routing_key="k")
        self.assertEqual(base_req["version_id"], v1)
        self.assertEqual(base_req["rollout_id"], rid, "冻结期调用仍归属当前批次")
        res = services.report_feedback(rid, f"fb-{_uid()}", base_req["request_id"],
                                       "failure", "test")
        self.assertFalse(res["credited"])
        self.assertEqual(res["reject_reason"], "hit_baseline")
        services.resume_rollout(rid, services.get_rollout(rid)["generation"], "test")

        # 不属于任何批次的请求：无 routing_key
        plain = plain_request(fid, "plain")
        self.assertIsNone(plain["rollout_id"])
        res = services.report_feedback(rid, f"fb-{_uid()}", plain["request_id"],
                                       "failure", "test")
        self.assertFalse(res["credited"])
        self.assertEqual(res["reject_reason"], "unrelated_request")

        # 被拒回执均不在 receipts 表，只在审计流
        receipts = services.list_receipts(rollout_id=rid)
        self.assertEqual(len(receipts), 1)
        self.assertIn("feedback.reject", audit_actions(rid))

    def test_request_of_other_rollout_unrelated(self):
        fid1, _, _, ro = make_family_with_candidate()
        setup_stoploss(ro)
        fid2, _, _, ro2 = make_family_with_candidate()
        setup_stoploss(ro2)
        req = candidate_request(fid2, "other")
        res = services.report_feedback(ro["rollout_id"], f"fb-{_uid()}",
                                       req["request_id"], "failure", "test")
        self.assertFalse(res["credited"])
        self.assertEqual(res["reject_reason"], "unrelated_request")
        self.assertEqual(services.list_receipts(rollout_id=ro["rollout_id"]), [])

    def test_stale_generation_after_manual_freeze_is_audit_only(self):
        fid, v1, v2, ro = make_family_with_candidate()
        rid = ro["rollout_id"]
        setup_stoploss(ro)
        old = candidate_request(fid, "gen1")  # gen1 的候选请求
        ro = services.freeze_rollout(rid, ro["generation"], "test")
        services.resume_rollout(rid, ro["generation"], "test")  # -> gen3
        res = services.report_feedback(rid, f"fb-{_uid()}", old["request_id"],
                                       "failure", "test")
        self.assertFalse(res["credited"])
        self.assertEqual(res["reject_reason"], "stale_generation")
        self.assertFalse(res["tripped"])
        # 新代次产生的新请求正常入账，窗口不重置
        new = candidate_request(fid, "gen3")
        res = services.report_feedback(rid, f"fb-{_uid()}", new["request_id"],
                                       "success", "test")
        self.assertTrue(res["credited"])
        self.assertEqual(res["window_seq"], 1, "普通冻结/恢复不重置统计窗口")

    def test_unconfigured_rollout_rejects_to_audit(self):
        fid, v1, v2, ro = make_family_with_candidate()
        req = candidate_request(fid, "nocfg")
        res = services.report_feedback(ro["rollout_id"], f"fb-{_uid()}",
                                       req["request_id"], "failure", "test")
        self.assertFalse(res["credited"])
        self.assertEqual(res["reject_reason"], "stoploss_not_configured")

    def test_late_receipt_outside_window_audit_only(self):
        fid, v1, v2, ro = make_family_with_candidate()
        rid = ro["rollout_id"]
        setup_stoploss(ro, window_seconds=60, min_sample=2, fail_ratio_limit=0.5)
        late = candidate_request(fid, "late")
        backdate(late["request_id"], "-3600 seconds")  # 1 小时前，窗口仅 60s
        res = services.report_feedback(rid, f"fb-{_uid()}", late["request_id"],
                                       "failure", "test")
        self.assertFalse(res["credited"])
        self.assertEqual(res["reject_reason"], "late_receipt")
        self.assertFalse(res["tripped"])
        self.assertEqual(services.list_receipts(rollout_id=rid), [])
        ok = candidate_request(fid, "intime")
        res = services.report_feedback(rid, f"fb-{_uid()}", ok["request_id"],
                                       "success", "test")
        self.assertTrue(res["credited"])

    def test_missing_request_and_bad_outcome(self):
        _, _, _, ro = make_family_with_candidate()
        with self.assertRaises(services.NotFound):
            services.report_feedback(ro["rollout_id"], f"fb-{_uid()}",
                                     f"missing-{_uid()}", "success", "test")
        setup_stoploss(ro, min_sample=1, fail_ratio_limit=0.5)
        req = candidate_request(ro["family_id"], "bad")
        with self.assertRaises(services.DomainError):
            services.report_feedback(ro["rollout_id"], f"fb-{_uid()}",
                                     req["request_id"], "weird", "test")


class DuplicateReceiptTest(unittest.TestCase):

    def test_same_feedback_id_only_credited_once(self):
        fid, v1, v2, ro = make_family_with_candidate()
        rid = ro["rollout_id"]
        setup_stoploss(ro)
        d1 = candidate_request(fid, "dup1")
        d2 = candidate_request(fid, "dup2")
        fb = f"DUP-FB-{_uid()}"
        ok = services.report_feedback(rid, fb, d1["request_id"], "success", "test")
        self.assertTrue(ok["credited"])
        # 同一 feedback_id 换个 request 再报 -> 409（幂等键先于一切）
        with self.assertRaises(services.Conflict):
            services.report_feedback(rid, fb, d2["request_id"], "failure", "test")
        # 即使 request 不存在也 409（调用方重试安全）
        with self.assertRaises(services.Conflict):
            services.report_feedback(rid, fb, f"missing-{_uid()}", "failure", "test")
        self.assertEqual(len(services.list_receipts(rollout_id=rid)), 1)

    def test_same_request_id_only_credited_once_even_after_trip(self):
        fid, v1, v2, ro = make_family_with_candidate()
        rid = ro["rollout_id"]
        setup_stoploss(ro, min_sample=1, fail_ratio_limit=0.0)
        e = candidate_request(fid, "once")
        res = services.report_feedback(rid, f"fb-{_uid()}", e["request_id"],
                                       "failure", "test")
        self.assertTrue(res["tripped"])
        # 已入账请求在冻结后重报 -> 仍是 409 重复，而不是 stale/tripped 审计
        with self.assertRaises(services.Conflict):
            services.report_feedback(rid, f"fb-{_uid()}", e["request_id"],
                                     "success", "test")


class ThresholdTest(unittest.TestCase):

    def test_below_min_sample_never_trips(self):
        fid, v1, v2, ro = make_family_with_candidate()
        rid = ro["rollout_id"]
        setup_stoploss(ro, min_sample=10, fail_ratio_limit=0.5)
        for i in range(9):  # 9 条全失败，失败率 100%，但样本不足
            req = candidate_request(fid, f"under{i}")
            res = services.report_feedback(rid, f"fb-{_uid()}", req["request_id"],
                                           "failure", "test")
            self.assertFalse(res["tripped"])
            self.assertFalse(res["threshold"]["reached_sample"])
        self.assertEqual(services.get_rollout(rid)["status"], "ramping")

    def test_ratio_equal_limit_does_not_trip(self):
        fid, v1, v2, ro = make_family_with_candidate()
        rid = ro["rollout_id"]
        setup_stoploss(ro, min_sample=10, fail_ratio_limit=0.4)
        outcomes = ["failure"] * 4 + ["success"] * 6  # 40% == 上限
        res = None
        for i, oc in enumerate(outcomes):
            req = candidate_request(fid, f"eq{i}")
            res = services.report_feedback(rid, f"fb-{_uid()}", req["request_id"],
                                           oc, "test")
        self.assertFalse(res["tripped"])
        self.assertEqual(services.get_rollout(rid)["status"], "ramping")
        # 第 11 条失败：5/11 ≈ 45.5% > 40%，严格越过 -> 触发
        over = candidate_request(fid, "eq-over")
        res = services.report_feedback(rid, f"fb-{_uid()}", over["request_id"],
                                       "failure", "test")
        self.assertTrue(res["tripped"])
        self.assertEqual(res["stats"]["total"], 11)
        self.assertEqual(res["stats"]["fails"], 5)

    def test_trip_freezes_and_saves_snapshot_and_routes_to_base(self):
        fid, v1, v2, ro = make_family_with_candidate(weight=100)
        rid = ro["rollout_id"]
        setup_stoploss(ro, min_sample=3, fail_ratio_limit=0.5)
        res = None
        reqs = []
        for i, oc in enumerate(["failure", "success", "failure"]):
            req = candidate_request(fid, f"trip{i}", key=f"k-trip{i}")
            reqs.append(req)
            res = services.report_feedback(rid, f"fb-{_uid()}", req["request_id"],
                                           oc, "test")
        self.assertTrue(res["tripped"])
        trigger_id = res["trigger_id"]

        # 单事务后果：批次冻结、代次 +1、标记置位
        ro_after = services.get_rollout(rid)
        self.assertEqual(ro_after["status"], "frozen")
        self.assertEqual(ro_after["generation"], ro["generation"] + 1)
        self.assertEqual(ro_after["stoploss_tripped"], 1)

        # 恰好一个触发快照，且内容与现场一致
        triggers = services.list_triggers(rid)
        self.assertEqual(len(triggers), 1)
        t = triggers[0]
        self.assertEqual(t["trigger_id"], trigger_id)
        self.assertEqual((t["total_sample"], t["fail_count"]), (3, 2))
        self.assertAlmostEqual(t["fail_ratio"], 2 / 3, places=6)
        self.assertEqual(t["candidate_version_id"], v2)
        self.assertEqual(t["base_version_id"], v1)
        self.assertEqual(t["weight"], 100)
        self.assertEqual(t["snapshot"]["stats"]["total"], 3)
        self.assertIn("回落基线", t["snapshot"]["traffic_action"])

        # 冻结后新流量（含本应 100% 命中候选的 key）全部回落基线；
        # 调用仍归属本批次并固化冻结代次
        for i in range(5):
            hit = services.invoke(fid, INPUTS, "test",
                                  request_id=f"req-after-{i}-{_uid()}",
                                  routing_key=f"after-{i}")
            self.assertEqual(hit["version_id"], v1)
            self.assertEqual(hit["rollout_id"], rid)
            self.assertEqual(hit["rollout_generation"], ro_after["generation"])

        # 触发后产生的请求回执只留审计（不二次触发），原因标为 stoploss_tripped
        post = services.invoke(fid, INPUTS, "test",
                               request_id=f"req-post-{_uid()}", routing_key="post")
        rpost = services.report_feedback(rid, f"fb-{_uid()}", post["request_id"],
                                         "failure", "test")
        self.assertFalse(rpost["credited"])
        self.assertEqual(rpost["reject_reason"], "stoploss_tripped")
        self.assertEqual(len(services.list_triggers(rid)), 1)
        # 普通 resume 被禁止
        with self.assertRaises(services.Conflict):
            services.resume_rollout(rid, ro_after["generation"], "test")

    def test_rolling_window_old_samples_drop_off(self):
        """滚动窗口：早于窗口的回执不参与当前判定（按请求产生时间）。"""
        fid, v1, v2, ro = make_family_with_candidate()
        rid = ro["rollout_id"]
        setup_stoploss(ro, window_seconds=60, min_sample=2, fail_ratio_limit=0.5)
        # 两条 5 分钟前的失败回执（落在 60s 窗口外）-> late_receipt
        for label in ("roll-a", "roll-b"):
            req = candidate_request(fid, label)
            backdate(req["request_id"], "-300 seconds")
            res = services.report_feedback(rid, f"fb-{_uid()}", req["request_id"],
                                           "failure", "test")
            self.assertFalse(res["credited"])
        # 窗口内一条新失败：样本 1（旧回执被排除），未达门槛，不触发
        new = candidate_request(fid, "roll-new")
        res = services.report_feedback(rid, f"fb-{_uid()}", new["request_id"],
                                       "failure", "test")
        self.assertTrue(res["credited"])
        self.assertEqual(res["stats"]["total"], 1)
        self.assertFalse(res["tripped"])


class ConcurrentTripTest(unittest.TestCase):

    def test_concurrent_over_limit_receipts_trip_exactly_once(self):
        fid, v1, v2, ro = make_family_with_candidate()
        rid = ro["rollout_id"]
        setup_stoploss(ro, min_sample=10, fail_ratio_limit=0.5)
        # 预生成 20 条候选请求；20 条失败回执并发提交：
        # 第 10 条入账时 10/10=100% 越界并冻结，其余事务看到 frozen -> 审计拒绝
        reqs = [candidate_request(fid, f"cc{i}") for i in range(20)]
        fbs = [f"FB-{_uid()}" for _ in reqs]

        credited, rejected, trips, errors = [], [], [], []
        lock = threading.Lock()
        barrier = threading.Barrier(len(reqs))

        def submit(req_id, fb_id):
            barrier.wait()
            try:
                r = services.report_feedback(rid, fb_id, req_id, "failure", "race")
                with lock:
                    if r.get("tripped"):
                        trips.append(req_id)
                    elif r["credited"]:
                        credited.append(req_id)
                    else:
                        rejected.append(req_id)
            except services.Conflict:
                with lock:
                    errors.append(req_id)

        threads = [threading.Thread(target=submit, args=(r["request_id"], fb))
                   for r, fb in zip(reqs, fbs)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(trips), 1, f"并发越界只能触发一次，实际 {len(trips)}")
        self.assertEqual(len(credited), 9, "触发前 9 条入账（第 10 条即触发）")
        self.assertEqual(len(rejected), 10, "触发后到达的 10 条只留审计")
        self.assertEqual(len(errors), 0)
        after = services.get_rollout(rid)
        self.assertEqual((after["status"], after["stoploss_tripped"]), ("frozen", 1))
        self.assertEqual(after["generation"], ro["generation"] + 1, "代次只能 +1 一次")
        self.assertEqual(len(services.list_triggers(rid)), 1, "只能有一个触发快照")
        receipts = services.list_receipts(rollout_id=rid)
        self.assertEqual(len(receipts), 10, "只有触发前（含触发条）10 条入账")
        # feedback_id / request_id 均无重复、一一对应
        got_fbs = [r["feedback_id"] for r in receipts]
        got_rids = [r["request_id"] for r in receipts]
        self.assertEqual(len(set(got_fbs)), 10)
        self.assertEqual(len(set(got_rids)), 10)
        self.assertTrue(set(got_fbs) <= set(fbs))


class RecoverTest(unittest.TestCase):

    def test_recover_opens_new_generation_and_resets_window_keeping_history(self):
        fid, v1, v2, ro = make_family_with_candidate()
        rid = ro["rollout_id"]
        setup_stoploss(ro, min_sample=1, fail_ratio_limit=0.5)
        r1 = candidate_request(fid, "keep", key="persist-key")
        rold = candidate_request(fid, "gen1-unreported", key="from-gen1")
        res = services.report_feedback(rid, f"fb-{_uid()}", r1["request_id"],
                                       "failure", "test")
        self.assertTrue(res["tripped"])
        frozen_gen = services.get_rollout(rid)["generation"]
        old_window = res["window_id"]
        req_before = services.get_request(r1["request_id"])

        ro2 = services.recover_rollout(rid, frozen_gen, "ops")
        self.assertEqual((ro2["status"], ro2["generation"], ro2["stoploss_tripped"]),
                         ("ramping", frozen_gen + 1, 0))

        # 新窗口 active、计数清零；旧窗口 tripped 保留并挂着触发快照
        ov = services.stoploss_overview(rid)
        self.assertEqual(len(ov["windows"]), 2)
        old = next(w for w in ov["windows"] if w["window_id"] == old_window)
        new = ov["active_window"]
        self.assertEqual((old["status"], old["total"], old["fails"]), ("tripped", 1, 1))
        self.assertTrue(old["trigger_id"])
        self.assertEqual((new["seq"], new["status"], new["total"], new["fails"]),
                         (2, "active", 0, 0))

        # 旧窗口历史回执仍可查；历史请求仍按原元数据重演
        self.assertEqual(len(services.list_receipts(window_id=old_window)), 1)
        rep = services.replay(r1["request_id"], "test")
        self.assertEqual(rep["verdict"], "reproduced")
        self.assertEqual(rep["replayed"]["version_id"], v2)
        self.assertEqual(req_before["rollout_generation"], 1)

        # 触发前产生、一直未回执的 gen1 请求：恢复后是旧代次，只留审计不进新窗
        stale = services.report_feedback(rid, f"fb-{_uid()}", rold["request_id"],
                                         "failure", "test")
        self.assertFalse(stale["credited"])
        self.assertEqual(stale["reject_reason"], "stale_generation")
        self.assertFalse(stale["tripped"])
        self.assertEqual(ov["active_window"]["total"], 0)

        # 恢复后的新流量属新代次，进入新窗口、计数从零开始
        r2 = candidate_request(fid, "fresh", key="fresh-key")
        self.assertEqual(r2["rollout_generation"], frozen_gen + 1)
        res2 = services.report_feedback(rid, f"fb-{_uid()}", r2["request_id"],
                                        "success", "test")
        self.assertTrue(res2["credited"])
        self.assertEqual(res2["window_seq"], 2)
        self.assertEqual(res2["stats"]["total"], 1, "新窗口统计必须从零开始")
        # 同 key 仍命中候选（桶号与权重/代次无关，权重保持 100% 不变）
        again = services.invoke(fid, INPUTS, "test",
                                request_id=f"req-again-{_uid()}", routing_key="fresh-key")
        self.assertEqual(again["version_id"], v2)

    def test_recover_cas_and_guards(self):
        fid, v1, v2, ro = make_family_with_candidate()
        rid = ro["rollout_id"]
        setup_stoploss(ro, min_sample=1, fail_ratio_limit=0.5)
        # ramping 状态不能 recover
        with self.assertRaises(services.Conflict):
            services.recover_rollout(rid, ro["generation"], "ops")
        req = candidate_request(fid, "cas")
        services.report_feedback(rid, f"fb-{_uid()}", req["request_id"], "failure", "test")
        frozen_gen = services.get_rollout(rid)["generation"]
        # 错误代次 -> 409
        with self.assertRaises(services.Conflict):
            services.recover_rollout(rid, frozen_gen + 99, "ops")
        # 正确代次恢复
        services.recover_rollout(rid, frozen_gen, "ops")
        # 恢复后再恢复 -> 冲突（已非止损冻结）
        with self.assertRaises(services.Conflict):
            services.recover_rollout(rid, frozen_gen + 1, "ops")

    def test_cancel_closes_active_window_keeping_receipts(self):
        fid, v1, v2, ro = make_family_with_candidate()
        rid = ro["rollout_id"]
        setup_stoploss(ro)
        req = candidate_request(fid, "window")
        services.report_feedback(rid, f"fb-{_uid()}", req["request_id"], "success", "test")
        services.cancel_rollout(rid, services.get_rollout(rid)["generation"], "test")
        ov = services.stoploss_overview(rid)
        self.assertIsNone(ov["active_window"])
        self.assertEqual(ov["windows"][0]["status"], "closed")
        self.assertEqual(len(ov["receipts"]), 1)


class HttpStoplossTest(unittest.TestCase):
    """JSON API 与页面冒烟。"""

    @classmethod
    def setUpClass(cls):
        os.environ["PROMPTGOV_SEED"] = "0"
        from promptgov import app
        cls.httpd = app.build_server()
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _req(self, method, path, body=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def _get(self, path):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}")
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read().decode(), resp.headers["Content-Type"]

    def test_stoploss_api_flow(self):
        fid, v1, v2, ro = make_family_with_candidate()
        rid = ro["rollout_id"]
        # 未配置时 GET config -> 404
        code, _ = self._req("GET", f"/api/rollouts/{rid}/stoploss/config")
        self.assertEqual(code, 404)
        # 配置
        code, cfg = self._req("POST", f"/api/rollouts/{rid}/stoploss/config",
                              {"window_seconds": 300, "min_sample": 2,
                               "fail_ratio_limit": 0.5})
        self.assertEqual(code, 200, cfg)
        # 缺字段 -> 400
        code, err = self._req("POST", f"/api/rollouts/{rid}/stoploss/config",
                              {"window_seconds": 300, "min_sample": 2})
        self.assertEqual(code, 400)
        # 两条候选请求 + 回执
        r1 = candidate_request(fid, "api1")
        r2 = candidate_request(fid, "api2")
        fb1 = f"H1-{_uid()}"
        code, res = self._req("POST", f"/api/rollouts/{rid}/feedback",
                              {"feedback_id": fb1, "request_id": r1["request_id"],
                               "outcome": "success"})
        self.assertEqual(code, 201, res)
        self.assertTrue(res["credited"])
        # 同一 feedback_id 再报（即使换 request_id）-> 409
        code, dup = self._req("POST", f"/api/rollouts/{rid}/feedback",
                              {"feedback_id": fb1, "request_id": r2["request_id"],
                               "outcome": "failure"})
        self.assertEqual(code, 409, dup)
        # 同一 request_id 再报（新 feedback_id）-> 409
        code, dup2 = self._req("POST", f"/api/rollouts/{rid}/feedback",
                               {"feedback_id": f"H1B-{_uid()}",
                                "request_id": r1["request_id"], "outcome": "failure"})
        self.assertEqual(code, 409, dup2)
        # 无 routing_key 的请求 -> 业务拒绝（200，credited=false）
        h3 = plain_request(fid, "api-plain")
        code, res = self._req("POST", f"/api/rollouts/{rid}/feedback",
                              {"feedback_id": f"H3-{_uid()}",
                               "request_id": h3["request_id"], "outcome": "failure"})
        self.assertEqual(code, 200)
        self.assertFalse(res["credited"])
        self.assertEqual(res["reject_reason"], "unrelated_request")
        # r2 failure：窗口内 1 成功 / 1 失败 = 50% == 上限，不触发；
        # 再补一条 failure（2/3）严格越界才触发
        code, res = self._req("POST", f"/api/rollouts/{rid}/feedback",
                              {"feedback_id": f"H2-{_uid()}", "request_id": r2["request_id"],
                               "outcome": "failure"})
        self.assertTrue(res["credited"])
        self.assertFalse(res["tripped"])
        r3 = candidate_request(fid, "api3")
        code, res = self._req("POST", f"/api/rollouts/{rid}/feedback",
                              {"feedback_id": f"H4-{_uid()}", "request_id": r3["request_id"],
                               "outcome": "failure"})
        self.assertEqual(code, 201)
        self.assertTrue(res["tripped"])
        trg = res["trigger_id"]
        # 快照 API
        code, t = self._req("GET", f"/api/stoploss/triggers/{trg}")
        self.assertEqual(code, 200)
        self.assertEqual(t["total_sample"], 3)
        code, lst = self._req("GET", "/api/stoploss/triggers")
        self.assertEqual(code, 200)
        self.assertTrue(any(x["trigger_id"] == trg for x in lst))
        # 错误代次恢复 -> 409；正确代次 -> 200
        frozen_gen = services.get_rollout(rid)["generation"]
        code, err = self._req("POST", f"/api/rollouts/{rid}/recover",
                              {"expected_generation": 999})
        self.assertEqual(code, 409)
        code, ro2 = self._req("POST", f"/api/rollouts/{rid}/recover",
                              {"expected_generation": frozen_gen})
        self.assertEqual(code, 200)
        self.assertEqual(ro2["status"], "ramping")
        self.assertEqual(ro2["generation"], frozen_gen + 1)
        # 新窗口统计归零，旧窗口/快照保留
        code, ov = self._req("GET", f"/api/rollouts/{rid}/stoploss")
        self.assertEqual(code, 200)
        self.assertEqual(len(ov["windows"]), 2)
        self.assertEqual(ov["active_window"]["total"], 0)
        self.assertEqual(len(ov["triggers"]), 1)
        # receipts API
        code, rcs = self._req("GET", "/api/feedback")
        self.assertEqual(code, 200)
        self.assertTrue({x["feedback_id"] for x in rcs})

    def test_pages_render(self):
        fid, v1, v2, ro = make_family_with_candidate()
        rid = ro["rollout_id"]
        setup_stoploss(ro, min_sample=1, fail_ratio_limit=0.5)
        p1 = candidate_request(fid, "page")
        services.report_feedback(rid, f"fb-{_uid()}", p1["request_id"], "failure", "test")
        for path in (f"/rollouts/{rid}/stoploss",
                     f"/families/{fid}/rollout",
                     f"/requests/{p1['request_id']}/replay", "/"):
            code, html, ctype = self._get(path)
            self.assertEqual(code, 200, path)
            self.assertIn("text/html", ctype)
        _, html, _ = self._get(f"/rollouts/{rid}/stoploss")
        self.assertIn("人工恢复", html)
        self.assertIn("自动止损", html)
        _, html, _ = self._get(f"/requests/{p1['request_id']}/replay")
        self.assertIn("效果回执", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
