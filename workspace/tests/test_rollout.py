"""分批放量机制的端到端验证（标准库 unittest，离线可跑）。

覆盖：
- 同键稳定：批次代次不变时同一 routing_key 的路由决定不漂移
- 异键按比例分流：不同 key 按权重百分比分流，且逐 key 与稳定散列预测一致
- 并发升档只有一方成功（expected_generation CAS）
- 冻结期间新调用仍走当前构件；恢复后路由决定复原
- 撤销后流量回归当前构件；完成后候选转正
- 历史调用固化命中构件/推理配置/参数指纹/批次代次，复查不受权重变化影响
- 候选新增可调用工具时，无专项授权不得放量
- 一步切换接口（promote/rollback）继续工作
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

_TMP = tempfile.mkdtemp(prefix="promptgov-rollout-test-")
os.environ["PROMPTGOV_DATA"] = _TMP
os.environ["PROMPTGOV_SEED"] = "0"
os.environ["PROMPTGOV_PORT"] = "0"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from promptgov import core, db, services  # noqa: E402

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


def make_family_with_candidate(tools_v2=None, approve_expansion=False):
    """建族：v1 上线，v2 评估+审批为已审核候选。返回 (fid, v1_id, v2_id)。"""
    fid = f"f-{_uid()}"
    services.create_family(fid, f"族{fid}", "", "test")
    services.create_testset(fid, "固定测试集", TEST_CASES, "test")
    v1 = services.create_version(fid, "1.0.0", INSTRUCTION_V1, CONTRACT,
                                 ["ticket.read"], PARAMS, "langfang-3-64k", "test")
    services.run_evaluation(services.start_evaluation(v1["version_id"], "test"), "test")
    services.approve(v1["version_id"], "release", "ops", "approved", "首发")
    services.promote(fid, v1["version_id"], "test")
    v2 = services.create_version(fid, "1.1.0", INSTRUCTION_V2, CONTRACT,
                                 tools_v2 or ["ticket.read"], PARAMS,
                                 "langfang-3-64k", "test")
    services.run_evaluation(services.start_evaluation(v2["version_id"], "test"), "test")
    services.approve(v2["version_id"], "release", "ops", "approved", "候选")
    if approve_expansion:
        services.approve(v2["version_id"], "tool_expansion", "sec", "approved", "专项授权")
    return fid, v1["version_id"], v2["version_id"]


def hit_key(rollout_id: str, weight: int, prefix: str = "k") -> str:
    """找一个（确定性地）会命中候选的 routing_key。"""
    i = 0
    while True:
        key = f"{prefix}-{i}"
        if core.stable_bucket(rollout_id, key) < weight:
            return key
        i += 1


def miss_key(rollout_id: str, weight: int, prefix: str = "k") -> str:
    i = 0
    while True:
        key = f"{prefix}-{i}"
        if core.stable_bucket(rollout_id, key) >= weight:
            return key
        i += 1


class RolloutLifecycleTest(unittest.TestCase):

    def test_same_key_stable_across_calls(self):
        fid, v1, v2 = make_family_with_candidate()
        ro = services.create_rollout(fid, v2, 50, "test")
        key = hit_key(ro["rollout_id"], 50)
        hits = {services.invoke(fid, INPUTS, "t", routing_key=key)["version_id"]
                for _ in range(5)}
        self.assertEqual(hits, {v2}, "同键在代次不变时必须稳定命中候选")
        key2 = miss_key(ro["rollout_id"], 50)
        hits2 = {services.invoke(fid, INPUTS, "t", routing_key=key2)["version_id"]
                 for _ in range(5)}
        self.assertEqual(hits2, {v1}, "同键在代次不变时必须稳定命中当前构件")

    def test_split_by_weight_and_no_drift_on_ramp(self):
        fid, v1, v2 = make_family_with_candidate()
        ro = services.create_rollout(fid, v2, 30, "test")
        keys = [f"user-{i}" for i in range(300)]
        hits = {k: services.invoke(fid, INPUTS, "t", routing_key=k)["version_id"]
                for k in keys}
        # 逐 key 精确断言：命中结果与稳定散列预测完全一致
        for k in keys:
            expect = v2 if core.stable_bucket(ro["rollout_id"], k) < 30 else v1
            self.assertEqual(hits[k], expect, f"key={k} 路由决定与稳定散列不一致")
        ratio = sum(1 for k in keys if hits[k] == v2) / len(keys)
        self.assertTrue(0.15 < ratio < 0.50, f"异键应按比例分流，实际候选占比 {ratio:.2%}")
        # 升档到 60：既走候选的 key 不得掉回当前构件（单调扩展）
        ro = services.get_rollout(ro["rollout_id"])
        services.ramp_rollout(ro["rollout_id"], 60, ro["generation"], "test")
        for k in keys:
            if hits[k] == v2:
                again = services.invoke(fid, INPUTS, "t", routing_key=k)["version_id"]
                self.assertEqual(again, v2, f"升档后 key={k} 从候选漂移回当前构件")

    def test_concurrent_ramp_single_winner(self):
        fid, v1, v2 = make_family_with_candidate()
        ro = services.create_rollout(fid, v2, 10, "test")
        gen = ro["generation"]
        barrier = threading.Barrier(2)
        results, errors = [], []

        def ramp(w):
            barrier.wait()
            try:
                results.append(services.ramp_rollout(ro["rollout_id"], w, gen, "race"))
            except services.Conflict as exc:
                errors.append(exc)

        t1 = threading.Thread(target=ramp, args=(40,))
        t2 = threading.Thread(target=ramp, args=(70,))
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertEqual(len(results), 1, "并发升档必须只有一方成功")
        self.assertEqual(len(errors), 1, "另一方必须收到 409 冲突")
        after = services.get_rollout(ro["rollout_id"])
        self.assertEqual(after["generation"], gen + 1, "代次只能 +1 一次")
        self.assertIn(after["weight"], (40, 70))

    def test_conflict_keeps_routing_table(self):
        fid, v1, v2 = make_family_with_candidate()
        ro = services.create_rollout(fid, v2, 25, "test")
        before = services.get_rollout(ro["rollout_id"])
        with self.assertRaises(services.Conflict):
            services.ramp_rollout(ro["rollout_id"], 80, before["generation"] + 99, "test")
        with self.assertRaises(services.DomainError):
            services.ramp_rollout(ro["rollout_id"], 10, before["generation"], "test")
        with self.assertRaises(services.Conflict):
            services.resume_rollout(ro["rollout_id"], before["generation"], "test")
        after = services.get_rollout(ro["rollout_id"])
        for field in ("weight", "status", "generation"):
            self.assertEqual(before[field], after[field],
                             f"失败/冲突不得改变已生效路由表字段 {field}")

    def test_freeze_routes_to_base_and_resume_restores(self):
        fid, v1, v2 = make_family_with_candidate()
        ro = services.create_rollout(fid, v2, 100, "test")  # 100%：所有 key 本应走候选
        key = hit_key(ro["rollout_id"], 100)
        self.assertEqual(services.invoke(fid, INPUTS, "t", routing_key=key)["version_id"], v2)
        ro = services.freeze_rollout(ro["rollout_id"], ro["generation"], "test")
        self.assertEqual(ro["status"], "frozen")
        hit = services.invoke(fid, INPUTS, "t", routing_key=key)
        self.assertEqual(hit["version_id"], v1, "冻结期间新调用必须走当前构件")
        # 冻结期调用仍固化批次/代次（命中基线），以便回执识别归属；不记候选命中
        self.assertIsNotNone(hit["rollout_id"], "冻结期调用应归属当前批次")
        self.assertEqual(hit["rollout_generation"], ro["generation"])
        ro = services.resume_rollout(ro["rollout_id"], ro["generation"], "test")
        self.assertEqual(ro["status"], "ramping")
        self.assertEqual(services.invoke(fid, INPUTS, "t", routing_key=key)["version_id"],
                         v2, "恢复后同 key 路由决定必须与冻结前一致")

    def test_cancel_returns_traffic_to_base(self):
        fid, v1, v2 = make_family_with_candidate()
        ro = services.create_rollout(fid, v2, 100, "test")
        key = hit_key(ro["rollout_id"], 100)
        self.assertEqual(services.invoke(fid, INPUTS, "t", routing_key=key)["version_id"], v2)
        services.cancel_rollout(ro["rollout_id"], ro["generation"], "test")
        self.assertEqual(services.invoke(fid, INPUTS, "t", routing_key=key)["version_id"],
                         v1, "撤销后流量必须回归当前构件")
        fam = services.get_family(fid)
        self.assertEqual(fam["active_version_id"], v1, "撤销不得移动线上指针")
        with self.assertRaises(services.Conflict):
            services.ramp_rollout(ro["rollout_id"], 50, 99, "test")  # 已终结

    def test_complete_promotes_candidate(self):
        fid, v1, v2 = make_family_with_candidate()
        ro = services.create_rollout(fid, v2, 20, "test")
        services.complete_rollout(ro["rollout_id"], ro["generation"], "test")
        fam = services.get_family(fid)
        self.assertEqual(fam["active_version_id"], v2, "完成后候选必须转正")
        self.assertEqual(services.get_rollout(ro["rollout_id"])["status"], "completed")
        self.assertEqual(services.get_version(v1)["status"], "superseded")
        key = "any-key"
        self.assertEqual(services.invoke(fid, INPUTS, "t", routing_key=key)["version_id"], v2)

    def test_complete_blocked_if_pointer_moved(self):
        fid, v1, v2 = make_family_with_candidate()
        ro = services.create_rollout(fid, v2, 20, "test")
        # 期间一步切换接口把线上切到 v3
        v3 = services.create_version(fid, "1.2.0", INSTRUCTION_V1 + "（v3）", CONTRACT,
                                     ["ticket.read"], PARAMS, "langfang-3-64k", "test")
        services.run_evaluation(services.start_evaluation(v3["version_id"], "test"), "test")
        services.approve(v3["version_id"], "release", "ops", "approved", "v3")
        services.promote(fid, v3["version_id"], "test")
        with self.assertRaises(services.Conflict):
            services.complete_rollout(ro["rollout_id"], ro["generation"], "test")
        self.assertEqual(services.get_family(fid)["active_version_id"], v3["version_id"],
                         "冲突不得改变已生效路由表")
        # 撤销仍可用，流量不受影响
        services.cancel_rollout(ro["rollout_id"], ro["generation"], "test")

    def test_tool_expansion_requires_special_approval(self):
        fid, v1, v2 = make_family_with_candidate(
            tools_v2=["ticket.read", "refund.execute"], approve_expansion=False)
        with self.assertRaises(services.Conflict) as ctx:
            services.create_rollout(fid, v2, 10, "test")
        self.assertIn("tool_expansion", str(ctx.exception))
        # 补上专项授权后即可建批
        services.approve(v2, "tool_expansion", "sec", "approved", "覆盖 refund.execute")
        ro = services.create_rollout(fid, v2, 100, "test")
        key = hit_key(ro["rollout_id"], 100)
        self.assertEqual(services.invoke(fid, INPUTS, "t", routing_key=key)["version_id"], v2)

    def test_create_rollout_gates(self):
        fid, v1, v2 = make_family_with_candidate()
        with self.assertRaises(services.DomainError):
            services.create_rollout(fid, v2, 101, "test")
        with self.assertRaises(services.DomainError):
            services.create_rollout(fid, v1, 10, "test")  # 候选不能是当前线上
        ro = services.create_rollout(fid, v2, 10, "test")
        with self.assertRaises(services.Conflict):
            services.create_rollout(fid, v2, 20, "test")  # 已有进行中批次
        services.cancel_rollout(ro["rollout_id"], ro["generation"], "test")
        # 未审核构件（无 release 审批）不可放量
        v3 = services.create_version(fid, "1.2.0", INSTRUCTION_V1 + "（v3）", CONTRACT,
                                     ["ticket.read"], PARAMS, "langfang-3-64k", "test")
        services.run_evaluation(services.start_evaluation(v3["version_id"], "test"), "test")
        with self.assertRaises(services.Conflict):
            services.create_rollout(fid, v3["version_id"], 10, "test")

    def test_request_evidence_and_replay_immune_to_weight_change(self):
        fid, v1, v2 = make_family_with_candidate()
        ro = services.create_rollout(fid, v2, 50, "test")
        key = hit_key(ro["rollout_id"], 50)
        res = services.invoke(fid, INPUTS, "t", routing_key=key)
        self.assertEqual(res["version_id"], v2)
        rid = res["request_id"]
        req = services.get_request(rid)
        # 固化证据：命中构件、批次代次、推理配置、参数指纹
        self.assertEqual(req["rollout_id"], ro["rollout_id"])
        self.assertEqual(req["rollout_generation"], ro["generation"])
        self.assertEqual(req["routing_key"], key)
        self.assertEqual(req["params_fingerprint"],
                         core.params_fingerprint(json.loads(req["params_json"])))
        self.assertEqual(json.loads(req["params_json"])["_bound_model"], "langfang-3-64k")
        # 权重变化 -> 冻结 -> 撤销，之后复查仍复现原结果
        ro2 = services.get_rollout(ro["rollout_id"])
        ro2 = services.ramp_rollout(ro["rollout_id"], 90, ro2["generation"], "test")
        ro2 = services.freeze_rollout(ro["rollout_id"], ro2["generation"], "test")
        services.cancel_rollout(ro["rollout_id"], ro2["generation"], "test")
        rep = services.replay(rid, "test")
        self.assertEqual(rep["verdict"], "reproduced", "历史调用必须能复现原结果")
        self.assertEqual(rep["replayed"]["version_id"], v2)
        req_after = services.get_request(rid)
        self.assertEqual(req_after["rollout_generation"], ro["generation"],
                         "复查读取的是命中时固化的代次，不受后续权重变化影响")

    def test_promote_rollback_still_work(self):
        fid, v1, v2 = make_family_with_candidate()
        services.promote(fid, v2, "test", expected_active=v1)
        self.assertEqual(services.get_family(fid)["active_version_id"], v2)
        services.rollback(fid, v1, "test", expected_active=v2)
        self.assertEqual(services.get_family(fid)["active_version_id"], v1)
        with self.assertRaises(services.Conflict):
            services.promote(fid, v2, "test", expected_active=v2)  # CAS 失败


class HttpApiTest(unittest.TestCase):
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

    def test_rollout_api_and_pages(self):
        fid, v1, v2 = make_family_with_candidate()
        # 建批
        code, ro = self._req("POST", f"/api/families/{fid}/rollouts",
                             {"candidate_version_id": v2, "weight": 40})
        self.assertEqual(code, 201, ro)
        self.assertEqual(ro["status"], "ramping")
        rid = ro["rollout_id"]
        # 缺 expected_generation -> 400
        code, err = self._req("POST", f"/api/rollouts/{rid}/ramp", {"weight": 60})
        self.assertEqual(code, 400)
        # 错误代次 -> 409，且路由表不变
        code, err = self._req("POST", f"/api/rollouts/{rid}/ramp",
                              {"weight": 60, "expected_generation": 99})
        self.assertEqual(code, 409)
        code, cur = self._req("GET", f"/api/rollouts/{rid}")
        self.assertEqual((cur["weight"], cur["generation"]), (40, 1))
        # 正确代次 -> 200
        code, ro = self._req("POST", f"/api/rollouts/{rid}/ramp",
                             {"weight": 60, "expected_generation": 1})
        self.assertEqual(code, 200)
        self.assertEqual((ro["weight"], ro["generation"]), (60, 2))
        # 携带 routing_key 调用 -> 记录命中证据
        key = hit_key(rid, 60)
        code, res = self._req("POST", f"/api/families/{fid}/invoke",
                              {"inputs": INPUTS, "routing_key": key})
        self.assertEqual(code, 201)
        self.assertEqual(res["version_id"], v2)
        self.assertEqual(res["rollout_generation"], 2)
        code, req = self._req("GET", f"/api/requests/{res['request_id']}")
        self.assertEqual(req["rollout_id"], rid)
        self.assertTrue(req["params_fingerprint"])
        # 冻结 -> 同 key 走当前构件
        code, ro = self._req("POST", f"/api/rollouts/{rid}/freeze",
                             {"expected_generation": 2})
        self.assertEqual(code, 200)
        code, res2 = self._req("POST", f"/api/families/{fid}/invoke",
                               {"inputs": INPUTS, "routing_key": key})
        self.assertEqual(res2["version_id"], v1)
        # 撤销 -> 流量回归
        code, ro = self._req("POST", f"/api/rollouts/{rid}/cancel",
                             {"expected_generation": 3})
        self.assertEqual(code, 200)
        code, res3 = self._req("POST", f"/api/families/{fid}/invoke",
                               {"inputs": INPUTS, "routing_key": key})
        self.assertEqual(res3["version_id"], v1)
        # 历史调用仍可复现
        code, rep = self._req("POST", f"/api/requests/{res['request_id']}/replay", {})
        self.assertEqual(rep["verdict"], "reproduced")
        # 页面冒烟
        for path in ("/", f"/families/{fid}", f"/families/{fid}/rollout",
                     f"/requests/{res['request_id']}/replay"):
            req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}")
            with urllib.request.urlopen(req) as resp:
                self.assertEqual(resp.status, 200, path)
                self.assertIn("text/html", resp.headers["Content-Type"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
