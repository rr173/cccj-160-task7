"""工具扩权审批：有效期 + 主动撤销 + 授权快照 的端到端验证（标准库 unittest）。

覆盖：
- 永久授权（含旧库 NULL 有效期行）持续兼容
- 授权尚未生效：建批 / 候选首次命中 / 一步发布 三处门禁全部拦下
- 恰好到期（t == valid_until，半开区间 [from, until)）：三处门禁全部拦下
- 主动撤销以 expected_version 做 CAS：错误版本 409，并发撤销只一胜
- 并发撤销 vs 放量完成（发布竞争）：恰好一方成功，线上指针/放量状态不出半状态
- 授权只覆盖部分工具：建批 / 命中 / 转正 全部拦下；覆盖全部工具后放行
- 撤销后重新审批：新记录生效，建批/命中/转正恢复
- 旧调用复核：命中时固化授权快照，随后到期/撤销不改写 replay 结论
- JSON API 与页面（审批操作页/评估页/复查页）冒烟
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

_TMP = tempfile.mkdtemp(prefix="promptgov-authz-test-")
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


def make_family(tools_v2, release_v2=True):
    """建族：v1 上线；v2（工具集=tools_v2）已评估，按需带 release 审批。"""
    fid = f"f-{_uid()}"
    services.create_family(fid, f"族{fid}", "", "test")
    services.create_testset(fid, "固定测试集", TEST_CASES, "test")
    v1 = services.create_version(fid, "1.0.0", INSTRUCTION_V1, CONTRACT,
                                 ["ticket.read"], PARAMS, "langfang-3-64k", "test")
    services.run_evaluation(services.start_evaluation(v1["version_id"], "test"), "test")
    services.approve(v1["version_id"], "release", "ops", "approved", "首发")
    services.promote(fid, v1["version_id"], "test")
    v2 = services.create_version(fid, "1.1.0", INSTRUCTION_V2, CONTRACT,
                                 tools_v2, PARAMS, "langfang-3-64k", "test")
    services.run_evaluation(services.start_evaluation(v2["version_id"], "test"), "test")
    if release_v2:
        services.approve(v2["version_id"], "release", "ops", "approved", "候选")
    return fid, v1["version_id"], v2["version_id"]


def find_hit_key(rollout_id: str, weight: int = 100, prefix: str = "hk") -> str:
    i = 0
    while True:
        key = f"{prefix}-{i}"
        if core.stable_bucket(rollout_id, key) < weight:
            return key
        i += 1


def latest_expansion(version_id: str) -> dict:
    rows = [a for a in services.list_approvals(version_id)
            if a["kind"] == "tool_expansion"]
    return rows[-1]


def set_window(approval_id: str, *, valid_from=None, valid_until=None,
               revoked_at="__keep__"):
    """直接改审批时刻列，制造恰好的时间边界（不依赖 sleep）。"""
    conn = db.get_conn()
    if valid_from is not None or valid_until is not None:
        conn.execute("UPDATE approvals SET valid_from=?, valid_until=? WHERE approval_id=?",
                     (valid_from, valid_until, approval_id))
    if revoked_at != "__keep__":
        conn.execute("UPDATE approvals SET revoked_at=?, revoked_by=?, revoke_reason=? "
                     "WHERE approval_id=?",
                     (revoked_at, "test" if revoked_at else "",
                      "测试撤销" if revoked_at else "", approval_id))
    conn.commit()


class ApprovalWindowTest(unittest.TestCase):

    def test_permanent_grant_compat_new_and_legacy_rows(self):
        """显式永久审批与旧库 NULL 有效期行都永久有效。"""
        fid, v1, v2 = make_family(["ticket.read", "refund.execute"])
        services.approve(v2, "tool_expansion", "sec", "approved", "永久授权")
        a = latest_expansion(v2)
        self.assertEqual(a["state"], "permanent")
        self.assertTrue(a["is_permanent"])
        self.assertTrue(a["is_active"])
        ro = services.create_rollout(fid, v2, 100, "test")
        self.assertEqual(
            services.invoke(fid, INPUTS, "t", routing_key=find_hit_key(ro["rollout_id"]))
            ["version_id"], v2)
        services.cancel_rollout(ro["rollout_id"], ro["generation"], "test")

        # 旧库行：有效期列 NULL（老审批），门禁仍认其永久有效
        fid2, w1, w2 = make_family(["ticket.read", "refund.execute"])
        conn = db.get_conn()
        conn.execute(
            "INSERT INTO approvals(approval_id,version_id,kind,decision,approver,reason,"
            "granted_tools,valid_from,valid_until) VALUES "
            "(?,?, 'tool_expansion','approved','legacy','旧永久审批',?, NULL,NULL)",
            (f"appr-legacy-{_uid()}", w2, json.dumps(["ticket.read", "refund.execute"])))
        conn.commit()
        ro2 = services.create_rollout(fid2, w2, 100, "test")
        self.assertEqual(
            services.invoke(fid2, INPUTS, "t",
                            routing_key=find_hit_key(ro2["rollout_id"]))["version_id"], w2)

    def test_pending_grant_blocks_all_three_gates(self):
        fid, v1, v2 = make_family(["ticket.read", "refund.execute"])
        now = services.db_now()
        services.approve(v2, "tool_expansion", "sec", "approved", "明天生效",
                         valid_from=services.shift_ts(now, 3600),
                         valid_until=services.shift_ts(now, 7200))
        a = latest_expansion(v2)
        self.assertEqual(a["state"], "pending")
        self.assertGreaterEqual(a["wait_seconds"], 3599)
        # ① 建批
        with self.assertRaises(services.Conflict) as ctx:
            services.create_rollout(fid, v2, 10, "test")
        self.assertIn("pending", str(ctx.exception))
        # ② 一步发布
        with self.assertRaises(services.Conflict) as ctx:
            services.promote(fid, v2, "test", expected_active=v1)
        self.assertIn("pending", str(ctx.exception))
        self.assertEqual(services.get_family(fid)["active_version_id"], v1)
        # 造一个批次（先把生效时刻挪到过去）再验证候选命中门禁
        set_window(a["approval_id"], valid_from=services.shift_ts(now, -10),
                   valid_until=services.shift_ts(now, 7200))
        ro = services.create_rollout(fid, v2, 100, "test")
        key = find_hit_key(ro["rollout_id"])
        # 授权改回"尚未生效"：候选命中必须拒绝，批次与指针不变
        set_window(a["approval_id"], valid_from=services.shift_ts(now, 3600),
                   valid_until=services.shift_ts(now, 7200))
        with self.assertRaises(services.Conflict) as ctx:
            services.invoke(fid, INPUTS, "t", routing_key=key)
        self.assertIn("pending", str(ctx.exception))
        self.assertEqual(services.get_family(fid)["active_version_id"], v1)
        self.assertEqual(services.get_rollout(ro["rollout_id"])["status"], "ramping")

    def test_exact_expiry_blocks_all_three_gates(self):
        """恰好到期：t == valid_until 即失效（半开区间，until 不含）。"""
        fid, v1, v2 = make_family(["ticket.read", "refund.execute"])
        now = services.db_now()
        services.approve(v2, "tool_expansion", "sec", "approved", "边界窗口",
                         valid_from=services.shift_ts(now, -10), valid_until=now)
        a = latest_expansion(v2)
        self.assertEqual(a["state"], "expired", "valid_until 必须不含（t==until 即到期）")
        with self.assertRaises(services.Conflict) as ctx:
            services.create_rollout(fid, v2, 10, "test")
        self.assertIn("expired", str(ctx.exception))
        with self.assertRaises(services.Conflict):
            services.promote(fid, v2, "test", expected_active=v1)
        # 命中门禁：先在有效期内建批，再把失效时刻恰好卡在当前秒
        set_window(a["approval_id"], valid_from=services.shift_ts(now, -3600),
                   valid_until=services.shift_ts(now, 3600))
        ro = services.create_rollout(fid, v2, 100, "test")
        key = find_hit_key(ro["rollout_id"])
        set_window(a["approval_id"], valid_from=services.shift_ts(now, -3600),
                   valid_until=now)
        with self.assertRaises(services.Conflict) as ctx:
            services.invoke(fid, INPUTS, "t", routing_key=key)
        self.assertIn("expired", str(ctx.exception))
        # 完成转正同样拦下，批次/指针不变
        with self.assertRaises(services.Conflict):
            services.complete_rollout(ro["rollout_id"], ro["generation"], "test")
        self.assertEqual(services.get_family(fid)["active_version_id"], v1)
        self.assertEqual(services.get_rollout(ro["rollout_id"])["status"], "ramping")

    def test_partial_tool_coverage_blocks_gates(self):
        fid, v1, v2 = make_family(["ticket.read", "refund.execute", "coupon.issue"])
        # 只覆盖新增工具之一：门禁按"候选全部工具"判定，部分覆盖不算就位
        services.approve(v2, "tool_expansion", "sec", "approved", "只批了退款",
                         granted_tools=["ticket.read", "refund.execute"])
        with self.assertRaises(services.Conflict) as ctx:
            services.create_rollout(fid, v2, 10, "test")
        self.assertIn("全部工具", str(ctx.exception))
        with self.assertRaises(services.Conflict):
            services.promote(fid, v2, "test", expected_active=v1)
        # 直接插一条全覆盖审批但只让它 pending —— 仍应失败（状态+覆盖双重要求）
        now = services.db_now()
        services.approve(v2, "tool_expansion", "sec", "approved", "全覆盖但未生效",
                         valid_from=services.shift_ts(now, 3600))
        with self.assertRaises(services.Conflict) as ctx:
            services.create_rollout(fid, v2, 10, "test")
        self.assertIn("pending", str(ctx.exception))
        # 重新审批一张全覆盖且生效的授权 -> 三处全放行
        services.approve(v2, "tool_expansion", "sec2", "approved", "补齐 coupon")
        ro = services.create_rollout(fid, v2, 100, "test")
        key = find_hit_key(ro["rollout_id"])
        self.assertEqual(services.invoke(fid, INPUTS, "t", routing_key=key)["version_id"], v2)
        services.complete_rollout(ro["rollout_id"], ro["generation"], "test")
        self.assertEqual(services.get_family(fid)["active_version_id"], v2)

    def test_revoke_cas_and_state_view(self):
        fid, v1, v2 = make_family(["ticket.read", "refund.execute"])
        services.approve(v2, "tool_expansion", "sec", "approved", "限时",
                         valid_from=services.db_now(),
                         valid_until=services.shift_ts(services.db_now(), 3600))
        a = services.get_approval(latest_expansion(v2)["approval_id"])
        self.assertEqual(a["state"], "approved")
        self.assertGreaterEqual(a["remaining_seconds"], 3599)
        self.assertTrue(a["can_revoke"])
        # 错误版本号 -> 409，授权不变
        with self.assertRaises(services.Conflict):
            services.revoke_approval(a["approval_id"], a["revoke_version"] + 1, "test")
        self.assertEqual(services.get_approval(a["approval_id"])["state"], "approved")
        # 正确版本 -> 撤销成功，版本号 +1
        rv = services.revoke_approval(a["approval_id"], a["revoke_version"], "test",
                                      "紧急止血")
        self.assertEqual(rv["state"], "revoked")
        self.assertEqual(rv["revoke_version"], a["revoke_version"] + 1)
        self.assertFalse(rv["can_revoke"])
        self.assertEqual(rv["revoked_by"], "test")
        # 重复撤销 -> 冲突
        with self.assertRaises(services.Conflict):
            services.revoke_approval(a["approval_id"], rv["revoke_version"], "test")
        # release 审批不可撤销（旧语义保留）
        rel = [x for x in services.list_approvals(v2) if x["kind"] == "release"][0]
        with self.assertRaises(services.DomainError):
            services.revoke_approval(rel["approval_id"], rel["revoke_version"], "test")

    def test_revoke_blocks_gates_and_pointer_unchanged(self):
        fid, v1, v2 = make_family(["ticket.read", "refund.execute"])
        services.approve(v2, "tool_expansion", "sec", "approved", "限期试用")
        a = latest_expansion(v2)
        ro = services.create_rollout(fid, v2, 100, "test")
        key = find_hit_key(ro["rollout_id"])
        # 撤销：建批/命中/转正立即失效，但不移动指针、不改批次状态
        services.revoke_approval(a["approval_id"], a["revoke_version"], "sec", "提前撤销")
        with self.assertRaises(services.Conflict) as ctx:
            services.invoke(fid, INPUTS, "t", routing_key=key)
        self.assertIn("revoked", str(ctx.exception))
        with self.assertRaises(services.Conflict):
            services.complete_rollout(ro["rollout_id"], ro["generation"], "test")
        with self.assertRaises(services.Conflict):
            services.promote(fid, v2, "test", expected_active=v1)
        self.assertEqual(services.get_family(fid)["active_version_id"], v1)
        self.assertEqual(services.get_rollout(ro["rollout_id"])["status"], "ramping")
        # 撤销后重新审批：新记录生效，命中/转正恢复
        services.approve(v2, "tool_expansion", "sec2", "approved", "重新审批放行")
        self.assertEqual(services.invoke(fid, INPUTS, "t", routing_key=key)["version_id"], v2)
        services.complete_rollout(ro["rollout_id"], ro["generation"], "test")
        self.assertEqual(services.get_family(fid)["active_version_id"], v2)

    def test_concurrent_revoke_and_complete_single_winner(self):
        """撤销 vs 放量完成（发布竞争）：写锁串行，只有两种合法结局，均无半状态。

        - 撤销先提交：完成的授权门禁失败 -> 指针不动、批次仍 ramping、授权 revoked；
        - 完成先提交：翻转指针时授权有效 -> 候选转正；随后撤销串行生效（已记录，
          但不追溯移动指针）。绝不允许"指针翻了但完成时授权已撤销"。
        """
        fid, v1, v2 = make_family(["ticket.read", "refund.execute"])
        services.approve(v2, "tool_expansion", "sec", "approved", "试用中")
        a = latest_expansion(v2)
        ro = services.create_rollout(fid, v2, 100, "test")
        gen = ro["generation"]
        ver = a["revoke_version"]
        barrier = threading.Barrier(2)
        outcomes = []

        def revoke():
            barrier.wait()
            try:
                services.revoke_approval(a["approval_id"], ver, "race", "并发撤销")
                outcomes.append("revoked")
            except services.Conflict:
                outcomes.append("revoke_lost")

        def complete():
            barrier.wait()
            try:
                services.complete_rollout(ro["rollout_id"], gen, "race")
                outcomes.append("completed")
            except services.Conflict:
                outcomes.append("complete_lost")

        t1 = threading.Thread(target=revoke)
        t2 = threading.Thread(target=complete)
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertEqual(len(outcomes), 2)
        after_ro = services.get_rollout(ro["rollout_id"])
        after_a = services.get_approval(a["approval_id"])
        pointer = services.get_family(fid)["active_version_id"]
        if "complete_lost" in outcomes:
            # 撤销先提交：指针/批次不变，候选路径封死（完成/撤销完成顺序不保证）
            self.assertEqual(set(outcomes), {"complete_lost", "revoked"})
            self.assertEqual(pointer, v1)
            self.assertEqual(after_ro["status"], "ramping")
            self.assertEqual(after_a["state"], "revoked")
            with self.assertRaises(services.Conflict):
                services.invoke(fid, INPUTS, "t",
                                routing_key=find_hit_key(ro["rollout_id"]))
        else:
            # 完成先提交：候选转正；撤销可能串行后到（记录在案，不追溯回退指针）
            self.assertEqual(pointer, v2)
            self.assertEqual(after_ro["status"], "completed")
            self.assertIn("revoked", outcomes)

    def test_concurrent_revoke_single_winner(self):
        fid, v1, v2 = make_family(["ticket.read", "refund.execute"])
        services.approve(v2, "tool_expansion", "sec", "approved", "x")
        a = latest_expansion(v2)
        ver = a["revoke_version"]
        barrier = threading.Barrier(8)
        wins, losses = [], []

        def worker():
            barrier.wait()
            try:
                services.revoke_approval(a["approval_id"], ver, f"race-{_uid()}", "并发")
                wins.append(1)
            except services.Conflict:
                losses.append(1)

        ts = [threading.Thread(target=worker) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(len(wins), 1, "并发撤销必须只有一方成功")
        self.assertEqual(len(losses), 7)
        self.assertEqual(services.get_approval(a["approval_id"])["revoke_version"], ver + 1)

    def test_old_call_replay_immune_to_later_revoke_and_expiry(self):
        fid, v1, v2 = make_family(["ticket.read", "refund.execute"])
        services.approve(v2, "tool_expansion", "sec", "approved", "快照测试")
        a = latest_expansion(v2)
        ro = services.create_rollout(fid, v2, 100, "test")
        key = find_hit_key(ro["rollout_id"])
        res = services.invoke(fid, INPUTS, "t", routing_key=key)
        self.assertEqual(res["version_id"], v2)
        rid = res["request_id"]
        # 命中时固化的授权快照
        snap = res["authz_snapshot"]
        self.assertTrue(snap["required"])
        self.assertEqual(snap["approval_id"], a["approval_id"])
        self.assertEqual(snap["state_at_check"], "permanent")
        self.assertEqual(set(snap["granted_tools"]),
                         {"ticket.read", "refund.execute"})
        self.assertEqual(snap["added_tools"], ["refund.execute"])
        stored = services.get_request(rid)["authz_snapshot"]
        self.assertEqual(stored["approval_id"], a["approval_id"])
        # 随后撤销授权
        services.revoke_approval(a["approval_id"], a["revoke_version"], "sec", "事后撤销")
        view = services.request_authz_view(rid)
        self.assertEqual(view["current"]["state"], "revoked")
        self.assertTrue(view["current"]["state"] != view["state_at_check"])
        # 旧调用精确复查：结论不被改写，且读的是固化快照而非当前授权
        rep = services.replay(rid, "test")
        self.assertEqual(rep["verdict"], "reproduced")
        self.assertEqual(rep["replayed"]["version_id"], v2)
        # 到期路径同理：重新审批一张限时授权，新调用固化新快照，到期后复查仍复现
        services.approve(v2, "tool_expansion", "sec2", "approved", "再放行",
                         valid_until=services.shift_ts(services.db_now(), 3600))
        res2 = services.invoke(fid, INPUTS, "t", routing_key=find_hit_key(
            ro["rollout_id"], prefix="hk2"))
        self.assertEqual(res2["authz_snapshot"]["state_at_check"], "approved")
        rid2 = res2["request_id"]
        # 先完成转正，再把新授权改到期
        services.complete_rollout(ro["rollout_id"], ro["generation"], "test")
        a2_id = res2["authz_snapshot"]["approval_id"]
        set_window(a2_id, valid_from=None,
                   valid_until=services.shift_ts(services.db_now(), -1))
        self.assertEqual(services.request_authz_view(rid2)["current"]["state"], "expired")
        self.assertEqual(services.replay(rid2, "test")["verdict"], "reproduced")

    def test_baseline_and_non_expansion_hits_have_no_required_snapshot(self):
        fid, v1, v2 = make_family(["ticket.read"])  # v2 未扩权
        services.approve(v2, "release", "ops", "approved", "候选")
        ro = services.create_rollout(fid, v2, 100, "test")
        key = find_hit_key(ro["rollout_id"])
        res = services.invoke(fid, INPUTS, "t", routing_key=key)
        self.assertEqual(res["version_id"], v2)
        self.assertFalse(res["authz_snapshot"]["required"])
        # 冻结期命中基线：同样无 required 快照
        services.freeze_rollout(ro["rollout_id"], ro["generation"], "test")
        res_b = services.invoke(fid, INPUTS, "t", routing_key=key)
        self.assertEqual(res_b["version_id"], v1)
        self.assertFalse(res_b["authz_snapshot"]["required"])
        self.assertFalse(
            services.request_authz_view(res_b["request_id"])["required"])

    def test_invalid_window_inputs(self):
        fid, v1, v2 = make_family(["ticket.read", "refund.execute"])
        with self.assertRaises(services.DomainError):
            services.approve(v2, "tool_expansion", "sec", "approved", "坏时刻",
                             valid_from="2026/10/04")
        with self.assertRaises(services.DomainError):
            services.approve(v2, "tool_expansion", "sec", "approved", "逆序",
                             valid_from="2026-10-10 00:00:00",
                             valid_until="2026-10-09 00:00:00")
        with self.assertRaises(services.DomainError):
            services.approve(v2, "tool_expansion", "sec", "approved", "相等",
                             valid_from="2026-10-10 00:00:00",
                             valid_until="2026-10-10 00:00:00")


class AuthzHttpApiTest(unittest.TestCase):
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
        request = urllib.request.Request(url, data=data, method=method,
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def _get(self, path):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}") as resp:
            return resp.status, resp.read().decode()

    def test_approval_window_and_revoke_api(self):
        fid, v1, v2 = make_family(["ticket.read", "refund.execute"])
        now = services.db_now()
        # 带有效期审批
        code, a = self._req("POST", f"/api/versions/{v2}/approve", {
            "kind": "tool_expansion", "approver": "sec", "decision": "approved",
            "reason": "API 限时授权",
            "valid_from": services.shift_ts(now, -10),
            "valid_until": services.shift_ts(now, 3600)})
        self.assertEqual(code, 201, a)
        aid = a["approval_id"]
        self.assertEqual(a["state"], "approved")
        self.assertGreaterEqual(a["remaining_seconds"], 3599)
        # 单查 / 列表
        code, one = self._req("GET", f"/api/approvals/{aid}")
        self.assertEqual(code, 200)
        self.assertEqual(one["state"], "approved")
        code, lst = self._req("GET", f"/api/approvals?version={v2}")
        self.assertEqual(code, 200)
        self.assertTrue(any(x["approval_id"] == aid for x in lst))
        # 缺 expected_version -> 400
        code, err = self._req("POST", f"/api/approvals/{aid}/revoke", {"reason": "x"})
        self.assertEqual(code, 400)
        # 错误版本 -> 409
        code, err = self._req("POST", f"/api/approvals/{aid}/revoke",
                              {"expected_version": 99})
        self.assertEqual(code, 409)
        # 到期授权建批被拦
        ro_before = None
        code, err = self._req("POST", f"/api/families/{fid}/rollouts",
                              {"candidate_version_id": v2, "weight": 100})
        self.assertEqual(code, 201, err)  # 当前仍生效 -> 成功
        rid = err["rollout_id"]
        # 撤销 -> 命中被拒
        code, rv = self._req("POST", f"/api/approvals/{aid}/revoke",
                             {"expected_version": a["revoke_version"], "reason": "API 撤销"})
        self.assertEqual(code, 200)
        self.assertEqual(rv["state"], "revoked")
        key = find_hit_key(rid)
        code, err = self._req("POST", f"/api/families/{fid}/invoke",
                              {"inputs": INPUTS, "routing_key": key})
        self.assertEqual(code, 409, err)
        self.assertIn("revoked", err["message"])
        # 批次状态/指针未变
        code, ro_now = self._req("GET", f"/api/rollouts/{rid}")
        self.assertEqual(ro_now["status"], "ramping")

    def test_pages_render(self):
        fid, v1, v2 = make_family(["ticket.read", "refund.execute"])
        services.approve(v2, "tool_expansion", "sec", "approved", "页面冒烟",
                         valid_until=services.shift_ts(services.db_now(), 3600))
        a = latest_expansion(v2)
        ro = services.create_rollout(fid, v2, 100, "test")
        res = services.invoke(fid, INPUTS, "t", routing_key=find_hit_key(ro["rollout_id"]))
        for path in ("/approvals", f"/approvals?version={v2}",
                     f"/versions/{v2}/eval", f"/families/{fid}/rollout",
                     f"/requests/{res['request_id']}/replay"):
            code, html = self._get(path)
            self.assertEqual(code, 200, path)
        # 复查页出现授权快照面板
        _, html = self._get(f"/requests/{res['request_id']}/replay")
        self.assertIn("工具扩权授权快照", html)
        self.assertIn(a["approval_id"], html)
        # 审批页含撤销按钮（expected_version）
        _, html = self._get("/approvals")
        self.assertIn("提前撤销", html)
        self.assertIn(str(a["revoke_version"]), html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
