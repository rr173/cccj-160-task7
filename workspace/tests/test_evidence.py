"""提示治理证据包（迁移归档）端到端验证（标准库 unittest，离线可跑）。

覆盖需求场景：
- 并发写入下导出稳定切点：导出快照事务期间另一线程持续写，包内只有切点前的
  完整闭包数据；切点之后的行不出现
- 正常包完整导入空实例：重建只读证据，评估/调用复查/放量/止损历史均可打开
- 篡改单个对象：内容哈希与清单不符，提交 422 拒绝，无半数据
- 缺失分片：提交 409 且会话保留，补齐后成功（断点续传）
- 上传中断后续传：关闭/重开到目标库的绑定（模拟进程重启），会话仍可继续
- 同包再次导入：同摘要幂等，返回原 pack_id
- 同标识冲突包：pack_id 相同但内容不同 -> 409，不留部分数据
- 并发提交：多会话提交同一包，恰好一方新建成功，其余幂等返回原包
- 失败路径均不暴露半导入数据：evidence_packs 无记录，业务表不被污染
- 版本范围 / 调用范围选择；JSON API 与页面冒烟；下载字节确定性
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
import uuid

_TMP = tempfile.mkdtemp(prefix="promptgov-evidence-test-")
os.environ["PROMPTGOV_DATA"] = os.path.join(_TMP, "primary")
os.environ["PROMPTGOV_SEED"] = "0"
os.environ["PROMPTGOV_PORT"] = "0"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from promptgov import db, evidence, seed, services  # noqa: E402

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


def _u() -> str:
    return uuid.uuid4().hex[:8]


def make_family_with_trial(min_sample: int = 5, fail_limit: float = 0.4):
    """建族：v1 上线、v2 已审核；建批次与止损配置，返回关键 id 元组。"""
    fid = f"f-{_u()}"
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
    ro = services.create_rollout(fid, v2["version_id"], 100, "test")
    services.configure_stoploss(ro["rollout_id"], 3600, min_sample, fail_limit, "test")
    return fid, v1["version_id"], v2["version_id"], ro["rollout_id"]


def hit_candidate(fid, label):
    rid = f"req-{label}-{_u()}"
    return services.invoke(fid, INPUTS, "test", request_id=rid,
                           routing_key=f"key-{rid}")


# --------------------------------------------------------------- 打包/解包助手

def split_pack(blob: bytes):
    """拆 .pgpack 为 (信封行, [数据分片...], envelope)。"""
    nl = blob.index(b"\n") + 1
    env_line, payload = blob[:nl], blob[nl:]
    envelope = json.loads(base64.b64decode(json.loads(env_line.decode())["data"]))
    shards = [payload[d["start"]:d["start"] + d["length"]] for d in envelope["shards"]]
    return env_line, shards, envelope


def envelope_line(env: dict) -> bytes:
    raw = json.dumps(env, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode()
    return json.dumps({"kind": "envelope", "sha256": hashlib.sha256(raw).hexdigest(),
                       "data": base64.b64encode(raw).decode()}).encode() + b"\n"


def fresh_target_db() -> str:
    path = os.path.join(tempfile.mkdtemp(prefix=f"pg-target-{_u()}-"), "promptgov.db")
    with evidence.bind_db(path):  # 建空实例 schema
        pass
    return path


def upload_all(path, env_line, shards, *, skip=()):
    """在目标库上初始化并上传（可缺片），返回 import_id。"""
    with evidence.bind_db(path):
        sess = evidence.init_import(env_line, "test")
        assert sess.get("import_id"), sess
        iid = sess["import_id"]
        for i, sh in enumerate(shards, start=1):
            if i in skip:
                continue
            evidence.put_import_shard(iid, i, sh)
        return iid


def commit_on(path, iid):
    with evidence.bind_db(path, init_schema=False):
        return evidence.commit_import(iid, "test")


def pack_count(path) -> int:
    with evidence.bind_db(path, init_schema=False) as c:
        return c.execute("SELECT COUNT(*) c FROM evidence_packs").fetchone()["c"]


# ================================================================ 导出

class ExportSnapshotTest(unittest.TestCase):

    def test_stable_cutpoint_under_concurrent_writes(self):
        """导出快照事务进行中，另一线程持续产生调用/回执：包只含切点前数据。"""
        fid, v1, v2, rid = make_family_with_trial()
        captured = {}
        stop = threading.Event()

        def writer():
            i = 0
            while not stop.is_set():
                try:
                    res = services.invoke(fid, INPUTS, "writer",
                                          request_id=f"concurrent-req-{_u()}-{i}",
                                          routing_key=f"ck-{i}-{_u()}")
                    if res["version_id"] == v2:
                        services.report_feedback(
                            rid, f"concurrent-fb-{_u()}-{i}", res["request_id"],
                            "success", "writer")
                except Exception:  # noqa: BLE001
                    pass
                i += 1

        writer_thread = threading.Thread(target=writer)

        def cb(cutpoint):
            captured.update(cutpoint)
            writer_thread.start()
            import time as _t
            _t.sleep(0.25)  # 让并发写入在闭包收集期间持续提交

        pack = evidence.build_pack({"kind": "family", "family_id": fid}, "test",
                                   shard_size_bytes=1024, snapshot_callback=cb)
        stop.set()
        writer_thread.join(timeout=5)

        view = evidence.PackView(pack["pack_id"])
        req_ids = {r["request_id"] for r in view.by_table["requests"]}
        fb_ids = {r["feedback_id"] for r in view.by_table["feedback_receipts"]}
        self.assertFalse(any("concurrent-req" in r for r in req_ids),
                         "切点之后的调用不得进入证据包")
        self.assertFalse(any("concurrent-fb" in r for r in fb_ids),
                         "切点之后的回执不得进入证据包")
        now_rows = db.get_conn().execute(
            "SELECT COUNT(*) c FROM requests WHERE request_id LIKE 'concurrent-req-%'",
        ).fetchone()["c"]
        self.assertGreater(now_rows, 0, "并发线程应已写入切点后数据")
        in_pack_audit_ids = {int(r["id"]) for r in view.by_table["audit_log"]}
        self.assertLessEqual(max(in_pack_audit_ids), captured["audit_max_id"])
        self.assertNotIn(captured["audit_max_id"] + 1, in_pack_audit_ids)
        pid, blob = evidence.pack_file_bytes(pack["pack_id"])
        self.assertTrue(evidence.verify_bytes(blob)["ok"])
        for r in view.by_table["requests"]:
            self.assertIsNotNone(view._get("versions", r["version_id"]))

    def test_export_scope_closure_no_dangling_refs(self):
        fid, v1, v2, ro_id = make_family_with_trial()
        req = hit_candidate(fid, "scope")
        services.report_feedback(ro_id, f"fb-{_u()}", req["request_id"], "success", "test")
        pack = evidence.build_pack({"kind": "family", "family_id": fid}, "test",
                                   shard_size_bytes=512)
        report = evidence.verify_bytes(evidence.pack_file_bytes(pack["pack_id"])[1])
        self.assertTrue(report["ok"], [e["message"] for e in report["errors"]])
        counts = pack["counts"]
        for t in ("families", "versions", "approvals", "testsets", "testcases",
                  "eval_runs", "eval_cases", "requests", "rollouts",
                  "stoploss_configs", "stoploss_windows", "feedback_receipts"):
            self.assertGreaterEqual(counts[t], 1, t)

    def test_version_scope_and_request_scope(self):
        fid, v1, v2, ro_id = make_family_with_trial()
        req = hit_candidate(fid, "rscope")
        vp = evidence.build_pack({"kind": "version", "version_id": v2}, "test")
        v = evidence.PackView(vp["pack_id"])
        self.assertTrue(v._get("families", fid))
        self.assertTrue(v._get("versions", v2))
        self.assertTrue(any(r["request_id"] == req["request_id"]
                            for r in v.by_table["requests"]))
        self.assertTrue(evidence.verify_bytes(
            evidence.pack_file_bytes(vp["pack_id"])[1])["ok"])
        rp = evidence.build_pack(
            {"kind": "requests", "request_ids": [req["request_id"]]}, "test")
        rv = evidence.PackView(rp["pack_id"])
        self.assertTrue(rv._get("requests", req["request_id"]))
        self.assertTrue(rv._get("versions", v2))
        self.assertTrue(evidence.verify_bytes(
            evidence.pack_file_bytes(rp["pack_id"])[1])["ok"])

    def test_version_scope_is_strict_no_sibling_or_rollout_leak(self):
        """勾选单个修订版：未勾选修订版及其请求、灰度批次与风控记录一律不入包；
        落在范围外的结构边（活动指针/批次/窗口）逐项声明为 external_refs，
        自检通过且无断链。"""
        fid, v1, v2, ro_id = make_family_with_trial()
        req = hit_candidate(fid, "strict")
        services.report_feedback(ro_id, f"fb-{_u()}", req["request_id"], "success", "test")
        # v1 是当前活动指针（族指针指向未勾选修订版）——必须不展开、不断链
        fam = services.get_family(fid)
        self.assertEqual(fam["active_version_id"], v1)

        vp = evidence.build_pack({"kind": "version", "version_id": v2}, "test")
        v = evidence.PackView(vp["pack_id"])
        # —— 未勾选修订版及其请求/审批/评估不得夹带 ——
        self.assertIsNone(v._get("versions", v1), "未勾选修订版不得入包")
        self.assertEqual(len(v.by_table["versions"]), 1)
        self.assertEqual({x["version_id"] for x in v.by_table["versions"]}, {v2})
        # —— 灰度与风控记录不得夹带 ——
        self.assertEqual(v.by_table["rollouts"], [])
        self.assertEqual(v.by_table["stoploss_configs"], [])
        self.assertEqual(v.by_table["stoploss_windows"], [])
        self.assertEqual(v.by_table["stoploss_triggers"], [])
        # 命中所选版本的调用及其入账回执保留（复查最小依赖）
        self.assertTrue(any(r["request_id"] == req["request_id"]
                            for r in v.by_table["requests"]))
        self.assertEqual(len(v.by_table["feedback_receipts"]), 1)
        # 评估证据 + 固定测试集 + 审批随所选版本保留
        self.assertTrue(v.by_table["eval_runs"])
        self.assertTrue(v.by_table["testcases"])
        self.assertTrue(v.by_table["approvals"])
        # 审计不得夹带族级 promote/rollback（明细含兄弟版本 id）
        actions = {a["action"] for a in v.by_table["audit_log"]}
        self.assertNotIn("version.promote", actions)
        self.assertNotIn("version.rollback", actions)
        for a in v.by_table["audit_log"]:
            self.assertNotIn(v1, str(a["detail"]),
                            "窄包审计明细不得泄露未勾选版本 id")
        # —— 边界外部引用显式声明 ——
        ext = {(it["table"], r["table"], r["id"])
               for it in v.manifest["items"] for r in it.get("external_refs", [])}
        self.assertIn(("families", "versions", v1), ext, "活动指针须声明为边界引用")
        self.assertIn(("requests", "rollouts", ro_id), ext)
        receipt = v.by_table["feedback_receipts"][0]
        self.assertIn(("feedback_receipts", "rollouts", ro_id), ext)
        self.assertIn(("feedback_receipts", "stoploss_windows",
                       receipt["window_id"]), ext)
        # 所有包内 refs 必须可解析（无断链）
        for it in v.manifest["items"]:
            for r in it["refs"]:
                self.assertIsNotNone(v._get(r["table"], r["id"]),
                                     f"{it['table']}/{it['id']} 断链 {r}")
        # 自检通过
        self.assertTrue(evidence.verify_bytes(
            evidence.pack_file_bytes(vp["pack_id"])[1])["ok"])

    def test_request_scope_is_strict(self):
        """调用范围：只含勾选调用、命中版本、重演与已入账回执；不夹带批次/风控/
        兄弟版本，也不夹带命中版本的审批与评估。"""
        fid, v1, v2, ro_id = make_family_with_trial()
        req_hit = hit_candidate(fid, "hit")          # 命中候选 v2
        services.report_feedback(ro_id, f"fb-{_u()}", req_hit["request_id"],
                                 "success", "test")
        # 一条命中基线 v1 的调用（冻结前权重 100% 不会命中基线；直接构造：
        # 用未参与放量的 routing 之外的普通调用走当前活动指针 v1——需要先冻结）
        services.freeze_rollout(ro_id, 1, "test")
        req_base = services.invoke(fid, INPUTS, "test",
                                   request_id=f"req-base-{_u()}",
                                   routing_key=f"bk-{_u()}")
        self.assertEqual(req_base["version_id"], v1)

        pack = evidence.build_pack(
            {"kind": "requests", "request_ids": [req_hit["request_id"]]}, "test")
        view = evidence.PackView(pack["pack_id"])
        self.assertEqual({r["request_id"] for r in view.by_table["requests"]},
                         {req_hit["request_id"]})
        self.assertEqual({x["version_id"] for x in view.by_table["versions"]}, {v2})
        self.assertIsNone(view._get("versions", v1))
        self.assertEqual(view.by_table["rollouts"], [])
        self.assertEqual(view.by_table["stoploss_configs"], [])
        self.assertEqual(view.by_table["stoploss_windows"], [])
        self.assertEqual(view.by_table["stoploss_triggers"], [])
        self.assertEqual(view.by_table["approvals"], [])
        self.assertEqual(view.by_table["eval_runs"], [])
        self.assertEqual(view.by_table["testsets"], [])
        self.assertEqual(len(view.by_table["feedback_receipts"]), 1)
        ext = {(it["table"], r["table"], r["id"])
               for it in view.manifest["items"] for r in it.get("external_refs", [])}
        self.assertIn(("requests", "rollouts", ro_id), ext)
        self.assertIn(("families", "versions", v1), ext)
        self.assertTrue(evidence.verify_bytes(
            evidence.pack_file_bytes(pack["pack_id"])[1])["ok"])

        # 多个勾选调用跨命中构件：两个版本都随包，但仍无批次/风控
        pack2 = evidence.build_pack(
            {"kind": "requests",
             "request_ids": [req_hit["request_id"], req_base["request_id"]]}, "test")
        v2view = evidence.PackView(pack2["pack_id"])
        self.assertEqual({x["version_id"] for x in v2view.by_table["versions"]},
                         {v1, v2})
        self.assertEqual(v2view.by_table["rollouts"], [])
        self.assertTrue(evidence.verify_bytes(
            evidence.pack_file_bytes(pack2["pack_id"])[1])["ok"])

    def test_narrow_pack_roundtrip_import_and_pages_open(self):
        """窄包导入空实例后，所选评估页与调用复查页所需最小依赖完整可打开；
        边界对象（批次/窗口/未勾选版本）不在包内但不断链。"""
        fid, v1, v2, ro_id = make_family_with_trial()
        req = hit_candidate(fid, "roundtrip")
        services.report_feedback(ro_id, f"fb-{_u()}", req["request_id"], "success", "test")
        pack = evidence.build_pack({"kind": "version", "version_id": v2}, "test")
        blob = evidence.pack_file_bytes(pack["pack_id"])[1]
        env_line, shards, _ = split_pack(blob)
        path = fresh_target_db()
        iid = upload_all(path, env_line, shards)
        res = commit_on(path, iid)
        with evidence.bind_db(path, init_schema=False):
            view = evidence.PackView(res["pack_id"])
            # 评估页最小依赖
            self.assertTrue(view.eval_runs(v2))
            run = view.eval_runs(v2)[0]
            self.assertEqual(len(view.eval_run(run["run_id"])["cases"]), run["total"])
            self.assertTrue(view.approvals(v2))
            # 调用复查页最小依赖：调用、命中版本、回执、族头
            self.assertIsNotNone(view.request(req["request_id"]))
            self.assertIsNotNone(view._get("versions", v2))
            self.assertIsNotNone(view.receipt(req["request_id"]))
            self.assertIsNone(view.rollout(ro_id), "边界批次不入包")
            # 边界引用仍在清单中
            ext = {(it["table"], r["table"], r["id"])
                   for it in view.manifest["items"] for r in it.get("external_refs", [])}
            self.assertIn(("families", "versions", v1), ext)

    def test_undeclared_boundary_ref_is_rejected(self):
        """篡改者把内部 refs 从清单删掉以制造断链：落库前校验必须 422 拒绝。"""
        fid, v1, v2, ro_id = make_family_with_trial()
        hit_candidate(fid, "tamper")
        pack = evidence.build_pack({"kind": "version", "version_id": v2}, "test",
                                   shard_size_bytes=4096)
        blob = evidence.pack_file_bytes(pack["pack_id"])[1]
        lines = [ln for ln in blob.split(b"\n") if ln]
        # 找到 requests 对象行：其记录内含 rollout_id；攻击者重算对象哈希但
        # 无法同步清单（清单哈希进信封），构造一个把 requests 行的 external
        # 声明清空、且把对象从载荷删掉的变体不可行（对象数会变），因此直接
        # 校验 verify_bytes 对"引用不可解析且未声明"的合成包报错：用最小方式
        # 验证——篡改清单中 families 项的 external_refs（清单行哈希会不符）。
        report = evidence.verify_bytes(blob)
        self.assertTrue(report["ok"])
        # 直接构造：把 families 对象的 active_version_id 清掉会触发内容哈希不符；
        # 这里验证校验链对边界声明缺失敏感：手工从 manifest items 移除外部声明。
        env_l = lines[0]
        envelope = json.loads(base64.b64decode(json.loads(env_l)["data"]))
        payload = b"\n".join(lines[1:]) + b"\n"
        man_wrapper = json.loads(payload.split(b"\n", 1)[0])
        manifest = json.loads(base64.b64decode(man_wrapper["data"]))
        for it in manifest["items"]:
            it.pop("external_refs", None)
        # 重算清单与载荷、信封（模拟能改一切但保留 families→v1 边界的场景）
        m_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode()
        # 对象行原样保留；只替换清单行
        obj_lines = payload.split(b"\n")[1:]
        new_man_line = json.dumps(
            {"kind": "manifest",
             "sha256": hashlib.sha256(m_bytes).hexdigest(),
             "data": base64.b64encode(m_bytes).decode()}).encode()
        new_payload = new_man_line + b"\n" + b"\n".join(obj_lines)
        env2 = dict(envelope)
        env2["manifest_sha"] = hashlib.sha256(m_bytes).hexdigest()
        env2["archive_sha"] = hashlib.sha256(new_payload).hexdigest()
        size = env2["shard_size_bytes"]
        chunks = [new_payload[s:s + size] for s in range(0, len(new_payload), size)]
        env2["shards"] = [{"index": i + 1, "sha256": hashlib.sha256(ch).hexdigest(),
                           "start": i * size, "length": len(ch)}
                          for i, ch in enumerate(chunks)]
        e_bytes = json.dumps(env2, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode()
        forged = json.dumps({"kind": "envelope",
                             "sha256": hashlib.sha256(e_bytes).hexdigest(),
                             "data": base64.b64encode(e_bytes).decode()}).encode() \
            + b"\n" + new_payload
        report2 = evidence.verify_bytes(forged)
        self.assertFalse(report2["ok"])
        self.assertTrue(any(e["code"] == "dangling_reference" for e in report2["errors"]),
                        [e["code"] for e in report2["errors"]])


    def test_bad_scope(self):
        with self.assertRaises(services.NotFound):
            evidence.build_pack({"kind": "family", "family_id": "nope"}, "test")
        with self.assertRaises(services.DomainError):
            evidence.build_pack({"kind": "weird"}, "test")
        with self.assertRaises(services.DomainError):
            evidence.build_pack({"kind": "requests", "request_ids": []}, "test")

    def test_download_is_byte_deterministic(self):
        fid, _, _, _ = make_family_with_trial()
        p = evidence.build_pack({"kind": "family", "family_id": fid}, "test",
                                shard_size_bytes=4096)
        self.assertEqual(evidence.pack_file_bytes(p["pack_id"])[1],
                         evidence.pack_file_bytes(p["pack_id"])[1])


# ================================================================ 导入

class ImportFlowTest(unittest.TestCase):
    """所有用例都把包导入到各自独立的空数据库文件（空实例重建）。"""

    def setUp(self):
        self.path = fresh_target_db()

    def _exported(self):
        fid, v1, v2, ro_id = make_family_with_trial()
        req = hit_candidate(fid, "imp")
        services.report_feedback(ro_id, f"fb-{_u()}", req["request_id"], "success", "test")
        pack = evidence.build_pack({"kind": "family", "family_id": fid}, "test",
                                   shard_size_bytes=512)
        return pack, evidence.pack_file_bytes(pack["pack_id"])[1]

    def test_full_import_into_empty_instance(self):
        pack, blob = self._exported()
        env_line, shards, envelope = split_pack(blob)
        iid = upload_all(self.path, env_line, shards)
        res = commit_on(self.path, iid)
        self.assertIsNone(res["already"], res)
        with evidence.bind_db(self.path, init_schema=False):
            view = evidence.PackView(res["pack_id"])
            self.assertGreaterEqual(len(view.by_table["versions"]), 2)
            self.assertTrue(view.by_table["rollouts"])
            ro_id0 = view.by_table["rollouts"][0]["rollout_id"]
            ov = view.stoploss_overview(ro_id0)
            self.assertGreaterEqual(len(ov["windows"]), 1)
            self.assertGreaterEqual(len(ov["receipts"]), 1)
            for run in view.by_table["eval_runs"]:
                d = view.eval_run(run["run_id"])
                self.assertEqual(len(d["cases"]), run["total"])
            meta = evidence.get_pack(res["pack_id"])
            self.assertEqual(meta["status"], "imported")
            self.assertEqual(meta["source_instance_id"], envelope["source_instance_id"])
            self.assertEqual(meta["cutpoint"]["audit_max_id"],
                             envelope["cutpoint"]["audit_max_id"])
            actions = {a["action"] for a in meta["audit"]}
            self.assertIn("import.init", actions)
            self.assertIn("import.commit", actions)
        # 业务表为空（导入证据不回写线上状态）
        with evidence.bind_db(self.path, init_schema=False) as c:
            for t in ("families", "versions", "requests", "rollouts",
                      "feedback_receipts", "eval_runs"):
                self.assertEqual(c.execute(f"SELECT COUNT(*) c FROM {t}").fetchone()["c"], 0, t)

    def test_tampered_single_object_rejected(self):
        pack, blob = self._exported()
        # 构造"对象被改"的恶意归档：只改某 object 行 data 的一个字节，
        # 并同步伪造该行 sha、所有分片 sha、archive_sha（攻击者拿不到清单哈希，
        # 故 manifest 行保持原样）——提交校验必须发现对象摘要与清单不符。
        lines = [ln for ln in blob.split(b"\n") if ln]
        obj_idx = max(k for k, ln in enumerate(lines)
                      if json.loads(ln).get("kind") == "object")
        wrapper = json.loads(lines[obj_idx])
        raw = base64.b64decode(wrapper["data"])
        b = bytearray(raw)
        b[len(b) // 2] ^= 0x01
        forged = bytes(b)
        wrapper["sha256"] = hashlib.sha256(forged).hexdigest()
        lines[obj_idx] = evidence._line("object", wrapper["sha256"], forged)
        env_line0, _, env = split_pack(blob)
        payload = b"\n".join(lines[1:]) + b"\n"
        # 重新按原分片边界切并重算信封
        shards = [payload[d["start"]:d["start"] + d["length"]] for d in env["shards"]]
        env2 = dict(env)
        env2["shards"] = [{"index": d["index"], "sha256": hashlib.sha256(ch).hexdigest(),
                           "start": d["start"], "length": len(ch)}
                          for d, ch in zip(env["shards"], shards)]
        env2["archive_sha"] = hashlib.sha256(payload).hexdigest()
        fake_env_line = envelope_line(env2)

        iid = upload_all(self.path, fake_env_line, shards)
        with self.assertRaises(evidence.VerificationRejected):
            commit_on(self.path, iid)
        self.assertEqual(pack_count(self.path), 0, "失败路径不得留下证据数据")
        with evidence.bind_db(self.path, init_schema=False) as c:
            status = c.execute("SELECT status FROM evidence_imports WHERE import_id=?",
                               (iid,)).fetchone()["status"]
        self.assertEqual(status, "failed")
        # 对原归档的纯校验也必须报错（不依赖上传路径）
        forged_blob = fake_env_line + payload
        report = evidence.verify_bytes(forged_blob)
        self.assertFalse(report["ok"])
        self.assertTrue(any(e["code"] == "object_sha_mismatch" for e in report["errors"]))

    def test_missing_shard_blocks_commit_then_resume(self):
        _, blob = self._exported()
        env_line, shards, envelope = split_pack(blob)
        iid = upload_all(self.path, env_line, shards, skip={2})
        with self.assertRaises(services.Conflict):
            commit_on(self.path, iid)
        with evidence.bind_db(self.path, init_schema=False):
            info = evidence.get_import(iid)
        self.assertEqual(info["status"], "staging")
        self.assertEqual(info["missing"], [2])
        self.assertEqual(pack_count(self.path), 0)
        with evidence.bind_db(self.path, init_schema=False):
            evidence.put_import_shard(iid, 2, shards[1])
        res = commit_on(self.path, iid)
        self.assertIsNone(res["already"])
        self.assertEqual(pack_count(self.path), 1)

    def test_interrupted_upload_resumes(self):
        """模拟进程中断：部分分片上传后关闭全部连接（退出 bind 上下文），
        随后重新打开目标库（新"进程"），会话从磁盘恢复并继续。"""
        _, blob = self._exported()
        env_line, shards, envelope = split_pack(blob)
        with evidence.bind_db(self.path, init_schema=False):
            sess = evidence.init_import(env_line, "test")
            iid = sess["import_id"]
            evidence.put_import_shard(iid, 1, shards[0])
            evidence.put_import_shard(iid, 3, shards[2])
        # —— 进程重启：新的绑定，内存里没有任何会话状态 ——
        with evidence.bind_db(self.path, init_schema=False):
            info = evidence.get_import(iid)
            self.assertEqual(info["status"], "staging")
            self.assertEqual(sorted(info["received"]), [1, 3])
            full = set(range(1, len(shards) + 1))
            self.assertEqual(set(info["missing"]), full - {1, 3})
            for i, sh in enumerate(shards, start=1):
                if i in (1, 3):
                    continue
                evidence.put_import_shard(iid, i, sh)
        res = commit_on(self.path, iid)
        self.assertFalse(isinstance(res, Exception), res)
        self.assertEqual(pack_count(self.path), 1)

    def test_reimport_same_pack_returns_original(self):
        pack, blob = self._exported()
        env_line, shards, envelope = split_pack(blob)
        iid = upload_all(self.path, env_line, shards)
        res1 = commit_on(self.path, iid)
        pid = res1["pack_id"]
        # init 即幂等返回原结果（同摘要再导入无副作用，不新建会话/包）
        with evidence.bind_db(self.path, init_schema=False):
            again = evidence.init_import(env_line, "test")
        self.assertEqual(again["already"], "committed")
        self.assertEqual(again["pack_id"], pid)
        # 模拟"上传恰好在别人提交后才完成"的在途会话：直接落一条 staging 会话，
        # 全分片上传后提交 -> 提交端返回原包而不是新建
        with evidence.bind_db(self.path, init_schema=False) as c:
            iid2 = f"imp_inflight_{_u()}"
            c.execute(
                "INSERT INTO evidence_imports(import_id,pack_id,outer_manifest_sha,"
                "envelope_json,status) VALUES (?,?,?,?,'staging')",
                (iid2, envelope["pack_id"], json.loads(env_line)["sha256"],
                 json.dumps({"line_sha": json.loads(env_line)["sha256"],
                             "envelope": envelope})))
            c.commit()
        with evidence.bind_db(self.path, init_schema=False):
            for i, sh in enumerate(shards, start=1):
                evidence.put_import_shard(iid2, i, sh)
        res2 = commit_on(self.path, iid2)
        self.assertEqual(res2["already"], "committed")
        self.assertEqual(res2["pack_id"], pid)
        self.assertEqual(pack_count(self.path), 1)

    def test_same_id_different_content_rejected(self):
        _, blob1 = self._exported()
        fid2, _, _, _ = make_family_with_trial()
        pack2 = evidence.build_pack({"kind": "family", "family_id": fid2}, "test",
                                    shard_size_bytes=512)
        blob2 = evidence.pack_file_bytes(pack2["pack_id"])[1]
        env_line1, shards1, _ = split_pack(blob1)
        env_line2, _, env2 = split_pack(blob2)
        # 先正常导入包1
        iid = upload_all(self.path, env_line1, shards1)
        pid1 = commit_on(self.path, iid)["pack_id"]
        # 包2 的信封改声明 pack_id=pid1（内容摘要完全不同）
        env2["pack_id"] = pid1
        fake_line = envelope_line(env2)
        with evidence.bind_db(self.path, init_schema=False):
            with self.assertRaises(services.Conflict):
                evidence.init_import(fake_line, "test")
        self.assertEqual(pack_count(self.path), 1, "冲突包不得落任何数据")

    def test_concurrent_commit_single_winner(self):
        _, blob = self._exported()
        env_line, shards, envelope = split_pack(blob)
        iids = []
        with evidence.bind_db(self.path, init_schema=False):
            for _ in range(6):
                sess = evidence.init_import(env_line, "test")
                iid = sess["import_id"]
                for i, sh in enumerate(shards, start=1):
                    evidence.put_import_shard(iid, i, sh)
                iids.append(iid)

        results, errors = [], []

        def worker(iid):
            # 每个工作线程绑定到同一目标库文件（各自独立连接，写锁串行化）
            try:
                with evidence.bind_db(self.path, init_schema=False):
                    results.append(evidence.commit_import(iid, "test"))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(iid,)) for iid in iids]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)
        self.assertFalse(errors, [str(e) for e in errors])
        self.assertEqual(len(results), len(iids))
        pids = {r["pack_id"] for r in results}
        self.assertEqual(len(pids), 1, "并发提交只能有同一个最终包")
        new_winners = [r for r in results if r["already"] is None]
        duplicates = [r for r in results if r["already"] == "committed"]
        self.assertEqual(len(new_winners), 1, "恰好一方新建，其余幂等返回原结果")
        self.assertEqual(len(duplicates), len(iids) - 1)
        self.assertEqual(pack_count(self.path), 1)

    def test_bad_shard_immediately_rejected(self):
        _, blob = self._exported()
        env_line, shards, envelope = split_pack(blob)
        with evidence.bind_db(self.path, init_schema=False):
            sess = evidence.init_import(env_line, "test")
            iid = sess["import_id"]
            bad = bytearray(shards[0])
            bad[10] ^= 0xFF
            with self.assertRaises(services.DomainError):
                evidence.put_import_shard(iid, 1, bytes(bad))
            self.assertEqual(evidence.get_import(iid)["received"], [])  # 坏分片不暂存
            evidence.put_import_shard(iid, 1, shards[0])
            evidence.put_import_shard(iid, 1, shards[0])  # 幂等重传
            self.assertEqual(evidence.get_import(iid)["received"], [1])
            with self.assertRaises(services.DomainError):
                evidence.put_import_shard(iid, 999, b"x")  # 序号越界


# ================================================================ HTTP 冒烟

class HttpSmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        seed.run()  # 幂等演示数据
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

    def test_evidence_api_and_pages(self):
        st, pack = self._req("POST", "/api/evidence/exports",
                             {"scope_kind": "family", "family_id": seed.FAMILY,
                              "shard_size_bytes": 4096})
        self.assertEqual(st, 201, pack)
        pid = pack["pack_id"]
        self.assertEqual(self._req("GET", "/api/evidence/packs")[0], 200)
        self.assertEqual(self._req("GET", f"/api/evidence/packs/{pid}")[0], 200)
        st, man = self._req("GET", f"/api/evidence/packs/{pid}/manifest")
        self.assertEqual(st, 200)
        st, rep = self._req("POST", f"/api/evidence/packs/{pid}/verify", {})
        self.assertEqual(st, 200)
        self.assertTrue(rep["ok"])
        raw = urllib.request.urlopen(
            f"http://127.0.0.1:{self.port}/api/evidence/packs/{pid}/download").read()
        # 规范化 JSON 按 key 排序，首字段是 data；信封行 kind=envelope
        self.assertEqual(json.loads(raw.split(b"\n", 1)[0])["kind"], "envelope")
        nl = raw.index(b"\n") + 1
        st, sess = self._req("POST", "/api/evidence/imports",
                             {"envelope_line": raw[:nl].decode()})
        self.assertEqual(st, 201)
        self.assertEqual(sess["already"], "committed")
        self.assertEqual(sess["pack_id"], pid)
        verid = next(i["id"] for i in man["items"] if i["table"] == "versions")
        roid = next(i["id"] for i in man["items"] if i["table"] == "rollouts")
        reqid = next(i["id"] for i in man["items"] if i["table"] == "requests")
        for path in ("/evidence", "/evidence/export?kind=family",
                     f"/evidence/packs/{pid}",
                     f"/evidence/packs/{pid}/versions/{verid}/eval",
                     f"/evidence/packs/{pid}/rollouts/{roid}/stoploss",
                     f"/evidence/packs/{pid}/requests/{reqid}/replay"):
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}") as resp:
                self.assertEqual(resp.status, 200, path)

    def test_shard_put_404(self):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/evidence/imports/imp_doesnotexist/shards/1",
            data=b"x", method="PUT",
            headers={"Content-Type": "application/octet-stream"})
        try:
            urllib.request.urlopen(req)
            self.fail("应 404")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
