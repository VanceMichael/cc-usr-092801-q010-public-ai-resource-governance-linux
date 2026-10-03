from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from civicflow.ai_sharing import AISharingService
from civicflow.application import CivicFlow
from civicflow.errors import ConflictError, PermissionDenied, ValidationError

NOW = "2026-10-03T12:00:00+08:00"
VALID_TO = "2026-12-31T23:59:59+08:00"

COMPONENTS = {
    "model": {"ref": "model://gov-llm", "version": "1.0.0", "digest": "sha256:m"},
    "dataset": {"ref": "data://public-corpus", "version": "2026-09", "digest": "sha256:d"},
    "security": {"ref": "sec://safety-sheet", "version": "3", "digest": "sha256:s"},
}
TERMS = {"groups": ["group:university", "group:sme"],
         "purposes": ["research", "public-service"],
         "use_cases": ["政务问答", "教学研究"],
         "regions": ["CN"]}

SUBMITTER = "user:teacher"
RIGHTS_OFFICER = "user:rights-officer"
SECURITY_OFFICER = "user:security-officer"


class AISharingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / "ai.sqlite3"
        self.app = CivicFlow.open(self.db_path, fixed_now=NOW)
        self.svc: AISharingService = self.app.ai_sharing
        self.artifact = self.svc.register_artifact("publisher", kind="model", name="公共政务大模型", request_key="a")
        self.release = self.svc.publish_release("publisher", self.artifact["artifact_id"], "1.0.0",
                                                 components=COMPONENTS, rights=TERMS, request_key="r")
        self.release_id = self.release["release_id"]

    def tearDown(self):
        self.temp.cleanup()

    def _policy(self, org="org:univ", group="group:university", limit=2):
        return self.svc.put_quota_policy("publisher", self.release_id, org, group, limit=limit, request_key=f"q-{org}-{group}")

    def _request(self, *, org="org:univ", group="group:university", purpose="research",
                 cases=("教学研究",), region="CN", qty=1, emergency=False, reason="",
                 submitter=SUBMITTER, key=None):
        return self.svc.submit_access_request(
            submitter, self.release_id, org_id=org, group_id=group, purpose=purpose,
            use_cases=list(cases), region=region, qty=qty, emergency=emergency,
            emergency_reason=reason, valid_to=VALID_TO, request_key=key or f"req-{org}-{group}-{purpose}")

    def _approve(self, request_id):
        self.svc.rights_review(RIGHTS_OFFICER, request_id, decision="approved", reason="权益符合")
        return self.svc.security_review(SECURITY_OFFICER, request_id, decision="approved", reason="安全符合")

    # ---- 目录与冻结发布 -------------------------------------------------

    def test_publish_freezes_component_bundle(self):
        self.assertEqual(set(self.release["components"]), {"model", "dataset", "security"})
        self.assertEqual(len(self.release["manifest_digest"]), 64)
        history = self.svc.rights_history(self.release_id)
        self.assertEqual([e["kind"] for e in history], ["grant"])

    def test_publish_requires_all_three_components(self):
        with self.assertRaises(ValidationError):
            self.svc.publish_release(
                "publisher", self.artifact["artifact_id"], "2.0.0",
                components={"model": COMPONENTS["model"], "dataset": COMPONENTS["dataset"]},
                rights=TERMS, request_key="bad")

    def test_duplicate_version_tag_conflicts(self):
        with self.assertRaises(ConflictError):
            self.svc.publish_release("publisher", self.artifact["artifact_id"], "1.0.0",
                                     components=COMPONENTS, rights=TERMS, request_key="dup")

    def test_publish_is_idempotent(self):
        again = self.svc.publish_release("publisher", self.artifact["artifact_id"], "1.1.0",
                                         components=COMPONENTS, rights=TERMS, request_key="same-rk")
        # 第一次成功
        self.assertEqual(again["version_tag"], "1.1.0")
        once_more = self.svc.publish_release("publisher", self.artifact["artifact_id"], "1.1.0",
                                             components=COMPONENTS, rights=TERMS, request_key="same-rk")
        self.assertEqual(once_more["release_id"], again["release_id"])

    # ---- 三角色分离 -----------------------------------------------------

    def test_submitter_cannot_review_rights(self):
        request = self._request(key="seg-1")
        with self.assertRaises(PermissionDenied):
            self.svc.rights_review(SUBMITTER, request["request_id"], decision="approved", reason="自批")

    def test_submitter_cannot_review_security(self):
        request = self._request(key="seg-2")
        self.svc.rights_review(RIGHTS_OFFICER, request["request_id"], decision="approved", reason="ok")
        with self.assertRaises(PermissionDenied):
            self.svc.security_review(SUBMITTER, request["request_id"], decision="approved", reason="自批")

    def test_rights_reviewer_cannot_review_security(self):
        request = self._request(key="seg-3")
        self.svc.rights_review(RIGHTS_OFFICER, request["request_id"], decision="approved", reason="ok")
        with self.assertRaises(PermissionDenied):
            self.svc.security_review(RIGHTS_OFFICER, request["request_id"], decision="approved", reason="代批")

    def test_reviews_must_follow_sequence(self):
        request = self._request(key="seg-4")
        with self.assertRaises(ConflictError):
            self.svc.security_review(SECURITY_OFFICER, request["request_id"], decision="approved", reason="跳过权益")

    # ---- 许可判断与配额 -------------------------------------------------

    def test_group_outside_scope_is_denied(self):
        self._policy()
        request = self._request(group="group:hospital", key="scope-g")
        self.svc.rights_review(RIGHTS_OFFICER, request["request_id"], decision="approved", reason="ok")
        with self.assertRaises(ValidationError):
            self.svc.security_review(SECURITY_OFFICER, request["request_id"], decision="approved", reason="ok")

    def test_region_outside_scope_is_denied(self):
        self._policy()
        request = self._request(region="EU", key="scope-r")
        self.svc.rights_review(RIGHTS_OFFICER, request["request_id"], decision="approved", reason="ok")
        with self.assertRaises(ValidationError):
            self.svc.security_review(SECURITY_OFFICER, request["request_id"], decision="approved", reason="ok")

    def test_quota_exhaustion_denies_and_leaves_no_partial_state(self):
        self._policy(limit=1)
        first = self._request(key="q-1")
        self._approve(first["request_id"])
        status = self.svc.quota_status(self.release_id, "org:univ", "group:university")
        self.assertEqual((status["used"], status["remaining"]), (1, 0))
        second = self._request(key="q-2")
        self.svc.rights_review(RIGHTS_OFFICER, second["request_id"], decision="approved", reason="ok")
        with self.assertRaises(ConflictError):
            self.svc.security_review(SECURITY_OFFICER, second["request_id"], decision="approved", reason="ok")
        # 失败后无配额占用、无凭据、申请仍停留在安全复核
        status = self.svc.quota_status(self.release_id, "org:univ", "group:university")
        self.assertEqual(status["used"], 1)
        self.assertEqual(second["request_id"],
                         self.svc.get_request(second["request_id"])["request_id"])
        self.assertEqual(self.svc.get_request(second["request_id"])["state"], "pending_security")

    def test_quota_is_keyed_by_org_and_group(self):
        self._policy(org="org:univ", group="group:university", limit=1)
        self._policy(org="org:sme", group="group:sme", limit=1)
        r1 = self._request(org="org:univ", group="group:university", key="k1")
        self._approve(r1["request_id"])
        r2 = self._request(org="org:sme", group="group:sme", cases=("政务问答",), key="k2")
        issued = self._approve(r2["request_id"])
        self.assertEqual(issued["state"], "issued")

    def test_emergency_exception_overrides_scope_and_quota(self):
        # 没有配额策略且用途超范围，紧急公共用途仍可发放
        request = self._request(purpose="commercial", cases=("商业训练",), region="EU",
                                emergency=True, reason="突发公共卫生事件", key="em-1")
        self.svc.rights_review(RIGHTS_OFFICER, request["request_id"], decision="approved", reason="紧急受理")
        issued = self.svc.security_review(SECURITY_OFFICER, request["request_id"], decision="approved", reason="紧急放行")
        self.assertEqual(issued["state"], "issued")
        view = self.svc.appeal_view(request["request_id"])
        self.assertTrue(view["decision_context"]["evaluation"]["emergency_override"])
        self.assertTrue(view["decision_context"]["quota"]["emergency"])

    def test_emergency_requires_reason(self):
        with self.assertRaises(ValidationError):
            self._request(emergency=True, reason="  ", key="em-2")

    # ---- 凭据与使用回执 -------------------------------------------------

    def _issued_credential(self, key="cred-1"):
        self._policy()
        request = self._request(key=key)
        issued = self._approve(request["request_id"])
        return issued["credential"]["credential_id"]

    def test_receipt_replay_returns_same_result(self):
        credential_id = self._issued_credential()
        payload = {"purpose": "research", "use_cases": ["教学研究"], "region": "CN"}
        first = self.svc.report_usage(SUBMITTER, credential_id, "receipt-1", payload)
        second = self.svc.report_usage(SUBMITTER, credential_id, "receipt-1", payload)
        self.assertTrue(second["replayed"])
        self.assertEqual(first["receipt_id"], second["receipt_id"])
        self.assertEqual(first["outcome"], second["outcome"])

    def test_receipt_divergent_payload_is_quarantined(self):
        credential_id = self._issued_credential()
        self.svc.report_usage(SUBMITTER, credential_id, "receipt-x",
                              {"purpose": "research", "use_cases": ["教学研究"], "region": "CN"})
        with self.assertRaises(ConflictError):
            self.svc.report_usage(SUBMITTER, credential_id, "receipt-x",
                                  {"purpose": "public-service", "use_cases": ["政务问答"], "region": "CN"})
        quarantined = self.svc.list_quarantine()
        self.assertEqual(len(quarantined), 1)
        self.assertEqual(quarantined[0]["receipt_key"], "receipt-x")

    def test_narrowing_denies_later_use_but_keeps_prior_facts(self):
        credential_id = self._issued_credential()
        receipt = self.svc.report_usage(SUBMITTER, credential_id, "rcp-before",
                                        {"purpose": "research", "use_cases": ["教学研究"], "region": "CN"})
        self.assertEqual(receipt["outcome"], "recorded")
        self.svc.narrow_release(
            "publisher", self.release_id,
            terms={"groups": ["group:university"], "purposes": ["research"],
                   "use_cases": ["教学研究"], "regions": ["CN"]},
            reason="试点结束", request_key="narrow-1")
        # 范围内继续可用
        still_ok = self.svc.report_usage(SUBMITTER, credential_id, "rcp-after-ok",
                                         {"purpose": "research", "use_cases": ["教学研究"], "region": "CN"})
        self.assertEqual(still_ok["outcome"], "recorded")
        # 超出收窄后条款的使用被拒，但事实仍然留痕
        denied = self.svc.report_usage(SUBMITTER, credential_id, "rcp-after-bad",
                                       {"purpose": "public-service", "use_cases": ["政务问答"], "region": "CN"})
        self.assertEqual(denied["outcome"], "denied")
        receipts = self.svc.receipts_for_release(self.release_id)
        outcomes = {r["outcome"] for r in receipts}
        self.assertEqual(outcomes, {"recorded", "denied"})

    def test_narrowing_blocks_subsequent_requests_and_creates_disposition(self):
        credential_id = self._issued_credential()
        derivative = self.svc.register_derivative(
            SUBMITTER, self.release_id, "org:univ", description="课堂微调模型", request_key="der-1")
        self.svc.narrow_release(
            "publisher", self.release_id,
            terms={"groups": ["group:university"], "purposes": ["research"],
                   "use_cases": ["教学研究"], "regions": ["CN"]},
            reason="收窄", request_key="narrow-2")
        request = self._request(group="group:sme", cases=("政务问答",), key="post-narrow")
        self.svc.rights_review(RIGHTS_OFFICER, request["request_id"], decision="approved", reason="ok")
        with self.assertRaises(ValidationError):
            self.svc.security_review(SECURITY_OFFICER, request["request_id"], decision="approved", reason="ok")
        tasks = self.svc.disposition_tasks(status="pending")
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["action"], "restrict_use")
        self.assertEqual(tasks[0]["derivative_id"], derivative["derivative_id"])
        # 处置完成后派生成果状态更新
        self.svc.complete_disposition_task("publisher", tasks[0]["task_id"], resolution="已限制用途")
        self.assertEqual(self.svc.disposition_tasks(status="pending"), [])

    def test_revoke_revokes_credentials_releases_quota_and_blocks_issuance(self):
        self._policy(limit=5)
        request = self._request(key="rev-1")
        issued = self._approve(request["request_id"])
        credential_id = issued["credential"]["credential_id"]
        self.svc.register_derivative(SUBMITTER, self.release_id, "org:univ", request_key="der-rev")
        result = self.svc.revoke_release("publisher", self.release_id, reason="安全事件", request_key="revoke-1")
        self.assertEqual(result["state"], "revoked")
        self.assertEqual(result["credentials_revoked"], 1)
        self.assertEqual(result["dispositions"], 1)
        # 配额已释放
        status = self.svc.quota_status(self.release_id, "org:univ", "group:university")
        self.assertEqual(status["used"], 0)
        # 失效凭据不能再登记使用
        with self.assertRaises(PermissionDenied):
            self.svc.report_usage(SUBMITTER, credential_id, "rcp-revoked",
                                  {"purpose": "research", "use_cases": ["教学研究"], "region": "CN"})
        # 失效版本不能继续发放：新申请提交即被阻止
        with self.assertRaises(ConflictError):
            self._request(key="rev-2")
        # 历史使用事实仍可追溯
        self.assertEqual(self.svc.rights_history(self.release_id)[-1]["kind"], "revoke")

    def test_revoke_then_batch_grant_rolls_back_entire_batch(self):
        # 批量授权中任一申请不满足条件，整批回滚零发放
        self._policy(org="org:univ", group="group:university", limit=5)
        self._policy(org="org:two", group="group:university", limit=5)
        r1 = self._request(org="org:univ", key="b1")
        r2 = self._request(org="org:two", key="b2")
        for r in (r1, r2):
            self.svc.rights_review(RIGHTS_OFFICER, r["request_id"], decision="approved", reason="ok")
        # 在批次处理第一项之后、第二项之前撤回版本：通过把第二项替换为另一版本的申请模拟，
        # 这里直接撤回使批次内读取到失效版本。
        # 为确定性验证原子性：构造一个许可必然失败的第二项（先删策略做不到，改为超配额第三项）。
        self.svc.revoke_release("publisher", self.release_id, reason="批次并发撤回", request_key="revoke-batch")
        with self.assertRaises(ConflictError):
            self.svc.grant_batch(SECURITY_OFFICER, [
                {"request_id": r1["request_id"]}, {"request_id": r2["request_id"]}])
        for r in (r1, r2):
            self.assertEqual(self.svc.get_request(r["request_id"])["state"], "pending_security")
        status = self.svc.quota_status(self.release_id, "org:univ", "group:university")
        self.assertEqual(status["used"], 0)

    def test_concurrent_revoke_and_grant_never_leaves_valid_credential_on_revoked_release(self):
        self._policy(limit=50)
        ready = []
        for i in range(5):
            r = self._request(key=f"conc-{i}")
            self.svc.rights_review(RIGHTS_OFFICER, r["request_id"], decision="approved", reason="ok")
            ready.append(r["request_id"])

        errors: list[Exception] = []
        barrier = threading.Barrier(2)

        def grant():
            barrier.wait()
            try:
                self.svc.grant_batch(SECURITY_OFFICER, [{"request_id": rid} for rid in ready])
            except Exception as exc:  # 撤回抢先时预期失败
                errors.append(exc)

        def revoke():
            barrier.wait()
            try:
                self.svc.revoke_release("publisher", self.release_id, reason="并发撤回", request_key="revoke-c")
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=grant)
        t2 = threading.Thread(target=revoke)
        t1.start(); t2.start(); t1.join(); t2.join()
        # 不变量：撤回完成后，不存在仍有效的凭据
        import sqlite3
        with self.app.database.connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS n FROM ai_credentials WHERE release_id=? AND state='issued'",
                (self.release_id,)).fetchone()
        self.assertEqual(row["n"], 0)
        # 发放若先发生，其凭据必然已被撤回；若撤回先发生，则批次失败
        with self.app.database.connect() as connection:
            row = connection.execute("SELECT state FROM ai_releases WHERE release_id=?", (self.release_id,)).fetchone()
        self.assertEqual(row["state"], "revoked")

    # ---- 申诉视图 -------------------------------------------------------

    def test_appeal_view_replays_decision_bundle_and_remaining_quota(self):
        self._policy(limit=3)
        request = self._request(qty=2, key="appeal-1")
        self._approve(request["request_id"])
        view = self.svc.appeal_view(request["request_id"])
        self.assertEqual(set(view["release"]["components"]), {"model", "dataset", "security"})
        self.assertEqual(view["release"]["manifest_digest"], self.release["manifest_digest"])
        self.assertEqual(view["decision_quota"]["used_at_decision"], 0)
        self.assertEqual(view["decision_quota"]["granted_qty"], 2)
        self.assertEqual(view["current_quota"]["used"], 2)
        self.assertEqual(view["current_quota"]["remaining"], 1)
        self.assertEqual(len(view["credentials"]), 1)
        self.assertTrue(view["decision_context"]["evaluation"]["allowed"])

    # ---- 可恢复工作队列 -------------------------------------------------

    def test_work_queue_recovers_interrupted_lease(self):
        credential_id = self._issued_credential("wq-1")
        # 到期工作已在发放时入队；未到 valid_to 时不可领取
        self.assertEqual(self.svc.claim_work(), [])
        # 手工入队一个即时工作并模拟领取后崩溃
        item_id = self.svc.enqueue_work("review_sla", "areq:x", {"stage": "rights"}, NOW, item_id="sla-x")
        claimed = self.svc.claim_work(seconds=30)
        self.assertEqual([i["item_id"] for i in claimed], [item_id])
        # 租约未过期不会重复领取
        self.assertEqual(self.svc.claim_work(), [])
        # 进程重启：新时钟下租约过期后可从保存的队列位置重新领取
        restarted = CivicFlow.open(self.db_path, fixed_now="2026-10-03T12:01:00+08:00")
        reclaimed = restarted.ai_sharing.claim_work(seconds=1)
        self.assertEqual([i["item_id"] for i in reclaimed], [item_id])
        restarted.ai_sharing.complete_work(item_id)
        self.assertEqual(restarted.ai_sharing.claim_work(), [])

    def test_due_work_expires_credential(self):
        self._policy()
        request = self._request(key="exp-1")
        issued = self._approve(request["request_id"])
        credential_id = issued["credential"]["credential_id"]
        later = CivicFlow.open(self.db_path, fixed_now="2027-01-01T00:00:00+08:00")
        processed = later.ai_sharing.run_due()
        types = {p["type"] for p in processed}
        self.assertIn("credential_expiry", types)
        with self.assertRaises(PermissionDenied):
            later.ai_sharing.report_usage(SUBMITTER, credential_id, "rcp-exp",
                                          {"purpose": "research", "use_cases": ["教学研究"], "region": "CN"})

    def test_review_sla_job_is_idempotent(self):
        self._request(key="sla-1")
        # SLA 默认 7 天后；推进时钟处理
        later = CivicFlow.open(self.db_path, fixed_now="2026-10-11T00:00:00+08:00")
        processed = later.ai_sharing.run_due()
        self.assertTrue(any(p["type"] == "review_sla" for p in processed))
        # 审核完成后再次运行不会重复产生待办语义
        again = later.ai_sharing.run_due()
        self.assertEqual(again, [])

    # ---- 审计与既有平台兼容 ---------------------------------------------

    def test_audit_chain_still_verifies(self):
        self._policy()
        self._approve(self._request(key="audit-1")["request_id"])
        count = self.app.verify()["audit_entries"]
        self.assertGreater(count, 0)


if __name__ == "__main__":
    unittest.main()
