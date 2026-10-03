from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from civicflow.application import CivicFlow
from civicflow.errors import ConflictError, PermissionDenied, ValidationError
from civicflow.security import AccessContext


class AISharingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / "test.sqlite3"
        self.app = CivicFlow.open(self.db_path, fixed_now="2026-10-03T12:00:00+08:00")
        self.system = AccessContext.system("tester")
        self.rights_reviewer = AccessContext.system("rights-reviewer")
        self.security_reviewer = AccessContext.system("security-reviewer")
        self._keys = 0

    def tearDown(self):
        self.temp.cleanup()

    def _key(self, label):
        self._keys += 1
        return f"{label}-{self._keys}"

    def reopen(self, fixed_now):
        self.app = CivicFlow.open(self.db_path, fixed_now=fixed_now)

    def make_assets(self):
        achievements = self.app.achievements()
        refs = {}
        for label, asset_type in (("model", "model"), ("dataset", "dataset"), ("safety", "safety_note")):
            asset = achievements.create(self.system, {"asset_type": asset_type, "title": label, "owner_org": "org:soe", "summary": label}, request_key=self._key(label))
            achievements.transition(self.system, asset["entity_id"], "active", expected_version=1, reason="上架", request_key=self._key("activate"))
            refs[label] = asset["entity_id"]
        return refs

    def make_version(self, *, refs=None, publish=True, groups=("researchers", "students"), purposes=("research", "education"), regions=("cn-east",), per_org=5, per_group=8, period="monthly", dependencies=()):
        refs = refs or self.make_assets()
        versions = self.app.achievement_versions()
        version = versions.create(self.system, {
            "asset_id": refs["model"],
            "version_label": "v1",
            "combination": {"model_ref": refs["model"], "dataset_refs": [refs["dataset"]], "safety_ref": refs["safety"], "tool_refs": []},
            "dependencies": list(dependencies),
            "rights": {"source": "国资委授权-2026-001", "license_class": "fair-access", "regions": list(regions), "purposes": list(purposes), "denied_purposes": [], "eligible_groups": list(groups)},
            "quota": {"period": period, "per_org": per_org, "per_group": per_group},
            "summary": "开放版本",
        }, request_key=self._key("version"))
        if not publish:
            return version
        return versions.publish(self.system, version["entity_id"], expected_version=1, request_key=self._key("publish"))

    def make_request(self, version_id, *, org="org:univ-1", group="researchers", purpose="research", region="cn-east", quantity=2, emergency=False, justification="", deadline="2026-10-10T00:00:00Z", submitter=None):
        return self.app.access_requests().submit(submitter or self.system, {"org_id": org, "org_type": "university", "beneficiary_group": group, "asset_version_id": version_id, "purpose": purpose, "region": region, "quantity": quantity, "emergency": emergency, "justification": justification, "review_deadline": deadline}, request_key=self._key("request"))

    def clear_request(self, request):
        requests = self.app.access_requests()
        requests.rights_review(self.rights_reviewer, request["entity_id"], approve=True, expected_version=1, reason="权益符合", request_key=self._key("rights"))
        return requests.security_review(self.security_reviewer, request["entity_id"], approve=True, expected_version=2, reason="安全通过", request_key=self._key("security"))

    def make_cleared_request(self, version_id, **kwargs):
        return self.clear_request(self.make_request(version_id, **kwargs))

    # ---- 目录与版本 ----

    def test_publish_freezes_combination(self):
        versions = self.app.achievement_versions()
        published = self.make_version()
        self.assertEqual(published["state"], "published")
        self.assertTrue(published["combination_digest"])
        frozen = {"model_ref": published["asset_id"], "dataset_refs": [], "safety_ref": "ai_assets:other", "tool_refs": []}
        with self.assertRaises(ValidationError):
            versions.revise(self.system, published["entity_id"], {"combination": frozen}, expected_version=2, request_key=self._key("revise"))
        with self.assertRaises(ValidationError):
            versions.revise(self.system, published["entity_id"], {"rights": published["rights"]}, expected_version=2, request_key=self._key("revise"))
        updated = versions.revise(self.system, published["entity_id"], {"summary": "补充说明"}, expected_version=2, request_key=self._key("revise"))
        self.assertEqual(updated["summary"], "补充说明")
        with self.assertRaises(ConflictError):
            versions.publish(self.system, published["entity_id"], expected_version=3, request_key=self._key("publish"))

    def test_publish_requires_active_refs(self):
        achievements = self.app.achievements()
        versions = self.app.achievement_versions()
        model = achievements.create(self.system, {"asset_type": "model", "title": "m", "owner_org": "org:soe", "summary": "m"}, request_key=self._key("model"))
        refs = self.make_assets()
        version = self.make_version(refs={**refs, "model": model["entity_id"]}, publish=False)
        with self.assertRaises(ValidationError):
            versions.publish(self.system, version["entity_id"], expected_version=1, request_key=self._key("publish"))

    def test_publish_requires_published_dependencies(self):
        versions = self.app.achievement_versions()
        draft = self.make_version(publish=False)
        dependent = self.make_version(dependencies=[draft["entity_id"]], publish=False)
        with self.assertRaises(ValidationError):
            versions.publish(self.system, dependent["entity_id"], expected_version=1, request_key=self._key("publish"))

    # ---- 授权原子性与配额 ----

    def test_grant_atomic_and_explain(self):
        version = self.make_version()
        request = self.make_cleared_request(version["entity_id"], quantity=2)
        grants = self.app.grants()
        result = grants.grant(self.system, request["entity_id"], request_key=self._key("grant"))
        credential = grants.credential(self.system, result["credential_id"])
        self.assertEqual(credential["status"], "active")
        self.assertEqual(result["expires_at"], "2026-11-01T00:00:00Z")
        self.assertEqual(result["decision"]["period_key"], "2026-10")
        self.assertEqual(result["decision"]["org_remaining"], 3)
        self.assertEqual(result["decision"]["group_remaining"], 6)
        self.assertEqual(result["decision"]["combination_digest"], version["combination_digest"])
        self.assertEqual(self.app.access_requests().get(self.system, request["entity_id"])["state"], "granted")
        with self.app.database.connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) AS n FROM quota_ledger").fetchone()["n"], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) AS n FROM license_decisions").fetchone()["n"], 1)
        self.assertGreaterEqual(self.app.verify()["audit_entries"], 1)
        explanation = grants.explain(self.system, request["entity_id"])
        self.assertEqual(explanation["combination_digest"], version["combination_digest"])
        self.assertTrue(all(explanation["judgment"].values()))
        self.assertEqual(explanation["org_remaining"], 3)
        self.assertEqual(explanation["group_remaining"], 6)
        self.assertEqual(explanation["decision"]["credential_id"], credential["credential_id"])

    def test_grant_failure_leaves_no_partial_state(self):
        version = self.make_version(per_org=1, per_group=1)
        request = self.make_cleared_request(version["entity_id"], quantity=5)
        with self.assertRaises(ConflictError):
            self.app.grants().grant(self.system, request["entity_id"], request_key=self._key("grant"))
        with self.app.database.connect() as connection:
            for table in ("quota_ledger", "access_credentials", "license_decisions"):
                self.assertEqual(connection.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"], 0)
        self.assertEqual(self.app.access_requests().get(self.system, request["entity_id"])["state"], "security_cleared")
        self.app.verify()

    def test_quota_per_org_and_group(self):
        version = self.make_version(per_org=3, per_group=5)
        grants = self.app.grants()
        first = self.make_cleared_request(version["entity_id"], org="org:a", quantity=3)
        grants.grant(self.system, first["entity_id"], request_key=self._key("grant"))
        second = self.make_cleared_request(version["entity_id"], org="org:a", quantity=1)
        with self.assertRaisesRegex(ConflictError, "机构周期配额不足"):
            grants.grant(self.system, second["entity_id"], request_key=self._key("grant"))
        third = self.make_cleared_request(version["entity_id"], org="org:b", quantity=2)
        grants.grant(self.system, third["entity_id"], request_key=self._key("grant"))
        fourth = self.make_cleared_request(version["entity_id"], org="org:c", quantity=1)
        with self.assertRaisesRegex(ConflictError, "受益群体周期配额不足"):
            grants.grant(self.system, fourth["entity_id"], request_key=self._key("grant"))

    def test_quarterly_quota_period(self):
        version = self.make_version(period="quarterly")
        request = self.make_cleared_request(version["entity_id"], quantity=1)
        result = self.app.grants().grant(self.system, request["entity_id"], request_key=self._key("grant"))
        self.assertEqual(result["decision"]["period_key"], "2026-Q4")
        self.assertEqual(result["expires_at"], "2027-01-01T00:00:00Z")

    def test_grant_replay_returns_same_credential(self):
        version = self.make_version()
        request = self.make_cleared_request(version["entity_id"], quantity=1)
        grants = self.app.grants()
        key = self._key("grant")
        first = grants.grant(self.system, request["entity_id"], request_key=key)
        second = grants.grant(self.system, request["entity_id"], request_key=key)
        self.assertEqual(first["credential_id"], second["credential_id"])
        with self.assertRaises(ConflictError):
            grants.grant(self.system, request["entity_id"], request_key=self._key("grant"))
        with self.app.database.connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) AS n FROM access_credentials").fetchone()["n"], 1)

    # ---- 许可判断与例外 ----

    def test_rights_denied_without_exception(self):
        version = self.make_version()
        grants = self.app.grants()
        for overrides in ({"purpose": "advertising"}, {"group": "citizens"}, {"region": "cn-north"}):
            request = self.make_cleared_request(version["entity_id"], **overrides)
            with self.assertRaises(PermissionDenied):
                grants.grant(self.system, request["entity_id"], request_key=self._key("grant"))

    def test_review_roles_must_be_distinct(self):
        version = self.make_version()
        requests = self.app.access_requests()
        submitter = AccessContext.system("applicant")
        request = self.make_request(version["entity_id"], submitter=submitter)
        with self.assertRaises(PermissionDenied):
            requests.rights_review(submitter, request["entity_id"], approve=True, expected_version=1, reason="自审", request_key=self._key("rights"))
        requests.rights_review(self.rights_reviewer, request["entity_id"], approve=True, expected_version=1, reason="通过", request_key=self._key("rights"))
        with self.assertRaises(PermissionDenied):
            requests.security_review(submitter, request["entity_id"], approve=True, expected_version=2, reason="自审", request_key=self._key("security"))
        with self.assertRaises(PermissionDenied):
            requests.security_review(self.rights_reviewer, request["entity_id"], approve=True, expected_version=2, reason="代批", request_key=self._key("security"))
        cleared = requests.security_review(self.security_reviewer, request["entity_id"], approve=True, expected_version=2, reason="通过", request_key=self._key("security"))
        self.assertEqual(cleared["state"], "security_cleared")

    def test_emergency_exception_still_requires_three_roles(self):
        version = self.make_version(per_org=1, per_group=1)
        requests = self.app.access_requests()
        submitter = AccessContext.system("applicant")
        request = self.make_request(version["entity_id"], purpose="disaster-response", quantity=5, emergency=True, justification="突发公共事件应急", submitter=submitter)
        with self.assertRaises(PermissionDenied):
            requests.rights_review(submitter, request["entity_id"], approve=True, expected_version=1, reason="自审", request_key=self._key("rights"))
        requests.rights_review(self.rights_reviewer, request["entity_id"], approve=True, expected_version=1, reason="紧急用途属实", request_key=self._key("rights"))
        with self.assertRaises(PermissionDenied):
            requests.security_review(self.rights_reviewer, request["entity_id"], approve=True, expected_version=2, reason="代批", request_key=self._key("security"))
        requests.security_review(self.security_reviewer, request["entity_id"], approve=True, expected_version=2, reason="安全可控", request_key=self._key("security"))
        result = self.app.grants().grant(self.system, request["entity_id"], request_key=self._key("grant"))
        self.assertTrue(result["decision"]["exception"])
        self.assertEqual(result["decision"]["org_remaining"], 1 - 5)

    def test_emergency_requires_justification(self):
        version = self.make_version()
        with self.assertRaises(ValidationError):
            self.make_request(version["entity_id"], emergency=True, justification="")

    def test_rejected_request_cannot_be_granted(self):
        version = self.make_version()
        requests = self.app.access_requests()
        request = self.make_request(version["entity_id"])
        requests.rights_review(self.rights_reviewer, request["entity_id"], approve=False, expected_version=1, reason="不符合公平可及", request_key=self._key("rights"))
        with self.assertRaises(ConflictError):
            self.app.grants().grant(self.system, request["entity_id"], request_key=self._key("grant"))

    # ---- 回执 ----

    def test_receipt_replay_and_quarantine(self):
        version = self.make_version(per_org=10, per_group=10)
        request = self.make_cleared_request(version["entity_id"], quantity=4)
        grants = self.app.grants()
        credential_id = grants.grant(self.system, request["entity_id"], request_key=self._key("grant"))["credential_id"]
        first = grants.record_receipt(self.system, credential_id, "receipt-1", {"amount": 3, "note": "训练任务"})
        self.assertEqual(first["remaining"], 1)
        replay = grants.record_receipt(self.system, credential_id, "receipt-1", {"amount": 3, "note": "训练任务"})
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["used_quantity"], 3)
        with self.assertRaises(ConflictError):
            grants.record_receipt(self.system, credential_id, "receipt-1", {"amount": 2, "note": "异文"})
        self.assertEqual(len(grants.quarantined(self.system)), 1)
        self.assertEqual(grants.credential(self.system, credential_id)["used_quantity"], 3)
        with self.assertRaises(ConflictError):
            grants.record_receipt(self.system, credential_id, "receipt-2", {"amount": 2})
        final = grants.record_receipt(self.system, credential_id, "receipt-3", {"amount": 1})
        self.assertEqual(final["status"], "exhausted")
        self.assertEqual(len(grants.receipts_for(self.system, credential_id)), 2)
        self.app.verify()

    # ---- 权利收窄与撤回 ----

    def test_narrow_rights_future_only_and_disposition(self):
        versions = self.app.achievement_versions()
        version = self.make_version()
        grants = self.app.grants()
        request = self.make_cleared_request(version["entity_id"], group="researchers", purpose="research", quantity=2)
        credential_id = grants.grant(self.system, request["entity_id"], request_key=self._key("grant"))["credential_id"]
        grants.record_receipt(self.system, credential_id, "receipt-1", {"amount": 1})
        narrowed = versions.narrow_rights(self.system, version["entity_id"], rights={"source": "国资委授权-2026-002", "license_class": "fair-access", "regions": ["cn-east"], "purposes": ["education"], "denied_purposes": [], "eligible_groups": ["students"]}, expected_version=2, reason="权利方收窄授权范围", request_key=self._key("narrow"))
        self.assertEqual(len(narrowed["disposition_tasks"]), 1)
        self.assertEqual(narrowed["rights_generation"], 2)
        receipt = grants.record_receipt(self.system, credential_id, "receipt-2", {"amount": 1})
        self.assertEqual(receipt["used_quantity"], 2)
        blocked = self.make_cleared_request(version["entity_id"], group="researchers", purpose="research")
        with self.assertRaises(PermissionDenied):
            grants.grant(self.system, blocked["entity_id"], request_key=self._key("grant"))
        allowed = self.make_cleared_request(version["entity_id"], group="students", purpose="education", quantity=1)
        grants.grant(self.system, allowed["entity_id"], request_key=self._key("grant"))
        task = grants.dispositions(self.system, status="pending")[0]
        grants.complete_disposition(self.system, task["task_id"], resolution="revoked", request_key=self._key("dispose"))
        self.assertEqual(grants.credential(self.system, credential_id)["status"], "revoked")
        with self.assertRaises(ConflictError):
            grants.record_receipt(self.system, credential_id, "receipt-3", {"amount": 1})
        self.assertEqual(len(grants.receipts_for(self.system, credential_id)), 2)
        self.assertEqual(len(versions.history(self.system, version["entity_id"])), 3)
        self.app.verify()

    def test_narrowing_rejects_expansion(self):
        versions = self.app.achievement_versions()
        version = self.make_version()
        expanded = {"source": "国资委授权-2026-002", "license_class": "fair-access", "regions": ["cn-east"], "purposes": ["research", "education", "commercial"], "denied_purposes": [], "eligible_groups": ["researchers", "students"]}
        with self.assertRaises(ValidationError):
            versions.narrow_rights(self.system, version["entity_id"], rights=expanded, expected_version=2, reason="越权扩权", request_key=self._key("narrow"))
        with self.assertRaises(ValidationError):
            versions.narrow_rights(self.system, version["entity_id"], quota={"period": "monthly", "per_org": 10, "per_group": 20}, expected_version=2, reason="调高配额", request_key=self._key("narrow"))

    def test_narrow_quota_affects_future_grants(self):
        versions = self.app.achievement_versions()
        version = self.make_version(per_org=5, per_group=8)
        versions.narrow_rights(self.system, version["entity_id"], quota={"period": "monthly", "per_org": 1, "per_group": 2}, expected_version=2, reason="压缩配额", request_key=self._key("narrow"))
        grants = self.app.grants()
        first = self.make_cleared_request(version["entity_id"], org="org:a", quantity=1)
        grants.grant(self.system, first["entity_id"], request_key=self._key("grant"))
        second = self.make_cleared_request(version["entity_id"], org="org:a", quantity=1)
        with self.assertRaisesRegex(ConflictError, "机构周期配额不足"):
            grants.grant(self.system, second["entity_id"], request_key=self._key("grant"))

    def test_dependency_narrowing_creates_tasks_for_derived(self):
        versions = self.app.achievement_versions()
        base = self.make_version()
        derived = self.make_version(dependencies=[base["entity_id"]])
        grants = self.app.grants()
        request = self.make_cleared_request(derived["entity_id"], quantity=1)
        credential_id = grants.grant(self.system, request["entity_id"], request_key=self._key("grant"))["credential_id"]
        narrowed = versions.narrow_rights(self.system, base["entity_id"], rights={"source": "国资委授权-2026-002", "license_class": "fair-access", "regions": ["cn-east"], "purposes": ["education"], "denied_purposes": [], "eligible_groups": ["students"]}, expected_version=2, reason="基础模型权利收窄", request_key=self._key("narrow"))
        self.assertEqual(len(narrowed["disposition_tasks"]), 1)
        task = grants.dispositions(self.system, status="pending")[0]
        self.assertEqual(task["credential_id"], credential_id)
        self.assertEqual(task["asset_version_id"], derived["entity_id"])
        self.assertEqual(task["kind"], "dependency")

    def test_withdraw_blocks_batch_grant(self):
        versions = self.app.achievement_versions()
        version = self.make_version(per_org=10, per_group=30)
        grants = self.app.grants()
        ids = [self.make_cleared_request(version["entity_id"], org=f"org:u{i}", quantity=1)["entity_id"] for i in range(3)]
        batch = grants.schedule_batch_grant(self.system, ids)
        first = grants.process_batch_grant(self.system, batch, page=1)
        self.assertEqual(first["processed"][0]["status"], "granted")
        self.assertFalse(first["done"])
        versions.withdraw(self.system, version["entity_id"], expected_version=2, reason="许可方撤回", request_key=self._key("withdraw"))
        rest = grants.process_batch_grant(self.system, batch, page=5)
        self.assertTrue(rest["done"])
        self.assertEqual([item["status"] for item in rest["processed"]], ["failed", "failed"])
        self.assertIn("撤回", rest["processed"][0]["error"])
        status = grants.batch_status(self.system, batch)
        self.assertEqual(status["position"], 3)
        self.assertEqual(len(status["items"]), 3)
        self.assertEqual(len(grants.dispositions(self.system, status="pending")), 1)
        with self.assertRaises(ConflictError):
            grants.grant(self.system, ids[1], request_key=self._key("grant"))
        self.app.verify()

    def test_concurrent_batch_and_withdraw_stay_consistent(self):
        versions = self.app.achievement_versions()
        version = self.make_version(per_org=100, per_group=100)
        grants = self.app.grants()
        ids = [self.make_cleared_request(version["entity_id"], org=f"org:t{i}", quantity=1)["entity_id"] for i in range(6)]
        batch = grants.schedule_batch_grant(self.system, ids)
        errors = []

        def worker():
            try:
                self.app.grants().process_batch_grant(self.system, batch, page=6)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        thread = threading.Thread(target=worker)
        thread.start()
        versions.withdraw(self.system, version["entity_id"], expected_version=2, reason="并发撤回", request_key=self._key("withdraw"))
        thread.join(timeout=30)
        self.assertFalse(errors)
        status = grants.batch_status(self.system, batch)
        self.assertEqual(status["position"], 6)
        self.assertEqual(len(status["items"]), 6)
        granted = [item for item in status["items"] if item["status"] == "granted"]
        failed = [item for item in status["items"] if item["status"] == "failed"]
        for item in failed:
            self.assertIn("撤回", item["detail"]["error"])
        self.assertEqual(len(grants.dispositions(self.system, status="pending")), len(granted))
        with self.app.database.connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) AS n FROM access_credentials").fetchone()["n"], len(granted))
        self.app.verify()

    # ---- 时点再现 ----

    def test_explain_shows_as_of_state_after_narrow(self):
        versions = self.app.achievement_versions()
        version = self.make_version()
        grants = self.app.grants()
        request = self.make_cleared_request(version["entity_id"], purpose="research", group="researchers", quantity=2)
        grants.grant(self.system, request["entity_id"], request_key=self._key("grant"))
        versions.narrow_rights(self.system, version["entity_id"], rights={"source": "国资委授权-2026-002", "license_class": "fair-access", "regions": ["cn-east"], "purposes": ["education"], "denied_purposes": [], "eligible_groups": ["students"]}, expected_version=2, reason="收窄", request_key=self._key("narrow"))
        explanation = grants.explain(self.system, request["entity_id"])
        self.assertTrue(explanation["judgment"]["purpose_allowed"])
        self.assertTrue(explanation["judgment"]["group_eligible"])
        self.assertEqual(explanation["org_remaining"], 3)
        self.assertEqual(explanation["version_revision"], 2)
        current = grants.explain(self.system, request["entity_id"], as_of="2026-10-04T00:00:00Z")
        self.assertFalse(current["judgment"]["purpose_allowed"])
        self.assertFalse(current["judgment"]["group_eligible"])
        self.assertEqual(current["version_revision"], 3)

    def test_explain_for_appeal_without_decision(self):
        version = self.make_version(per_org=5, per_group=5)
        request = self.make_cleared_request(version["entity_id"], quantity=7)
        grants = self.app.grants()
        with self.assertRaises(ConflictError):
            grants.grant(self.system, request["entity_id"], request_key=self._key("grant"))
        explanation = grants.explain(self.system, request["entity_id"])
        self.assertIsNone(explanation["decision"])
        self.assertEqual(explanation["request_state"], "security_cleared")
        self.assertEqual(explanation["org_remaining"], 5)
        self.assertTrue(all(explanation["judgment"].values()))

    # ---- 可恢复扫描与任务队列 ----

    def test_credential_expiry_sweep_resumes_from_cursor(self):
        version = self.make_version(per_org=10, per_group=10)
        grants = self.app.grants()
        ids = []
        for i in range(2):
            request = self.make_cleared_request(version["entity_id"], org=f"org:u{i}", quantity=1)
            ids.append(grants.grant(self.system, request["entity_id"], request_key=self._key("grant"))["credential_id"])
        self.reopen("2026-11-02T00:00:00Z")
        grants = self.app.grants()
        first = grants.run_sweep(self.system, "credential_expiry", page=1)
        self.assertEqual(first["processed"], 1)
        self.assertFalse(first["completed"])
        second = grants.run_sweep(self.system, "credential_expiry", page=5)
        self.assertEqual(second["processed"], 1)
        self.assertTrue(second["completed"])
        for credential_id in ids:
            self.assertEqual(grants.credential(self.system, credential_id)["status"], "expired")
        with self.assertRaises(ConflictError):
            grants.record_receipt(self.system, ids[0], "receipt-late", {"amount": 1})
        self.assertEqual(grants.run_sweep(self.system, "credential_expiry")["processed"], 0)

    def test_request_deadline_sweep_expires_pending_review(self):
        version = self.make_version()
        request = self.make_request(version["entity_id"], deadline="2026-10-05T00:00:00Z")
        self.reopen("2026-10-06T00:00:00Z")
        result = self.app.grants().run_sweep(self.system, "request_deadline", page=5)
        self.assertEqual(result["processed"], 1)
        self.assertTrue(result["completed"])
        self.assertEqual(self.app.access_requests().get(self.system, request["entity_id"])["state"], "expired")

    def test_withdrawal_fanout_sweep_backstops(self):
        versions = self.app.achievement_versions()
        version = self.make_version()
        grants = self.app.grants()
        request = self.make_cleared_request(version["entity_id"], quantity=1)
        grants.grant(self.system, request["entity_id"], request_key=self._key("grant"))
        versions.withdraw(self.system, version["entity_id"], expected_version=2, reason="许可撤回", request_key=self._key("withdraw"))
        self.assertEqual(len(grants.dispositions(self.system, status="pending")), 1)
        with self.app.database.transaction() as connection:
            connection.execute("DELETE FROM disposition_tasks")
        result = grants.run_sweep(self.system, "withdrawal_fanout", page=5)
        self.assertEqual(result["processed"], 1)
        self.assertTrue(result["completed"])
        self.assertEqual(len(grants.dispositions(self.system, status="pending")), 1)

    def test_scheduled_jobs_drive_batch_and_sweeps(self):
        version = self.make_version(per_org=10, per_group=30)
        grants = self.app.grants()
        ids = [self.make_cleared_request(version["entity_id"], org=f"org:j{i}", quantity=1)["entity_id"] for i in range(3)]
        batch = grants.schedule_batch_grant(self.system, ids)
        grants.schedule_sweep(self.system, "credential_expiry")
        outcomes = grants.run_due_jobs(self.system)
        self.assertEqual(len(outcomes), 2)
        self.assertTrue(all(outcome["status"] == "finished" for outcome in outcomes))
        status = grants.batch_status(self.system, batch)
        self.assertEqual(status["position"], 3)
        self.assertTrue(all(item["status"] == "granted" for item in status["items"]))
        self.reopen("2026-11-02T00:00:00Z")
        grants = self.app.grants()
        grants.schedule_sweep(self.system, "credential_expiry")
        outcomes = grants.run_due_jobs(self.system)
        self.assertEqual(outcomes[0]["status"], "finished")
        for item in status["items"]:
            credential_id = item["detail"]["credential_id"]
            self.assertEqual(grants.credential(self.system, credential_id)["status"], "expired")


if __name__ == "__main__":
    unittest.main()
