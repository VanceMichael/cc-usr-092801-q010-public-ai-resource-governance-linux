"""人工智能成果开放共享治理。

覆盖成果目录与冻结发布、权利来源与收窄/撤回、适用人群与用途/区域限制、
按机构与受益群体的周期配额、三角色分离的申请审批、访问凭据签发、
使用回执幂等与异文隔离、派生成果处置任务，以及可中断接续的工作队列。

所有写操作都在单个 SQLite 即时事务内完成：配额占用、凭据签发、权利校验、
工作入队和审计分录要么全部生效，要么全部回滚。
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Callable, Iterable, Mapping, TypeVar
import json
import sqlite3

from .audit import AuditLog
from .database import Database
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .identifiers import new_id, require_safe
from .idempotency import IdempotencyStore
from .jsonutil import canonical_json, digest_json
from .timeutil import Clock, canonical_instant, parse_instant

T = TypeVar("T")

ARTIFACT_KINDS = ("model", "dataset", "compute")
COMPONENT_KINDS = ("model", "dataset", "security")
RIGHTS_GRANT = "grant"
RIGHTS_NARROW = "narrow"
RIGHTS_REVOKE = "revoke"
GRANT_BIT = 1
PERIOD_KINDS = ("monthly",)

REQUEST_STATES = (
    "pending_rights", "rights_rejected", "pending_security",
    "security_rejected", "issued",
)

# 申请提交后的权益审核时限，超时由工作队列提醒。
DEFAULT_REVIEW_SLA_HOURS = 24 * 7
MAX_WORK_ATTEMPTS = 5


@dataclass(frozen=True)
class AISharingService:
    """人工智能成果授权与公平可及领域服务。"""

    database: Database
    clock: Clock
    audit: AuditLog
    idempotency: IdempotencyStore

    # ---- 成果目录与发布 -------------------------------------------------

    def register_artifact(self, actor: str, *, kind: str, name: str, summary: str = "", request_key: str) -> dict:
        require_safe(actor, "操作者")
        if kind not in ARTIFACT_KINDS:
            raise ValidationError("成果类型必须是 model、dataset 或 compute")
        name = _require_text(name, "成果名称")
        body = {"kind": kind, "name": name, "summary": summary.strip()}
        with self.database.transaction() as connection:
            def operation() -> dict:
                artifact_id = new_id("artifact"); now = self.clock.now()
                connection.execute(
                    "INSERT INTO ai_catalog(artifact_id,kind,name,state,payload_json,version,created_at,updated_at,created_by,updated_by) VALUES(?,?,?,?,?,1,?,?,?,?)",
                    (artifact_id, kind, name, "active", canonical_json(body), now, now, actor, actor))
                self._audit(connection, actor, "ai.artifact.register", "ai_catalog", artifact_id, 1, body)
                return {"artifact_id": artifact_id, **body, "state": "active", "version": 1}
            return self._idem(connection, "ai.artifact.register", request_key, body, operation)

    def publish_release(self, actor: str, artifact_id: str, version_tag: str, *,
                        components: Mapping[str, Mapping[str, str]], rights: Mapping[str, object],
                        request_key: str) -> dict:
        """冻结模型、数据集与安全说明的组合，并记录初始权利来源。"""
        require_safe(actor, "操作者"); require_safe(artifact_id, "成果标识")
        version_tag = _require_text(version_tag, "版本号")
        frozen = _freeze_components(components)
        terms = _normalize_terms(rights)
        with self.database.transaction() as connection:
            def operation() -> dict:
                artifact = self._locked_artifact(connection, artifact_id)
                duplicate = connection.execute(
                    "SELECT 1 FROM ai_releases WHERE artifact_id=? AND version_tag=?", (artifact_id, version_tag)).fetchone()
                if duplicate:
                    raise ConflictError("同一成果的版本号已经存在")
                release_id = new_id("release"); now = self.clock.now()
                manifest_digest = digest_json({
                    "artifact_id": artifact_id, "version_tag": version_tag,
                    "components": frozen, "rights": terms})
                connection.execute(
                    "INSERT INTO ai_releases(release_id,artifact_id,version_tag,components_json,manifest_digest,state,rights_position,published_at,published_by) VALUES(?,?,?,?,?,'published',?,?,?)",
                    (release_id, artifact_id, version_tag, canonical_json(frozen), manifest_digest, GRANT_BIT, now, actor))
                connection.execute(
                    "INSERT INTO ai_rights_events(release_id,kind,source,terms_json,reason,effective_at,actor_id,prior_event_id) VALUES(?,?,?,?,?,?,?,0)",
                    (release_id, RIGHTS_GRANT, "publisher", canonical_json(terms), "首次发布授权", now, actor))
                event_id = connection.execute("SELECT last_insert_rowid()").fetchone()[0]
                payload = json.loads(artifact["payload_json"])
                connection.execute(
                    "UPDATE ai_catalog SET version=version+1,updated_at=?,updated_by=? WHERE artifact_id=?", (now, actor, artifact_id))
                self._audit(connection, actor, "ai.release.publish", "ai_releases", release_id, 1,
                            {"artifact_id": artifact_id, "version_tag": version_tag, "manifest_digest": manifest_digest,
                             "components": frozen, "terms": terms, "rights_event_id": event_id})
                return self._release_dict(connection.execute("SELECT * FROM ai_releases WHERE release_id=?", (release_id,)).fetchone())
            return self._idem(connection, f"ai.release.publish:{artifact_id}", request_key,
                             {"version_tag": version_tag, "components": frozen, "rights": terms}, operation)

    def narrow_release(self, actor: str, release_id: str, *, terms: Mapping[str, object], reason: str, request_key: str) -> dict:
        """权利收窄：只影响后续访问，不改动已冻结组合与既有使用事实。"""
        reason = _require_text(reason, "收窄原因")
        narrowed = _normalize_terms(terms)
        with self.database.transaction() as connection:
            def operation() -> dict:
                release = self._locked_release(connection, release_id)
                if release["state"] != "published" or not release["rights_position"] & GRANT_BIT:
                    raise ConflictError("版本未处于授权状态，不能收窄")
                now = self.clock.now()
                prior = connection.execute("SELECT event_id FROM ai_rights_events WHERE release_id=? ORDER BY event_id DESC LIMIT 1", (release_id,)).fetchone()
                connection.execute(
                    "INSERT INTO ai_rights_events(release_id,kind,source,terms_json,reason,effective_at,actor_id,prior_event_id) VALUES(?,?,?,?,?,?,?,?)",
                    (release_id, RIGHTS_NARROW, "publisher", canonical_json(narrowed), reason, now, actor, prior["event_id"]))
                event_id = connection.execute("SELECT last_insert_rowid()").fetchone()[0]
                count = 0
                for derivative in connection.execute("SELECT derivative_id FROM ai_derivatives WHERE release_id=? AND state='active'", (release_id,)).fetchall():
                    self._create_disposition(connection, derivative["derivative_id"], release_id, event_id, "restrict_use", now)
                    self._enqueue_work(connection, item_type="derivative_disposition", ref_id=derivative["derivative_id"],
                                       payload={"release_id": release_id, "event_id": event_id}, run_at=now)
                    count += 1
                self._audit(connection, actor, "ai.rights.narrow", "ai_releases", release_id, release["rights_position"],
                            {"terms": narrowed, "reason": reason, "event_id": event_id, "active_derivatives": count})
                return self._release_dict(self._locked_release(connection, release_id),
                                          extra={"event_id": event_id, "dispositions": count})
            return self._idem(connection, f"ai.rights.narrow:{release_id}", request_key, {"terms": narrowed, "reason": reason}, operation)

    def revoke_release(self, actor: str, release_id: str, *, reason: str, request_key: str) -> dict:
        """许可撤回：阻止失效版本继续发放，派生成果生成处置任务，历史事实保留。"""
        reason = _require_text(reason, "撤回原因")
        with self.database.transaction() as connection:
            def operation() -> dict:
                release = self._locked_release(connection, release_id)
                if release["state"] == "revoked":
                    raise ConflictError("版本已经撤回")
                now = self.clock.now()
                prior = connection.execute("SELECT event_id FROM ai_rights_events WHERE release_id=? ORDER BY event_id DESC LIMIT 1", (release_id,)).fetchone()
                connection.execute(
                    "INSERT INTO ai_rights_events(release_id,kind,source,terms_json,reason,effective_at,actor_id,prior_event_id) VALUES(?,?,?,?,?,?,?,?)",
                    (release_id, RIGHTS_REVOKE, "publisher", canonical_json({}), reason, now, actor, prior["event_id"]))
                event_id = connection.execute("SELECT last_insert_rowid()").fetchone()[0]
                connection.execute(
                    "UPDATE ai_releases SET rights_position=0,state='revoked' WHERE release_id=?", (release_id,))
                credentials = connection.execute(
                    "SELECT c.*, r.period_key AS req_period_key, r.requested_qty AS req_qty FROM ai_credentials c JOIN ai_access_requests r ON r.request_id=c.request_id WHERE c.release_id=? AND c.state='issued'", (release_id,)).fetchall()
                released_quota = 0
                for credential in credentials:
                    connection.execute(
                        "UPDATE ai_credentials SET state='revoked',revoke_event_id=?,revoked_at=? WHERE credential_id=?",
                        (event_id, now, credential["credential_id"]))
                    self._quota_move(connection, release_id, credential["org_id"], credential["group_id"],
                                     direction="release", qty=credential["req_qty"],
                                     reference=f"revoke:{credential['credential_id']}", actor=actor, now=now,
                                     period_key=credential["req_period_key"])
                    released_quota += int(credential["req_qty"])
                count = 0
                for derivative in connection.execute("SELECT derivative_id FROM ai_derivatives WHERE release_id=? AND state='active'", (release_id,)).fetchall():
                    self._create_disposition(connection, derivative["derivative_id"], release_id, event_id, "cease_and_destroy", now)
                    self._enqueue_work(connection, item_type="derivative_disposition", ref_id=derivative["derivative_id"],
                                       payload={"release_id": release_id, "event_id": event_id}, run_at=now)
                    count += 1
                self._audit(connection, actor, "ai.rights.revoke", "ai_releases", release_id, 0,
                            {"reason": reason, "event_id": event_id, "credentials_revoked": len(credentials),
                             "dispositions": count})
                return {"release_id": release_id, "state": "revoked", "event_id": event_id,
                        "credentials_revoked": len(credentials), "quota_released": released_quota,
                        "dispositions": count}
            return self._idem(connection, f"ai.rights.revoke:{release_id}", request_key, {"reason": reason}, operation)

    def get_release(self, release_id: str) -> dict:
        with self.database.connect() as connection:
            return self._release_dict(self._require_release(connection, release_id))

    def list_releases(self, artifact_id: str) -> list[dict]:
        with self.database.connect() as connection:
            rows = connection.execute("SELECT * FROM ai_releases WHERE artifact_id=? ORDER BY published_at", (artifact_id,)).fetchall()
            return [self._release_dict(row) for row in rows]

    def rights_history(self, release_id: str) -> list[dict]:
        with self.database.connect() as connection:
            self._require_release(connection, release_id)
            rows = connection.execute("SELECT * FROM ai_rights_events WHERE release_id=? ORDER BY event_id", (release_id,)).fetchall()
            return [{"event_id": r["event_id"], "kind": r["kind"], "source": r["source"],
                     "terms": json.loads(r["terms_json"]), "reason": r["reason"],
                     "effective_at": r["effective_at"], "actor_id": r["actor_id"],
                     "prior_event_id": r["prior_event_id"]} for r in rows]

    # ---- 派生成果与处置任务 ---------------------------------------------

    def register_derivative(self, actor: str, release_id: str, org_id: str, *,
                            description: str = "", manifest_digest: str = "",
                            credential_id: str = "", request_key: str) -> dict:
        require_safe(org_id, "机构标识")
        with self.database.transaction() as connection:
            def operation() -> dict:
                self._require_release(connection, release_id)
                derivative_id = new_id("derivative"); now = self.clock.now()
                connection.execute(
                    "INSERT INTO ai_derivatives(derivative_id,release_id,credential_id,org_id,description,manifest_digest,state,created_at,created_by) VALUES(?,?,?,?,?,?,'active',?,?)",
                    (derivative_id, release_id, credential_id, org_id, description.strip(), manifest_digest.strip(), now, actor))
                tasks = 0
                revoke = connection.execute(
                    "SELECT event_id FROM ai_rights_events WHERE release_id=? AND kind=? ORDER BY event_id DESC LIMIT 1",
                    (release_id, RIGHTS_REVOKE)).fetchone()
                if revoke:
                    self._create_disposition(connection, derivative_id, release_id, revoke["event_id"], "cease_and_destroy", now)
                    self._enqueue_work(connection, item_type="derivative_disposition", ref_id=derivative_id,
                                       payload={"release_id": release_id, "event_id": revoke["event_id"]}, run_at=now)
                    tasks = 1
                self._audit(connection, actor, "ai.derivative.register", "ai_derivatives", derivative_id, 1,
                            {"release_id": release_id, "org_id": org_id, "backlog_tasks": tasks})
                return {"derivative_id": derivative_id, "release_id": release_id, "org_id": org_id,
                        "state": "active", "dispositions": tasks}
            return self._idem(connection, f"ai.derivative.register:{release_id}:{org_id}", request_key,
                             {"description": description, "manifest_digest": manifest_digest, "credential_id": credential_id},
                             operation)

    def disposition_tasks(self, *, status: str | None = None) -> list[dict]:
        sql = "SELECT * FROM ai_disposition_tasks"; params: list[object] = []
        if status:
            sql += " WHERE status=?"; params.append(status)
        sql += " ORDER BY created_at,task_id"
        with self.database.connect() as connection:
            return [dict(r) for r in connection.execute(sql, params).fetchall()]

    def complete_disposition_task(self, actor: str, task_id: str, *, resolution: str) -> dict:
        resolution = _require_text(resolution, "处置结果")
        with self.database.transaction() as connection:
            row = connection.execute("SELECT * FROM ai_disposition_tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row:
                raise NotFoundError("处置任务不存在")
            if row["status"] != "pending":
                raise ConflictError("处置任务已经完成")
            now = self.clock.now()
            connection.execute(
                "UPDATE ai_disposition_tasks SET status='done',resolution=?,completed_at=? WHERE task_id=?",
                (resolution, now, task_id))
            pending = connection.execute(
                "SELECT COUNT(*) AS n FROM ai_disposition_tasks WHERE derivative_id=? AND status='pending'",
                (row["derivative_id"],)).fetchone()["n"]
            if pending == 0:
                connection.execute("UPDATE ai_derivatives SET state='handled' WHERE derivative_id=? AND state='active'",
                                   (row["derivative_id"],))
            self._audit(connection, actor, "ai.disposition.complete", "ai_disposition_tasks", task_id, 1,
                        {"derivative_id": row["derivative_id"], "resolution": resolution})
            return {"task_id": task_id, "status": "done", "resolution": resolution}

    # ---- 配额 -----------------------------------------------------------

    def put_quota_policy(self, actor: str, release_id: str, org_id: str, group_id: str, *,
                         period_kind: str = "monthly", limit: int, request_key: str) -> dict:
        require_safe(org_id, "机构标识"); require_safe(group_id, "受益群体")
        if period_kind not in PERIOD_KINDS:
            raise ValidationError("配额周期必须是 monthly")
        if not isinstance(limit, int) or limit < 0:
            raise ValidationError("配额上限必须是非负整数")
        with self.database.transaction() as connection:
            def operation() -> dict:
                self._require_release(connection, release_id)
                now = self.clock.now()
                existing = connection.execute(
                    "SELECT policy_id FROM ai_quota_policies WHERE release_id=? AND org_id=? AND group_id=?",
                    (release_id, org_id, group_id)).fetchone()
                if existing:
                    connection.execute(
                        "UPDATE ai_quota_policies SET period_kind=?,limit_qty=?,updated_at=? WHERE policy_id=?",
                        (period_kind, limit, now, existing["policy_id"]))
                    policy_id = existing["policy_id"]
                else:
                    policy_id = new_id("quota")
                    connection.execute(
                        "INSERT INTO ai_quota_policies(policy_id,release_id,org_id,group_id,period_kind,limit_qty,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                        (policy_id, release_id, org_id, group_id, period_kind, limit, now, now))
                self._audit(connection, actor, "ai.quota.policy", "ai_quota_policies", policy_id, 1,
                            {"release_id": release_id, "org_id": org_id, "group_id": group_id,
                             "period_kind": period_kind, "limit": limit})
                return {"policy_id": policy_id, "release_id": release_id, "org_id": org_id,
                        "group_id": group_id, "period_kind": period_kind, "limit": limit}
            return self._idem(connection, f"ai.quota.policy:{release_id}:{org_id}:{group_id}", request_key,
                             {"period_kind": period_kind, "limit": limit}, operation)

    def quota_status(self, release_id: str, org_id: str, group_id: str, *, at: str | None = None) -> dict:
        instant = parse_instant(at) if at else parse_instant(self.clock.now())
        period_key = _period_key(instant)
        with self.database.connect() as connection:
            self._require_release(connection, release_id)
            policy = connection.execute(
                "SELECT * FROM ai_quota_policies WHERE release_id=? AND org_id=? AND group_id=?",
                (release_id, org_id, group_id)).fetchone()
            used = self._quota_used(connection, release_id, org_id, group_id, period_key)
            limit = policy["limit_qty"] if policy else None
            return {"release_id": release_id, "org_id": org_id, "group_id": group_id,
                    "period_kind": policy["period_kind"] if policy else "monthly", "period_key": period_key,
                    "limit": limit, "used": used,
                    "remaining": None if limit is None else max(0, limit - used)}

    # ---- 申请与三角色分离审批 -------------------------------------------

    def submit_access_request(self, actor: str, release_id: str, *, org_id: str, group_id: str,
                              purpose: str, use_cases: Iterable[str], region: str, qty: int = 1,
                              emergency: bool = False, emergency_reason: str = "",
                              valid_to: str | None = None, request_key: str = "") -> dict:
        require_safe(actor, "提交者"); require_safe(org_id, "机构标识"); require_safe(group_id, "受益群体")
        purpose = _require_text(purpose, "用途"); region = _require_text(region, "适用区域")
        cases = _clean_cases(use_cases)
        if not cases:
            raise ValidationError("至少声明一个具体用途场景")
        if not isinstance(qty, int) or qty <= 0:
            raise ValidationError("申请数量必须是正整数")
        if emergency and not emergency_reason.strip():
            raise ValidationError("紧急公共用途例外必须说明理由")
        request_key = request_key or new_id("reqkey")
        with self.database.transaction() as connection:
            def operation() -> dict:
                self._require_grant(connection, release_id)
                request_id = new_id("areq"); now = self.clock.now()
                expiry = canonical_instant(valid_to) if valid_to else \
                    (parse_instant(now) + timedelta(days=90)).isoformat().replace("+00:00", "Z")
                if parse_instant(expiry) <= parse_instant(now):
                    raise ValidationError("访问有效期必须晚于当前时间")
                period_key = _period_key(parse_instant(now))
                connection.execute(
                    "INSERT INTO ai_access_requests(request_id,release_id,org_id,group_id,purpose,use_cases_json,region,requested_qty,emergency,emergency_reason,state,submitter,rights_position,period_key,valid_to,submitted_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (request_id, release_id, org_id, group_id, purpose, canonical_json(cases), region, qty,
                     1 if emergency else 0, emergency_reason.strip(), "pending_rights", actor,
                     GRANT_BIT, period_key, expiry, now))
                sla = (parse_instant(now) + timedelta(hours=DEFAULT_REVIEW_SLA_HOURS)).isoformat().replace("+00:00", "Z")
                self._enqueue_work(connection, item_type="review_sla", ref_id=request_id,
                                   payload={"stage": "rights"}, run_at=sla,
                                   item_id=f"review-sla:{request_id}")
                self._audit(connection, actor, "ai.request.submit", "ai_access_requests", request_id, 1,
                            {"release_id": release_id, "org_id": org_id, "group_id": group_id,
                             "purpose": purpose, "qty": qty, "emergency": emergency, "period_key": period_key})
                return self._request_dict(self._locked_request(connection, request_id))
            return self._idem(connection, f"ai.request.submit:{actor}", request_key,
                             {"release_id": release_id, "org_id": org_id, "group_id": group_id,
                              "purpose": purpose, "use_cases": cases, "region": region, "qty": qty,
                              "emergency": emergency}, operation)

    def rights_review(self, actor: str, request_id: str, *, decision: str, reason: str) -> dict:
        _require_reviewer(actor, "权益审核人")
        reason = _require_text(reason, "审核理由")
        if decision not in ("approved", "rejected"):
            raise ValidationError("决策必须是 approved 或 rejected")
        with self.database.transaction() as connection:
            request = self._locked_request(connection, request_id)
            if request["state"] != "pending_rights":
                raise ConflictError("申请不在待权益审核状态")
            _assert_segregation(actor, request["submitter"], "权益审核人不能是提交者")
            now = self.clock.now()
            if decision == "rejected":
                connection.execute(
                    "UPDATE ai_access_requests SET rights_reviewer=?,rights_decision='rejected',rights_reason=?,rights_at=?,state='rights_rejected',decided_at=? WHERE request_id=?",
                    (actor, reason, now, now, request_id))
            else:
                connection.execute(
                    "UPDATE ai_access_requests SET rights_reviewer=?,rights_decision='approved',rights_reason=?,rights_at=?,state='pending_security' WHERE request_id=?",
                    (actor, reason, now, request_id))
            self._audit(connection, actor, "ai.request.rights_review", "ai_access_requests", request_id, 1,
                        {"decision": decision, "reason": reason})
            return self._request_dict(self._locked_request(connection, request_id))

    def security_review(self, actor: str, request_id: str, *, decision: str, reason: str) -> dict:
        """安全复核通过即原子完成许可判断、配额占用、凭据签发与审计。"""
        _require_reviewer(actor, "安全复核人")
        reason = _require_text(reason, "复核理由")
        if decision not in ("approved", "rejected"):
            raise ValidationError("决策必须是 approved 或 rejected")
        with self.database.transaction() as connection:
            return self._security_review(connection, actor, request_id, decision=decision, reason=reason)

    def _security_review(self, connection: sqlite3.Connection, actor: str, request_id: str, *,
                         decision: str, reason: str) -> dict:
        request = self._locked_request(connection, request_id)
        if request["state"] != "pending_security":
            raise ConflictError("申请不在待安全复核状态")
        _assert_segregation(actor, request["submitter"], "安全复核人不能是提交者")
        _assert_segregation(actor, request["rights_reviewer"], "安全复核人不能代行权益审核")
        now = self.clock.now()
        if decision == "rejected":
            connection.execute(
                "UPDATE ai_access_requests SET security_reviewer=?,security_decision='rejected',security_reason=?,security_at=?,state='security_rejected',decided_at=? WHERE request_id=?",
                (actor, reason, now, now, request_id))
            self._audit(connection, actor, "ai.request.security_review", "ai_access_requests", request_id, 1,
                        {"decision": "rejected", "reason": reason})
            return self._request_dict(self._locked_request(connection, request_id))

        release = self._locked_release(connection, request["release_id"])
        terms = self._current_terms(connection, request["release_id"])
        emergency = bool(request["emergency"])
        evaluation = _evaluate(terms, group_id=request["group_id"], purpose=request["purpose"],
                               use_cases=json.loads(request["use_cases_json"]), region=request["region"],
                               emergency=emergency)
        if not emergency and not evaluation["allowed"]:
            raise ValidationError("许可判断不通过: " + "; ".join(evaluation["reasons"]))
        # 撤回与批量发放并发时，这里的即时锁保证失效版本拿不到凭据。
        if release["state"] != "published" or not release["rights_position"] & GRANT_BIT:
            raise ConflictError("成果版本已经失效，不能继续发放凭据")
        qty = request["requested_qty"]
        quota = self._quota_used(connection, release["release_id"], request["org_id"],
                                request["group_id"], request["period_key"])
        policy = connection.execute(
            "SELECT limit_qty FROM ai_quota_policies WHERE release_id=? AND org_id=? AND group_id=?",
            (release["release_id"], request["org_id"], request["group_id"])).fetchone()
        limit = policy["limit_qty"] if policy else None
        if not emergency:
            if limit is None:
                raise ValidationError("该机构与受益群体没有配额策略")
            if quota + qty > limit:
                raise ConflictError(f"周期配额不足：已用 {quota}，上限 {limit}，申请 {qty}")
        self._quota_move(connection, release["release_id"], request["org_id"], request["group_id"],
                         direction="hold", qty=qty, reference=f"request:{request_id}", actor=actor, now=now,
                         period_key=request["period_key"])
        credential_id = new_id("cred"); token = secrets.token_urlsafe(32)
        connection.execute(
            "INSERT INTO ai_credentials(credential_id,request_id,release_id,org_id,group_id,token_digest,state,issued_at,valid_from,valid_to) VALUES(?,?,?,?,?,?,'issued',?,?,?)",
            (credential_id, request_id, release["release_id"], request["org_id"], request["group_id"],
             hashlib.sha256(token.encode("utf-8")).hexdigest(), now, now, request["valid_to"]))
        self._enqueue_work(connection, item_type="credential_expiry", ref_id=credential_id,
                           payload={"request_id": request_id}, run_at=request["valid_to"],
                           item_id=f"expiry:{credential_id}")
        context_snapshot = {"terms": terms, "evaluation": evaluation, "manifest_digest": release["manifest_digest"],
                            "components": json.loads(release["components_json"]),
                            "quota": {"period_key": request["period_key"], "limit": limit,
                                      "used_before": quota, "qty": qty, "emergency": emergency},
                            "rights_position": release["rights_position"], "decided_at": now}
        connection.execute(
            "UPDATE ai_access_requests SET security_reviewer=?,security_decision='approved',security_reason=?,security_at=?,state='issued',rights_position=?,decided_at=?,decision_context_json=? WHERE request_id=?",
            (actor, reason, now, GRANT_BIT, now, canonical_json(context_snapshot), request_id))
        self._audit(connection, actor, "ai.credential.issue", "ai_credentials", credential_id, 1,
                    {"request_id": request_id, "release_id": release["release_id"],
                     "org_id": request["org_id"], "group_id": request["group_id"],
                     "period_key": request["period_key"], "qty": qty, "emergency": emergency,
                     "evaluation": evaluation})
        result = self._request_dict(self._locked_request(connection, request_id))
        result["credential"] = {"credential_id": credential_id, "token": token,
                                "valid_to": request["valid_to"], "state": "issued"}
        return result

    def grant_batch(self, actor: str, items: Iterable[Mapping[str, str]]) -> dict:
        """批量安全复核与发放；任一申请不满足条件则整批回滚，零发放。"""
        _require_reviewer(actor, "安全复核人")
        items = [dict(item) for item in items]
        if not items:
            raise ValidationError("批量内容不能为空")
        with self.database.transaction() as connection:
            issued: list[dict] = []
            for item in items:
                if "request_id" not in item:
                    raise ValidationError("批量项缺少 request_id")
                # 同一即时事务内逐项判断与发放；任一异常触发整体回滚。
                result = self._security_review(connection, actor, item["request_id"],
                                               decision="approved", reason=item.get("reason", "批量授权"))
                issued.append({"request_id": item["request_id"],
                               "credential_id": result["credential"]["credential_id"]})
            self._audit(connection, actor, "ai.credential.grant_batch", "ai_credentials",
                        issued[0]["credential_id"], 1,
                        {"count": len(issued), "request_ids": [i["request_id"] for i in items]})
            return {"issued": issued, "count": len(issued)}

    def get_request(self, request_id: str) -> dict:
        with self.database.connect() as connection:
            return self._request_dict(self._require_request(connection, request_id))

    def list_requests(self, *, state: str | None = None, org_id: str | None = None) -> list[dict]:
        sql = "SELECT * FROM ai_access_requests"; clauses: list[str] = []; params: list[object] = []
        if state:
            if state not in REQUEST_STATES:
                raise ValidationError("未知申请状态")
            clauses.append("state=?"); params.append(state)
        if org_id:
            clauses.append("org_id=?"); params.append(org_id)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY submitted_at,request_id"
        with self.database.connect() as connection:
            return [self._request_dict(r) for r in connection.execute(sql, params).fetchall()]

    # ---- 使用回执与异文隔离 ---------------------------------------------

    def report_usage(self, reporter: str, credential_id: str, receipt_key: str, payload: Mapping[str, object]) -> dict:
        """登记一次使用事实。同键重试沿用原结果；同键异文进入隔离。"""
        require_safe(reporter, "报告人"); require_safe(receipt_key, "回执键"); require_safe(credential_id, "凭据标识")
        body = _normalize_usage(payload)
        request_digest = digest_json({"credential_id": credential_id, "payload": body})
        quarantined = False
        with self.database.transaction() as connection:
            credential = connection.execute("SELECT * FROM ai_credentials WHERE credential_id=?", (credential_id,)).fetchone()
            if not credential:
                raise NotFoundError("凭据不存在")
            if credential["state"] != "issued":
                raise PermissionDenied(f"凭据状态为 {credential['state']}，不能登记使用")
            now = self.clock.now()
            if parse_instant(now) < parse_instant(credential["valid_from"]) or parse_instant(now) > parse_instant(credential["valid_to"]):
                raise PermissionDenied("凭据不在有效期内")
            existing = connection.execute(
                "SELECT * FROM ai_usage_receipts WHERE receipt_key=?", (receipt_key,)).fetchone()
            if existing:
                if existing["request_digest"] == request_digest:
                    return {"receipt_id": existing["receipt_id"], "outcome": existing["outcome"],
                            "result": json.loads(existing["result_json"]), "replayed": True}
                # 异文必须留痕：隔离记录与审计先在本事务提交，随后在事务外拒绝。
                connection.execute(
                    "INSERT INTO ai_receipt_quarantine(receipt_key,existing_digest,incoming_digest,payload_json,received_at,reporter) VALUES(?,?,?,?,?,?)",
                    (receipt_key, existing["request_digest"], request_digest, canonical_json(body), now, reporter))
                self._audit(connection, reporter, "ai.receipt.quarantine", "ai_usage_receipts",
                            existing["receipt_id"], 0, {"receipt_key": receipt_key})
                quarantined = True
            else:
                request = self._require_request(connection, credential["request_id"])
                terms = self._current_terms(connection, credential["release_id"])
                evaluation = _evaluate(terms, group_id=credential["group_id"], purpose=body["purpose"],
                                       use_cases=body["use_cases"], region=body["region"],
                                       emergency=bool(request["emergency"]))
                allowed = evaluation["allowed"]
                receipt_id = new_id("receipt")
                result = {"allowed": allowed, "reasons": evaluation["reasons"],
                          "terms_event": evaluation["terms_event"], "reported_at": now}
                connection.execute(
                    "INSERT INTO ai_usage_receipts(receipt_id,receipt_key,request_digest,credential_id,release_id,payload_json,outcome,result_json,reported_at,reporter) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (receipt_id, receipt_key, request_digest, credential_id, credential["release_id"],
                     canonical_json(body), "recorded" if allowed else "denied", canonical_json(result), now, reporter))
                self._audit(connection, reporter, "ai.receipt.report", "ai_usage_receipts", receipt_id, 1,
                            {"credential_id": credential_id, "release_id": credential["release_id"],
                             "outcome": result["allowed"], "reasons": evaluation["reasons"]})
                recorded = {"receipt_id": receipt_id, "outcome": "recorded" if allowed else "denied",
                            "result": result, "replayed": False}
        if quarantined:
            raise ConflictError("相同回执键对应不同内容，已进入隔离")
        return recorded

    def list_quarantine(self) -> list[dict]:
        with self.database.connect() as connection:
            return [dict(r) for r in connection.execute(
                "SELECT quarantine_id,receipt_key,existing_digest,incoming_digest,received_at,reporter FROM ai_receipt_quarantine ORDER BY quarantine_id").fetchall()]

    def receipts_for_release(self, release_id: str) -> list[dict]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT receipt_id,receipt_key,credential_id,outcome,result_json,reported_at,reporter FROM ai_usage_receipts WHERE release_id=? ORDER BY reported_at,receipt_id",
                (release_id,)).fetchall()
            return [{"receipt_id": r["receipt_id"], "receipt_key": r["receipt_key"],
                     "credential_id": r["credential_id"], "outcome": r["outcome"],
                     "result": json.loads(r["result_json"]), "reported_at": r["reported_at"],
                     "reporter": r["reporter"]} for r in rows]

    # ---- 再申请与申诉：还原当时的组合、判断、配额 ------------------------

    def appeal_view(self, request_id: str, *, at: str | None = None) -> dict:
        """呈现申请裁决时的成果组合、许可判断、群体配额与剩余额度。"""
        with self.database.connect() as connection:
            request = self._require_request(connection, request_id)
            release = self._require_release(connection, request["release_id"])
            decision = json.loads(request["decision_context_json"]) if request["decision_context_json"] else {}
            quota = None
            if decision.get("quota"):
                q = decision["quota"]
                quota = {"period_key": q.get("period_key", request["period_key"]), "limit": q.get("limit"),
                         "used_at_decision": q.get("used_before"), "granted_qty": q.get("qty")}
            current = None
            instant = at or self.clock.now()
            period_key = _period_key(parse_instant(canonical_instant(instant)))
            policy = connection.execute(
                "SELECT limit_qty FROM ai_quota_policies WHERE release_id=? AND org_id=? AND group_id=?",
                (request["release_id"], request["org_id"], request["group_id"])).fetchone()
            used = self._quota_used(connection, request["release_id"], request["org_id"],
                                    request["group_id"], period_key)
            limit = policy["limit_qty"] if policy else None
            current = {"period_key": period_key, "limit": limit, "used": used,
                       "remaining": None if limit is None else max(0, limit - used)}
            credentials = [dict(r) for r in connection.execute(
                "SELECT credential_id,state,issued_at,valid_to,revoked_at,revoke_event_id FROM ai_credentials WHERE request_id=?",
                (request_id,)).fetchall()]
            receipts = [dict(r) for r in connection.execute(
                "SELECT receipt_id,receipt_key,outcome,reported_at FROM ai_usage_receipts WHERE credential_id IN (SELECT credential_id FROM ai_credentials WHERE request_id=?) ORDER BY reported_at",
                (request_id,)).fetchall()]
            return {"request": self._request_dict(request),
                    "release": {"release_id": release["release_id"], "state": release["state"],
                                "version_tag": release["version_tag"],
                                "components": json.loads(release["components_json"]),
                                "manifest_digest": release["manifest_digest"],
                                "published_at": release["published_at"]},
                    "decision_context": decision, "decision_quota": quota,
                    "current_quota": current, "credentials": credentials, "receipts": receipts}

    # ---- 可恢复工作队列 -------------------------------------------------

    def enqueue_work(self, item_type: str, ref_id: str, payload: Mapping[str, object], run_at: str,
                     item_id: str | None = None) -> str:
        with self.database.transaction() as connection:
            return self._enqueue_work(connection, item_type=item_type, ref_id=ref_id,
                                      payload=dict(payload), run_at=run_at, item_id=item_id)

    def claim_work(self, *, seconds: int = 30, limit: int = 20) -> list[dict]:
        if seconds < 1 or limit < 1:
            raise ValidationError("工作租约参数不合法")
        lease_until = (parse_instant(self.clock.now()) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
        with self.database.transaction() as connection:
            # 等待中的工作按时领取；running 但租约已过期说明处理进程中断，从保存的队列位置接续。
            rows = connection.execute(
                "SELECT * FROM ai_work_queue WHERE run_at<=? AND (status IN ('waiting','retry') OR (status='running' AND lease_until<?)) ORDER BY seq LIMIT ?",
                (self.clock.now(), self.clock.now(), limit)).fetchall()
            claimed = []
            for row in rows:
                changed = connection.execute(
                    "UPDATE ai_work_queue SET status='running',lease_until=?,attempts=attempts+1 WHERE seq=? AND run_at<=? AND (status IN ('waiting','retry') OR (status='running' AND lease_until<?))",
                    (lease_until, row["seq"], self.clock.now(), self.clock.now())).rowcount
                if changed:
                    item = dict(row); item["status"] = "running"; item["lease_until"] = lease_until
                    claimed.append(item)
            return claimed

    def complete_work(self, item_id: str) -> None:
        with self.database.transaction() as connection:
            changed = connection.execute(
                "UPDATE ai_work_queue SET status='done',lease_until=NULL,last_error='' WHERE item_id=? AND status='running'",
                (item_id,)).rowcount
            if changed != 1:
                raise ConflictError("工作项没有有效运行租约")

    def fail_work(self, item_id: str, *, error: str, retry_at: str | None = None) -> str:
        retry_at = canonical_instant(retry_at) if retry_at else \
            (parse_instant(self.clock.now()) + timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
        with self.database.transaction() as connection:
            row = connection.execute("SELECT attempts FROM ai_work_queue WHERE item_id=?", (item_id,)).fetchone()
            if not row:
                raise NotFoundError("工作项不存在")
            status = "dead" if row["attempts"] >= MAX_WORK_ATTEMPTS else "retry"
            connection.execute(
                "UPDATE ai_work_queue SET status=?,run_at=?,lease_until=NULL,last_error=? WHERE item_id=?",
                (status, retry_at, error[:500], item_id))
            return status

    def run_due(self, *, limit: int = 20) -> list[dict]:
        """领取并处理到期工作；处理器全部幂等，崩溃后凭持久队列位置接续。"""
        processed = []
        for item in self.claim_work(limit=limit):
            try:
                outcome = self._handle_work(item)
                self.complete_work(item["item_id"])
                processed.append({"item_id": item["item_id"], "type": item["item_type"], "outcome": outcome})
            except Exception as exc:  # 中断后保留队列位置，等待重新领取
                self.fail_work(item["item_id"], error=str(exc))
                processed.append({"item_id": item["item_id"], "type": item["item_type"], "error": str(exc)})
        return processed

    # ---- 内部辅助 -------------------------------------------------------

    def _handle_work(self, item: Mapping[str, object]) -> dict:
        item_type = item["item_type"]; payload = json.loads(item["payload_json"])
        with self.database.transaction() as connection:
            now = self.clock.now()
            if item_type == "credential_expiry":
                changed = connection.execute(
                    "UPDATE ai_credentials SET state='expired' WHERE credential_id=? AND state='issued' AND valid_to<=?",
                    (item["ref_id"], now)).rowcount
                self._audit(connection, "system", "ai.credential.expire", "ai_credentials", item["ref_id"], 1,
                            {"expired": bool(changed)})
                return {"expired": bool(changed)}
            if item_type == "review_sla":
                row = connection.execute("SELECT state FROM ai_access_requests WHERE request_id=?", (item["ref_id"],)).fetchone()
                pending = bool(row and row["state"] in ("pending_rights", "pending_security"))
                if pending:
                    self._audit(connection, "system", "ai.request.review_overdue", "ai_access_requests",
                                item["ref_id"], 0, {"state": row["state"]})
                return {"pending": pending}
            if item_type == "derivative_disposition":
                # 幂等补建：撤回事务若中断，这里从保存的队列位置接续。
                existing = connection.execute(
                    "SELECT 1 FROM ai_disposition_tasks WHERE derivative_id=? AND trigger_event_id=?",
                    (item["ref_id"], payload["event_id"])).fetchone()
                created = False
                if not existing:
                    self._create_disposition(connection, item["ref_id"], payload["release_id"],
                                             payload["event_id"], "restrict_use", now)
                    created = True
                return {"backfilled": created}
            raise ValidationError(f"未知工作类型: {item_type}")

    def _enqueue_work(self, connection: sqlite3.Connection, *, item_type: str, ref_id: str,
                      payload: Mapping[str, object], run_at: str, item_id: str | None = None) -> str:
        item_id = item_id or new_id("work")
        run_at = canonical_instant(run_at); now = self.clock.now()
        connection.execute(
            "INSERT OR IGNORE INTO ai_work_queue(item_id,item_type,ref_id,run_at,payload_json,status,enqueued_at) VALUES(?,?,?,?,?,'waiting',?)",
            (item_id, item_type, ref_id, run_at, canonical_json(dict(payload)), now))
        return item_id

    def _quota_move(self, connection: sqlite3.Connection, release_id: str, org_id: str, group_id: str, *,
                    direction: str, qty: int, reference: str, actor: str, now: str,
                    period_key: str | None = None) -> None:
        if direction not in ("hold", "release"):
            raise ValidationError("配额方向必须是 hold 或 release")
        period_key = period_key or _period_key(parse_instant(now))
        entry_id = new_id("qentry")
        connection.execute(
            "INSERT INTO ai_quota_ledger(entry_id,release_id,org_id,group_id,period_key,direction,qty,reference,created_at,actor_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (entry_id, release_id, org_id, group_id, period_key, direction, qty, reference, now, actor))

    @staticmethod
    def _quota_used(connection: sqlite3.Connection, release_id: str, org_id: str, group_id: str, period_key: str) -> int:
        row = connection.execute(
            "SELECT COALESCE(SUM(CASE direction WHEN 'hold' THEN qty ELSE -qty END),0) AS used FROM ai_quota_ledger WHERE release_id=? AND org_id=? AND group_id=? AND period_key=?",
            (release_id, org_id, group_id, period_key)).fetchone()
        return int(row["used"])

    @staticmethod
    def _current_terms(connection: sqlite3.Connection, release_id: str) -> dict:
        row = connection.execute(
            "SELECT terms_json FROM ai_rights_events WHERE release_id=? ORDER BY event_id DESC LIMIT 1",
            (release_id,)).fetchone()
        return json.loads(row["terms_json"]) if row and row["terms_json"] else {}

    @staticmethod
    def _locked_artifact(connection: sqlite3.Connection, artifact_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM ai_catalog WHERE artifact_id=? ", (artifact_id,)).fetchone()
        if not row:
            raise NotFoundError("成果不存在")
        return row

    @staticmethod
    def _locked_release(connection: sqlite3.Connection, release_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM ai_releases WHERE release_id=?", (release_id,)).fetchone()
        if not row:
            raise NotFoundError("成果版本不存在")
        return row

    def _require_release(self, connection: sqlite3.Connection, release_id: str) -> sqlite3.Row:
        return self._locked_release(connection, release_id)

    def _require_grant(self, connection: sqlite3.Connection, release_id: str) -> sqlite3.Row:
        row = self._locked_release(connection, release_id)
        if row["state"] != "published" or not row["rights_position"] & GRANT_BIT:
            raise ConflictError("成果版本未处于可申请状态")
        return row

    @staticmethod
    def _locked_request(connection: sqlite3.Connection, request_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM ai_access_requests WHERE request_id=?", (request_id,)).fetchone()
        if not row:
            raise NotFoundError("访问申请不存在")
        return row

    def _require_request(self, connection: sqlite3.Connection, request_id: str) -> sqlite3.Row:
        return self._locked_request(connection, request_id)

    @staticmethod
    def _release_dict(row: sqlite3.Row, *, extra: dict | None = None) -> dict:
        result = {"release_id": row["release_id"], "artifact_id": row["artifact_id"],
                  "version_tag": row["version_tag"], "state": row["state"],
                  "components": json.loads(row["components_json"]),
                  "manifest_digest": row["manifest_digest"],
                  "rights_position": row["rights_position"],
                  "published_at": row["published_at"], "published_by": row["published_by"]}
        if extra:
            result.update(extra)
        return result

    @staticmethod
    def _request_dict(row: sqlite3.Row) -> dict:
        return {"request_id": row["request_id"], "release_id": row["release_id"], "org_id": row["org_id"],
                "group_id": row["group_id"], "purpose": row["purpose"],
                "use_cases": json.loads(row["use_cases_json"]), "region": row["region"],
                "requested_qty": row["requested_qty"], "emergency": bool(row["emergency"]),
                "emergency_reason": row["emergency_reason"], "state": row["state"],
                "submitter": row["submitter"], "rights_reviewer": row["rights_reviewer"],
                "rights_decision": row["rights_decision"], "rights_reason": row["rights_reason"],
                "rights_at": row["rights_at"], "security_reviewer": row["security_reviewer"],
                "security_decision": row["security_decision"], "security_reason": row["security_reason"],
                "security_at": row["security_at"], "rights_position": row["rights_position"],
                "period_key": row["period_key"], "valid_to": row["valid_to"],
                "submitted_at": row["submitted_at"], "decided_at": row["decided_at"]}

    @staticmethod
    def _create_disposition(connection: sqlite3.Connection, derivative_id: str, release_id: str,
                            event_id: int, action: str, now: str) -> None:
        task_id = new_id("dtask")
        connection.execute(
            "INSERT OR IGNORE INTO ai_disposition_tasks(task_id,derivative_id,release_id,trigger_event_id,action,status,created_at) VALUES(?,?,?,?,?,'pending',?)",
            (task_id, derivative_id, release_id, event_id, action, now))

    def _audit(self, connection: sqlite3.Connection, actor: str, action: str, entity_type: str,
               entity_id: str, version: int, detail: Mapping[str, object]) -> None:
        self.audit.append(connection, actor_id=actor, action=action, entity_type=entity_type,
                          entity_id=entity_id, version=version, detail=dict(detail))

    def _idem(self, connection: sqlite3.Connection, scope: str, request_key: str,
              request: Mapping[str, object], operation: Callable[[], T]) -> T:
        return self.idempotency.execute(connection, scope=scope, request_key=request_key,
                                        request=dict(request), operation=operation)


# ---- 纯函数：条款、组件、周期与许可判断 ------------------------------------

def _freeze_components(components: Mapping[str, Mapping[str, str]]) -> dict:
    if not isinstance(components, Mapping):
        raise ValidationError("冻结组件必须是对象")
    missing = [kind for kind in COMPONENT_KINDS if kind not in components]
    if missing:
        raise ValidationError("发布必须冻结模型、数据集和安全说明: 缺少 " + ", ".join(missing))
    unknown = [kind for kind in components if kind not in COMPONENT_KINDS]
    if unknown:
        raise ValidationError("未知组件类型: " + ", ".join(sorted(unknown)))
    frozen: dict = {}
    for kind in COMPONENT_KINDS:
        component = components[kind]
        if not isinstance(component, Mapping):
            raise ValidationError(f"{kind} 组件必须是对象")
        ref = _require_text(component.get("ref", ""), f"{kind} 组件引用")
        version = _require_text(component.get("version", ""), f"{kind} 组件版本")
        digest = _require_text(component.get("digest", ""), f"{kind} 组件摘要")
        frozen[kind] = {"ref": ref, "version": version, "digest": digest}
    return frozen


def _normalize_terms(rights: Mapping[str, object]) -> dict:
    if not isinstance(rights, Mapping):
        raise ValidationError("权利条款必须是对象")
    return {"groups": _clean_cases(rights.get("groups", [])),
            "purposes": _clean_cases(rights.get("purposes", [])),
            "use_cases": _clean_cases(rights.get("use_cases", [])),
            "regions": _clean_cases(rights.get("regions", []))}


def _evaluate(terms: Mapping[str, object], *, group_id: str, purpose: str,
              use_cases: list[str], region: str, emergency: bool) -> dict:
    reasons: list[str] = []
    groups = terms.get("groups") or []
    purposes = terms.get("purposes") or []
    allowed_cases = terms.get("use_cases") or []
    regions = terms.get("regions") or []
    if groups and group_id not in groups:
        reasons.append(f"受益群体 {group_id} 不在适用人群范围内")
    if purposes and purpose not in purposes:
        reasons.append(f"用途 {purpose} 不在许可范围内")
    extra_cases = sorted(set(use_cases) - set(allowed_cases))
    if allowed_cases and extra_cases:
        reasons.append("用途场景超出许可: " + ", ".join(extra_cases))
    if regions and region not in regions:
        reasons.append(f"区域 {region} 不在许可范围内")
    allowed = not reasons
    if reasons and emergency:
        return {"allowed": True, "emergency_override": True, "reasons": reasons,
                "terms_event": "current"}
    return {"allowed": allowed, "emergency_override": False, "reasons": reasons,
            "terms_event": "current"}


def _normalize_usage(payload: Mapping[str, object]) -> dict:
    if not isinstance(payload, Mapping):
        raise ValidationError("使用回执内容必须是对象")
    purpose = _require_text(payload.get("purpose", ""), "使用用途")
    region = _require_text(payload.get("region", ""), "使用区域")
    cases = _clean_cases(payload.get("use_cases", []))
    if not cases:
        raise ValidationError("至少声明一个使用场景")
    qty = payload.get("qty", 1)
    if not isinstance(qty, int) or qty <= 0:
        raise ValidationError("使用数量必须是正整数")
    return {"purpose": purpose, "region": region, "use_cases": cases, "qty": qty}


def _clean_cases(value: object) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, Iterable) or isinstance(value, (bytes, bytearray)):
        raise ValidationError("列表字段必须是数组")
    result = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValidationError("列表项必须是非空字符串")
        result.append(item.strip())
    return sorted(set(result))


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{label}不能为空")
    return value.strip()


def _require_reviewer(actor: str, label: str) -> str:
    require_safe(actor, label)
    return actor


def _assert_segregation(actor: str, other: str | None, message: str) -> None:
    if other and actor == other:
        raise PermissionDenied(message)


def _period_key(instant) -> str:
    return instant.strftime("%Y-%m")
