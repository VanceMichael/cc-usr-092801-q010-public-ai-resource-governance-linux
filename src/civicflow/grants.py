"""人工智能成果授权、使用回执、处置任务与可恢复扫描。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta

from .airules import evaluate_rights, period_end_for, period_key_for, rights_satisfied
from .audit import AuditLog
from .database import Database
from .errors import CivicFlowError, ConflictError, NotFoundError, PermissionDenied, ValidationError
from .identifiers import new_id, require_safe
from .idempotency import IdempotencyStore
from .jobs import JobQueue
from .jsonutil import canonical_json, digest_json
from .repository import EntityRepository
from .security import AccessContext
from .timeutil import Clock, canonical_instant, parse_instant

SWEEP_KINDS = ("credential_expiry", "request_deadline", "withdrawal_fanout")
DISPOSITION_RESOLUTIONS = ("revoked", "allow_to_expiry", "migrated")


@dataclass(frozen=True)
class GrantService:
    """授权核心：配额占用、凭据签发与审计分录原子一致，工作队列可接续。"""

    database: Database
    repository: EntityRepository
    clock: Clock
    audit: AuditLog
    idempotency: IdempotencyStore
    jobs: JobQueue

    # ---- 授权 ----

    def grant(self, context: AccessContext, request_id: str, *, request_key: str) -> dict:
        """发放访问凭据：配额占用、凭据签发与审计分录在同一事务内提交。"""
        context.require("grant:access_requests")
        require_safe(request_id, "申请标识")
        with self.database.transaction() as connection:
            def operation() -> dict:
                return self._grant_in(connection, context.actor_id, request_id)
            return self.idempotency.execute(connection, scope=f"grant:{request_id}", request_key=request_key, request={"request_id": request_id}, operation=operation)

    def _grant_in(self, connection, actor: str, request_id: str) -> dict:
        """在既有事务内执行发放；所有校验先于任何写入，失败不留半成品。"""
        request_row = connection.execute("SELECT * FROM entities WHERE entity_type='access_requests' AND entity_id=?", (request_id,)).fetchone()
        if not request_row:
            raise NotFoundError(f"access_requests/{request_id} 不存在")
        request = json.loads(request_row["payload_json"])
        if request_row["state"] != "security_cleared":
            raise ConflictError(f"申请状态为 {request_row['state']}，不能发放凭据")
        deadline = request.get("review_deadline")
        if deadline and deadline <= self.clock.now():
            raise ConflictError("申请复核期限已过")
        version_row = connection.execute("SELECT * FROM entities WHERE entity_type='ai_versions' AND entity_id=?", (request["asset_version_id"],)).fetchone()
        if not version_row:
            raise NotFoundError("成果版本不存在")
        if version_row["state"] != "published":
            raise ConflictError("成果版本已撤回或未发布，停止发放")
        version = json.loads(version_row["payload_json"])
        rights = version["rights"]
        judgment = evaluate_rights(rights, request)
        exception = bool(request.get("emergency"))
        if not rights_satisfied(judgment) and not exception:
            raise PermissionDenied("申请不符合成果许可、区域限制或公平可及要求")
        now = self.clock.now()
        quota = version["quota"]
        period_key = period_key_for(now, quota["period"])
        quantity = int(request["quantity"])
        org_used = self._quota_used(connection, period_key, request["asset_version_id"], group=request["beneficiary_group"], org=request["org_id"])
        group_used = self._quota_used(connection, period_key, request["asset_version_id"], group=request["beneficiary_group"])
        if not exception:
            if org_used + quantity > quota["per_org"]:
                raise ConflictError("机构周期配额不足")
            if group_used + quantity > quota["per_group"]:
                raise ConflictError("受益群体周期配额不足")
        credential_id = new_id("cred")
        expires_at = period_end_for(now, quota["period"])
        connection.execute("INSERT INTO quota_ledger(entry_id,period_key,org_id,beneficiary_group,asset_version_id,quantity,request_id,credential_id,occurred_at) VALUES(?,?,?,?,?,?,?,?,?)", (new_id("quota"), period_key, request["org_id"], request["beneficiary_group"], request["asset_version_id"], quantity, request_id, credential_id, now))
        connection.execute("INSERT INTO access_credentials(credential_id,request_id,asset_version_id,org_id,beneficiary_group,purpose,region,period_key,quantity,used_quantity,issued_at,expires_at,status,issued_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (credential_id, request_id, request["asset_version_id"], request["org_id"], request["beneficiary_group"], request["purpose"], request["region"], period_key, quantity, 0, now, expires_at, "active", actor))
        decision = {
            "request_id": request_id,
            "credential_id": credential_id,
            "asset_version_id": request["asset_version_id"],
            "version_revision": version_row["version"],
            "combination": version["combination"],
            "combination_digest": version.get("combination_digest", ""),
            "rights": rights,
            "judgment": judgment,
            "exception": exception,
            "period_key": period_key,
            "per_org": quota["per_org"],
            "per_group": quota["per_group"],
            "quantity": quantity,
            "org_remaining": quota["per_org"] - org_used - quantity,
            "group_remaining": quota["per_group"] - group_used - quantity,
            "submitter": request.get("submitter", ""),
            "rights_reviewer": request.get("rights_reviewer", ""),
            "security_reviewer": request.get("security_reviewer", ""),
            "decided_by": actor,
            "decided_at": now,
        }
        connection.execute("INSERT INTO license_decisions(request_id,credential_id,decision_json,decided_at) VALUES(?,?,?,?)", (request_id, credential_id, canonical_json(decision), now))
        self.repository.update_in(connection, "access_requests", request_id, {"state": "granted", "credential_id": credential_id, "granted_at": now}, actor=actor, expected_version=request_row["version"], request_key=f"grant-state:{credential_id}")
        self.audit.append(connection, actor_id=actor, action="grant", entity_type="access_credentials", entity_id=credential_id, version=1, detail=decision)
        return {"credential_id": credential_id, "period_key": period_key, "expires_at": expires_at, "decision": decision}

    @staticmethod
    def _quota_used(connection, period_key: str, version_id: str, *, group: str, org: str | None = None, as_of: str | None = None) -> int:
        sql = "SELECT COALESCE(SUM(quantity),0) AS used FROM quota_ledger WHERE period_key=? AND beneficiary_group=? AND asset_version_id=?"
        params: list[object] = [period_key, group, version_id]
        if org is not None:
            sql += " AND org_id=?"
            params.append(org)
        if as_of is not None:
            sql += " AND occurred_at<=?"
            params.append(as_of)
        return int(connection.execute(sql, params).fetchone()["used"])

    # ---- 批量授权（从保存的队列位置接续）----

    def schedule_batch_grant(self, context: AccessContext, request_ids: list[str], *, run_at: str | None = None) -> str:
        context.require("grant:access_requests")
        ids = [require_safe(str(item), "申请标识") for item in request_ids]
        if not ids:
            raise ValidationError("批量授权不能为空")
        batch_id = new_id("batch")
        with self.database.transaction() as connection:
            connection.execute("INSERT INTO batch_cursors(cursor_key,position,updated_at) VALUES(?,?,?)", (f"batch:{batch_id}", "0", self.clock.now()))
            connection.execute("INSERT INTO scheduled_jobs(job_id,job_type,subject_id,run_at,payload_json,status) VALUES(?,?,?,?,?,'waiting')", (new_id("job"), "batch_grant", batch_id, run_at or self.clock.now(), canonical_json({"batch_id": batch_id, "request_ids": ids})))
        return batch_id

    def process_batch_grant(self, context: AccessContext, batch_id: str, *, page: int = 10) -> dict:
        """按游标位置续跑批量授权；每一项与其游标推进在同一事务内提交。"""
        context.require("grant:access_requests")
        if page < 1:
            raise ValidationError("页大小不合法")
        cursor_key = f"batch:{batch_id}"
        with self.database.connect() as connection:
            job = connection.execute("SELECT payload_json FROM scheduled_jobs WHERE job_type='batch_grant' AND subject_id=?", (batch_id,)).fetchone()
            if not job:
                raise NotFoundError("批量任务不存在")
            request_ids = json.loads(job["payload_json"])["request_ids"]
        results: list[dict] = []
        while len(results) < page:
            with self.database.transaction() as connection:
                row = connection.execute("SELECT position FROM batch_cursors WHERE cursor_key=?", (cursor_key,)).fetchone()
                if not row:
                    raise NotFoundError("批量游标不存在")
                index = int(row["position"])
                if index >= len(request_ids):
                    return {"batch_id": batch_id, "done": True, "processed": results}
                request_id = request_ids[index]
                connection.execute("SAVEPOINT batch_item")
                try:
                    outcome = self._grant_in(connection, context.actor_id, request_id)
                    connection.execute("RELEASE SAVEPOINT batch_item")
                    item = {"request_id": request_id, "status": "granted", "credential_id": outcome["credential_id"]}
                except CivicFlowError as exc:
                    connection.execute("ROLLBACK TO SAVEPOINT batch_item")
                    connection.execute("RELEASE SAVEPOINT batch_item")
                    item = {"request_id": request_id, "status": "failed", "error": str(exc)}
                connection.execute("INSERT INTO batch_items(cursor_key,item_index,subject_id,status,detail_json,processed_at) VALUES(?,?,?,?,?,?)", (cursor_key, index, request_id, item["status"], canonical_json(item), self.clock.now()))
                connection.execute("UPDATE batch_cursors SET position=?,updated_at=? WHERE cursor_key=?", (str(index + 1), self.clock.now(), cursor_key))
                results.append(item)
        return {"batch_id": batch_id, "done": False, "processed": results}

    def batch_status(self, context: AccessContext, batch_id: str) -> dict:
        context.require("read:access_requests")
        cursor_key = f"batch:{batch_id}"
        with self.database.connect() as connection:
            cursor = connection.execute("SELECT * FROM batch_cursors WHERE cursor_key=?", (cursor_key,)).fetchone()
            if not cursor:
                raise NotFoundError("批量任务不存在")
            items = []
            for row in connection.execute("SELECT * FROM batch_items WHERE cursor_key=? ORDER BY item_index", (cursor_key,)):
                item = dict(row)
                item["detail"] = json.loads(item.pop("detail_json"))
                items.append(item)
            job = connection.execute("SELECT status FROM scheduled_jobs WHERE job_type='batch_grant' AND subject_id=?", (batch_id,)).fetchone()
        return {"batch_id": batch_id, "position": int(cursor["position"]), "items": items, "job_status": job["status"] if job else None}

    # ---- 使用回执 ----

    def record_receipt(self, context: AccessContext, credential_id: str, receipt_key: str, payload: dict) -> dict:
        """登记使用回执：同一回执重试沿用原结果，异文进入隔离。"""
        context.require("receipt:access_requests")
        require_safe(receipt_key, "回执标识")
        if not isinstance(payload, dict):
            raise ValidationError("回执内容必须是对象")
        amount = payload.get("amount")
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < 1:
            raise ValidationError("回执用量必须为正整数")
        digest = digest_json(payload)
        with self.database.transaction() as connection:
            row = connection.execute("SELECT * FROM usage_receipts WHERE receipt_key=?", (receipt_key,)).fetchone()
            divergent = row is not None and row["payload_digest"] != digest
            if divergent:
                connection.execute("INSERT INTO receipt_quarantine(receipt_key,credential_id,existing_digest,incoming_digest,payload_json,received_at) VALUES(?,?,?,?,?,?)", (receipt_key, credential_id, row["payload_digest"], digest, canonical_json(payload), self.clock.now()))
        if divergent:
            raise ConflictError("相同回执标识内容不一致，已进入隔离")
        if row is not None:
            return {**json.loads(row["result_json"]), "replayed": True}
        outcome: tuple[str, object]
        with self.database.transaction() as connection:
            again = connection.execute("SELECT * FROM usage_receipts WHERE receipt_key=?", (receipt_key,)).fetchone()
            if again:
                outcome = ("replay", json.loads(again["result_json"]))
            else:
                credential = connection.execute("SELECT * FROM access_credentials WHERE credential_id=?", (credential_id,)).fetchone()
                if not credential:
                    raise NotFoundError("凭据不存在")
                now = self.clock.now()
                status = credential["status"]
                if status == "active" and credential["expires_at"] <= now:
                    connection.execute("UPDATE access_credentials SET status='expired' WHERE credential_id=?", (credential_id,))
                    status = "expired"
                if status != "active":
                    outcome = ("error", ConflictError(f"凭据状态为 {status}，不能登记回执"))
                else:
                    used = int(credential["used_quantity"]) + amount
                    if used > int(credential["quantity"]):
                        outcome = ("error", ConflictError("回执用量超出凭据额度"))
                    else:
                        new_status = "exhausted" if used == int(credential["quantity"]) else "active"
                        connection.execute("UPDATE access_credentials SET used_quantity=?,status=? WHERE credential_id=?", (used, new_status, credential_id))
                        result = {"receipt_key": receipt_key, "credential_id": credential_id, "used_quantity": used, "remaining": int(credential["quantity"]) - used, "status": new_status, "recorded_at": now}
                        connection.execute("INSERT INTO usage_receipts(receipt_key,credential_id,payload_digest,payload_json,result_json,received_at) VALUES(?,?,?,?,?,?)", (receipt_key, credential_id, digest, canonical_json(payload), canonical_json(result), now))
                        self.audit.append(connection, actor_id=context.actor_id, action="receipt", entity_type="access_credentials", entity_id=credential_id, version=1, detail={"receipt_key": receipt_key, "amount": amount, "used_quantity": used})
                        outcome = ("ok", result)
        kind, value = outcome
        if kind == "error":
            raise value
        if kind == "replay":
            return {**value, "replayed": True}
        return value

    def receipts_for(self, context: AccessContext, credential_id: str) -> list[dict]:
        """凭据的全部使用事实，吊销或到期后仍然可追溯。"""
        context.require("read:access_requests")
        with self.database.connect() as connection:
            rows = connection.execute("SELECT * FROM usage_receipts WHERE credential_id=? ORDER BY received_at,receipt_key", (credential_id,)).fetchall()
            return [{"receipt_key": row["receipt_key"], "payload": json.loads(row["payload_json"]), "result": json.loads(row["result_json"]), "received_at": row["received_at"]} for row in rows]

    def quarantined(self, context: AccessContext) -> list[dict]:
        context.require("read:access_requests")
        with self.database.connect() as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM receipt_quarantine ORDER BY quarantine_id")]

    def credential(self, context: AccessContext, credential_id: str) -> dict:
        context.require("read:access_requests")
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM access_credentials WHERE credential_id=?", (credential_id,)).fetchone()
            if not row:
                raise NotFoundError("凭据不存在")
            return dict(row)

    # ---- 处置任务 ----

    def complete_disposition(self, context: AccessContext, task_id: str, *, resolution: str, request_key: str) -> dict:
        context.require("dispose:access_requests")
        if resolution not in DISPOSITION_RESOLUTIONS:
            raise ValidationError("未知处置方式")
        with self.database.transaction() as connection:
            def operation() -> dict:
                row = connection.execute("SELECT * FROM disposition_tasks WHERE task_id=?", (task_id,)).fetchone()
                if not row:
                    raise NotFoundError("处置任务不存在")
                if row["status"] != "pending":
                    raise ConflictError("处置任务已办结")
                now = self.clock.now()
                connection.execute("UPDATE disposition_tasks SET status='done',resolved_at=?,resolution=? WHERE task_id=?", (now, resolution, task_id))
                if resolution == "revoked":
                    connection.execute("UPDATE access_credentials SET status='revoked' WHERE credential_id=? AND status IN ('active','exhausted')", (row["credential_id"],))
                self.audit.append(connection, actor_id=context.actor_id, action="dispose", entity_type="disposition_tasks", entity_id=task_id, version=1, detail={"resolution": resolution, "credential_id": row["credential_id"]})
                return {"task_id": task_id, "resolution": resolution, "resolved_at": now}
            return self.idempotency.execute(connection, scope=f"dispose:{task_id}", request_key=request_key, request={"resolution": resolution}, operation=operation)

    def dispositions(self, context: AccessContext, *, status: str | None = None) -> list[dict]:
        context.require("read:access_requests")
        sql = "SELECT * FROM disposition_tasks"
        params: list[object] = []
        if status is not None:
            sql += " WHERE status=?"
            params.append(status)
        sql += " ORDER BY created_at,task_id"
        with self.database.connect() as connection:
            return [dict(row) for row in connection.execute(sql, params)]

    # ---- 可恢复扫描与任务队列 ----

    def schedule_sweep(self, context: AccessContext, kind: str, *, run_at: str | None = None) -> str:
        context.require("sweep:access_requests")
        if kind not in SWEEP_KINDS:
            raise ValidationError("未知扫描类型")
        return self.jobs.schedule(job_type="ai_sweep", subject_id=kind, run_at=run_at or self.clock.now(), payload={"kind": kind})

    def run_sweep(self, context: AccessContext, kind: str, *, page: int = 25) -> dict:
        """处理到期、撤回与待审工作；每一项处理后保存队列位置，中断后可接续。"""
        context.require("sweep:access_requests")
        if kind not in SWEEP_KINDS:
            raise ValidationError("未知扫描类型")
        if page < 1:
            raise ValidationError("页大小不合法")
        cursor_key = f"sweep:{kind}"
        processed = 0
        while processed < page:
            with self.database.transaction() as connection:
                row = connection.execute("SELECT position FROM batch_cursors WHERE cursor_key=?", (cursor_key,)).fetchone()
                position = row["position"] if row else ""
                now = self.clock.now()
                if kind == "credential_expiry":
                    target = connection.execute("SELECT * FROM access_credentials WHERE status='active' AND expires_at<=? AND credential_id>? ORDER BY credential_id LIMIT 1", (now, position)).fetchone()
                    if not target:
                        self._save_cursor(connection, cursor_key, "")
                        return {"kind": kind, "processed": processed, "completed": True}
                    connection.execute("UPDATE access_credentials SET status='expired' WHERE credential_id=?", (target["credential_id"],))
                    self.audit.append(connection, actor_id=context.actor_id, action="expire", entity_type="access_credentials", entity_id=target["credential_id"], version=1, detail={"kind": kind})
                    self._save_cursor(connection, cursor_key, target["credential_id"])
                elif kind == "request_deadline":
                    target = connection.execute("SELECT * FROM entities WHERE entity_type='access_requests' AND state IN ('submitted','rights_cleared') AND entity_id>? ORDER BY entity_id LIMIT 1", (position,)).fetchone()
                    if not target:
                        self._save_cursor(connection, cursor_key, "")
                        return {"kind": kind, "processed": processed, "completed": True}
                    payload = json.loads(target["payload_json"])
                    deadline = payload.get("review_deadline")
                    if deadline and deadline <= now:
                        self.repository.update_in(connection, "access_requests", target["entity_id"], {"state": "expired", "expire_reason": "复核超期"}, actor=context.actor_id, expected_version=target["version"], request_key=f"sweep-expire:{target['entity_id']}:{target['version']}")
                    self._save_cursor(connection, cursor_key, target["entity_id"])
                else:
                    target = connection.execute("SELECT c.credential_id AS credential_id, c.asset_version_id AS asset_version_id FROM access_credentials c JOIN entities e ON e.entity_type='ai_versions' AND e.entity_id=c.asset_version_id WHERE c.status='active' AND e.state='withdrawn' AND c.credential_id>? AND NOT EXISTS (SELECT 1 FROM disposition_tasks t WHERE t.credential_id=c.credential_id AND t.status='pending') ORDER BY c.credential_id LIMIT 1", (position,)).fetchone()
                    if not target:
                        self._save_cursor(connection, cursor_key, "")
                        return {"kind": kind, "processed": processed, "completed": True}
                    task_id = new_id("task")
                    connection.execute("INSERT INTO disposition_tasks(task_id,asset_version_id,credential_id,kind,reason,status,created_at) VALUES(?,?,?,?,?,?,?)", (task_id, target["asset_version_id"], target["credential_id"], "withdrawn", "许可撤回兜底处置", "pending", now))
                    self.audit.append(connection, actor_id=context.actor_id, action="disposition", entity_type="disposition_tasks", entity_id=task_id, version=1, detail={"kind": kind, "credential_id": target["credential_id"]})
                    self._save_cursor(connection, cursor_key, target["credential_id"])
                processed += 1
        return {"kind": kind, "processed": processed, "completed": False}

    def run_due_jobs(self, context: AccessContext, *, limit: int = 10, page: int = 50) -> list[dict]:
        """驱动到期的批量授权与扫描任务；中断的任务从保存的位置接续。"""
        context.require("sweep:access_requests")
        outcomes = []
        for job in self.jobs.claim_due(limit=limit):
            try:
                if job["job_type"] == "ai_sweep":
                    result = self.run_sweep(context, json.loads(job["payload_json"])["kind"], page=page)
                    finished = result["completed"]
                elif job["job_type"] == "batch_grant":
                    result = self.process_batch_grant(context, job["subject_id"], page=page)
                    finished = result["done"]
                else:
                    raise ValidationError(f"未知任务类型 {job['job_type']}")
                if finished:
                    self.jobs.finish(job["job_id"])
                    outcomes.append({"job_id": job["job_id"], "status": "finished", "result": result})
                else:
                    self.jobs.retry(job["job_id"], error="工作未完成，继续", retry_at=self.clock.now())
                    outcomes.append({"job_id": job["job_id"], "status": "continue", "result": result})
            except CivicFlowError as exc:
                retry_at = (parse_instant(self.clock.now()) + timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
                self.jobs.retry(job["job_id"], error=str(exc), retry_at=retry_at)
                outcomes.append({"job_id": job["job_id"], "status": "retry", "error": str(exc)})
        return outcomes

    def _save_cursor(self, connection, cursor_key: str, position: str) -> None:
        connection.execute("INSERT INTO batch_cursors(cursor_key,position,updated_at) VALUES(?,?,?) ON CONFLICT(cursor_key) DO UPDATE SET position=excluded.position,updated_at=excluded.updated_at", (cursor_key, position, self.clock.now()))

    # ---- 时点再现 ----

    def explain(self, context: AccessContext, request_id: str, *, as_of: str | None = None) -> dict:
        """再现当时的成果组合、许可判断、群体配额与剩余额度，供再次申请或申诉核对。"""
        context.require("read:access_requests")
        request = self.repository.get("access_requests", request_id)
        with self.database.connect() as connection:
            decision_row = connection.execute("SELECT * FROM license_decisions WHERE request_id=?", (request_id,)).fetchone()
            decision = json.loads(decision_row["decision_json"]) if decision_row else None
            moment = canonical_instant(as_of) if as_of else (decision_row["decided_at"] if decision_row else request["updated_at"])
            if decision is not None and not as_of:
                snapshot = self.repository.revision("ai_versions", request["asset_version_id"], int(decision["version_revision"]))
            else:
                snapshot = self.repository.snapshot("ai_versions", request["asset_version_id"], as_of=moment)
            rights = snapshot["rights"]
            quota = snapshot["quota"]
            judgment = evaluate_rights(rights, request)
            period_key = period_key_for(moment, quota["period"])
            org_used = self._quota_used(connection, period_key, request["asset_version_id"], group=request["beneficiary_group"], org=request["org_id"], as_of=moment)
            group_used = self._quota_used(connection, period_key, request["asset_version_id"], group=request["beneficiary_group"], as_of=moment)
        return {
            "request_id": request_id,
            "request_state": request["state"],
            "as_of": moment,
            "combination": snapshot["combination"],
            "combination_digest": snapshot.get("combination_digest", ""),
            "version_revision": snapshot["version"],
            "rights": rights,
            "judgment": judgment,
            "period_key": period_key,
            "per_org": quota["per_org"],
            "per_group": quota["per_group"],
            "org_used": org_used,
            "group_used": group_used,
            "org_remaining": quota["per_org"] - org_used,
            "group_remaining": quota["per_group"] - group_used,
            "decision": decision,
        }
