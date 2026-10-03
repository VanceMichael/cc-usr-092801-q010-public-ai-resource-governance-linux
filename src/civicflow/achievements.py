"""人工智能成果目录与成果版本：发布冻结、权利收窄与撤回。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Mapping

from .airules import (assert_quota_narrowing, assert_rights_narrowing,
                      evaluate_rights, rights_satisfied, validate_quota,
                      validate_rights)
from .audit import AuditLog
from .database import Database
from .errors import ConflictError, NotFoundError, ValidationError
from .identifiers import new_id, require_safe
from .idempotency import IdempotencyStore
from .jsonutil import digest_json
from .repository import EntityRepository
from .security import AccessContext
from .timeutil import Clock

ASSET_ENTITY_TYPE = "ai_assets"
ASSET_TYPES = ("model", "dataset", "compute_tool", "safety_note")
ASSET_STATES = ("draft", "active", "retired")
ASSET_TRANSITIONS = {
    "draft": {"active"},
    "active": {"retired"},
    "retired": {"retired"},
}
ASSET_FIELDS = ("asset_type", "title", "owner_org", "summary")

VERSION_ENTITY_TYPE = "ai_versions"
VERSION_STATES = ("draft", "published", "withdrawn")
VERSION_FIELDS = ("asset_id", "version_label", "combination", "dependencies", "rights", "quota", "summary")
FROZEN_AFTER_PUBLISH = ("asset_id", "version_label", "combination", "dependencies", "rights", "quota")


@dataclass(frozen=True)
class AchievementService:
    """人工智能成果目录：模型、数据集、算力工具与安全说明。"""

    _repository: EntityRepository

    @property
    def entity_type(self) -> str:
        return ASSET_ENTITY_TYPE

    def create(self, context: AccessContext, values: Mapping[str, object], *, request_key: str) -> dict:
        context.require("write:ai_assets")
        payload = self._validate(values, partial=False)
        payload["state"] = ASSET_STATES[0]
        return self._repository.create(self.entity_type, payload, actor=context.actor_id, request_key=request_key)

    def revise(self, context: AccessContext, entity_id: str, values: Mapping[str, object], *, expected_version: int, request_key: str) -> dict:
        context.require("write:ai_assets")
        payload = self._validate(values, partial=True)
        if "state" in payload:
            raise ValidationError("状态必须通过 transition 修改")
        return self._repository.update(self.entity_type, entity_id, payload, actor=context.actor_id, expected_version=expected_version, request_key=request_key)

    def transition(self, context: AccessContext, entity_id: str, target: str, *, expected_version: int, reason: str, request_key: str) -> dict:
        context.require("transition:ai_assets")
        current = self._repository.get(self.entity_type, entity_id)
        allowed = ASSET_TRANSITIONS.get(str(current["state"]), set())
        if target not in allowed:
            raise ConflictError(f"不允许从 {current['state']} 转到 {target}")
        if not reason.strip():
            raise ValidationError("状态变更必须说明原因")
        return self._repository.update(self.entity_type, entity_id, {"state": target, "transition_reason": reason.strip()}, actor=context.actor_id, expected_version=expected_version, request_key=request_key)

    def get(self, context: AccessContext, entity_id: str) -> dict:
        context.require("read:ai_assets")
        return self._repository.get(self.entity_type, entity_id)

    def list_current(self, context: AccessContext, *, state: str | None = None, limit: int = 100) -> list[dict]:
        context.require("read:ai_assets")
        if state is not None and state not in ASSET_STATES:
            raise ValidationError("未知状态")
        return self._repository.list(self.entity_type, state=state, limit=limit)

    def history(self, context: AccessContext, entity_id: str) -> list[dict]:
        context.require("history:ai_assets")
        rows = self._repository.history(self.entity_type, entity_id)
        if not rows:
            raise NotFoundError(f"{self.entity_type}/{entity_id} 不存在")
        return rows

    def _validate(self, values: Mapping[str, object], *, partial: bool) -> dict:
        unknown = set(values) - set(ASSET_FIELDS) - {"state", "transition_reason"}
        if unknown:
            raise ValidationError("未知字段: " + ", ".join(sorted(unknown)))
        if not partial:
            missing = [field for field in ASSET_FIELDS if field not in values]
            if missing:
                raise ValidationError("缺少字段: " + ", ".join(missing))
        payload = dict(values)
        if "asset_type" in payload and payload["asset_type"] not in ASSET_TYPES:
            raise ValidationError("成果类型必须是 model、dataset、compute_tool 或 safety_note")
        if "owner_org" in payload:
            payload["owner_org"] = require_safe(str(payload["owner_org"]), "权属机构")
        for key in ("title", "summary"):
            if key in payload:
                text = str(payload[key]).strip()
                if not text:
                    raise ValidationError(f"{key} 不能为空字符串")
                payload[key] = text
        return payload


@dataclass(frozen=True)
class AchievementVersionService:
    """成果版本：发布即冻结组合，权利收窄只影响后续访问并生成处置任务。"""

    _repository: EntityRepository
    _database: Database
    _clock: Clock
    _audit: AuditLog
    _idempotency: IdempotencyStore

    @property
    def entity_type(self) -> str:
        return VERSION_ENTITY_TYPE

    def create(self, context: AccessContext, values: Mapping[str, object], *, request_key: str) -> dict:
        context.require("write:ai_versions")
        payload = self._validate(values, partial=False)
        payload["state"] = VERSION_STATES[0]
        payload["rights_generation"] = 1
        return self._repository.create(self.entity_type, payload, actor=context.actor_id, request_key=request_key)

    def revise(self, context: AccessContext, version_id: str, values: Mapping[str, object], *, expected_version: int, request_key: str) -> dict:
        context.require("write:ai_versions")
        current = self._repository.get(self.entity_type, version_id)
        payload = self._validate(values, partial=True)
        if "state" in payload:
            raise ValidationError("状态必须通过 publish、narrow_rights 或 withdraw 修改")
        if current["state"] != "draft" and set(payload) & set(FROZEN_AFTER_PUBLISH):
            raise ValidationError("发布后成果组合与权利已冻结，权利调整请使用 narrow_rights")
        return self._repository.update(self.entity_type, version_id, payload, actor=context.actor_id, expected_version=expected_version, request_key=request_key)

    def publish(self, context: AccessContext, version_id: str, *, expected_version: int, request_key: str) -> dict:
        """发布版本并冻结模型、数据与安全说明的组合。"""
        context.require("transition:ai_versions")
        current = self._repository.get(self.entity_type, version_id)
        if current["state"] != "draft":
            raise ConflictError("只有草稿版本可以发布")
        self._check_combination_refs(current["asset_id"], current["combination"])
        self._check_dependencies(current["dependencies"])
        changes = {"state": "published", "combination_digest": digest_json(current["combination"]), "published_at": self._clock.now()}
        return self._repository.update(self.entity_type, version_id, changes, actor=context.actor_id, expected_version=expected_version, request_key=request_key)

    def narrow_rights(self, context: AccessContext, version_id: str, *, rights: Mapping[str, object] | None = None, quota: Mapping[str, object] | None = None, expected_version: int, reason: str, request_key: str) -> dict:
        """收窄权利或配额：只影响后续访问，并为仍有效的派生成果生成处置任务。"""
        context.require("transition:ai_versions")
        if not reason.strip():
            raise ValidationError("收窄权利必须说明原因")
        if rights is None and quota is None:
            raise ValidationError("收窄内容不能为空")
        new_rights = validate_rights(rights, allow_empty=True) if rights is not None else None
        new_quota = validate_quota(quota) if quota is not None else None
        with self._database.transaction() as connection:
            def operation() -> dict:
                row = self._row(connection, version_id)
                current = json.loads(row["payload_json"])
                if row["state"] != "published":
                    raise ConflictError("只有已发布版本可以收窄权利")
                changes: dict = {}
                if new_rights is not None:
                    assert_rights_narrowing(current["rights"], new_rights)
                    changes["rights"] = new_rights
                if new_quota is not None:
                    assert_quota_narrowing(current["quota"], new_quota)
                    changes["quota"] = new_quota
                changes["rights_generation"] = int(current.get("rights_generation", 1)) + 1
                changes["narrow_reason"] = reason.strip()
                updated = self._repository.update_in(connection, self.entity_type, version_id, changes, actor=context.actor_id, expected_version=expected_version, request_key=request_key)
                effective_rights = changes.get("rights", current["rights"])
                tasks = self._fan_out_dispositions(connection, version_id, kind="narrowed", reason=reason.strip(), rights=effective_rights)
                self._audit.append(connection, actor_id=context.actor_id, action="narrow_rights", entity_type=self.entity_type, entity_id=version_id, version=updated["version"], detail={"changes": changes, "disposition_tasks": tasks})
                return {**updated, "disposition_tasks": tasks}
            return self._idempotency.execute(connection, scope=f"narrow:{version_id}", request_key=request_key, request={"rights": new_rights, "quota": new_quota, "reason": reason.strip(), "expected_version": expected_version}, operation=operation)

    def withdraw(self, context: AccessContext, version_id: str, *, expected_version: int, reason: str, request_key: str) -> dict:
        """撤回许可：后续发放立即停止，仍有效的凭据转入处置。"""
        context.require("transition:ai_versions")
        if not reason.strip():
            raise ValidationError("撤回必须说明原因")
        with self._database.transaction() as connection:
            def operation() -> dict:
                row = self._row(connection, version_id)
                if row["state"] != "published":
                    raise ConflictError("只有已发布版本可以撤回")
                changes = {"state": "withdrawn", "withdraw_reason": reason.strip(), "withdrawn_at": self._clock.now()}
                updated = self._repository.update_in(connection, self.entity_type, version_id, changes, actor=context.actor_id, expected_version=expected_version, request_key=request_key)
                tasks = self._fan_out_dispositions(connection, version_id, kind="withdrawn", reason=reason.strip(), rights=None)
                self._audit.append(connection, actor_id=context.actor_id, action="withdraw", entity_type=self.entity_type, entity_id=version_id, version=updated["version"], detail={"reason": reason.strip(), "disposition_tasks": tasks})
                return {**updated, "disposition_tasks": tasks}
            return self._idempotency.execute(connection, scope=f"withdraw:{version_id}", request_key=request_key, request={"reason": reason.strip(), "expected_version": expected_version}, operation=operation)

    def get(self, context: AccessContext, version_id: str) -> dict:
        context.require("read:ai_versions")
        return self._repository.get(self.entity_type, version_id)

    def list_current(self, context: AccessContext, *, state: str | None = None, limit: int = 100) -> list[dict]:
        context.require("read:ai_versions")
        if state is not None and state not in VERSION_STATES:
            raise ValidationError("未知状态")
        return self._repository.list(self.entity_type, state=state, limit=limit)

    def history(self, context: AccessContext, version_id: str) -> list[dict]:
        context.require("history:ai_versions")
        rows = self._repository.history(self.entity_type, version_id)
        if not rows:
            raise NotFoundError(f"{self.entity_type}/{version_id} 不存在")
        return rows

    def snapshot(self, context: AccessContext, version_id: str, *, as_of: str) -> dict:
        context.require("history:ai_versions")
        return self._repository.snapshot(self.entity_type, version_id, as_of=as_of)

    def _row(self, connection, version_id: str):
        row = connection.execute("SELECT * FROM entities WHERE entity_type=? AND entity_id=?", (self.entity_type, version_id)).fetchone()
        if not row:
            raise NotFoundError(f"{self.entity_type}/{version_id} 不存在")
        return row

    def _fan_out_dispositions(self, connection, version_id: str, *, kind: str, reason: str, rights: Mapping[str, object] | None) -> list[str]:
        """为不再合规的既有凭据与仍有效的派生成果生成处置任务。"""
        now = self._clock.now()
        tasks: list[str] = []
        rows = connection.execute("SELECT * FROM access_credentials WHERE asset_version_id=? AND status='active'", (version_id,)).fetchall()
        for credential in rows:
            if rights is not None:
                judgment = evaluate_rights(rights, {"beneficiary_group": credential["beneficiary_group"], "purpose": credential["purpose"], "region": credential["region"]})
                if rights_satisfied(judgment):
                    continue
            task_id = new_id("task")
            connection.execute("INSERT INTO disposition_tasks(task_id,asset_version_id,credential_id,kind,reason,status,created_at) VALUES(?,?,?,?,?,?,?)", (task_id, version_id, credential["credential_id"], kind, reason, "pending", now))
            tasks.append(task_id)
        dependents = connection.execute("SELECT entity_id,payload_json FROM entities WHERE entity_type=? AND state='published'", (self.entity_type,)).fetchall()
        for dependent in dependents:
            payload = json.loads(dependent["payload_json"])
            if version_id not in payload.get("dependencies", []):
                continue
            derived = connection.execute("SELECT * FROM access_credentials WHERE asset_version_id=? AND status='active'", (dependent["entity_id"],)).fetchall()
            for credential in derived:
                task_id = new_id("task")
                connection.execute("INSERT INTO disposition_tasks(task_id,asset_version_id,credential_id,kind,reason,status,created_at) VALUES(?,?,?,?,?,?,?)", (task_id, dependent["entity_id"], credential["credential_id"], "dependency", f"依赖版本 {version_id} 权利变化: {reason}", "pending", now))
                tasks.append(task_id)
        return tasks

    def _check_combination_refs(self, asset_id: str, combination: Mapping[str, object]) -> None:
        if combination["model_ref"] != asset_id:
            raise ValidationError("组合中的模型引用必须与版本所属成果一致")
        self._check_asset_ref(combination["model_ref"], "model")
        self._check_asset_ref(combination["safety_ref"], "safety_note")
        for ref in combination["dataset_refs"]:
            self._check_asset_ref(ref, "dataset")
        for ref in combination["tool_refs"]:
            self._check_asset_ref(ref, "compute_tool")

    def _check_asset_ref(self, ref: str, expected_type: str) -> None:
        try:
            asset = self._repository.get(ASSET_ENTITY_TYPE, ref)
        except NotFoundError as exc:
            raise ValidationError(f"成果组合引用的目录条目不存在: {ref}") from exc
        if asset["asset_type"] != expected_type:
            raise ValidationError(f"目录条目 {ref} 类型应为 {expected_type}")
        if asset["state"] != "active":
            raise ValidationError(f"目录条目 {ref} 未上架")

    def _check_dependencies(self, dependencies: list[str]) -> None:
        for dependency in dependencies:
            try:
                row = self._repository.get(self.entity_type, dependency)
            except NotFoundError as exc:
                raise ValidationError(f"依赖的成果版本不存在: {dependency}") from exc
            if row["state"] != "published":
                raise ValidationError(f"依赖的成果版本未发布: {dependency}")

    def _validate(self, values: Mapping[str, object], *, partial: bool) -> dict:
        unknown = set(values) - set(VERSION_FIELDS) - {"state", "transition_reason"}
        if unknown:
            raise ValidationError("未知字段: " + ", ".join(sorted(unknown)))
        if not partial:
            missing = [field for field in ("asset_id", "version_label", "combination", "rights", "quota") if field not in values]
            if missing:
                raise ValidationError("缺少字段: " + ", ".join(missing))
        payload = dict(values)
        if "asset_id" in payload:
            payload["asset_id"] = require_safe(str(payload["asset_id"]), "成果标识")
        if "version_label" in payload:
            label = str(payload["version_label"]).strip()
            if not label:
                raise ValidationError("版本标识不能为空")
            payload["version_label"] = label
        if "summary" in payload:
            payload["summary"] = str(payload["summary"]).strip()
        if "combination" in payload:
            payload["combination"] = self._validate_combination(payload["combination"])
        if "dependencies" in payload:
            payload["dependencies"] = self._validate_dependencies(payload["dependencies"])
        if "rights" in payload:
            payload["rights"] = validate_rights(payload["rights"])
        if "quota" in payload:
            payload["quota"] = validate_quota(payload["quota"])
        if not partial:
            payload.setdefault("dependencies", [])
            payload.setdefault("summary", "")
        return payload

    @staticmethod
    def _validate_combination(combination: object) -> dict:
        if not isinstance(combination, Mapping):
            raise ValidationError("成果组合必须是对象")
        unknown = set(combination) - {"model_ref", "dataset_refs", "safety_ref", "tool_refs"}
        if unknown:
            raise ValidationError("成果组合包含未知字段: " + ", ".join(sorted(unknown)))
        dataset_refs = combination.get("dataset_refs", [])
        tool_refs = combination.get("tool_refs", [])
        if not isinstance(dataset_refs, (list, tuple)) or not isinstance(tool_refs, (list, tuple)):
            raise ValidationError("数据集与算力工具引用必须是列表")
        return {
            "model_ref": require_safe(str(combination.get("model_ref", "")), "模型引用"),
            "safety_ref": require_safe(str(combination.get("safety_ref", "")), "安全说明引用"),
            "dataset_refs": [require_safe(str(item), "数据集引用") for item in dataset_refs],
            "tool_refs": [require_safe(str(item), "算力工具引用") for item in tool_refs],
        }

    @staticmethod
    def _validate_dependencies(dependencies: object) -> list[str]:
        if not isinstance(dependencies, (list, tuple)):
            raise ValidationError("版本依赖必须是列表")
        return [require_safe(str(item), "依赖版本") for item in dependencies]
