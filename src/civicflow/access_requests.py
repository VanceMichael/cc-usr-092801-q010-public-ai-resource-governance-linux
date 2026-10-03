"""人工智能成果访问申请与分级复核。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .identifiers import require_safe
from .repository import EntityRepository
from .security import AccessContext
from .timeutil import Clock, canonical_instant

ENTITY_TYPE = "access_requests"
ORG_TYPES = ("university", "sme", "public_institution")
STATES = ("submitted", "rights_cleared", "security_cleared", "granted", "rejected", "expired", "withdrawn")
FIELDS = ("org_id", "org_type", "beneficiary_group", "asset_version_id", "purpose", "region", "quantity", "emergency", "justification", "review_deadline")


@dataclass(frozen=True)
class AccessRequestService:
    """访问申请：提交、权益审核与安全复核，三个角色不得互相代批。"""

    _repository: EntityRepository
    _clock: Clock

    @property
    def entity_type(self) -> str:
        return ENTITY_TYPE

    def submit(self, context: AccessContext, values: Mapping[str, object], *, request_key: str) -> dict:
        context.require("write:access_requests")
        payload = self._validate(values)
        try:
            version = self._repository.get("ai_versions", payload["asset_version_id"])
        except NotFoundError as exc:
            raise ValidationError("申请的成果版本不存在") from exc
        if version["state"] != "published":
            raise ConflictError("成果版本未发布或已撤回")
        payload["state"] = STATES[0]
        payload["submitter"] = context.actor_id
        payload["submitted_at"] = self._clock.now()
        return self._repository.create(self.entity_type, payload, actor=context.actor_id, request_key=request_key)

    def rights_review(self, context: AccessContext, request_id: str, *, approve: bool, expected_version: int, reason: str, request_key: str) -> dict:
        """权益审核：核对许可与公平可及要求，提交者不能审核自己的事项。"""
        context.require("review:access_requests")
        current = self._repository.get(self.entity_type, request_id)
        if current["state"] != "submitted":
            raise ConflictError("申请不在权益审核环节")
        if context.actor_id == current["submitter"]:
            raise PermissionDenied("提交者不能审核自己的事项")
        if not reason.strip():
            raise ValidationError("复核必须说明理由")
        target = "rights_cleared" if approve else "rejected"
        changes = {"state": target, "rights_reviewer": context.actor_id, "rights_decision": {"approve": bool(approve), "reason": reason.strip(), "at": self._clock.now()}}
        return self._repository.update(self.entity_type, request_id, changes, actor=context.actor_id, expected_version=expected_version, request_key=request_key)

    def security_review(self, context: AccessContext, request_id: str, *, approve: bool, expected_version: int, reason: str, request_key: str) -> dict:
        """安全复核：提交者与权益审核人都不能代行安全复核。"""
        context.require("review:access_requests")
        current = self._repository.get(self.entity_type, request_id)
        if current["state"] != "rights_cleared":
            raise ConflictError("申请不在安全复核环节")
        if context.actor_id in {current["submitter"], current.get("rights_reviewer")}:
            raise PermissionDenied("提交者、权益审核人与安全复核人不得互相代批")
        if not reason.strip():
            raise ValidationError("复核必须说明理由")
        target = "security_cleared" if approve else "rejected"
        changes = {"state": target, "security_reviewer": context.actor_id, "security_decision": {"approve": bool(approve), "reason": reason.strip(), "at": self._clock.now()}}
        return self._repository.update(self.entity_type, request_id, changes, actor=context.actor_id, expected_version=expected_version, request_key=request_key)

    def cancel(self, context: AccessContext, request_id: str, *, expected_version: int, reason: str, request_key: str) -> dict:
        context.require("write:access_requests")
        current = self._repository.get(self.entity_type, request_id)
        if current["state"] not in {"submitted", "rights_cleared"}:
            raise ConflictError("当前状态不能撤回申请")
        if context.actor_id != current["submitter"] and not context.allows("transition:access_requests"):
            raise PermissionDenied("只有提交者可以撤回申请")
        if not reason.strip():
            raise ValidationError("撤回必须说明原因")
        return self._repository.update(self.entity_type, request_id, {"state": "withdrawn", "withdraw_reason": reason.strip()}, actor=context.actor_id, expected_version=expected_version, request_key=request_key)

    def get(self, context: AccessContext, request_id: str) -> dict:
        context.require("read:access_requests")
        return self._repository.get(self.entity_type, request_id)

    def list_current(self, context: AccessContext, *, state: str | None = None, limit: int = 100) -> list[dict]:
        context.require("read:access_requests")
        if state is not None and state not in STATES:
            raise ValidationError("未知状态")
        return self._repository.list(self.entity_type, state=state, limit=limit)

    def history(self, context: AccessContext, request_id: str) -> list[dict]:
        context.require("history:access_requests")
        rows = self._repository.history(self.entity_type, request_id)
        if not rows:
            raise NotFoundError(f"{self.entity_type}/{request_id} 不存在")
        return rows

    def _validate(self, values: Mapping[str, object]) -> dict:
        unknown = set(values) - set(FIELDS)
        if unknown:
            raise ValidationError("未知字段: " + ", ".join(sorted(unknown)))
        missing = [field for field in ("org_id", "org_type", "beneficiary_group", "asset_version_id", "purpose", "region", "quantity") if field not in values]
        if missing:
            raise ValidationError("缺少字段: " + ", ".join(missing))
        payload = dict(values)
        payload["org_id"] = require_safe(str(payload["org_id"]), "机构标识")
        if payload["org_type"] not in ORG_TYPES:
            raise ValidationError("机构类型必须是 university、sme 或 public_institution")
        payload["beneficiary_group"] = require_safe(str(payload["beneficiary_group"]), "受益群体")
        payload["asset_version_id"] = require_safe(str(payload["asset_version_id"]), "成果版本标识")
        payload["purpose"] = require_safe(str(payload["purpose"]), "用途")
        payload["region"] = require_safe(str(payload["region"]), "区域")
        quantity = payload["quantity"]
        if isinstance(quantity, bool) or not isinstance(quantity, int) or quantity < 1:
            raise ValidationError("申请数量必须是正整数")
        emergency = payload.get("emergency", False)
        if not isinstance(emergency, bool):
            raise ValidationError("emergency 必须是布尔值")
        payload["emergency"] = emergency
        justification = str(payload.get("justification", "")).strip()
        if emergency and not justification:
            raise ValidationError("紧急公共用途必须说明例外理由")
        payload["justification"] = justification
        deadline = payload.get("review_deadline")
        payload["review_deadline"] = canonical_instant(deadline) if deadline else ""
        return payload
