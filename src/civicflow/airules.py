"""人工智能成果共享的许可判断、配额周期与权利收窄规则。"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Mapping

from .errors import ValidationError
from .identifiers import require_safe
from .timeutil import parse_instant

QUOTA_PERIODS = ("monthly", "quarterly")


def period_key_for(instant: str, period: str) -> str:
    """把时点归入配额周期键，例如 2026-10 或 2026-Q4。"""
    moment = parse_instant(instant)
    if period == "monthly":
        return f"{moment.year:04d}-{moment.month:02d}"
    if period == "quarterly":
        return f"{moment.year:04d}-Q{(moment.month - 1) // 3 + 1}"
    raise ValidationError("未知配额周期")


def period_end_for(instant: str, period: str) -> str:
    """配额周期结束（下一周期开始）的时点，用作凭据到期时间。"""
    moment = parse_instant(instant)
    if period == "monthly":
        year, month = (moment.year + 1, 1) if moment.month == 12 else (moment.year, moment.month + 1)
    elif period == "quarterly":
        month = ((moment.month - 1) // 3) * 3 + 4
        year, month = (moment.year + 1, 1) if month > 12 else (moment.year, month)
    else:
        raise ValidationError("未知配额周期")
    return datetime(year, month, 1, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def evaluate_rights(rights: Mapping[str, object], request: Mapping[str, object]) -> dict:
    """对照成果许可、区域限制与适用人群判断一次申请是否合规。"""
    purposes = set(rights.get("purposes", []))
    denied = set(rights.get("denied_purposes", []))
    purpose = str(request.get("purpose", ""))
    return {
        "group_eligible": str(request.get("beneficiary_group", "")) in set(rights.get("eligible_groups", [])),
        "purpose_allowed": purpose in purposes and purpose not in denied,
        "region_allowed": str(request.get("region", "")) in set(rights.get("regions", [])),
    }


def rights_satisfied(judgment: Mapping[str, bool]) -> bool:
    return all(bool(value) for value in judgment.values())


def _safe_list(value: object, label: str, *, allow_empty: bool) -> list[str]:
    if not isinstance(value, (list, tuple)):
        raise ValidationError(f"{label}必须是列表")
    result = [require_safe(str(item), label) for item in value]
    if not result and not allow_empty:
        raise ValidationError(f"{label}不能为空")
    if len(set(result)) != len(result):
        raise ValidationError(f"{label}不能重复")
    return result


def validate_rights(rights: object, *, allow_empty: bool = False) -> dict:
    """校验权利声明结构：权利来源、许可类别、区域、用途与适用人群。"""
    if not isinstance(rights, Mapping):
        raise ValidationError("权利声明必须是对象")
    unknown = set(rights) - {"source", "license_class", "regions", "purposes", "denied_purposes", "eligible_groups"}
    if unknown:
        raise ValidationError("权利声明包含未知字段: " + ", ".join(sorted(unknown)))
    source = rights.get("source")
    if not isinstance(source, str) or not source.strip():
        raise ValidationError("权利来源不能为空")
    return {
        "source": source.strip(),
        "license_class": require_safe(str(rights.get("license_class", "")), "许可类别"),
        "regions": _safe_list(rights.get("regions"), "适用区域", allow_empty=allow_empty),
        "purposes": _safe_list(rights.get("purposes"), "允许用途", allow_empty=allow_empty),
        "denied_purposes": _safe_list(rights.get("denied_purposes", []), "禁止用途", allow_empty=True),
        "eligible_groups": _safe_list(rights.get("eligible_groups"), "适用人群", allow_empty=allow_empty),
    }


def validate_quota(quota: object) -> dict:
    """校验周期配额结构：周期、机构上限与受益群体上限。"""
    if not isinstance(quota, Mapping):
        raise ValidationError("配额声明必须是对象")
    unknown = set(quota) - {"period", "per_org", "per_group"}
    if unknown:
        raise ValidationError("配额声明包含未知字段: " + ", ".join(sorted(unknown)))
    period = quota.get("period")
    if period not in QUOTA_PERIODS:
        raise ValidationError("配额周期必须是 monthly 或 quarterly")
    per_org = quota.get("per_org")
    per_group = quota.get("per_group")
    for label, value in (("机构配额", per_org), ("群体配额", per_group)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValidationError(f"{label}必须是正整数")
    if per_org > per_group:
        raise ValidationError("机构配额不能大于群体配额")
    return {"period": period, "per_org": per_org, "per_group": per_group}


def assert_rights_narrowing(current: Mapping[str, object], narrowed: Mapping[str, object]) -> None:
    """权利只能收窄：集合只能缩小、禁止用途只能增加。"""
    for key, label in (("regions", "适用区域"), ("purposes", "允许用途"), ("eligible_groups", "适用人群")):
        if not set(narrowed[key]) <= set(current[key]):
            raise ValidationError(f"{label}只能收窄，不能新增")
    if not set(narrowed["denied_purposes"]) >= set(current["denied_purposes"]):
        raise ValidationError("禁止用途只能增加，不能减少")


def assert_quota_narrowing(current: Mapping[str, object], narrowed: Mapping[str, object]) -> None:
    """配额只能调低，且收窄不能改变周期口径。"""
    if narrowed["period"] != current["period"]:
        raise ValidationError("收窄不能改变配额周期")
    if narrowed["per_org"] > current["per_org"] or narrowed["per_group"] > current["per_group"]:
        raise ValidationError("配额只能调低，不能调高")
