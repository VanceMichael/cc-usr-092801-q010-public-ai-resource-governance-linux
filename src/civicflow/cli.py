"""命令行入口。"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .application import CivicFlow
from .cases import CaseService
from .security import AccessContext


def emit(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def demo(app: CivicFlow) -> dict:
    context = AccessContext.system("demo-operator")
    cases = CaseService(app.repository)
    created = cases.create(context, {"case_type": "协同事项", "subject": "示例联合处置", "owner_org": "org:demo", "priority": "high", "opened_at": app.clock.now()}, request_key="demo-case")
    accepted = app.inbox.receive(source="demo", source_key=created["entity_id"], sequence=1, payload={"kind": "opened"}, occurred_at=app.clock.now())
    reservation = app.reservations.reserve(resource_id="room:joint", subject_id=created["entity_id"], quantity=2, capacity=10, start_at="2026-09-28T10:00:00+08:00", end_at="2026-09-28T11:00:00+08:00", actor=context.actor_id)
    debit = app.ledger.post(journal_key="demo", account="coordination", currency="CNY", amount="12.34", direction="debit", reference="demo-debit", actor=context.actor_id)
    credit = app.ledger.post(journal_key="demo", account="coordination", currency="CNY", amount="12.34", direction="credit", reference="demo-credit", actor=context.actor_id)
    message = app.outbox.enqueue(topic="case.opened", aggregate_id=created["entity_id"], payload={"case_id": created["entity_id"]})
    return {"case": created, "inbox": accepted, "reservation": reservation, "entries": [debit, credit], "balance": app.ledger.balance("demo", currency="CNY"), "message_id": message, "verification": app.verify()}


def demo_ai(app: CivicFlow) -> dict:
    operator = AccessContext.system("demo-operator")
    rights_reviewer = AccessContext.system("demo-rights")
    security_reviewer = AccessContext.system("demo-security")
    achievements = app.achievements(); versions = app.achievement_versions(); requests = app.access_requests(); grants = app.grants()
    assets = {}
    for key, asset_type, title in (("model", "model", "区域中文基础模型"), ("dataset", "dataset", "脱敏公开语料"), ("safety", "safety_note", "安全说明与评估")):
        asset = achievements.create(operator, {"asset_type": asset_type, "title": title, "owner_org": "org:soe-ai", "summary": title}, request_key=f"demo-ai-{key}")
        achievements.transition(operator, asset["entity_id"], "active", expected_version=1, reason="目录上架", request_key=f"demo-ai-{key}-active")
        assets[key] = asset["entity_id"]
    version = versions.create(operator, {"asset_id": assets["model"], "version_label": "v1.0", "combination": {"model_ref": assets["model"], "dataset_refs": [assets["dataset"]], "safety_ref": assets["safety"], "tool_refs": []}, "dependencies": [], "rights": {"source": "国资委开放授权-2026-001", "license_class": "fair-access", "regions": ["cn-east"], "purposes": ["research", "education"], "denied_purposes": ["military"], "eligible_groups": ["researchers", "students"]}, "quota": {"period": "monthly", "per_org": 10, "per_group": 100}, "summary": "首个开放版本"}, request_key="demo-ai-version")
    published = versions.publish(operator, version["entity_id"], expected_version=1, request_key="demo-ai-publish")
    application = requests.submit(operator, {"org_id": "org:univ-demo", "org_type": "university", "beneficiary_group": "researchers", "asset_version_id": version["entity_id"], "purpose": "research", "region": "cn-east", "quantity": 2, "emergency": False, "justification": "", "review_deadline": "2026-12-31T00:00:00Z"}, request_key="demo-ai-request")
    requests.rights_review(rights_reviewer, application["entity_id"], approve=True, expected_version=1, reason="符合公平可及要求", request_key="demo-ai-rights")
    cleared = requests.security_review(security_reviewer, application["entity_id"], approve=True, expected_version=2, reason="安全复核通过", request_key="demo-ai-security")
    granted = grants.grant(operator, application["entity_id"], request_key="demo-ai-grant")
    receipt = grants.record_receipt(operator, granted["credential_id"], "demo-ai-receipt-1", {"amount": 1, "note": "首次推理调用"})
    explanation = grants.explain(operator, application["entity_id"])
    return {"version": published, "request": cleared, "grant": granted, "receipt": receipt, "explain": explanation, "verification": app.verify()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="协同事务平台")
    parser.add_argument("--db", default=os.getenv("CIVICFLOW_DB", "civicflow.sqlite3"))
    parser.add_argument("--now", default=None, help="测试或演示使用的固定时间")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("demo")
    commands.add_parser("demo-ai")
    commands.add_parser("verify")
    commands.add_parser("list-cases")
    args = parser.parse_args(argv)
    app = CivicFlow.open(Path(args.db), fixed_now=args.now)
    if args.command == "demo": emit(demo(app))
    elif args.command == "demo-ai": emit(demo_ai(app))
    elif args.command == "verify": emit(app.verify())
    elif args.command == "list-cases": emit(CaseService(app.repository).list_current(AccessContext.system("cli")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
