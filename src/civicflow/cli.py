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


def ai_demo(app: CivicFlow) -> dict:
    """人工智能成果共享治理离线演示。"""
    svc = app.ai_sharing
    artifact = svc.register_artifact("demo-operator", kind="model", name="公共政务大模型", request_key="demo-artifact")
    release = svc.publish_release(
        "demo-operator", artifact["artifact_id"], "1.0.0",
        components={"model": {"ref": "model://gov-llm", "version": "1.0.0", "digest": "sha256:m"},
                    "dataset": {"ref": "data://public-corpus", "version": "2026-09", "digest": "sha256:d"},
                    "security": {"ref": "sec://safety-sheet", "version": "3", "digest": "sha256:s"}},
        rights={"groups": ["group:university", "group:sme"],
                "purposes": ["research", "public-service"],
                "use_cases": ["政务问答", "教学研究"],
                "regions": ["CN"]},
        request_key="demo-release")
    svc.put_quota_policy("demo-operator", release["release_id"], "org:univ", "group:university", limit=2, request_key="demo-quota")
    request = svc.submit_access_request(
        "user:teacher", release["release_id"], org_id="org:univ", group_id="group:university",
        purpose="research", use_cases=["教学研究"], region="CN",
        valid_to="2026-12-31T23:59:59+08:00", request_key="demo-request")
    svc.rights_review("user:rights-officer", request["request_id"], decision="approved", reason="符合开放范围")
    issued = svc.security_review("user:security-officer", request["request_id"], decision="approved", reason="安全复核通过")
    credential_id = issued["credential"]["credential_id"]
    receipt = svc.report_usage(
        "user:teacher", credential_id, "receipt-1",
        {"purpose": "research", "use_cases": ["教学研究"], "region": "CN"})
    replay = svc.report_usage(
        "user:teacher", credential_id, "receipt-1",
        {"purpose": "research", "use_cases": ["教学研究"], "region": "CN"})
    svc.register_derivative("user:teacher", release["release_id"], "org:univ",
                            description="课堂微调模型", request_key="demo-derivative")
    narrowed = svc.narrow_release(
        "demo-operator", release["release_id"],
        terms={"groups": ["group:university"], "purposes": ["research"],
               "use_cases": ["教学研究"], "regions": ["CN"]},
        reason="中小企业试点结束", request_key="demo-narrow")
    appeal = svc.appeal_view(request["request_id"])
    work = svc.run_due()
    return {"artifact": artifact, "release": release, "quota": svc.quota_status(release["release_id"], "org:univ", "group:university"),
            "request_state": issued["state"], "receipt": receipt, "receipt_replayed": replay["replayed"],
            "narrow": narrowed, "disposition_tasks": svc.disposition_tasks(),
            "appeal_quota": appeal["decision_quota"], "work_processed": work, "verification": app.verify()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="协同事务平台")
    parser.add_argument("--db", default=os.getenv("CIVICFLOW_DB", "civicflow.sqlite3"))
    parser.add_argument("--now", default=None, help="测试或演示使用的固定时间")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("demo")
    commands.add_parser("ai-demo")
    commands.add_parser("verify")
    commands.add_parser("list-cases")
    args = parser.parse_args(argv)
    app = CivicFlow.open(Path(args.db), fixed_now=args.now)
    if args.command == "demo": emit(demo(app))
    elif args.command == "ai-demo": emit(ai_demo(app))
    elif args.command == "verify": emit(app.verify())
    elif args.command == "list-cases": emit(CaseService(app.repository).list_current(AccessContext.system("cli")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
