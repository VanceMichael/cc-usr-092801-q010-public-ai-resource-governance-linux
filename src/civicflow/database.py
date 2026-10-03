"""SQLite 连接、事务和数据库初始化。"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = r"""
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS entities (
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    state TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    PRIMARY KEY(entity_type, entity_id)
);
CREATE TABLE IF NOT EXISTS entity_versions (
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    state TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    request_key TEXT NOT NULL,
    PRIMARY KEY(entity_type, entity_id, version)
);
CREATE INDEX IF NOT EXISTS entity_versions_asof ON entity_versions(entity_type, entity_id, valid_from, version);
CREATE TABLE IF NOT EXISTS idempotency_keys (
    scope TEXT NOT NULL,
    request_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(scope, request_key)
);
CREATE TABLE IF NOT EXISTS audit_entries (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    detail_json TEXT NOT NULL,
    previous_digest TEXT NOT NULL,
    entry_digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS inbox_messages (
    source TEXT NOT NULL,
    source_key TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    payload_digest TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    status TEXT NOT NULL,
    PRIMARY KEY(source, source_key, sequence)
);
CREATE TABLE IF NOT EXISTS inbox_conflicts (
    conflict_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    source_key TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    existing_digest TEXT NOT NULL,
    incoming_digest TEXT NOT NULL,
    received_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS outbox_messages (
    message_id TEXT PRIMARY KEY,
    topic TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    available_at TEXT NOT NULL,
    lease_until TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    delivered_at TEXT
);
CREATE INDEX IF NOT EXISTS outbox_ready ON outbox_messages(status, available_at, lease_until);
CREATE TABLE IF NOT EXISTS journal_entries (
    entry_id TEXT PRIMARY KEY,
    journal_key TEXT NOT NULL,
    account TEXT NOT NULL,
    currency TEXT NOT NULL,
    amount_minor INTEGER NOT NULL,
    direction TEXT NOT NULL,
    reference TEXT NOT NULL,
    reversed_entry_id TEXT,
    occurred_at TEXT NOT NULL,
    posted_by TEXT NOT NULL,
    FOREIGN KEY(reversed_entry_id) REFERENCES journal_entries(entry_id)
);
CREATE INDEX IF NOT EXISTS journal_reference ON journal_entries(journal_key, reference, occurred_at);
CREATE TABLE IF NOT EXISTS resource_reservations (
    reservation_id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    start_at TEXT NOT NULL,
    end_at TEXT NOT NULL,
    status TEXT NOT NULL,
    version INTEGER NOT NULL,
    created_by TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS reservation_window ON resource_reservations(resource_id, start_at, end_at, status);
CREATE TABLE IF NOT EXISTS scheduled_jobs (
    job_id TEXT PRIMARY KEY,
    job_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    run_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 0,
    lease_until TEXT,
    last_error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS jobs_due ON scheduled_jobs(status, run_at, lease_until);
-- 人工智能成果共享治理
CREATE TABLE IF NOT EXISTS ai_catalog (
    artifact_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    state TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    updated_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_releases (
    release_id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL,
    version_tag TEXT NOT NULL,
    components_json TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    state TEXT NOT NULL,
    rights_position INTEGER NOT NULL DEFAULT 0,
    published_at TEXT NOT NULL,
    published_by TEXT NOT NULL,
    UNIQUE(artifact_id, version_tag)
);
CREATE TABLE IF NOT EXISTS ai_rights_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    release_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    terms_json TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    effective_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    prior_event_id INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ai_rights_release ON ai_rights_events(release_id, event_id);
CREATE TABLE IF NOT EXISTS ai_derivatives (
    derivative_id TEXT PRIMARY KEY,
    release_id TEXT NOT NULL,
    credential_id TEXT NOT NULL DEFAULT '',
    org_id TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    manifest_digest TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ai_derivatives_release ON ai_derivatives(release_id, state);
CREATE TABLE IF NOT EXISTS ai_disposition_tasks (
    task_id TEXT PRIMARY KEY,
    derivative_id TEXT NOT NULL,
    release_id TEXT NOT NULL,
    trigger_event_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    resolution TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE(derivative_id, trigger_event_id)
);
CREATE INDEX IF NOT EXISTS ai_disposition_status ON ai_disposition_tasks(status, created_at);
CREATE TABLE IF NOT EXISTS ai_quota_policies (
    policy_id TEXT PRIMARY KEY,
    release_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    period_kind TEXT NOT NULL,
    limit_qty INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(release_id, org_id, group_id)
);
CREATE TABLE IF NOT EXISTS ai_quota_ledger (
    entry_id TEXT PRIMARY KEY,
    release_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    period_key TEXT NOT NULL,
    direction TEXT NOT NULL,
    qty INTEGER NOT NULL,
    reference TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    UNIQUE(reference, direction)
);
CREATE INDEX IF NOT EXISTS ai_quota_sum ON ai_quota_ledger(release_id, org_id, group_id, period_key);
CREATE TABLE IF NOT EXISTS ai_access_requests (
    request_id TEXT PRIMARY KEY,
    release_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    use_cases_json TEXT NOT NULL,
    region TEXT NOT NULL,
    requested_qty INTEGER NOT NULL,
    emergency INTEGER NOT NULL DEFAULT 0,
    emergency_reason TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL,
    submitter TEXT NOT NULL,
    rights_reviewer TEXT,
    rights_decision TEXT,
    rights_reason TEXT NOT NULL DEFAULT '',
    rights_at TEXT,
    security_reviewer TEXT,
    security_decision TEXT,
    security_reason TEXT NOT NULL DEFAULT '',
    security_at TEXT,
    rights_position INTEGER NOT NULL DEFAULT 0,
    period_key TEXT NOT NULL DEFAULT '',
    valid_to TEXT,
    decision_context_json TEXT NOT NULL DEFAULT '{}',
    submitted_at TEXT NOT NULL,
    decided_at TEXT
);
CREATE INDEX IF NOT EXISTS ai_requests_state ON ai_access_requests(state, submitted_at);
CREATE TABLE IF NOT EXISTS ai_credentials (
    credential_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    release_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    token_digest TEXT NOT NULL,
    state TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT NOT NULL,
    revoke_event_id INTEGER,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS ai_credentials_release ON ai_credentials(release_id, state);
CREATE TABLE IF NOT EXISTS ai_usage_receipts (
    receipt_id TEXT PRIMARY KEY,
    receipt_key TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    release_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    outcome TEXT NOT NULL,
    result_json TEXT NOT NULL,
    reported_at TEXT NOT NULL,
    reporter TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_receipt_quarantine (
    quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_key TEXT NOT NULL,
    existing_digest TEXT NOT NULL,
    incoming_digest TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    received_at TEXT NOT NULL,
    reporter TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ai_quarantine_key ON ai_receipt_quarantine(receipt_key, quarantine_id);
CREATE TABLE IF NOT EXISTS ai_work_queue (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id TEXT NOT NULL UNIQUE,
    item_type TEXT NOT NULL,
    ref_id TEXT NOT NULL,
    run_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    lease_until TEXT,
    last_error TEXT NOT NULL DEFAULT '',
    enqueued_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ai_work_ready ON ai_work_queue(status, run_at, lease_until);
"""


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(SCHEMA)

    @contextmanager
    def transaction(self, *, immediate: bool = True) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
