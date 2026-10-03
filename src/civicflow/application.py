"""应用装配。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .access_requests import AccessRequestService
from .achievements import AchievementService, AchievementVersionService
from .audit import AuditLog
from .database import Database
from .grants import GrantService
from .idempotency import IdempotencyStore
from .inbox import Inbox
from .jobs import JobQueue
from .ledger import Ledger
from .outbox import Outbox
from .repository import EntityRepository
from .reservations import ReservationBook
from .timeutil import Clock


@dataclass(frozen=True)
class CivicFlow:
    database: Database
    clock: Clock
    audit: AuditLog
    idempotency: IdempotencyStore
    repository: EntityRepository
    inbox: Inbox
    outbox: Outbox
    ledger: Ledger
    reservations: ReservationBook
    jobs: JobQueue

    @classmethod
    def open(cls, path: str | Path, *, fixed_now: str | None = None) -> "CivicFlow":
        database = Database(path); database.initialize(); clock = Clock(fixed_now)
        audit = AuditLog(clock); idempotency = IdempotencyStore(clock)
        repository = EntityRepository(database, clock, audit, idempotency)
        return cls(database=database, clock=clock, audit=audit, idempotency=idempotency, repository=repository, inbox=Inbox(database, clock), outbox=Outbox(database, clock), ledger=Ledger(database, clock), reservations=ReservationBook(database), jobs=JobQueue(database, clock))

    def achievements(self) -> AchievementService:
        return AchievementService(self.repository)

    def achievement_versions(self) -> AchievementVersionService:
        return AchievementVersionService(self.repository, self.database, self.clock, self.audit, self.idempotency)

    def access_requests(self) -> AccessRequestService:
        return AccessRequestService(self.repository, self.clock)

    def grants(self) -> GrantService:
        return GrantService(self.database, self.repository, self.clock, self.audit, self.idempotency, self.jobs)

    def verify(self) -> dict:
        with self.database.connect() as connection:
            audit_count = AuditLog(self.clock).verify(connection)
            entity_count = connection.execute("SELECT COUNT(*) AS n FROM entities").fetchone()["n"]
            conflict_count = connection.execute("SELECT COUNT(*) AS n FROM inbox_conflicts").fetchone()["n"]
            credential_count = connection.execute("SELECT COUNT(*) AS n FROM access_credentials").fetchone()["n"]
            task_count = connection.execute("SELECT COUNT(*) AS n FROM disposition_tasks").fetchone()["n"]
        return {"audit_entries": audit_count, "entities": entity_count, "inbox_conflicts": conflict_count, "access_credentials": credential_count, "disposition_tasks": task_count}
