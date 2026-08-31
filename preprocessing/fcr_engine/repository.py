"""
Forensic Correlation Record (FCR) Repository Implementation
============================================================
Thread-safe repository for persisting, indexing, and querying Stage-3 CorrelationRecord (FCR) objects.
"""

from __future__ import annotations

import logging
import threading
from typing import Optional, Sequence

from preprocessing.fcr_engine.schemas import CorrelationRecord

logger = logging.getLogger(__name__)


class FCRRepository:
    """
    In-memory thread-safe FCR Repository with multi-field indexing.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._by_id: dict[str, CorrelationRecord] = {}
        self._by_case: dict[str, set[str]] = {}
        self._by_host: dict[str, set[str]] = {}
        self._by_artifact: dict[str, set[str]] = {}
        self._by_rel: dict[str, set[str]] = {}

    def add_record(self, record: CorrelationRecord) -> bool:
        """
        Store a CorrelationRecord in the repository.

        Args:
            record: Validated CorrelationRecord instance.

        Returns:
            True if stored, False if duplicate correlation_id already exists.
        """
        if not isinstance(record, CorrelationRecord):
            raise TypeError("record must be an instance of CorrelationRecord")

        with self._lock:
            cid = record.correlation_id
            if cid in self._by_id:
                return False

            self._by_id[cid] = record

            # Index by case_id
            if record.case_id:
                self._by_case.setdefault(record.case_id, set()).add(cid)

            # Index by host
            if record.host:
                self._by_host.setdefault(record.host.lower(), set()).add(cid)

            # Index by artifact_id
            for aid in record.artifact_ids:
                self._by_artifact.setdefault(aid, set()).add(cid)

            # Index by relationship_type
            for rel in record.relationship_type:
                self._by_rel.setdefault(rel, set()).add(cid)

            return True

    def add_records(self, records: Sequence[CorrelationRecord]) -> int:
        """Store multiple CorrelationRecord instances. Returns count of new records stored."""
        count = 0
        with self._lock:
            for rec in records:
                if self.add_record(rec):
                    count += 1
        return count

    def get_record(self, correlation_id: str) -> Optional[CorrelationRecord]:
        """Retrieve CorrelationRecord by correlation_id."""
        with self._lock:
            return self._by_id.get(correlation_id)

    def list_by_case(self, case_id: str) -> list[CorrelationRecord]:
        """Retrieve all CorrelationRecord objects for a given case_id."""
        with self._lock:
            cids = self._by_case.get(case_id, set())
            return [self._by_id[cid] for cid in cids if cid in self._by_id]

    def list_by_host(self, host: str) -> list[CorrelationRecord]:
        """Retrieve all CorrelationRecord objects for a given host."""
        with self._lock:
            cids = self._by_host.get(host.lower(), set())
            return [self._by_id[cid] for cid in cids if cid in self._by_id]

    def list_by_artifact(self, artifact_id: str) -> list[CorrelationRecord]:
        """Retrieve all CorrelationRecord objects referencing a specific artifact_id."""
        with self._lock:
            cids = self._by_artifact.get(artifact_id, set())
            return [self._by_id[cid] for cid in cids if cid in self._by_id]

    def list_by_relationship(self, relationship_type: str) -> list[CorrelationRecord]:
        """Retrieve all CorrelationRecord objects matching a relationship_type."""
        with self._lock:
            cids = self._by_rel.get(relationship_type, set())
            return [self._by_id[cid] for cid in cids if cid in self._by_id]

    def count(self) -> int:
        """Total count of CorrelationRecords in the repository."""
        with self._lock:
            return len(self._by_id)

    def clear(self) -> None:
        """Reset repository."""
        with self._lock:
            self._by_id.clear()
            self._by_case.clear()
            self._by_host.clear()
            self._by_artifact.clear()
            self._by_rel.clear()

    def persist_to_postgres(self, db_conn: Any = None) -> int:
        """
        Optional SQL persistence method.
        Persists in-memory FCR records to PostgreSQL table fcr_records using parameterized queries.
        Returns count of new records inserted. If PostgreSQL is unavailable or fails, returns 0 cleanly.
        """
        with self._lock:
            if not self._by_id:
                return 0

            records_to_save = list(self._by_id.values())

        inserted_count = 0
        try:
            conn = db_conn
            close_conn = False

            if conn is None:
                try:
                    import psycopg2
                    from config.settings import settings
                    conn = psycopg2.connect(
                        host=settings.postgres_host,
                        port=settings.postgres_port,
                        dbname=settings.postgres_db,
                        user=settings.postgres_user,
                        password=settings.postgres_password,
                        connect_timeout=2
                    )
                    close_conn = True
                except Exception as e:
                    logger.debug("PostgreSQL not reachable for FCR persistence: %s", e)
                    return 0

            with conn.cursor() as cur:
                # Ensure table exists
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS fcr_records (
                        correlation_id VARCHAR(128) PRIMARY KEY,
                        case_id VARCHAR(128) NOT NULL,
                        relationship_type TEXT[] NOT NULL,
                        artifact_ids TEXT[] NOT NULL,
                        confidence DOUBLE PRECISION NOT NULL,
                        host VARCHAR(256),
                        shared_value TEXT,
                        strategy_params JSONB,
                        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
                    );
                    CREATE INDEX IF NOT EXISTS idx_fcr_case_id ON fcr_records(case_id);
                    CREATE INDEX IF NOT EXISTS idx_fcr_host ON fcr_records(host);
                """)
                
                import json
                for rec in records_to_save:
                    cur.execute("""
                        INSERT INTO fcr_records (
                            correlation_id, case_id, relationship_type, artifact_ids,
                            confidence, host, shared_value, strategy_params, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (correlation_id) DO NOTHING;
                    """, (
                        rec.correlation_id,
                        rec.case_id,
                        rec.relationship_type,
                        rec.artifact_ids,
                        rec.confidence,
                        rec.host,
                        rec.shared_value,
                        json.dumps(rec.strategy_params),
                        rec.created_at
                    ))
                    if cur.rowcount > 0:
                        inserted_count += 1

            if close_conn:
                conn.commit()
                conn.close()

        except Exception as e:
            logger.debug("FCR SQL persistence skipped or failed: %s", e)
            return 0

        return inserted_count
