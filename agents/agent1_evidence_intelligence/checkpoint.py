"""
ARGUS Agent 1 — Persistent Checkpoint & Resume Manager
======================================================
Stores and retrieves execution checkpoint state for Agent 1 runs.
Enables resumable batch execution across process restarts.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set

logger = logging.getLogger(__name__)

_CHECKPOINT_TABLE_INITIALIZED = False


def _ensure_checkpoint_table_initialized(conn):
    global _CHECKPOINT_TABLE_INITIALIZED
    if _CHECKPOINT_TABLE_INITIALIZED:
        return
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS agent_checkpoints (
            id                 SERIAL PRIMARY KEY,
            run_id             TEXT NOT NULL,
            agent_id           TEXT NOT NULL DEFAULT 'agent1_evidence_intelligence',
            case_id            TEXT NOT NULL,
            batch_id           TEXT NOT NULL,
            batch_number       INT NOT NULL,
            fir_range          TEXT,
            status             TEXT NOT NULL DEFAULT 'COMPLETED',
            claims_count       INT DEFAULT 0,
            created_at         TIMESTAMPTZ DEFAULT NOW(),
            metadata           JSONB DEFAULT '{}',
            UNIQUE(run_id, batch_id)
        );
    """)
    conn.commit()
    _CHECKPOINT_TABLE_INITIALIZED = True


class Agent1CheckpointManager:
    """
    Manages batch execution state for Agent 1 full corpus runs.
    Uses PostgreSQL `agent_checkpoints` table with in-memory fallback.
    """

    _in_memory_checkpoints: Dict[str, Set[str]] = {}

    def __init__(self, run_id: str, agent_id: str = "agent1_evidence_intelligence"):
        self.run_id = run_id
        self.agent_id = agent_id

    def get_completed_batches(self) -> Set[str]:
        """Returns set of batch_ids that have completed for this run_id."""
        completed = set()

        # Check in-memory store
        if self.run_id in self._in_memory_checkpoints:
            completed.update(self._in_memory_checkpoints[self.run_id])

        # Query PostgreSQL
        try:
            import psycopg2
            from config.settings import settings
            conn = psycopg2.connect(
                host=settings.postgres_host,
                port=settings.postgres_port,
                database=settings.postgres_db,
                user=settings.postgres_user,
                password=settings.postgres_password,
                connect_timeout=3
            )
            _ensure_checkpoint_table_initialized(conn)
            cur = conn.cursor()
            cur.execute("""
                SELECT batch_id FROM agent_checkpoints
                WHERE run_id = %s AND status = 'COMPLETED'
            """, (self.run_id,))
            rows = cur.fetchall()
            for r in rows:
                completed.add(r[0])
            conn.close()
        except Exception as exc:
            logger.debug("PostgreSQL checkpoint fetch error: %s", exc)

        return completed

    def is_batch_completed(self, batch_id: str) -> bool:
        """Checks if a batch is marked completed."""
        return batch_id in self.get_completed_batches()

    def mark_batch_completed(
        self,
        case_id: str,
        batch_id: str,
        batch_number: int,
        fir_range: str,
        claims_count: int = 0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Marks a batch as completed atomically."""
        # 1. Update in-memory set
        if self.run_id not in self._in_memory_checkpoints:
            self._in_memory_checkpoints[self.run_id] = set()
        self._in_memory_checkpoints[self.run_id].add(batch_id)

        # 2. Persist to PostgreSQL
        try:
            import psycopg2
            from config.settings import settings
            conn = psycopg2.connect(
                host=settings.postgres_host,
                port=settings.postgres_port,
                database=settings.postgres_db,
                user=settings.postgres_user,
                password=settings.postgres_password,
                connect_timeout=3
            )
            _ensure_checkpoint_table_initialized(conn)
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO agent_checkpoints
                    (run_id, agent_id, case_id, batch_id, batch_number, fir_range, status, claims_count, created_at, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (run_id, batch_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    claims_count = EXCLUDED.claims_count,
                    created_at = EXCLUDED.created_at,
                    metadata = EXCLUDED.metadata;
            """, (
                self.run_id,
                self.agent_id,
                case_id,
                batch_id,
                batch_number,
                fir_range,
                "COMPLETED",
                claims_count,
                datetime.now(timezone.utc),
                json.dumps(metadata or {})
            ))
            conn.commit()
            conn.close()
            logger.info("Checkpoint saved for run_id=%s batch_id=%s", self.run_id, batch_id)
        except Exception as exc:
            logger.warning("PostgreSQL checkpoint save error: %s", exc)
