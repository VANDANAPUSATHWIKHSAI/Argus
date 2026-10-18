"""
Cross-Cutting Investigation State Management (ISM) — Checkpointing & Recovery
==============================================================================
Provides durable case/stage state, retries, idempotency, checkpoints, and resume capability.
Dual-persistence architecture:
1. Redis (live fast state & execution checkpoints)
2. PostgreSQL (durable relational ism_state storage)
With transparent thread-safe in-memory fallback for resilient local operation.
"""

import os
import json
import logging
import threading
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from config.settings import settings

logger = logging.getLogger("ArgusISM")


def build_ism_idempotency_key(
    case_id: str,
    tenant_id: str = "default",
    evidence_ids: Optional[List[str]] = None,
    pipeline_version: str = "1.0.0",
    execution_context: Optional[Dict[str, Any]] = None
) -> str:
    """
    Helper to generate deterministic idempotency key for ISM deduplication.
    Covers tenant, case, sorted evidence set, pipeline version, and execution context.
    Prevents stale checkpoints from skipping work when inputs or pipeline versions change.
    """
    import hashlib
    ev_list = sorted(evidence_ids) if evidence_ids else []
    sorted_ev = ",".join(ev_list)
    ctx_str = f":{json.dumps(execution_context, sort_keys=True)}" if execution_context else ""
    ver_str = f":{pipeline_version}" if pipeline_version != "1.0.0" else ""
    raw = f"{case_id}:{tenant_id}:{sorted_ev}{ver_str}{ctx_str}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class Checkpointer:
    """
    Cross-cutting state and checkpoint manager.
    Coordinates between Redis and PostgreSQL ism_state table.
    Enforces tenant isolation, idempotency key matching, and failure resilience.
    """
    _in_memory_state: Dict[str, Dict[str, Any]] = {}
    _lock = threading.Lock()

    def __init__(self, postgres_conn=None, redis_client=None):
        self._pg_conn = postgres_conn
        self._redis = redis_client
        self._pg_unreachable = False

    def _get_redis(self):
        if self._redis is not None:
            return self._redis
        try:
            from databases.redis_client import redis_client
            return redis_client
        except Exception:
            return None

    def _get_pg_conn(self):
        if self._pg_conn is not None:
            return self._pg_conn
        if self._pg_unreachable:
            return None
        try:
            import psycopg2
            conn = psycopg2.connect(
                host=settings.postgres_host,
                port=settings.postgres_port,
                user=settings.postgres_user,
                password=settings.postgres_password,
                dbname=settings.postgres_db,
                connect_timeout=3
            )
            return conn
        except Exception as e:
            logger.debug("Postgres connection unavailable for ISM checkpointer: %s", e)
            self._pg_unreachable = True
            return None

    def save_stage_checkpoint(
        self,
        case_id: str,
        stage: str,
        state: Dict[str, Any],
        status: str = "COMPLETED",
        retry_count: int = 0,
        tenant_id: str = "default",
        idempotency_key: Optional[str] = None,
        pipeline_version: str = "1.0.0"
    ) -> bool:
        """
        Saves a stage checkpoint durably to Redis, PostgreSQL ism_state, and in-memory cache.
        Enforces tenant isolation, idempotency key tracking, and graceful fallback on DB/Redis failures.
        """
        payload = {
            "case_id": case_id,
            "tenant_id": tenant_id,
            "stage": stage,
            "status": status,
            "retry_count": retry_count,
            "idempotency_key": idempotency_key,
            "pipeline_version": pipeline_version,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checkpoint": state
        }
        json_str = json.dumps(payload, default=str)

        # 1. Update in-memory fallback (thread-safe, tenant-aware + legacy flat)
        with self._lock:
            if case_id not in self._in_memory_state:
                self._in_memory_state[case_id] = {}
            self._in_memory_state[case_id][stage] = payload

            scoped_key = f"{tenant_id}:{case_id}"
            if scoped_key not in self._in_memory_state:
                self._in_memory_state[scoped_key] = {}
            self._in_memory_state[scoped_key][stage] = payload

        # 2. Redis fast checkpoint
        rc = self._get_redis()
        if rc:
            try:
                rc.set_checkpoint(case_id, stage, json_str)
                if tenant_id != "default":
                    rc.set_checkpoint(f"{tenant_id}:{case_id}", stage, json_str)
            except Exception as re:
                logger.warning("Redis checkpoint write warning: %s", re)

        # 3. PostgreSQL durable ism_state
        conn = self._get_pg_conn()
        if conn:
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS ism_state (
                            case_id         TEXT NOT NULL,
                            stage           TEXT NOT NULL,
                            status          TEXT NOT NULL,
                            retry_count     INT DEFAULT 0,
                            last_updated    TIMESTAMPTZ DEFAULT NOW(),
                            checkpoint      JSONB DEFAULT '{}',
                            PRIMARY KEY (case_id, stage)
                        );
                    """)
                    cur.execute("""
                        INSERT INTO cases (case_id, tenant_id, created_by)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (case_id) DO NOTHING;
                    """, (case_id, tenant_id or "default", "argus_system"))
                    cur.execute("""
                        INSERT INTO ism_state (case_id, stage, status, retry_count, last_updated, checkpoint)
                        VALUES (%s, %s, %s, %s, NOW(), %s)
                        ON CONFLICT (case_id, stage) DO UPDATE SET
                            status = EXCLUDED.status,
                            retry_count = ism_state.retry_count + EXCLUDED.retry_count,
                            last_updated = NOW(),
                            checkpoint = EXCLUDED.checkpoint;
                    """, (case_id, stage, status, retry_count, json_str))
                conn.commit()
            except Exception as pe:
                logger.warning("PostgreSQL ism_state write warning: %s", pe)
                try:
                    conn.rollback()
                except Exception:
                    pass

        return True

    def get_stage_checkpoint(
        self,
        case_id: str,
        stage: str,
        tenant_id: Optional[str] = None,
        expected_idempotency_key: Optional[str] = None,
        expected_version: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieves stage checkpoint from Redis first, then PostgreSQL, then in-memory.
        Enforces tenant isolation, idempotency key matching, and version freshness.
        Returns None if checkpoint is missing or stale.
        """
        candidate = None

        # 1. Redis
        rc = self._get_redis()
        if rc:
            try:
                if tenant_id and tenant_id != "default":
                    cached = rc.get_checkpoint(f"{tenant_id}:{case_id}", stage)
                    if cached:
                        candidate = json.loads(cached)
                if not candidate:
                    cached = rc.get_checkpoint(case_id, stage)
                    if cached:
                        candidate = json.loads(cached)
            except Exception as re:
                logger.debug("Redis checkpoint read warning: %s", re)

        # 2. PostgreSQL
        if not candidate:
            conn = self._get_pg_conn()
            if conn:
                try:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT status, retry_count, last_updated, checkpoint FROM ism_state WHERE case_id = %s AND stage = %s",
                            (case_id, stage)
                        )
                        row = cur.fetchone()
                        if row:
                            status, retries, updated, cp_data = row
                            if isinstance(cp_data, str):
                                cp_data = json.loads(cp_data)
                            if isinstance(cp_data, dict) and "checkpoint" in cp_data:
                                candidate = cp_data
                            else:
                                candidate = {
                                    "case_id": case_id,
                                    "stage": stage,
                                    "status": status,
                                    "retry_count": retries,
                                    "timestamp": str(updated),
                                    "checkpoint": cp_data
                                }
                except Exception as pe:
                    logger.debug("PostgreSQL ism_state read warning: %s", pe)

        # 3. In-memory fallback
        if not candidate:
            with self._lock:
                if tenant_id:
                    candidate = self._in_memory_state.get(f"{tenant_id}:{case_id}", {}).get(stage)
                if not candidate:
                    candidate = self._in_memory_state.get(case_id, {}).get(stage)

        if not candidate:
            return None

        # --- AUDIT & VALIDATION GATES ---
        # 1. Tenant Isolation
        if tenant_id and "tenant_id" in candidate:
            stored_tenant = candidate.get("tenant_id")
            if stored_tenant and stored_tenant != tenant_id and stored_tenant != "default":
                logger.warning(
                    "Tenant isolation mismatch for case %s: requested %s but checkpoint belongs to %s",
                    case_id, tenant_id, stored_tenant
                )
                return None

        # 2. Stale Checkpoint Prevention: Idempotency Key Validation
        if expected_idempotency_key and candidate.get("idempotency_key"):
            if candidate["idempotency_key"] != expected_idempotency_key:
                logger.info(
                    "Stale checkpoint detected for case %s stage %s: idempotency_key mismatch (%s vs %s). Skipping stale checkpoint.",
                    case_id, stage, candidate["idempotency_key"], expected_idempotency_key
                )
                return None

        # 3. Version Freshness Validation
        if expected_version and candidate.get("pipeline_version"):
            if candidate["pipeline_version"] != expected_version:
                logger.info(
                    "Stale checkpoint detected for case %s stage %s: version mismatch (%s vs %s). Skipping stale checkpoint.",
                    case_id, stage, candidate["pipeline_version"], expected_version
                )
                return None

        return candidate

    def get_case_state(self, case_id: str, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Retrieves all stages and cumulative status for a case.
        """
        stages = {}
        # From in-memory
        with self._lock:
            if tenant_id:
                stages.update(self._in_memory_state.get(f"{tenant_id}:{case_id}", {}))
            if not stages:
                stages.update(self._in_memory_state.get(case_id, {}))

        # Supplement from PostgreSQL
        conn = self._get_pg_conn()
        if conn:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT stage, status, retry_count, last_updated, checkpoint FROM ism_state WHERE case_id = %s",
                        (case_id,)
                    )
                    for stage, status, retries, updated, cp_data in cur.fetchall():
                        if isinstance(cp_data, str):
                            cp_data = json.loads(cp_data)
                        if tenant_id and isinstance(cp_data, dict):
                            stored_tenant = cp_data.get("tenant_id")
                            if stored_tenant and stored_tenant != tenant_id and stored_tenant != "default":
                                continue
                        stages[stage] = {
                            "case_id": case_id,
                            "stage": stage,
                            "status": status,
                            "retry_count": retries,
                            "timestamp": str(updated),
                            "checkpoint": cp_data
                        }
            except Exception:
                pass

        return stages

    # Legacy method compatibility
    def save(self, case_id: str, stage: str, state: dict) -> bool:
        return self.save_stage_checkpoint(case_id=case_id, stage=stage, state=state)

    def load(self, case_id: str) -> dict:
        return self.get_case_state(case_id=case_id)
