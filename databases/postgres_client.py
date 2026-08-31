# ──────────────────────────────────────────────────────────────
# PostgreSQL Client
# ──────────────────────────────────────────────────────────────
# What is stored here:
#   - FIR findings (fact, confidence, severity, MITRE mapping,
#     evidence reference, timestamp)
#   - Case sessions (case_id, tenant_id, status, created_by)
#   - Chain-of-custody records (immutable append-only log)
#   - Audit logs (every action on every evidence item)
#   - Agent outputs (structured claims per agent, per case)
#   - Confidence scores (per claim, per verification check)
#   - ISM state (per-case stage tracking, retry counts)
# ──────────────────────────────────────────────────────────────

import asyncpg
import asyncio
from contextlib import asynccontextmanager
from typing import Any, List, Optional
from config.settings import settings


class PostgresClient:
    """
    Async PostgreSQL client using asyncpg.
    Used across all layers that need structured/relational storage.
    """

    def __init__(self):
        self._pool: Optional[asyncpg.Pool] = None

    async def connect(self):
        """Initialize the connection pool."""
        self._pool = await asyncpg.create_pool(
            dsn=settings.postgres_url,
            min_size=2,
            max_size=10,
            command_timeout=60,
        )

    async def disconnect(self):
        """Close the connection pool."""
        if self._pool:
            await self._pool.close()

    @asynccontextmanager
    async def transaction(self):
        """Context manager for a single transactional connection."""
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                yield conn

    async def fetch_one(self, query: str, *args) -> Optional[dict]:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(query, *args)
            return dict(row) if row else None

    async def fetch_all(self, query: str, *args) -> List[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, *args)
            return [dict(r) for r in rows]

    async def execute(self, query: str, *args) -> str:
        async with self._pool.acquire() as conn:
            return await conn.execute(query, *args)

    async def execute_many(self, query: str, args_list: list):
        async with self._pool.acquire() as conn:
            await conn.executemany(query, args_list)

    async def create_tables(self):
        """Create all Argus tables if they don't exist."""
        async with self._pool.acquire() as conn:
            await conn.execute("""
                -- Case Sessions
                CREATE TABLE IF NOT EXISTS case_sessions (
                    case_id     TEXT PRIMARY KEY,
                    tenant_id   TEXT NOT NULL,
                    created_by  TEXT NOT NULL,
                    created_at  TIMESTAMPTZ DEFAULT NOW(),
                    status      TEXT DEFAULT 'pending'
                );

                -- Evidence records
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id         TEXT PRIMARY KEY,
                    case_id             TEXT REFERENCES case_sessions(case_id),
                    filename            TEXT NOT NULL,
                    minio_bucket        TEXT NOT NULL,
                    minio_object_key    TEXT NOT NULL,
                    uploaded_by         TEXT NOT NULL,
                    upload_timestamp    TIMESTAMPTZ DEFAULT NOW(),
                    status              TEXT DEFAULT 'UPLOADED',
                    sandbox_result      TEXT,
                    sha256_hash         TEXT,
                    encrypted           BOOLEAN DEFAULT FALSE,
                    rfc3161_timestamp   TEXT,
                    file_size_bytes     BIGINT,
                    metadata            JSONB DEFAULT '{}'
                );

                -- Chain-of-custody log (immutable, append-only)
                CREATE TABLE IF NOT EXISTS custody_log (
                    id              SERIAL PRIMARY KEY,
                    evidence_id     TEXT REFERENCES evidence(evidence_id),
                    action          TEXT NOT NULL,
                    actor           TEXT NOT NULL,
                    timestamp       TIMESTAMPTZ DEFAULT NOW(),
                    notes           TEXT
                );

                -- Audit log (every action on every evidence item)
                CREATE TABLE IF NOT EXISTS audit_log (
                    id          SERIAL PRIMARY KEY,
                    case_id     TEXT,
                    evidence_id TEXT,
                    tenant_id   TEXT,
                    action      TEXT NOT NULL,
                    actor       TEXT NOT NULL,
                    timestamp   TIMESTAMPTZ DEFAULT NOW(),
                    details     JSONB DEFAULT '{}'
                );

                -- FIR findings (Forensic Intelligence Repository)
                CREATE TABLE IF NOT EXISTS fir_findings (
                    finding_id          TEXT PRIMARY KEY,
                    case_id             TEXT REFERENCES case_sessions(case_id),
                    fact                TEXT NOT NULL,
                    confidence          FLOAT NOT NULL,
                    severity            TEXT NOT NULL,
                    mitre_mapping       TEXT,
                    evidence_reference  TEXT[] NOT NULL DEFAULT '{}',
                    layer               TEXT NOT NULL,
                    timestamp           TIMESTAMPTZ DEFAULT NOW(),
                    raw_data            JSONB DEFAULT '{}'
                );

                -- Agent outputs (structured claims per agent per case)
                CREATE TABLE IF NOT EXISTS agent_outputs (
                    id              SERIAL PRIMARY KEY,
                    case_id         TEXT REFERENCES case_sessions(case_id),
                    agent_id        TEXT NOT NULL,
                    claim           TEXT NOT NULL,
                    evidence_ids    TEXT[] DEFAULT '{}',
                    confidence      FLOAT,
                    verified        BOOLEAN,
                    flags           JSONB DEFAULT '[]',
                    created_at      TIMESTAMPTZ DEFAULT NOW()
                );

                -- ISM state tracking
                CREATE TABLE IF NOT EXISTS ism_state (
                    case_id         TEXT REFERENCES case_sessions(case_id),
                    stage           TEXT NOT NULL,
                    status          TEXT NOT NULL,
                    retry_count     INT DEFAULT 0,
                    last_updated    TIMESTAMPTZ DEFAULT NOW(),
                    checkpoint      JSONB DEFAULT '{}',
                    PRIMARY KEY (case_id, stage)
                );
            """)


# Singleton instance
postgres = PostgresClient()
