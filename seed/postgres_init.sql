-- ══════════════════════════════════════════════════════════════
-- Argus — PostgreSQL Schema Seed
-- Runs automatically the FIRST TIME the postgres container starts.
-- What gets committed to git: this schema file, NOT the actual data.
-- ══════════════════════════════════════════════════════════════

-- ── Cases (one row per investigation) ──────────────────────────
CREATE TABLE IF NOT EXISTS cases (
    case_id      UUID        PRIMARY KEY,
    tenant_id    TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by   TEXT        NOT NULL,
    status       TEXT        NOT NULL DEFAULT 'open'   -- open / closed / archived
);

-- ── Evidence (one row per uploaded file) ───────────────────────
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id       UUID        PRIMARY KEY,
    case_id           UUID        REFERENCES cases(case_id),
    filename          TEXT        NOT NULL,
    uploaded_by       TEXT        NOT NULL,
    upload_timestamp  TIMESTAMPTZ NOT NULL DEFAULT now(),
    status            TEXT        NOT NULL DEFAULT 'uploaded',
    sha256_hash       TEXT,
    encrypted         BOOLEAN     DEFAULT FALSE,
    rfc3161_timestamp TEXT,
    metadata          JSONB       DEFAULT '{}',
    repository_path   TEXT        -- MinIO object key (production) or local path (dev)
);

-- ── Chain-of-Custody Log (append-only, evidentiary) ────────────
CREATE TABLE IF NOT EXISTS custody_log (
    id          SERIAL      PRIMARY KEY,
    evidence_id UUID        REFERENCES evidence(evidence_id),
    actor       TEXT        NOT NULL,
    action      TEXT        NOT NULL,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT now(),
    notes       TEXT
);

-- ── Audit Log (operational, not evidentiary) ───────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id          SERIAL      PRIMARY KEY,
    case_id     UUID,
    evidence_id UUID,
    tenant_id   TEXT,
    event       TEXT        NOT NULL,
    actor       TEXT,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT now(),
    detail      JSONB       DEFAULT '{}'
);

-- ── FIR Findings (Forensic Intelligence Repository) ────────────
-- finding_id format: "F-2291" -- matches what agents cite in evidence_ids
-- MIGRATION NOTE FOR EXISTING DEPLOYMENTS:
-- To migrate an existing database with scalar TEXT evidence_reference:
-- ALTER TABLE fir_findings ALTER COLUMN evidence_reference TYPE TEXT[]
--   USING CASE WHEN evidence_reference LIKE '%,%' THEN string_to_array(evidence_reference, ', ') ELSE ARRAY[evidence_reference] END;
CREATE TABLE IF NOT EXISTS fir_findings (
    finding_id         TEXT        PRIMARY KEY,
    evidence_id        UUID        REFERENCES evidence(evidence_id),
    case_id            UUID        REFERENCES cases(case_id),
    source_engine      TEXT        NOT NULL,   -- e.g. "log_analysis", "network_analysis"
    fact               TEXT        NOT NULL,
    confidence         FLOAT,
    severity           TEXT,
    mitre_mapping      TEXT,
    evidence_reference TEXT[]      DEFAULT '{}',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    raw_data           JSONB       DEFAULT '{}'
);

-- ── Agent Outputs (structured claims per agent, per case) ───────
CREATE TABLE IF NOT EXISTS agent_outputs (
    id           SERIAL      PRIMARY KEY,
    case_id      UUID        REFERENCES cases(case_id),
    agent_id     TEXT        NOT NULL,   -- e.g. "agent1", "agent7_call1"
    claim        TEXT        NOT NULL,
    evidence_ids TEXT[]      DEFAULT '{}',
    confidence   FLOAT,
    verified     BOOLEAN,
    flags        JSONB       DEFAULT '[]',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── ISM State (per-case stage tracking) ────────────────────────
CREATE TABLE IF NOT EXISTS ism_state (
    case_id      UUID        REFERENCES cases(case_id),
    stage        TEXT        NOT NULL,
    status       TEXT        NOT NULL,
    retry_count  INT         DEFAULT 0,
    last_updated TIMESTAMPTZ DEFAULT now(),
    checkpoint   JSONB       DEFAULT '{}',
    PRIMARY KEY (case_id, stage)
);

-- ── Sample seed row so local FIR is not completely empty ────────
INSERT INTO cases (case_id, tenant_id, created_by)
VALUES ('00000000-0000-0000-0000-000000000001', 'dev-team', 'team-lead')
ON CONFLICT DO NOTHING;
