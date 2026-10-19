-- ══════════════════════════════════════════════════════════════
-- Argus — PostgreSQL Schema Seed
-- Runs automatically the FIRST TIME the postgres container starts.
-- What gets committed to git: this schema file, NOT the actual data.
-- ══════════════════════════════════════════════════════════════

-- ── Cases (one row per investigation) ──────────────────────────
CREATE TABLE IF NOT EXISTS cases (
    case_id      TEXT        PRIMARY KEY,
    tenant_id    TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by   TEXT        NOT NULL,
    status       TEXT        NOT NULL DEFAULT 'open'   -- open / closed / archived
);

-- ── Evidence (one row per uploaded file) ───────────────────────
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id       TEXT        PRIMARY KEY,
    case_id           TEXT        REFERENCES cases(case_id),
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
    evidence_id TEXT        REFERENCES evidence(evidence_id),
    actor       TEXT        NOT NULL,
    action      TEXT        NOT NULL,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT now(),
    notes       TEXT
);

-- ── Audit Log (operational, not evidentiary) ───────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id          SERIAL      PRIMARY KEY,
    case_id     TEXT,
    evidence_id TEXT,
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
    evidence_id        TEXT        REFERENCES evidence(evidence_id),
    case_id            TEXT        REFERENCES cases(case_id),
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
    case_id      TEXT        REFERENCES cases(case_id),
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
    case_id      TEXT        REFERENCES cases(case_id),
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

-- -- Case Notes ------------------------------------------------
CREATE TABLE IF NOT EXISTS case_notes (
    note_id VARCHAR PRIMARY KEY,
    case_id VARCHAR REFERENCES cases(case_id),
    tenant_id TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    type TEXT NOT NULL,
    priority TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    related_evidence_id TEXT,
    related_finding_id TEXT
);

-- -- Users (roles and credentials) --------------------------------
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(255) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,
    phone VARCHAR(50),
    doj VARCHAR(50)
);

INSERT INTO users (id, email, password_hash, role, name, phone, doj) VALUES
('2', 'admin2@argus.local', '$2b$12$R00p584VWscdIX6j2MUTSOE5rafy3w8BUQYifTUST8lgxCdqXusSC', 'admin', 'System Administrator', '+1-555-0100', '2025-01-01'),
('4', 'vandanapusathwikhsai88@gmail.com', '$2b$12$R00p584VWscdIX6j2MUTSOE5rafy3w8BUQYifTUST8lgxCdqXusSC', 'analyst', 'sathwik', '+1-555-0101', '2025-01-15'),
('5', 'analyst5@argus.local', '$2b$12$R00p584VWscdIX6j2MUTSOE5rafy3w8BUQYifTUST8lgxCdqXusSC', 'analyst', 'Analyst 5', '+1-555-0102', '2025-01-15'),
('6', 'remakhat115@gmail.com', '$2b$12$R00p584VWscdIX6j2MUTSOE5rafy3w8BUQYifTUST8lgxCdqXusSC', 'senior_analyst', 'Senior Analyst 6', '+1-555-0103', '2025-01-10'),
('7', 'senior7@argus.local', '$2b$12$R00p584VWscdIX6j2MUTSOE5rafy3w8BUQYifTUST8lgxCdqXusSC', 'senior_analyst', 'Senior Analyst 7', '+1-555-0104', '2025-01-10'),
('8', 'senior8@argus.local', '$2b$12$R00p584VWscdIX6j2MUTSOE5rafy3w8BUQYifTUST8lgxCdqXusSC', 'senior_analyst', 'Senior Analyst 8', '+1-555-0105', '2025-01-10'),
('12', 'auditor12@argus.local', '$2b$12$R00p584VWscdIX6j2MUTSOE5rafy3w8BUQYifTUST8lgxCdqXusSC', 'auditor', 'Auditor 12', '+1-555-0106', '2025-01-20')
ON CONFLICT DO NOTHING;
