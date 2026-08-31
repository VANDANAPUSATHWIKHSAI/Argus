-- Runs automatically the first time the postgres container starts.
-- This is what gets committed to git -- the SCHEMA, not the data.

CREATE TABLE IF NOT EXISTS cases (
    case_id      UUID PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by   TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'open'
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id       UUID PRIMARY KEY,
    case_id           UUID REFERENCES cases(case_id),
    filename          TEXT NOT NULL,
    uploaded_by       TEXT NOT NULL,
    upload_timestamp  TIMESTAMPTZ NOT NULL DEFAULT now(),
    status            TEXT NOT NULL DEFAULT 'uploaded',
    sha256_hash       TEXT,
    encrypted         BOOLEAN DEFAULT FALSE,
    rfc3161_timestamp TEXT,
    metadata          JSONB DEFAULT '{}',
    repository_path   TEXT   -- points to the MinIO object key, not the file itself
);

CREATE TABLE IF NOT EXISTS custody_log (
    id          SERIAL PRIMARY KEY,
    evidence_id UUID REFERENCES evidence(evidence_id),
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT now(),
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id    TEXT PRIMARY KEY,   -- e.g. "F-2291", matches evidence_ids cited by agents
    evidence_id   UUID REFERENCES evidence(evidence_id),
    source_engine TEXT NOT NULL,      -- e.g. "log_analysis", "network_analysis"
    fact          TEXT NOT NULL,
    confidence    FLOAT,
    severity      TEXT,
    mitre_mapping TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Sample seed row so everyone's local FIR isn't completely empty on first run
INSERT INTO cases (case_id, tenant_id, created_by)
VALUES ('00000000-0000-0000-0000-000000000001', 'dev-team', 'team-lead')
ON CONFLICT DO NOTHING;
