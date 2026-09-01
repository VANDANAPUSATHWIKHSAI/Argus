import psycopg2

def fix_table():
    conn = psycopg2.connect(
        host="localhost",
        port=5433,
        dbname="argus",
        user="argus_user",
        password="argus_dev"
    )
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS fir_findings (
            finding_id          TEXT PRIMARY KEY,
            case_id             TEXT NOT NULL,
            tenant_id           TEXT NOT NULL DEFAULT 'default',
            fact                TEXT NOT NULL,
            sanitized_fact      TEXT,
            confidence          FLOAT NOT NULL DEFAULT 1.0,
            severity            TEXT NOT NULL DEFAULT 'medium',
            mitre_mapping       TEXT,
            evidence_reference  TEXT[] NOT NULL DEFAULT '{}',
            source_artifact_id  TEXT,
            finding_fingerprint TEXT,
            review_status       TEXT NOT NULL DEFAULT 'pending_review',
            reviewed_by         TEXT,
            injection_flagged   BOOLEAN DEFAULT FALSE,
            injection_score     FLOAT DEFAULT 0.0,
            layer               TEXT NOT NULL DEFAULT 'unknown',
            timestamp           TIMESTAMPTZ DEFAULT NOW(),
            raw_data            JSONB DEFAULT '{}'
        );
        ALTER TABLE fir_findings DROP CONSTRAINT IF EXISTS fir_findings_case_id_fkey;
        ALTER TABLE fir_findings ALTER COLUMN case_id TYPE TEXT USING case_id::text;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS source_engine TEXT;
        ALTER TABLE fir_findings ALTER COLUMN source_engine DROP NOT NULL;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS sanitized_fact TEXT;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS source_artifact_id TEXT;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS finding_fingerprint TEXT;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS review_status TEXT DEFAULT 'pending_review';
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS reviewed_by TEXT;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS injection_flagged BOOLEAN DEFAULT FALSE;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS injection_score FLOAT DEFAULT 0.0;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS layer TEXT DEFAULT 'unknown';
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS timestamp TIMESTAMPTZ DEFAULT NOW();
    """)
    conn.commit()
    conn.close()
    print("Idempotent schema fix applied successfully on Postgres port 5433.")

if __name__ == "__main__":
    fix_table()
