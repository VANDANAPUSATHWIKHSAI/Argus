import psycopg2

def init_table():
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
    """)
    conn.commit()
    conn.close()
    print("Table 'fir_findings' checked/created on Postgres port 5433 successfully.")

if __name__ == "__main__":
    init_table()
