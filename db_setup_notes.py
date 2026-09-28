from config.settings import settings
import psycopg2

def create_table():
    try:
        conn = psycopg2.connect(
            host=settings.postgres_host,
            port=settings.postgres_port,
            database=settings.postgres_db,
            user=settings.postgres_user,
            password=settings.postgres_password
        )
        cur = conn.cursor()
        
        # Create case_notes table
        cur.execute("""
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
        """)
        conn.commit()
        print("Table 'case_notes' created successfully.")
        
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    create_table()
