"""
PostgreSQL Inspection Helper Script for ARGUS
==============================================
Connects to ARGUS PostgreSQL database and displays tables, FIR findings,
and Agent Outputs.
"""

import json
import psycopg2
from config.settings import settings


def main():
    print("=" * 70)
    print("           ARGUS POSTGRESQL DATABASE INSPECTOR")
    print("=" * 70)
    print(f"Connecting to: {settings.postgres_host}:{settings.postgres_port}/{settings.postgres_db} as {settings.postgres_user}...")

    try:
        conn = psycopg2.connect(
            host=settings.postgres_host,
            port=settings.postgres_port,
            database=settings.postgres_db,
            user=settings.postgres_user,
            password=settings.postgres_password,
            connect_timeout=5
        )
        cur = conn.cursor()
        print("[+] PostgreSQL Connection SUCCESSFUL!\n")

        # 1. List all tables
        cur.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            ORDER BY table_name;
        """)
        tables = [row[0] for row in cur.fetchall()]
        print(f"[+] Tables in database '{settings.postgres_db}': {tables}")

        # 2. Inspect agent_outputs table
        if "agent_outputs" in tables:
            cur.execute("SELECT COUNT(*) FROM agent_outputs;")
            count = cur.fetchone()[0]
            print(f"\n[+] Total rows in 'agent_outputs' table: {count}")

            cur.execute("""
                SELECT id, case_id, agent_id, claim, confidence, verified, execution_status, created_at
                FROM agent_outputs
                ORDER BY created_at DESC
                LIMIT 10;
            """)
            rows = cur.fetchall()
            if rows:
                print("\n--- Recent Agent Outputs ---")
                for r in rows:
                    print(f"ID: {r[0]} | Case: {r[1]} | Agent: {r[2]} | Status: {r[6]}")
                    print(f"  Claim      : {r[3][:100]}...")
                    print(f"  Confidence : {r[4]} | Verified: {r[5]} | Date: {r[7]}")
                    print("-" * 50)

        # 3. Inspect fir_findings table
        if "fir_findings" in tables:
            cur.execute("SELECT COUNT(*) FROM fir_findings;")
            count = cur.fetchone()[0]
            print(f"\n[+] Total rows in 'fir_findings' table: {count}")

        conn.close()

    except Exception as exc:
        print(f"[-] PostgreSQL connection error: {exc}")

if __name__ == "__main__":
    main()
