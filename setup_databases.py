"""
Database Startup Script
=======================
Run this ONCE after `docker compose up -d` to:
  1. Verify all 4 containers are healthy
  2. Create MinIO buckets (argus-raw-evidence, argus-encrypted-evidence)
  3. Confirm PostgreSQL tables exist (created by seed/postgres_init.sql)
  4. Confirm Qdrant and Neo4j are reachable

Usage:
    python setup_databases.py
"""

import sys
import time
import requests
from config.settings import settings

# ── 1. Check PostgreSQL ──────────────────────────────────────────
def check_postgres():
    print("\n[1/4] PostgreSQL...")
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=settings.postgres_host,
            port=settings.postgres_port,
            database=settings.postgres_db,
            user=settings.postgres_user,
            password=settings.postgres_password,
            connect_timeout=5
        )
        cur = conn.cursor()
        cur.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename;")
        tables = [row[0] for row in cur.fetchall()]
        conn.close()
        print(f"  OK - Connected. Tables: {tables}")
        expected = {"cases", "evidence", "custody_log", "audit_log", "fir_findings", "agent_outputs", "ism_state"}
        missing = expected - set(tables)
        if missing:
            print(f"  WARNING: Missing tables: {missing}")
            print("  --> Run: docker compose down -v && docker compose up -d   (to re-seed)")
        else:
            print("  All required tables present.")
        return True
    except Exception as e:
        print(f"  FAIL - {e}")
        return False


# ── 2. Check MinIO + create buckets ─────────────────────────────
def check_minio():
    print("\n[2/4] MinIO...")
    try:
        from minio import Minio
        # Parse host and port from endpoint
        endpoint = settings.minio_endpoint
        if "://" in endpoint:
            endpoint = endpoint.split("://")[1]
        
        client = Minio(
            endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            secure=settings.minio_secure
        )
        buckets_needed = [settings.minio_bucket_raw_evidence, settings.minio_bucket_encrypted]
        for bucket in buckets_needed:
            if not client.bucket_exists(bucket):
                client.make_bucket(bucket)
                print(f"  Created bucket: {bucket}")
            else:
                print(f"  Bucket exists: {bucket}")
        print(f"  OK - MinIO ready at {endpoint}")
        return True
    except Exception as e:
        print(f"  FAIL - {e}")
        return False


# ── 3. Check Qdrant ──────────────────────────────────────────────
def check_qdrant():
    print("\n[3/4] Qdrant...")
    try:
        url = settings.qdrant_url
        r = requests.get(f"{url}/healthz", timeout=5)
        if r.status_code == 200:
            print(f"  OK - Qdrant healthy. Dashboard: {url}/dashboard")
            return True
        else:
            print(f"  FAIL - Status {r.status_code}")
            return False
    except Exception as e:
        print(f"  FAIL - {e}")
        return False


# ── 4. Check Neo4j ───────────────────────────────────────────────
def check_neo4j():
    print("\n[4/4] Neo4j...")
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password)
        )
        with driver.session() as session:
            result = session.run("RETURN 1 AS ok")
            result.single()
        driver.close()
        print(f"  OK - Neo4j connected. Browser: {settings.neo4j_uri.replace('bolt://', 'http://').split(':')[0]}:7474")
        return True
    except Exception as e:
        print(f"  FAIL - {e}")
        return False


# ── Main ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("  Argus — Database Health Check & Setup")
    print("=" * 55)

    results = {
        "PostgreSQL": check_postgres(),
        "MinIO":      check_minio(),
        "Qdrant":     check_qdrant(),
        "Neo4j":      check_neo4j(),
    }

    print("\n" + "=" * 55)
    all_ok = all(results.values())
    for db, ok in results.items():
        status = "OK  " if ok else "FAIL"
        print(f"  [{status}] {db}")
    print("=" * 55)

    if all_ok:
        print("\n  All 4 databases are ready. You can now run:")
        print("  python -m infrastructure.pipeline")
    else:
        failed = [k for k, v in results.items() if not v]
        print(f"\n  Fix: {', '.join(failed)} before continuing.")
        print("  Tip: docker compose ps   (check which containers are unhealthy)")
        sys.exit(1)
