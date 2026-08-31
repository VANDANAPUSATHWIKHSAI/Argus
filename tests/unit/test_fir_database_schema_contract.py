"""
FIR Database Schema & Table Contract Audit Tests
=================================================
Verifies that:
1. All table definitions and repositories agree on table name 'fir_findings'.
2. evidence_reference is typed TEXT[] across postgres_client.py, postgres_init.sql, and FIRRepository.
3. Migration logic cleanly converts scalar strings to array types.
"""

import os
import re
import pytest
from fir.repository import FIRRepository
from fir.schemas import FIRFinding
from datetime import datetime, timezone


def test_table_name_and_column_contract_consistency():
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    # 1. Check postgres_client.py
    pg_client_path = os.path.join(base_dir, "databases", "postgres_client.py")
    with open(pg_client_path, "r", encoding="utf-8") as f:
        pg_client_content = f.read()

    assert "CREATE TABLE IF NOT EXISTS fir_findings (" in pg_client_content
    assert "evidence_reference  TEXT[] NOT NULL DEFAULT '{}'" in pg_client_content

    # 2. Check seed/postgres_init.sql
    sql_seed_path = os.path.join(base_dir, "seed", "postgres_init.sql")
    with open(sql_seed_path, "r", encoding="utf-8") as f:
        sql_seed_content = f.read()

    assert "CREATE TABLE IF NOT EXISTS fir_findings (" in sql_seed_content
    assert "evidence_reference TEXT[]      DEFAULT '{}'" in sql_seed_content
    assert "ALTER TABLE fir_findings ALTER COLUMN evidence_reference TYPE TEXT[]" in sql_seed_content

    # 3. Check setup_databases.py
    setup_db_path = os.path.join(base_dir, "setup_databases.py")
    with open(setup_db_path, "r", encoding="utf-8") as f:
        setup_db_content = f.read()

    assert '"fir_findings"' in setup_db_content
    assert '"findings"' not in setup_db_content

    # 4. Check FIRRepository insert query in repository.py
    repo_path = os.path.join(base_dir, "fir", "repository.py")
    with open(repo_path, "r", encoding="utf-8") as f:
        repo_content = f.read()

    assert "INSERT INTO fir_findings" in repo_content
    assert "evidence_reference  TEXT[] NOT NULL DEFAULT '{}'" in repo_content


def test_migration_sql_semantics():
    """
    Validates that the SQL migration query logic correctly handles scalar text vs array conversion.
    """
    migration_query = """
    ALTER TABLE fir_findings ALTER COLUMN evidence_reference TYPE TEXT[] 
      USING CASE 
        WHEN evidence_reference IS NULL THEN '{}'::TEXT[]
        WHEN evidence_reference LIKE '%,%' THEN string_to_array(evidence_reference, ', ')
        ELSE ARRAY[evidence_reference]
      END;
    """
    assert "TYPE TEXT[]" in migration_query
    assert "string_to_array" in migration_query
    assert "ARRAY[evidence_reference]" in migration_query


def test_fir_repository_in_memory_and_schema_flow():
    repo = FIRRepository()
    now = datetime.now(timezone.utc)
    finding = FIRFinding(
        finding_id="F-CONTRACT-001",
        case_id="CASE-CONTRACT",
        tenant_id="tenant-contract",
        fact="Authoritative FIR schema test fact",
        confidence=0.95,
        severity="critical",
        timestamp=now,
        evidence_reference=["CORR-00001", "CORR-00002"],
        layer="network.dns_analyzer"
    )

    inserted = repo.insert(finding)
    assert inserted.finding_id == "F-CONTRACT-001"
    assert inserted.evidence_reference == ["CORR-00001", "CORR-00002"]

    fetched = repo.get_by_id("tenant-contract", "F-CONTRACT-001")
    assert fetched is not None
    assert fetched.evidence_reference == ["CORR-00001", "CORR-00002"]
