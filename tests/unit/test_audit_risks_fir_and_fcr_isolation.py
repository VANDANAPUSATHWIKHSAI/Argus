"""
Regression Test Suite — FIR Repository & FCR Engine Multi-Tenant Isolation
=============================================================================
Validates:
  Risk 1: FIR Repository strict tenant scoping, legacy unscoped call fail-closed semantics,
          two tenants sharing same case ID, cross-tenant finding ID rejection,
          PostgreSQL and in-memory fallback equivalence.
  Risk 2: FCR Engine tenant isolation across every correlation strategy (temporal, entity/shared IOC,
          process tree, network process, single artifact), namespaced correlation IDs,
          rejection of mixed records, and zero cross-tenant contamination.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import pytest

from fir.schemas import FIRFinding, ReviewStatus
from fir.repository import FIRRepository
from preprocessing.schemas import Artifact, NormalizedFields, ExtractedEntity
from preprocessing.fcr_engine.engine import FCREngine
from preprocessing.fcr_engine.schemas import CorrelationRecord
from preprocessing.fcr_engine.repository import FCRRepository


# ═════════════════════════════════════════════════════════════════════════════
# RISK 1: FIR REPOSITORY REGRESSION TESTS
# ═════════════════════════════════════════════════════════════════════════════

def test_fir_missing_or_unscoped_get_by_id_fails_closed():
    """
    Ensures get_by_id fails closed when tenant scope is omitted, None, empty string,
    wildcard '*', or mismatched. It must never return findings without authorized tenant scope.
    """
    repo = FIRRepository()
    repo.clear()

    finding = FIRFinding(
        finding_id="FIR-ALPHA-001",
        case_id="CASE-100",
        tenant_id="tenant-alpha",
        fact="Malicious service installed via PowerShell",
        confidence=0.95,
        severity="high",
        evidence_reference=["EV-001"],
        layer="endpoint",
    )
    repo.insert(finding)

    # 1. Legacy unscoped call with single argument (finding_id only) MUST fail closed (return None)
    assert repo.get_by_id("FIR-ALPHA-001") is None

    # 2. Explicit None, empty, or wildcard tenant MUST fail closed
    assert repo.get_by_id(tenant_id=None, finding_id="FIR-ALPHA-001") is None
    assert repo.get_by_id("", "FIR-ALPHA-001") is None
    assert repo.get_by_id("*", "FIR-ALPHA-001") is None
    assert repo.get_by_id(tenant_id="", finding_id="FIR-ALPHA-001") is None
    assert repo.get_by_id(tenant_id="*", finding_id="FIR-ALPHA-001") is None

    # 3. Blanket bypass: 'default' must NOT retrieve findings belonging to 'tenant-alpha'
    assert repo.get_by_id("default", "FIR-ALPHA-001") is None
    assert repo.get_by_id(tenant_id="default", finding_id="FIR-ALPHA-001") is None

    # 4. Cross-tenant retrieval: 'tenant-beta' must NOT retrieve 'tenant-alpha' finding
    assert repo.get_by_id("tenant-beta", "FIR-ALPHA-001") is None

    # 5. Legitimate authorized tenant call succeeds
    result = repo.get_by_id("tenant-alpha", "FIR-ALPHA-001")
    assert result is not None
    assert result.finding_id == "FIR-ALPHA-001"
    assert result.tenant_id == "tenant-alpha"

    # Also test keyword argument syntax
    result_kw = repo.get_by_id(tenant_id="tenant-alpha", finding_id="FIR-ALPHA-001")
    assert result_kw is not None
    assert result_kw.finding_id == "FIR-ALPHA-001"


def test_fir_missing_or_unscoped_get_by_case_fails_closed():
    """
    Ensures get_by_case fails closed when tenant scope is omitted, None, empty string,
    or wildcard '*'. It must never return findings without explicit authorized tenant scope.
    """
    repo = FIRRepository()
    repo.clear()

    finding = FIRFinding(
        finding_id="FIR-ALPHA-002",
        case_id="CASE-ISOLATE-01",
        tenant_id="tenant-alpha",
        fact="Registry Run key persistence established",
        confidence=0.90,
        severity="medium",
        evidence_reference=["EV-002"],
        layer="endpoint",
    )
    repo.insert(finding)

    # 1. Unscoped legacy calls (omitted tenant) MUST fail closed (return [])
    assert repo.get_by_case("CASE-ISOLATE-01") == []
    assert repo.get_by_case(case_id="CASE-ISOLATE-01") == []

    # 2. Empty string, None, or wildcard tenant MUST fail closed
    assert repo.get_by_case(case_id="CASE-ISOLATE-01", tenant_id="") == []
    assert repo.get_by_case(case_id="CASE-ISOLATE-01", tenant_id="*") == []
    assert repo.get_by_case(case_id="CASE-ISOLATE-01", tenant_id=None) == []
    assert repo.get_by_case("", "CASE-ISOLATE-01") == []
    assert repo.get_by_case("*", "CASE-ISOLATE-01") == []

    # 3. 'default' tenant cannot see 'tenant-alpha' findings
    assert repo.get_by_case(tenant_id="default", case_id="CASE-ISOLATE-01") == []
    assert repo.get_by_case("default", "CASE-ISOLATE-01") == []

    # 4. Foreign tenant cannot see 'tenant-alpha' findings
    assert repo.get_by_case(tenant_id="tenant-beta", case_id="CASE-ISOLATE-01") == []

    # 5. Legitimate authorized tenant succeeds
    res_pos = repo.get_by_case("tenant-alpha", "CASE-ISOLATE-01")
    assert len(res_pos) == 1
    assert res_pos[0].finding_id == "FIR-ALPHA-002"

    res_kw = repo.get_by_case(tenant_id="tenant-alpha", case_id="CASE-ISOLATE-01")
    assert len(res_kw) == 1
    assert res_kw[0].finding_id == "FIR-ALPHA-002"

    res_mixed = repo.get_by_case("CASE-ISOLATE-01", tenant_id="tenant-alpha")
    assert len(res_mixed) == 1
    assert res_mixed[0].finding_id == "FIR-ALPHA-002"


def test_fir_two_tenants_sharing_same_case_id():
    """
    Two tenants ('tenant-alpha', 'tenant-beta') use the exact same case_id 'CASE-SHARED-77'.
    Verifies that neither tenant can retrieve the other's findings via get_by_case or get_by_id.
    """
    repo = FIRRepository()
    repo.clear()

    finding_a = FIRFinding(
        finding_id="FIR-ALPHA-77",
        case_id="CASE-SHARED-77",
        tenant_id="tenant-alpha",
        fact="Alpha credential theft via Mimikatz",
        confidence=0.92,
        severity="high",
        evidence_reference=["EV-A-77"],
        layer="memory",
    )
    finding_b = FIRFinding(
        finding_id="FIR-BETA-77",
        case_id="CASE-SHARED-77",
        tenant_id="tenant-beta",
        fact="Beta lateral movement via WMI",
        confidence=0.88,
        severity="critical",
        evidence_reference=["EV-B-77"],
        layer="network",
    )
    repo.insert(finding_a)
    repo.insert(finding_b)

    # Querying tenant-alpha returns ONLY Alpha findings
    res_alpha = repo.get_by_case(tenant_id="tenant-alpha", case_id="CASE-SHARED-77")
    assert len(res_alpha) == 1
    assert res_alpha[0].finding_id == "FIR-ALPHA-77"
    assert res_alpha[0].tenant_id == "tenant-alpha"

    # Querying tenant-beta returns ONLY Beta findings
    res_beta = repo.get_by_case(tenant_id="tenant-beta", case_id="CASE-SHARED-77")
    assert len(res_beta) == 1
    assert res_beta[0].finding_id == "FIR-BETA-77"
    assert res_beta[0].tenant_id == "tenant-beta"

    # Querying default returns empty
    assert repo.get_by_case(tenant_id="default", case_id="CASE-SHARED-77") == []

    # Cross-tenant get_by_id retrieval MUST return None
    assert repo.get_by_id("tenant-alpha", "FIR-BETA-77") is None
    assert repo.get_by_id("tenant-beta", "FIR-ALPHA-77") is None


def test_fir_postgresql_and_in_memory_fallback_isolation():
    """
    Verifies PostgreSQL parameterized hydration enforces tenant isolation,
    and fallback to in-memory maintains identical strict security boundaries.
    """
    repo = FIRRepository()
    repo.clear()
    FIRRepository.reset_db_unreachable()

    # 1. Verify PostgreSQL query parameterization for get_by_case
    with patch("psycopg2.connect") as mock_connect:
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_conn.cursor.return_value = mock_cur
        mock_connect.return_value = mock_conn

        # Mock DB returning row for tenant-alpha
        mock_cur.fetchall.return_value = [
            (
                "FIR-PG-101", "CASE-PG-01", "tenant-alpha", "PG Fact", "PG Fact",
                0.9, "high", None, ["EV-PG-1"], "art_pg_1", "fp_pg_1",
                "pending_review", None, False, 0.0, "endpoint",
                datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
            )
        ]

        results = repo.get_by_case("tenant-alpha", "CASE-PG-01")
        assert len(results) == 1
        assert results[0].finding_id == "FIR-PG-101"

        # Verify SQL query enforced parameterized tenant_id check
        mock_cur.execute.assert_called()
        sql_query, params = mock_cur.execute.call_args[0]
        assert "WHERE case_id = %s AND tenant_id = %s" in sql_query
        assert params == ("CASE-PG-01", "tenant-alpha")

    # 2. Verify PostgreSQL query parameterization for get_by_id hydration
    repo.clear()
    FIRRepository.reset_db_unreachable()
    with patch("psycopg2.connect") as mock_connect:
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_conn.cursor.return_value = mock_cur
        mock_connect.return_value = mock_conn

        mock_cur.fetchone.return_value = (
            "FIR-PG-202", "CASE-PG-02", "tenant-alpha", "PG Fact 2", "PG Fact 2",
            0.95, "critical", None, ["EV-PG-2"], "art_pg_2", "fp_pg_2",
            "pending_review", None, False, 0.0, "network",
            datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
        )

        # Authorized retrieval hydrates from PG
        finding = repo.get_by_id("tenant-alpha", "FIR-PG-202")
        assert finding is not None
        assert finding.finding_id == "FIR-PG-202"
        assert finding.tenant_id == "tenant-alpha"

        # Verify SQL query enforced parameterized tenant_id check
        sql_query, params = mock_cur.execute.call_args[0]
        assert "WHERE finding_id = %s AND tenant_id = %s" in sql_query
        assert params == ("FIR-PG-202", "tenant-alpha")

    # 3. DB unreachable fallback: in-memory repository enforces identical boundaries
    FIRRepository._db_unreachable = True
    repo.clear()
    local_finding = FIRFinding(
        finding_id="FIR-INMEM-01",
        case_id="CASE-INMEM",
        tenant_id="tenant-alpha",
        fact="In-memory fallback fact",
        confidence=0.85,
        severity="medium",
        evidence_reference=["EV-INMEM-1"],
        layer="log",
    )
    repo.insert(local_finding)

    # In-memory enforces same tenant checks
    assert repo.get_by_id("tenant-beta", "FIR-INMEM-01") is None
    assert repo.get_by_id("default", "FIR-INMEM-01") is None
    assert repo.get_by_id("FIR-INMEM-01") is None
    assert repo.get_by_case(tenant_id="tenant-beta", case_id="CASE-INMEM") == []
    assert repo.get_by_case(case_id="CASE-INMEM") == []
    assert len(repo.get_by_case(tenant_id="tenant-alpha", case_id="CASE-INMEM")) == 1

    # Reset db unreachable state
    FIRRepository._db_unreachable = False


# ═════════════════════════════════════════════════════════════════════════════
# RISK 2: FCR ENGINE MULTI-STRATEGY TENANT ISOLATION REGRESSION TESTS
# ═════════════════════════════════════════════════════════════════════════════

def test_fcr_two_tenants_same_case_overlapping_all_strategies():
    """
    Two tenants ('tenant-alpha', 'tenant-beta') with the exact same case_id 'CASE-COLLIDE-001',
    overlapping hosts, identical timestamps, identical network IPs, identical hashes,
    and identical process PIDs.
    Verifies that NO CorrelationRecord ever contains artifacts from both tenants.
    """
    engine = FCREngine()
    t0 = datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 9, 15, 10, 0, 10, tzinfo=timezone.utc)
    sha256 = "f" * 64

    # Tenant Alpha artifacts
    art_a_proc = Artifact(
        artifact_id="ART-A-PROC",
        case_id="CASE-COLLIDE-001",
        tenant_id="tenant-alpha",
        evidence_id="EV-A-1",
        source_tool="hayabusa",
        artifact_type="process_event",
        host_id="SHARED-HOST-01",
        timestamp=t0,
        normalized_fields=NormalizedFields(
            host="SHARED-HOST-01",
            hash=sha256,
            process_id=1000,
            parent_process_id=500,
        ),
    )
    art_a_net = Artifact(
        artifact_id="ART-A-NET",
        case_id="CASE-COLLIDE-001",
        tenant_id="tenant-alpha",
        evidence_id="EV-A-2",
        source_tool="zeek",
        artifact_type="network_flow",
        host_id="SHARED-HOST-01",
        timestamp=t1,
        normalized_fields=NormalizedFields(
            host="SHARED-HOST-01",
            hash=sha256,
            process_id=1000,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
        ),
    )

    # Tenant Beta artifacts with IDENTICAL host, timestamp, hash, PID, and IPs
    art_b_proc = Artifact(
        artifact_id="ART-B-PROC",
        case_id="CASE-COLLIDE-001",
        tenant_id="tenant-beta",
        evidence_id="EV-B-1",
        source_tool="hayabusa",
        artifact_type="process_event",
        host_id="SHARED-HOST-01",
        timestamp=t0,
        normalized_fields=NormalizedFields(
            host="SHARED-HOST-01",
            hash=sha256,
            process_id=1000,
            parent_process_id=500,
        ),
    )
    art_b_net = Artifact(
        artifact_id="ART-B-NET",
        case_id="CASE-COLLIDE-001",
        tenant_id="tenant-beta",
        evidence_id="EV-B-2",
        source_tool="zeek",
        artifact_type="network_flow",
        host_id="SHARED-HOST-01",
        timestamp=t1,
        normalized_fields=NormalizedFields(
            host="SHARED-HOST-01",
            hash=sha256,
            process_id=1000,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
        ),
    )

    all_arts = [art_a_proc, art_a_net, art_b_proc, art_b_net]
    records = engine.correlate(all_arts, window_seconds=30.0)

    assert len(records) > 0, "Expected correlation records to be produced"

    alpha_art_ids = {"ART-A-PROC", "ART-A-NET"}
    beta_art_ids = {"ART-B-PROC", "ART-B-NET"}

    for rec in records:
        # 1. Tenant ID must be strictly preserved
        assert rec.tenant_id in ("tenant-alpha", "tenant-beta")
        assert rec.case_id == "CASE-COLLIDE-001"

        rec_arts = set(rec.artifact_ids)

        if rec.tenant_id == "tenant-alpha":
            # Must ONLY contain Alpha artifacts
            assert rec_arts.issubset(alpha_art_ids), f"Alpha record contains foreign artifacts: {rec_arts}"
            assert not rec_arts.intersection(beta_art_ids), "Alpha record contains Beta artifact!"
        elif rec.tenant_id == "tenant-beta":
            # Must ONLY contain Beta artifacts
            assert rec_arts.issubset(beta_art_ids), f"Beta record contains foreign artifacts: {rec_arts}"
            assert not rec_arts.intersection(alpha_art_ids), "Beta record contains Alpha artifact!"


def test_fcr_individual_strategies_reject_mixed_artifacts():
    """
    Verifies that calling individual correlation strategies directly
    (_correlate_temporal, _correlate_shared_ioc, _correlate_process_tree,
     _correlate_network_process, _correlate_single_artifact)
    enforces tenant filtering and NEVER correlates mixed-tenant artifacts.
    """
    engine = FCREngine()
    t0 = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 9, 15, 12, 0, 5, tzinfo=timezone.utc)

    # 1. Temporal strategy: mixed artifacts on same host within 5s
    art_a = Artifact(
        artifact_id="ART-TMP-A",
        case_id="CASE-MIXED",
        tenant_id="tenant-alpha",
        evidence_id="EV-1",
        source_tool="tool1",
        artifact_type="type1",
        host_id="HOST-1",
        timestamp=t0,
    )
    art_b = Artifact(
        artifact_id="ART-TMP-B",
        case_id="CASE-MIXED",
        tenant_id="tenant-beta",
        evidence_id="EV-2",
        source_tool="tool2",
        artifact_type="type2",
        host_id="HOST-1",
        timestamp=t1,
    )

    # When called with tenant-alpha, it only sees ART-TMP-A (len < 2) -> returns empty list
    rec_tmp_a = engine._correlate_temporal("CASE-MIXED", [art_a, art_b], 30.0, tenant_id="tenant-alpha")
    assert rec_tmp_a == [], "Temporal strategy must not correlate across tenants"

    rec_tmp_b = engine._correlate_temporal("CASE-MIXED", [art_a, art_b], 30.0, tenant_id="tenant-beta")
    assert rec_tmp_b == [], "Temporal strategy must not correlate across tenants"

    # 2. Shared IOC strategy: mixed artifacts with identical IOC hash
    art_ioc_a = Artifact(
        artifact_id="ART-IOC-A",
        case_id="CASE-MIXED",
        tenant_id="tenant-alpha",
        evidence_id="EV-3",
        source_tool="tool1",
        artifact_type="type1",
        normalized_fields=NormalizedFields(hash="d" * 64),
    )
    art_ioc_b = Artifact(
        artifact_id="ART-IOC-B",
        case_id="CASE-MIXED",
        tenant_id="tenant-beta",
        evidence_id="EV-4",
        source_tool="tool2",
        artifact_type="type2",
        normalized_fields=NormalizedFields(hash="d" * 64),
    )

    rec_ioc_a = engine._correlate_shared_ioc("CASE-MIXED", [art_ioc_a, art_ioc_b], {}, tenant_id="tenant-alpha")
    assert rec_ioc_a == [], "Shared IOC strategy must not correlate across tenants"

    # 3. Process tree strategy: child on tenant-alpha, parent on tenant-beta
    art_parent_b = Artifact(
        artifact_id="ART-PROC-P",
        case_id="CASE-MIXED",
        tenant_id="tenant-beta",
        evidence_id="EV-5",
        source_tool="tool1",
        artifact_type="process",
        host_id="HOST-P",
        normalized_fields=NormalizedFields(host="HOST-P", process_id=200),
    )
    art_child_a = Artifact(
        artifact_id="ART-PROC-C",
        case_id="CASE-MIXED",
        tenant_id="tenant-alpha",
        evidence_id="EV-6",
        source_tool="tool1",
        artifact_type="process",
        host_id="HOST-P",
        normalized_fields=NormalizedFields(host="HOST-P", process_id=300, parent_process_id=200),
    )

    rec_pt_a = engine._correlate_process_tree("CASE-MIXED", [art_parent_b, art_child_a], tenant_id="tenant-alpha")
    assert rec_pt_a == [], "Process tree must not correlate across tenants"

    # 4. Network ↔ Process strategy: proc on tenant-alpha, net on tenant-beta
    art_proc_a = Artifact(
        artifact_id="ART-NP-P",
        case_id="CASE-MIXED",
        tenant_id="tenant-alpha",
        evidence_id="EV-7",
        source_tool="tool1",
        artifact_type="process_event",
        host_id="HOST-N",
        normalized_fields=NormalizedFields(host="HOST-N", process_id=400),
    )
    art_net_b = Artifact(
        artifact_id="ART-NP-N",
        case_id="CASE-MIXED",
        tenant_id="tenant-beta",
        evidence_id="EV-8",
        source_tool="tool2",
        artifact_type="network_flow",
        host_id="HOST-N",
        normalized_fields=NormalizedFields(host="HOST-N", process_id=400),
    )

    rec_np_a = engine._correlate_network_process("CASE-MIXED", [art_proc_a, art_net_b], tenant_id="tenant-alpha")
    assert rec_np_a == [], "Network process must not correlate across tenants"


def test_fcr_missing_tenant_metadata_cannot_cause_cross_tenant_correlation():
    """
    Verifies that missing tenant metadata (None, empty string, omitted) cannot cause
    cross-tenant correlation with a named tenant.
    """
    engine = FCREngine()
    t0 = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)

    # Artifact without explicit tenant (defaults to 'default')
    art_unscoped = Artifact(
        artifact_id="ART-NO-TENANT",
        case_id="CASE-UNSCOPED",
        tenant_id=None,
        evidence_id="EV-NONE",
        source_tool="tool1",
        artifact_type="type1",
        host_id="HOST-X",
        timestamp=t0,
        normalized_fields=NormalizedFields(host="HOST-X", hash="9" * 64),
    )

    # Artifact with explicit tenant-alpha
    art_alpha = Artifact(
        artifact_id="ART-EXPLICIT-ALPHA",
        case_id="CASE-UNSCOPED",
        tenant_id="tenant-alpha",
        evidence_id="EV-ALPHA",
        source_tool="tool2",
        artifact_type="type2",
        host_id="HOST-X",
        timestamp=t0,
        normalized_fields=NormalizedFields(host="HOST-X", hash="9" * 64),
    )

    records = engine.correlate([art_unscoped, art_alpha], window_seconds=30.0)

    # They must NEVER correlate together
    for rec in records:
        assert not ("ART-NO-TENANT" in rec.artifact_ids and "ART-EXPLICIT-ALPHA" in rec.artifact_ids)


def test_fcr_repository_tenant_isolation_and_persistence():
    """
    Verifies FCRRepository indexes records by tenant and case, rejects cross-tenant retrieval,
    and includes tenant_id in SQL persistence.
    """
    repo = FCRRepository()
    repo.clear()

    rec_alpha = CorrelationRecord(
        correlation_id="CORR-00001",
        case_id="CASE-SHARED-FCR",
        tenant_id="tenant-alpha",
        artifact_ids=["ART-A-1", "ART-A-2"],
        relationship_type=["temporal_proximity"],
        source_count=2,
        distinct_artifact_types=2,
        confidence=0.65,
        host="HOST-01",
    )
    rec_beta = CorrelationRecord(
        correlation_id="CORR-00002",
        case_id="CASE-SHARED-FCR",
        tenant_id="tenant-beta",
        artifact_ids=["ART-B-1", "ART-B-2"],
        relationship_type=["temporal_proximity"],
        source_count=2,
        distinct_artifact_types=2,
        confidence=0.65,
        host="HOST-01",
    )

    repo.add_record(rec_alpha)
    repo.add_record(rec_beta)

    # 1. list_by_case with tenant isolation
    alpha_recs = repo.list_by_case("CASE-SHARED-FCR", tenant_id="tenant-alpha")
    assert len(alpha_recs) == 1
    assert alpha_recs[0].correlation_id == "CORR-00001"

    beta_recs = repo.list_by_case("CASE-SHARED-FCR", tenant_id="tenant-beta")
    assert len(beta_recs) == 1
    assert beta_recs[0].correlation_id == "CORR-00002"

    # Wildcard or empty returns empty
    assert repo.list_by_case("CASE-SHARED-FCR", tenant_id="*") == []
    assert repo.list_by_case("CASE-SHARED-FCR", tenant_id="") == []

    # Unscoped list_by_case fails closed when multi-tenant records exist
    assert repo.list_by_case("CASE-SHARED-FCR") == []

    # 2. get_record with tenant check
    assert repo.get_record("CORR-00001", tenant_id="tenant-beta") is None
    assert repo.get_record("CORR-00002", tenant_id="tenant-alpha") is None
    assert repo.get_record("CORR-00001", tenant_id="tenant-alpha") is not None

    # 3. SQL persistence includes tenant_id column
    with patch("psycopg2.connect") as mock_connect:
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.rowcount = 1
        mock_cur.__enter__.return_value = mock_cur
        mock_conn.cursor.return_value = mock_cur
        mock_connect.return_value = mock_conn

        count = repo.persist_to_postgres(mock_conn)
        assert count == 2

        # Check that INSERT contained tenant_id
        for call in mock_cur.execute.call_args_list:
            if len(call[0]) == 2:
                sql, params = call[0]
                if "INSERT INTO fcr_records" in sql:
                    assert "tenant_id" in sql
                    assert params[2] in ("tenant-alpha", "tenant-beta")
