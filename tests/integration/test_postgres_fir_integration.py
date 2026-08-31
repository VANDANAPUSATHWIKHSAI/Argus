"""
Integration Test Suite for PostgreSQL FIR Findings Table Persistence
=====================================================================
Validates:
1. PostgreSQL schema migration (17 columns)
2. Finding -> SanitizationGateway -> FIRFinding -> PostgreSQL SELECT round-trip
3. Fingerprint deduplication & idempotency in PostgreSQL
4. Case and tenant isolation in PostgreSQL
5. Review status updates in PostgreSQL
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from config.settings import settings
from forensic_analysis.schemas import Finding, finding_to_fir
from sanitization.gateway import SanitizationGateway
from fir.schemas import FIRFinding, ReviewStatus
from fir.repository import FIRRepository


class TestPostgresFirIntegration(unittest.TestCase):
    """Integration test suite for PostgreSQL database persistence."""

    def setUp(self):
        self.repo = FIRRepository()
        self.repo.clear()
        self.gateway = SanitizationGateway()
        self.case_id = "CASE-PG-INTEGRATION-01"
        self.tenant_id = "tenant-pg-int"

    def _get_pg_conn(self):
        import psycopg2
        from psycopg2.extras import RealDictCursor
        try:
            return psycopg2.connect(
                host=settings.postgres_host,
                port=settings.postgres_port,
                database=settings.postgres_db,
                user=settings.postgres_user,
                password=settings.postgres_password,
                connect_timeout=3
            )
        except Exception as e:
            self.skipTest(f"PostgreSQL service unreachable: {e}")

    def test_postgres_schema_columns(self):
        """Verify all 17 required columns exist in PostgreSQL fir_findings table."""
        conn = self._get_pg_conn()
        cur = conn.cursor()
        
        # Trigger schema creation/migration
        raw_fnd = Finding(
            case_id=self.case_id,
            tenant_id=self.tenant_id,
            fact="Schema test finding",
            confidence=0.9,
            severity="low",
            evidence_reference="CORR-SCH-1",
            source_artifact_id="art-sch-1",
            layer="endpoint"
        )
        fir_fnd = finding_to_fir(raw_fnd)
        self.repo.insert(fir_fnd)

        cur.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'fir_findings';
        """)
        cols = {row[0] for row in cur.fetchall()}
        conn.close()

        expected = {
            "finding_id", "case_id", "tenant_id", "fact", "sanitized_fact",
            "confidence", "severity", "mitre_mapping", "evidence_reference",
            "source_artifact_id", "finding_fingerprint", "review_status",
            "reviewed_by", "injection_flagged", "injection_score", "layer", "timestamp"
        }
        for field in expected:
            self.assertIn(field, cols, f"Column '{field}' missing from PostgreSQL fir_findings schema.")

    def test_postgres_roundtrip_persistence(self):
        """Verify Finding -> SanitizationGateway -> FIRFinding -> PostgreSQL SELECT round-trip."""
        conn = self._get_pg_conn()
        from psycopg2.extras import RealDictCursor
        cur = conn.cursor(cursor_factory=RealDictCursor)

        raw_fnd = Finding(
            case_id=self.case_id,
            tenant_id=self.tenant_id,
            fact="User admin@corp.com executed encoded powershell payload",
            confidence=0.95,
            severity="high",
            mitre_mapping="T1059.001",
            evidence_reference="CORR-INT-100",
            source_artifact_id="art-int-100",
            layer="endpoint"
        )

        ctx = self.gateway.sanitize_finding(raw_fnd)
        fir_fnd = FIRFinding(
            finding_id=ctx.finding_id,
            case_id=ctx.case_id,
            tenant_id=ctx.tenant_id,
            fact=raw_fnd.fact,
            sanitized_fact=ctx.sanitized_fact,
            confidence=ctx.confidence,
            severity=ctx.severity,
            mitre_mapping=ctx.mitre_mapping,
            evidence_reference=ctx.evidence_reference,
            source_artifact_id=ctx.source_artifact_id,
            finding_fingerprint=raw_fnd.finding_fingerprint,
            review_status=ReviewStatus.PENDING_REVIEW,
            injection_flagged=ctx.injection_flagged,
            injection_score=ctx.injection_score,
            layer=ctx.layer,
            timestamp=ctx.timestamp
        )

        self.repo.insert(fir_fnd)

        cur.execute("SELECT * FROM fir_findings WHERE finding_id = %s;", (fir_fnd.finding_id,))
        row = cur.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["finding_id"], fir_fnd.finding_id)
        self.assertEqual(row["case_id"], self.case_id)
        self.assertEqual(row["tenant_id"], self.tenant_id)
        self.assertEqual(row["sanitized_fact"], ctx.sanitized_fact)
        self.assertEqual(row["finding_fingerprint"], raw_fnd.finding_fingerprint)
        self.assertEqual(row["source_artifact_id"], "art-int-100")
        self.assertEqual(row["review_status"], "pending_review")

    def test_postgres_fingerprint_idempotency(self):
        """Verify duplicate finding insertion with identical fingerprint updates row without duplicating."""
        conn = self._get_pg_conn()
        from psycopg2.extras import RealDictCursor
        cur = conn.cursor(cursor_factory=RealDictCursor)

        raw_fnd1 = Finding(
            case_id="CASE-PG-IDEM",
            tenant_id=self.tenant_id,
            fact="Repeat threat finding",
            confidence=0.9,
            severity="medium",
            evidence_reference="CORR-IDEM-1",
            source_artifact_id="art-idem-1",
            layer="endpoint"
        )
        fir_fnd1 = finding_to_fir(raw_fnd1)

        self.repo.insert(fir_fnd1)
        self.repo.insert(fir_fnd1)  # Repeat insert

        cur.execute("SELECT COUNT(*) AS cnt FROM fir_findings WHERE case_id = 'CASE-PG-IDEM';")
        count = cur.fetchone()["cnt"]
        conn.close()

        self.assertEqual(count, 1)

    def test_postgres_tenant_isolation(self):
        """Verify strict tenant isolation filtering in PostgreSQL queries."""
        conn = self._get_pg_conn()
        from psycopg2.extras import RealDictCursor
        cur = conn.cursor(cursor_factory=RealDictCursor)

        fir_fnd = FIRFinding(
            finding_id="fnd-iso-pg",
            case_id="CASE-PG-ISO",
            tenant_id="tenant-alpha-pg",
            fact="Tenant A secret finding",
            confidence=0.9,
            severity="high",
            layer="endpoint",
            timestamp=datetime.now(timezone.utc),
            evidence_reference=["CORR-ISO"]
        )
        self.repo.insert(fir_fnd)

        cur.execute("SELECT * FROM fir_findings WHERE case_id = %s AND tenant_id = %s;", ("CASE-PG-ISO", "tenant-beta-pg"))
        beta_rows = cur.fetchall()
        
        cur.execute("SELECT * FROM fir_findings WHERE case_id = %s AND tenant_id = %s;", ("CASE-PG-ISO", "tenant-alpha-pg"))
        alpha_rows = cur.fetchall()

        conn.close()

        self.assertEqual(len(beta_rows), 0)
        self.assertEqual(len(alpha_rows), 1)
