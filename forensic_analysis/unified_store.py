"""
Unified Evidence Store — Central Forensic Finding Repository
============================================================
Central store all forensic analysis modules write findings to and read from.
Follows the Postgres connection pattern from infrastructure/repository/evidence_store.py
with local in-memory fallback when Postgres is unconfigured or disconnected.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Optional, Union
from forensic_analysis.schemas import Finding

logger = logging.getLogger(__name__)


class UnifiedEvidenceStore:
    """
    Central persistent/in-memory store that all analysis engines write to and read from.
    Enforces case-scoping and tenant-isolation on every query.
    """

    def __init__(self):
        # In-memory store fallback: dict[case_id, dict[finding_id, Finding]]
        self._memory_store: Dict[str, Dict[str, Finding]] = {}
        # Fingerprint index for semantic deduplication: dict[case_id, dict[fingerprint, finding_id]]
        self._fingerprints: Dict[str, Dict[str, str]] = {}

    def write_finding(self, finding: Union[Finding, dict]) -> None:
        """
        Persist a single Finding (or finding dict) to the store with fingerprint deduplication.
        """
        if isinstance(finding, dict):
            finding_obj = Finding(**finding)
        else:
            finding_obj = finding

        case_id = finding_obj.case_id
        fp = finding_obj.finding_fingerprint

        if case_id not in self._memory_store:
            self._memory_store[case_id] = {}
            self._fingerprints[case_id] = {}

        # Semantic Deduplication: Check if fingerprint already exists for this case
        if fp in self._fingerprints[case_id]:
            existing_id = self._fingerprints[case_id][fp]
            # Update finding preserving the original finding_id
            finding_obj.finding_id = existing_id
            self._memory_store[case_id][existing_id] = finding_obj
        else:
            self._memory_store[case_id][finding_obj.finding_id] = finding_obj
            self._fingerprints[case_id][fp] = finding_obj.finding_id

        # Attempt Postgres write if available
        try:
            import psycopg2
            from config.settings import settings
            conn = psycopg2.connect(
                host=settings.postgres_host,
                port=settings.postgres_port,
                database=settings.postgres_db,
                user=settings.postgres_user,
                password=settings.postgres_password,
                connect_timeout=3
            )
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS forensic_findings (
                    finding_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    fact TEXT NOT NULL,
                    confidence FLOAT NOT NULL,
                    severity TEXT NOT NULL,
                    mitre_mapping TEXT,
                    timestamp TIMESTAMPTZ NOT NULL,
                    evidence_reference TEXT NOT NULL,
                    layer TEXT NOT NULL,
                    metadata JSONB
                );
                """
            )
            cur.execute(
                """
                INSERT INTO forensic_findings 
                    (finding_id, case_id, tenant_id, fact, confidence, severity, mitre_mapping, timestamp, evidence_reference, layer, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (finding_id) DO UPDATE SET
                    fact = EXCLUDED.fact,
                    confidence = EXCLUDED.confidence,
                    severity = EXCLUDED.severity,
                    mitre_mapping = EXCLUDED.mitre_mapping,
                    timestamp = EXCLUDED.timestamp,
                    metadata = EXCLUDED.metadata;
                """,
                (
                    finding_obj.finding_id,
                    finding_obj.case_id,
                    finding_obj.tenant_id,
                    finding_obj.fact,
                    finding_obj.confidence,
                    finding_obj.severity,
                    finding_obj.mitre_mapping,
                    finding_obj.timestamp,
                    finding_obj.evidence_reference,
                    finding_obj.layer,
                    json.dumps(finding_obj.metadata),
                )
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.debug("Postgres persistence skipped for write_finding: %s", e)

    def read_findings(self, case_id: str, tenant_id: Optional[str] = None) -> List[Finding]:
        """
        Return all findings associated with the given case_id, enforcing tenant isolation.
        """
        if not case_id or not case_id.strip():
            raise ValueError("case_id is required to read findings.")

        findings: List[Finding] = []

        # Check Postgres first
        try:
            import psycopg2
            from config.settings import settings
            conn = psycopg2.connect(
                host=settings.postgres_host,
                port=settings.postgres_port,
                database=settings.postgres_db,
                user=settings.postgres_user,
                password=settings.postgres_password,
                connect_timeout=3
            )
            cur = conn.cursor()
            if tenant_id:
                cur.execute(
                    "SELECT finding_id, case_id, tenant_id, fact, confidence, severity, mitre_mapping, timestamp, evidence_reference, layer, metadata FROM forensic_findings WHERE case_id = %s AND tenant_id = %s ORDER BY timestamp ASC;",
                    (case_id, tenant_id)
                )
            else:
                cur.execute(
                    "SELECT finding_id, case_id, tenant_id, fact, confidence, severity, mitre_mapping, timestamp, evidence_reference, layer, metadata FROM forensic_findings WHERE case_id = %s ORDER BY timestamp ASC;",
                    (case_id,)
                )
            rows = cur.fetchall()
            conn.close()

            for row in rows:
                meta = row[10]
                if isinstance(meta, str):
                    meta = json.loads(meta)
                elif meta is None:
                    meta = {}
                findings.append(Finding(
                    finding_id=row[0],
                    case_id=row[1],
                    tenant_id=row[2],
                    fact=row[3],
                    confidence=row[4],
                    severity=row[5],
                    mitre_mapping=row[6],
                    timestamp=row[7],
                    evidence_reference=row[8],
                    layer=row[9],
                    metadata=meta,
                ))
            if findings:
                return findings
        except Exception as e:
            logger.debug("Postgres query skipped for read_findings: %s", e)

        # In-memory fallback
        case_findings = self._memory_store.get(case_id, {})
        for f in case_findings.values():
            if tenant_id is None or f.tenant_id == tenant_id:
                findings.append(f)

        return sorted(findings, key=lambda x: (x.timestamp, x.finding_id))

    def get_findings_by_layer(
        self, case_id: str, layer: str, tenant_id: Optional[str] = None
    ) -> List[Finding]:
        """
        Return findings produced by a specific sub-analyzer layer (e.g. 'network.dns_analyzer'),
        enforcing case-scoping and tenant-isolation.
        """
        all_case_findings = self.read_findings(case_id, tenant_id=tenant_id)
        return [f for f in all_case_findings if f.layer == layer]
