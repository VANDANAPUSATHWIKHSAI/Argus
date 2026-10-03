"""
Agent 3 — Deterministic Candidate Attack Path Builder
======================================================
Builds candidate attack paths across FIR findings.
Supports:
  1. Neo4j Cypher path queries when Neo4j database is online.
  2. In-memory chronological & entity-sharing path graph builder when Neo4j is offline.
"""

import re
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)

# Basic forensic stage keyword mapping for candidate path ordering
STAGE_PATTERNS = {
    "Initial Access": [r"phish", r"email", r"ingress", r"attachment", r"exploit", r"web_access", r"download"],
    "Execution": [r"powershell", r"cmd", r"execution", r"process_create", r"script", r"vbs", r"bat", r"wmi"],
    "Persistence": [r"run_key", r"scheduled_task", r"service_create", r"registry", r"startup"],
    "Privilege Escalation": [r"system", r"uac", r"impersonat", r"privilege"],
    "Credential Access": [r"lsass", r"mimikatz", r"dump", r"vault", r"sam_hive", r"browser_pass"],
    "Lateral Movement": [r"smb", r"rdp", r"psexec", r"winrm", r"remote_logon", r"4624"],
    "Exfiltration": [r"exfil", r"outbound", r"upload", r"mega", r"dropbox"],
}

class CandidatePathBuilder:
    """
    Deterministic candidate path builder for Agent 3.
    """

    def __init__(self, neo4j_client: Optional[Any] = None):
        self.neo4j_client = neo4j_client

    def build_candidate_paths(
        self,
        case_id: str,
        tenant_id: str,
        findings: List[Any],
        agent2_correlation: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Builds candidate attack paths and returns structured path dictionary.
        """
        if not findings:
            return {"candidate_paths": [], "path_count": 0, "source": "none"}

        # Try Neo4j if client exists
        if self.neo4j_client:
            try:
                neo_paths = self._query_neo4j_paths(case_id, tenant_id)
                if neo_paths:
                    return {
                        "candidate_paths": neo_paths,
                        "path_count": len(neo_paths),
                        "source": "neo4j"
                    }
            except Exception as exc:
                logger.debug("Neo4j candidate path query failed: %s. Using in-memory engine.", exc)

        # In-memory candidate path builder
        return self._build_in_memory_paths(case_id, findings, agent2_correlation)

    def _query_neo4j_paths(self, case_id: str, tenant_id: str) -> List[Dict[str, Any]]:
        query_str = (
            "MATCH (a1:Artifact {case_id: $case_id, tenant_id: $tenant_id})"
            "-[r:CORRELATED]->(e:Entity {case_id: $case_id, tenant_id: $tenant_id})"
            "<-[:CORRELATED]-(a2:Artifact {case_id: $case_id, tenant_id: $tenant_id}) "
            "WHERE a1.id < a2.id "
            "RETURN a1.id AS source_finding, e.type AS shared_type, e.value AS shared_value, a2.id AS target_finding "
            "LIMIT 50"
        )
        if hasattr(self.neo4j_client, "query"):
            return self.neo4j_client.query(query_str, {"case_id": case_id, "tenant_id": tenant_id})
        elif hasattr(self.neo4j_client, "session"):
            with self.neo4j_client.session() as session:
                res = session.run(query_str, {"case_id": case_id, "tenant_id": tenant_id})
                return [rec.data() for rec in res]
        return []

    def _build_in_memory_paths(
        self,
        case_id: str,
        findings: List[Any],
        agent2_correlation: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        # 1. Order findings chronologically
        dated_findings = []
        undated = []

        for f in findings:
            fid = self._get_val(f, "finding_id") or "f-unknown"
            fact = self._get_val(f, "fact") or self._get_val(f, "event_summary") or ""
            ts = self._get_val(f, "timestamp")
            stage = self._classify_stage(fact)

            dt = None
            if isinstance(ts, datetime):
                dt = ts
            elif isinstance(ts, str) and ts:
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except Exception:
                    dt = None

            if dt:
                dated_findings.append((dt, fid, fact, stage, f))
            else:
                undated.append((fid, fact, stage, f))

        dated_findings.sort(key=lambda x: x[0])

        all_ordered = [(dt, fid, fact, stage, f) for dt, fid, fact, stage, f in dated_findings]
        for fid, fact, stage, f in undated:
            all_ordered.append((None, fid, fact, stage, f))

        # 2. Extract shared entities per finding
        entity_map = defaultdict(set) # (entity_type, entity_val) -> set(finding_ids)
        finding_entities = {}

        for _, fid, fact, _, f in all_ordered:
            extracted = self._extract_entities(f, fact)
            finding_entities[fid] = extracted
            for etype, vals in extracted.items():
                for val in vals:
                    entity_map[(etype, val)].add(fid)

        # 3. Form candidate paths by joining findings with shared entities
        paths = []
        visited_pairs = set()

        for (etype, val), fids in entity_map.items():
            if len(fids) > 1:
                fid_list = sorted(list(fids))
                for i in range(len(fid_list) - 1):
                    src_id = fid_list[i]
                    tgt_id = fid_list[i + 1]
                    if (src_id, tgt_id) not in visited_pairs:
                        visited_pairs.add((src_id, tgt_id))
                        paths.append({
                            "source_finding": src_id,
                            "shared_type": etype,
                            "shared_value": val,
                            "target_finding": tgt_id
                        })

        # 4. Incorporate Agent 2 graph communities if available
        if agent2_correlation and isinstance(agent2_correlation, dict):
            communities = agent2_correlation.get("graph_communities") or []
            for comm in communities:
                comm_fids = comm.get("finding_ids") or []
                for i in range(len(comm_fids) - 1):
                    src_id = comm_fids[i]
                    tgt_id = comm_fids[i + 1]
                    if (src_id, tgt_id) not in visited_pairs:
                        visited_pairs.add((src_id, tgt_id))
                        paths.append({
                            "source_finding": src_id,
                            "shared_type": "graph_community",
                            "shared_value": comm.get("community_id", "community"),
                            "target_finding": tgt_id
                        })

        return {
            "candidate_paths": paths[:30],
            "path_count": len(paths),
            "source": "in_memory_engine"
        }

    def _classify_stage(self, text: str) -> str:
        text_lower = text.lower()
        for stage, patterns in STAGE_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, text_lower):
                    return stage
        return "Execution"

    def _extract_entities(self, finding: Any, text: str) -> Dict[str, Set[str]]:
        entities = defaultdict(set)
        
        # Check structured entities attribute if present
        structured_entities = self._get_val(finding, "entities") or []
        if isinstance(structured_entities, list):
            for e in structured_entities:
                if isinstance(e, dict):
                    etype = e.get("entity_type") or "entity"
                    val = e.get("value")
                    if val:
                        entities[str(etype).lower()].add(str(val).lower())

        text_str = str(text)
        # Extract IPs
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text_str)
        for ip in ips:
            if not ip.startswith("127.") and ip != "0.0.0.0":
                entities["ip"].add(ip)

        # Extract Hashes
        hashes = re.findall(r'\b[a-fA-F0-9]{64}\b', text_str)
        for h in hashes:
            entities["sha256"].add(h.lower())

        # Extract File names
        files = re.findall(r'\b[a-zA-Z0-9_\-\.]+\.(?:exe|dll|ps1|bat|vbs|sys|elf)\b', text_str, re.IGNORECASE)
        for f in files:
            entities["filename"].add(f.lower())

        return entities

    def _get_val(self, obj: Any, key: str, default: Any = None) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)
