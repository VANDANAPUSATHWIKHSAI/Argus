"""
Agent 2 — Deterministic Knowledge Graph & Community Engine
============================================================
Extracts forensic entities (IPs, hashes, users, files, hosts, processes),
builds deterministic relationships, interacts with Neo4j / WCC, and provides
an in-memory graph fallback when Neo4j is offline.
"""

import re
import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict

from agents.agent2_evidence_correlation.schemas import GraphCommunity

logger = logging.getLogger(__name__)

# Entity extraction regex patterns
IPV4_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')
MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')
USER_REGEX = re.compile(r'\b(?:user|account|username|domain\\user)\s*[:=]\s*([a-zA-Z0-9_\-\.\\]+)', re.IGNORECASE)
FILE_PROC_REGEX = re.compile(r'\b[a-zA-Z0-9_\-\.]+\.(?:exe|dll|ps1|bat|vbs|sys|elf)\b', re.IGNORECASE)


class GraphBuilder:
    """
    Deterministic Knowledge Graph builder and Community Detection (WCC) engine.
    """

    def __init__(self, neo4j_client: Optional[Any] = None):
        self.neo4j_client = neo4j_client

    def build_graph_and_communities(
        self,
        case_id: str,
        findings: List[Any]
    ) -> Tuple[List[GraphCommunity], Dict[str, Any]]:
        """
        Processes FIR findings, extracts entities, builds graph representation,
        computes Weakly Connected Components (WCC), and returns:
        (list_of_graph_communities, graph_metrics_dict)
        """
        # Step 1: Extract entities per finding
        finding_entities: Dict[str, Dict[str, Set[str]]] = {}
        entity_to_findings: Dict[Tuple[str, str], Set[str]] = defaultdict(set) # (type, value) -> set(finding_ids)

        for finding in findings:
            fid = self._extract_finding_id(finding)
            fact_text = self._extract_text(finding)
            
            extracted = self._extract_entities_from_finding(finding, fact_text)
            finding_entities[fid] = extracted

            for etype, values in extracted.items():
                for val in values:
                    entity_to_findings[(etype, val)].add(fid)

        # Step 2: Build local adjacency graph between findings based on shared entities
        adjacency: Dict[str, Set[str]] = defaultdict(set)
        edge_count = 0
        relationship_types_used: Set[str] = set()

        for (etype, val), f_ids in entity_to_findings.items():
            if len(f_ids) > 1:
                rel_type = f"SHARED_{etype.upper()}"
                relationship_types_used.add(rel_type)
                f_list = list(f_ids)
                for i in range(len(f_list)):
                    for j in range(i + 1, len(f_list)):
                        u, v = f_list[i], f_list[j]
                        if v not in adjacency[u]:
                            adjacency[u].add(v)
                            adjacency[v].add(u)
                            edge_count += 1

        # Step 3: Compute Weakly Connected Components (WCC)
        visited: Set[str] = set()
        components: List[Set[str]] = []

        all_finding_ids = list(finding_entities.keys())
        for fid in all_finding_ids:
            if fid not in visited:
                comp: Set[str] = set()
                queue = [fid]
                visited.add(fid)
                while queue:
                    curr = queue.pop(0)
                    comp.add(curr)
                    for nbr in adjacency[curr]:
                        if nbr not in visited:
                            visited.add(nbr)
                            queue.append(nbr)
                components.append(comp)

        # Step 4: Optional Neo4j synchronization & WCC query
        neo4j_synced = False
        if self.neo4j_client:
            try:
                self._sync_to_neo4j(case_id, finding_entities, entity_to_findings)
                neo4j_synced = True
            except Exception as exc:
                logger.warning("Neo4j graph sync failed; falling back to in-memory WCC: %s", exc)

        # Step 5: Format communities
        communities: List[GraphCommunity] = []
        for idx, comp in enumerate(components, 1):
            comp_findings = list(comp)
            
            # Aggregate entity names & types for this community
            comm_entities: Set[str] = set()
            comm_etypes: Set[str] = set()
            for fid in comp_findings:
                for etype, vals in finding_entities.get(fid, {}).items():
                    if vals:
                        comm_etypes.add(etype)
                        comm_entities.update(vals)

            comm_rels = [f"SHARED_{et.upper()}" for et in comm_etypes]

            communities.append(
                GraphCommunity(
                    community_id=f"GC-{idx:03d}",
                    finding_ids=sorted(comp_findings),
                    entity_names=sorted(list(comm_entities)),
                    entity_types=sorted(list(comm_etypes)),
                    relationship_types=sorted(comm_rels),
                    wcc_component_id=idx
                )
            )

        metrics = {
            "total_nodes": len(all_finding_ids),
            "total_edges": edge_count,
            "total_communities": len(communities),
            "neo4j_synced": neo4j_synced
        }

        return communities, metrics

    def _sync_to_neo4j(
        self,
        case_id: str,
        finding_entities: Dict[str, Dict[str, Set[str]]],
        entity_to_findings: Dict[Tuple[str, str], Set[str]]
    ):
        """
        Pushes nodes and relationships to Neo4j if driver/client is available.
        """
        if not hasattr(self.neo4j_client, "query"):
            return

        # Insert Artifact nodes
        for fid in finding_entities.keys():
            self.neo4j_client.query(
                "MERGE (a:Artifact {id: $fid, case_id: $case_id})",
                {"fid": fid, "case_id": case_id}
            )

        # Insert Entity nodes & CORRELATED edges
        for (etype, val), fids in entity_to_findings.items():
            if len(fids) > 1:
                entity_id = f"{etype}:{val}"
                self.neo4j_client.query(
                    "MERGE (e:Entity {id: $eid, type: $etype, value: $val, case_id: $case_id})",
                    {"eid": entity_id, "etype": etype, "val": val, "case_id": case_id}
                )
                for fid in fids:
                    self.neo4j_client.query(
                        "MATCH (a:Artifact {id: $fid, case_id: $case_id}), (e:Entity {id: $eid, case_id: $case_id}) "
                        "MERGE (a)-[r:CORRELATED {rel_type: $rel_type}]->(e)",
                        {"fid": fid, "eid": entity_id, "case_id": case_id, "rel_type": f"HAS_{etype.upper()}"}
                    )

    def _extract_entities_from_finding(self, finding: Any, text: str) -> Dict[str, Set[str]]:
        entities: Dict[str, Set[str]] = defaultdict(set)

        # Text regex extraction
        if text:
            for ip in IPV4_REGEX.findall(text):
                if not ip.startswith("127.") and not ip == "0.0.0.0":
                    entities["ip"].add(ip)
            
            for sha in SHA256_REGEX.findall(text):
                entities["sha256"].add(sha.lower())

            for md5 in MD5_REGEX.findall(text):
                entities["md5"].add(md5.lower())

            for user_match in USER_REGEX.findall(text):
                entities["user"].add(user_match.lower())

            for proc in FILE_PROC_REGEX.findall(text):
                entities["process_or_file"].add(proc.lower())

        # Metadata dictionary extraction if present
        meta = {}
        if isinstance(finding, dict):
            meta = finding
        elif hasattr(finding, "model_dump"):
            meta = finding.model_dump()
        elif hasattr(finding, "__dict__"):
            meta = finding.__dict__

        source_art = meta.get("source_artifact_id")
        if source_art:
            entities["artifact_id"].add(str(source_art))

        layer = meta.get("layer")
        if layer:
            entities["layer"].add(str(layer))

        return entities

    def _extract_finding_id(self, finding: Any) -> str:
        if isinstance(finding, dict):
            return finding.get("finding_id") or finding.get("id") or "F-UNKNOWN"
        elif hasattr(finding, "finding_id"):
            return getattr(finding, "finding_id")
        elif hasattr(finding, "id"):
            return getattr(finding, "id")
        return "F-UNKNOWN"

    def _extract_text(self, finding: Any) -> str:
        if isinstance(finding, dict):
            return str(finding.get("fact") or finding.get("sanitized_fact") or "")
        elif hasattr(finding, "sanitized_fact") and getattr(finding, "sanitized_fact"):
            return str(getattr(finding, "sanitized_fact"))
        elif hasattr(finding, "fact"):
            return str(getattr(finding, "fact"))
        return ""
