"""
Agent 2 — Deterministic Knowledge Graph & Community Engine
============================================================
Extracts forensic entities (IPs, hashes, users, files, hosts, processes),
builds deterministic relationships, interacts with Neo4j / WCC, and enforces
mandatory Neo4j + GDS execution.
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
    Deterministic Knowledge Graph builder and Community Detection (WCC) engine using Neo4j + GDS.
    Enforces tenant and case isolation at Neo4j query boundaries. Neo4j + GDS are mandatory.
    """

    def __init__(self, neo4j_client: Optional[Any] = None):
        if neo4j_client is not None:
            self.neo4j_client = neo4j_client
        else:
            self.neo4j_client = self._init_default_driver()

    def _init_default_driver(self) -> Optional[Any]:
        try:
            from neo4j import GraphDatabase
            from config.settings import settings
            driver = GraphDatabase.driver(
                settings.neo4j_uri,
                auth=(settings.neo4j_user, settings.neo4j_password)
            )
            return driver
        except Exception as exc:
            logger.warning("Default Neo4j driver initialization failed: %s", exc)
            return None

    def build_graph_and_communities(
        self,
        case_id: str,
        findings: List[Any],
        tenant_id: str = "default"
    ) -> Tuple[List[GraphCommunity], Dict[str, Any]]:
        """
        Processes FIR findings, extracts entities, builds Neo4j graph representation with tenant isolation,
        executes Neo4j GDS Weakly Connected Components (WCC), and returns:
        (list_of_graph_communities, graph_metrics_dict)
        
        Raises RuntimeError if Neo4j or GDS is unavailable.
        """
        if not self.neo4j_client:
            raise RuntimeError("Neo4j database connection unavailable. Neo4j + GDS is required for Agent 2 graph execution.")

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

        # Step 2: Push nodes and relationships to Neo4j with strict case_id & tenant_id isolation
        try:
            edge_count = self._sync_to_neo4j(case_id, tenant_id, finding_entities, entity_to_findings)
        except Exception as exc:
            logger.error("Neo4j graph construction error: %s", exc)
            raise RuntimeError(f"Neo4j graph construction failed: {exc}") from exc

        # Step 3: Execute GDS WCC / Cypher Community Detection on Neo4j
        try:
            communities, wcc_success = self._run_neo4j_gds_wcc(case_id, tenant_id, finding_entities)
        except Exception as exc:
            logger.error("Neo4j GDS WCC computation error: %s", exc)
            raise RuntimeError(f"Neo4j GDS WCC computation failed: {exc}") from exc

        all_finding_ids = list(finding_entities.keys())
        metrics = {
            "total_nodes": len(all_finding_ids),
            "total_edges": edge_count,
            "total_communities": len(communities),
            "neo4j_synced": True,
            "gds_executed": wcc_success
        }

        return communities, metrics

    def _sync_to_neo4j(
        self,
        case_id: str,
        tenant_id: str,
        finding_entities: Dict[str, Dict[str, Set[str]]],
        entity_to_findings: Dict[Tuple[str, str], Set[str]]
    ) -> int:
        """
        Pushes nodes and relationships to Neo4j with case_id and tenant_id isolation.
        """
        edge_count = 0
        
        # Determine query executor
        if hasattr(self.neo4j_client, "session"):
            # Driver object
            with self.neo4j_client.session() as session:
                return self._execute_cypher_sync(session.run, case_id, tenant_id, finding_entities, entity_to_findings)
        elif hasattr(self.neo4j_client, "query"):
            # Custom client wrapper
            return self._execute_cypher_sync(self.neo4j_client.query, case_id, tenant_id, finding_entities, entity_to_findings)
        else:
            raise RuntimeError("Provided Neo4j client lacks session() or query() method.")

    def _execute_cypher_sync(
        self,
        query_fn: Any,
        case_id: str,
        tenant_id: str,
        finding_entities: Dict[str, Dict[str, Set[str]]],
        entity_to_findings: Dict[Tuple[str, str], Set[str]]
    ) -> int:
        edge_count = 0

        # Step 0: Clear pre-existing graph nodes for this case_id & tenant_id to guarantee freshness
        query_fn(
            "MATCH (n {case_id: $case_id, tenant_id: $tenant_id}) DETACH DELETE n",
            {"case_id": case_id, "tenant_id": tenant_id}
        )

        # Create Artifact nodes
        for fid in finding_entities.keys():
            query_fn(
                "MERGE (a:Artifact {id: $fid, case_id: $case_id, tenant_id: $tenant_id})",
                {"fid": fid, "case_id": case_id, "tenant_id": tenant_id}
            )

        # Create Entity nodes & CORRELATED relationships
        for (etype, val), fids in entity_to_findings.items():
            if len(fids) > 1:
                entity_id = f"{etype}:{val}"
                query_fn(
                    "MERGE (e:Entity {id: $eid, type: $etype, value: $val, case_id: $case_id, tenant_id: $tenant_id})",
                    {"eid": entity_id, "etype": etype, "val": val, "case_id": case_id, "tenant_id": tenant_id}
                )
                for fid in fids:
                    query_fn(
                        "MATCH (a:Artifact {id: $fid, case_id: $case_id, tenant_id: $tenant_id}), "
                        "(e:Entity {id: $eid, case_id: $case_id, tenant_id: $tenant_id}) "
                        "MERGE (a)-[r:CORRELATED {rel_type: $rel_type, case_id: $case_id, tenant_id: $tenant_id}]->(e)",
                        {"fid": fid, "eid": entity_id, "case_id": case_id, "tenant_id": tenant_id, "rel_type": f"HAS_{etype.upper()}"}
                    )
                    edge_count += 1
        return edge_count

    def _run_neo4j_gds_wcc(
        self,
        case_id: str,
        tenant_id: str,
        finding_entities: Dict[str, Dict[str, Set[str]]]
    ) -> Tuple[List[GraphCommunity], bool]:
        """
        Executes Neo4j Graph Data Science (GDS) Weakly Connected Components (WCC) graph community detection.
        No in-memory fallback: Neo4j + GDS are mandatory. Fails closed if GDS or Neo4j is unavailable.
        """
        graph_name = f"argus_{case_id}_{tenant_id}".replace("-", "_").replace(".", "_")

        exec_fn = None
        session_obj = None
        if hasattr(self.neo4j_client, "session"):
            session_obj = self.neo4j_client.session()
            exec_fn = session_obj.run
        elif hasattr(self.neo4j_client, "query"):
            exec_fn = self.neo4j_client.query

        if not exec_fn:
            raise RuntimeError("No executable Cypher query function found on Neo4j client. Neo4j + GDS is required.")

        # Check GDS procedure availability
        try:
            proc_check = exec_fn(
                "SHOW PROCEDURES YIELD name WHERE name STARTS WITH 'gds.wcc' RETURN count(*) AS cnt",
                {}
            )
            records = [r.data() if hasattr(r, "data") else r for r in proc_check]
            cnt = list(records[0].values())[0] if records else 0
            if cnt == 0:
                raise RuntimeError("Neo4j GDS plugin (gds.wcc.stream) is not installed or available.")
        except Exception as exc:
            if "Neo4j GDS" in str(exc):
                raise exc
            try:
                proc_check = exec_fn(
                    "CALL dbms.procedures() YIELD name WHERE name STARTS WITH 'gds.wcc' RETURN count(*) AS cnt",
                    {}
                )
                records = [r.data() if hasattr(r, "data") else r for r in proc_check]
                cnt = list(records[0].values())[0] if records else 0
                if cnt == 0:
                    raise RuntimeError("Neo4j GDS plugin (gds.wcc.stream) is not installed or available.")
            except Exception as e2:
                raise RuntimeError(f"Neo4j GDS procedure check failed: {exc}") from exc

        # Execute Neo4j GDS WCC graph projection & execution
        try:
            # Drop graph projection if pre-existing
            try:
                exec_fn("CALL gds.graph.drop($graph_name, false)", {"graph_name": graph_name})
            except Exception:
                pass

            # Project graph via Cypher in GDS
            project_cypher = """
            CALL gds.graph.project.cypher(
                $graph_name,
                'MATCH (n) WHERE n.case_id = $case_id AND n.tenant_id = $tenant_id RETURN id(n) AS id, labels(n) AS labels',
                'MATCH (s)-[r:CORRELATED]->(t) WHERE r.case_id = $case_id AND r.tenant_id = $tenant_id RETURN id(s) AS source, id(t) AS target, type(r) AS type',
                {parameters: {case_id: $case_id, tenant_id: $tenant_id}}
            )
            """
            exec_fn(project_cypher, {"graph_name": graph_name, "case_id": case_id, "tenant_id": tenant_id})

            # Stream WCC results from GDS
            wcc_cypher = """
            CALL gds.wcc.stream($graph_name)
            YIELD nodeId, componentId
            RETURN gds.util.asNode(nodeId).id AS node_id, labels(gds.util.asNode(nodeId)) AS labels, componentId AS communityId
            ORDER BY communityId
            """
            res = exec_fn(wcc_cypher, {"graph_name": graph_name})
            wcc_records = [r.data() if hasattr(r, "data") else r for r in res]

            # Cleanup projected GDS graph
            try:
                exec_fn("CALL gds.graph.drop($graph_name, false)", {"graph_name": graph_name})
            except Exception:
                pass
        except Exception as exc:
            try:
                exec_fn("CALL gds.graph.drop($graph_name, false)", {"graph_name": graph_name})
            except Exception:
                pass
            raise RuntimeError(f"Neo4j GDS WCC execution failed: {exc}") from exc
        finally:
            if session_obj and hasattr(session_obj, "close"):
                try:
                    session_obj.close()
                except Exception:
                    pass

        # Build GraphCommunities from GDS WCC records
        community_map = defaultdict(lambda: {"findings": set(), "entities": set(), "entity_types": set()})

        for rec in wcc_records:
            nid = rec.get("node_id")
            lbls = rec.get("labels", [])
            cid = rec.get("communityId")
            if cid is None or not nid:
                continue
            if "Artifact" in lbls:
                community_map[cid]["findings"].add(nid)
            elif "Entity" in lbls:
                if ":" in nid:
                    etype, val = nid.split(":", 1)
                    community_map[cid]["entities"].add(val)
                    community_map[cid]["entity_types"].add(etype)

        communities: List[GraphCommunity] = []
        for idx, (cid, data) in enumerate(sorted(community_map.items(), key=lambda x: x[0]), 1):
            findings_list = sorted(list(data["findings"]))
            if not findings_list:
                continue
            comm_entities = sorted(list(data["entities"]))
            comm_etypes = sorted(list(data["entity_types"]))
            comm_rels = sorted([f"SHARED_{et.upper()}" for et in comm_etypes])
            communities.append(
                GraphCommunity(
                    community_id=f"GC-{idx:03d}",
                    finding_ids=findings_list,
                    entity_names=comm_entities,
                    entity_types=comm_etypes,
                    relationship_types=comm_rels,
                    wcc_component_id=int(cid)
                )
            )

        return communities, True

    def _extract_entities_from_finding(self, finding: Any, text: str) -> Dict[str, Set[str]]:
        entities: Dict[str, Set[str]] = defaultdict(set)

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

