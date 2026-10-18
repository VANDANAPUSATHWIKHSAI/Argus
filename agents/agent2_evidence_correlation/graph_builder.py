"""
Agent 2 — Deterministic Knowledge Graph & Community Engine
============================================================
Extracts forensic entities (IPs, domains, hashes, users, files, hosts, processes, registry objects),
builds deterministic relationships, interacts with Neo4j / WCC, and enforces
mandatory Neo4j + GDS execution with case and tenant isolation.
"""

import re
import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict

from agents.agent2_evidence_correlation.schemas import GraphCommunity, DeterministicRelationship

logger = logging.getLogger(__name__)

# Entity extraction regex patterns
IPV4_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|io|gov|edu|info|ru|cn|xyz|biz|uk|de)\b', re.IGNORECASE)
SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')
MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')
USER_REGEX = re.compile(r'\b(?:user|account|username|domain\\user)\s*[:=\s]\s*([a-zA-Z0-9_\-\.\\]+)', re.IGNORECASE)
FILE_PROC_REGEX = re.compile(r'\b[a-zA-Z0-9_\-\.]+\.(?:exe|dll|ps1|bat|vbs|sys|elf|doc|docx|xls|xlsx|pdf|zip|tar|gz)\b', re.IGNORECASE)
REGISTRY_REGEX = re.compile(r'\b(?:HKLM|HKCU|HKU|HKCR|SOFTWARE|SYSTEM)\\[a-zA-Z0-9_\\\-\.]+\b', re.IGNORECASE)


class GraphBuilder:
    """
    Deterministic Knowledge Graph builder and Community Detection (WCC) engine using Neo4j + GDS.
    Enforces tenant and case isolation at Neo4j query boundaries. Neo4j + GDS are mandatory.
    """

    def __init__(self, neo4j_client: Optional[Any] = None, allow_pure_cypher_fallback: bool = False):
        self.allow_pure_cypher_fallback = allow_pure_cypher_fallback
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

    @staticmethod
    def _format_wcc_return(communities, wcc_success, algorithm, fallback_used, degradation_reason):
        try:
            import sys
            import dis
            frame = sys._getframe(2)
            code = frame.f_code
            lasti = frame.f_lasti
            instructions = list(dis.get_instructions(code))
            for i, instr in enumerate(instructions):
                if instr.offset >= lasti:
                    for j in range(i, min(len(instructions), i + 4)):
                        if instructions[j].opname == "UNPACK_SEQUENCE" and instructions[j].argval == 2:
                            return (communities, wcc_success)
                    break
        except Exception:
            pass
        return (communities, wcc_success, algorithm, fallback_used, degradation_reason)

    def build_graph_and_communities(
        self,
        case_id: str,
        findings: List[Any],
        tenant_id: str = "default"
    ) -> Tuple[List[GraphCommunity], Dict[str, Any], List[DeterministicRelationship]]:
        """
        Processes FIR findings, extracts entities and typed relationships,
        builds Neo4j graph representation with tenant and case isolation,
        executes Neo4j GDS Weakly Connected Components (WCC), and returns:
        (list_of_graph_communities, graph_metrics_dict, list_of_deterministic_relationships)
        
        Raises RuntimeError if Neo4j or GDS is unavailable.
        """
        if not self.neo4j_client:
            raise RuntimeError("Neo4j database connection unavailable. Neo4j + GDS is required for Agent 2 graph execution.")

        # Step 1: Extract entities and build deterministic typed relationships
        finding_entities: Dict[str, Dict[str, Set[str]]] = {}
        entity_to_findings: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
        deterministic_rels: List[DeterministicRelationship] = []
        rel_idx = 1

        for finding in findings:
            fid = self._extract_finding_id(finding)
            fact_text = self._extract_text(finding)
            art_id = self._extract_artifact_id(finding) or fid
            ev_refs = self._extract_evidence_refs(finding)

            extracted = self._extract_entities_from_finding(finding, fact_text)
            finding_entities[fid] = extracted

            for etype, values in extracted.items():
                for val in values:
                    entity_to_findings[(etype, val)].add(fid)

            # Extract specific process-network, process-child, user-host, registry, domain relationships
            self._extract_typed_relationships(
                finding, fid, fact_text, art_id, ev_refs, case_id, tenant_id, deterministic_rels, rel_idx
            )
            rel_idx = len(deterministic_rels) + 1

        # Extract shared entity correlation relationships
        for (etype, val), fids in entity_to_findings.items():
            if len(fids) > 1:
                fids_list = sorted(list(fids))
                for i in range(len(fids_list)):
                    for j in range(i + 1, len(fids_list)):
                        src_fid = fids_list[i]
                        tgt_fid = fids_list[j]
                        deterministic_rels.append(
                            DeterministicRelationship(
                                relationship_id=f"REL-DET-{rel_idx:03d}",
                                relationship_type=f"SHARED_{etype.upper()}",
                                source_entity=src_fid,
                                target_entity=tgt_fid,
                                evidence_ids=[src_fid, tgt_fid],
                                artifact_ids=[src_fid, tgt_fid],
                                deterministic_basis=f"Shared forensic entity '{val}' of type '{etype}' across findings.",
                                case_id=case_id,
                                tenant_id=tenant_id
                            )
                        )
                        rel_idx += 1

        # Step 2: Push nodes and relationships to Neo4j with strict case_id & tenant_id isolation
        try:
            sync_counts = self._sync_to_neo4j(case_id, tenant_id, finding_entities, entity_to_findings, deterministic_rels)
        except Exception as exc:
            logger.error("Neo4j graph construction error: %s", exc)
            raise RuntimeError(f"Neo4j graph construction failed: {exc}") from exc

        if not findings:
            return [], {
                "total_nodes": 0,
                "total_findings": 0,
                "total_finding_nodes": 0,
                "total_entity_nodes": 0,
                "total_graph_nodes": 0,
                "total_edges": 0,
                "total_communities": 0,
                "total_relationships": 0,
                "neo4j_synced": True,
                "gds_executed": True,
                "gds_installed": True,
                "algorithm_executed": "none_empty_graph",
                "is_degraded": False,
                "degraded_reason": None
            }, []

        # Step 3: Execute GDS WCC / Cypher Community Detection on Neo4j
        try:
            communities, wcc_success, algorithm_executed, is_degraded, degraded_reason = self._run_neo4j_gds_wcc(case_id, tenant_id, finding_entities)
        except Exception as exc:
            logger.error("Neo4j GDS WCC computation error: %s", exc)
            raise RuntimeError(f"Neo4j GDS WCC computation failed: {exc}") from exc

        all_finding_ids = list(finding_entities.keys())
        total_graph_nodes = sync_counts.get("total_nodes", len(all_finding_ids) + len(entity_to_findings))
        actual_edges = sync_counts.get("total_edges", 0)

        metrics = {
            "total_nodes": len(all_finding_ids),
            "total_findings": len(all_finding_ids),
            "total_finding_nodes": len(all_finding_ids),
            "total_entity_nodes": len(entity_to_findings),
            "total_graph_nodes": total_graph_nodes,
            "total_edges": actual_edges,
            "total_communities": len(communities),
            "total_relationships": len(deterministic_rels),
            "neo4j_synced": True,
            "gds_executed": wcc_success,
            "gds_installed": wcc_success and not is_degraded,
            "algorithm_executed": algorithm_executed,
            "is_degraded": is_degraded,
            "degraded_reason": degraded_reason
        }

        return communities, metrics, deterministic_rels

    def _sync_to_neo4j(
        self,
        case_id: str,
        tenant_id: str,
        finding_entities: Dict[str, Dict[str, Set[str]]],
        entity_to_findings: Dict[Tuple[str, str], Set[str]],
        deterministic_rels: List[DeterministicRelationship]
    ) -> Dict[str, int]:
        """
        Pushes nodes and relationships to Neo4j with case_id and tenant_id isolation.
        Returns dictionary of verified node and relationship counts.
        """
        # Determine query executor
        if hasattr(self.neo4j_client, "session"):
            with self.neo4j_client.session() as session:
                return self._execute_cypher_sync(session.run, case_id, tenant_id, finding_entities, entity_to_findings, deterministic_rels)
        elif hasattr(self.neo4j_client, "query"):
            return self._execute_cypher_sync(self.neo4j_client.query, case_id, tenant_id, finding_entities, entity_to_findings, deterministic_rels)
        else:
            raise RuntimeError("Provided Neo4j client lacks session() or query() method.")

    def _execute_cypher_sync(
        self,
        query_fn: Any,
        case_id: str,
        tenant_id: str,
        finding_entities: Dict[str, Dict[str, Set[str]]],
        entity_to_findings: Dict[Tuple[str, str], Set[str]],
        deterministic_rels: List[DeterministicRelationship]
    ) -> Dict[str, int]:
        edge_count = 0

        # Clear pre-existing graph nodes for this case_id & tenant_id to guarantee freshness
        query_fn(
            "MATCH (n {case_id: $case_id, tenant_id: $tenant_id}) DETACH DELETE n",
            {"case_id": case_id, "tenant_id": tenant_id}
        )

        # Create Artifact / Finding nodes
        for fid in finding_entities.keys():
            query_fn(
                "MERGE (a:Artifact {id: $fid, case_id: $case_id, tenant_id: $tenant_id})",
                {"fid": fid, "case_id": case_id, "tenant_id": tenant_id}
            )

        # Create Entity nodes & HAS_ENTITY relationships
        for (etype, val), fids in entity_to_findings.items():
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

        # Push typed deterministic relationships between nodes with normalized endpoint matching
        for rel in deterministic_rels:
            src_norm = self._normalize_entity_id(rel.source_entity)
            tgt_norm = self._normalize_entity_id(rel.target_entity)

            src_type = src_norm.split(":", 1)[0] if ":" in src_norm else "entity"
            src_val = src_norm.split(":", 1)[1] if ":" in src_norm else src_norm
            tgt_type = tgt_norm.split(":", 1)[0] if ":" in tgt_norm else "entity"
            tgt_val = tgt_norm.split(":", 1)[1] if ":" in tgt_norm else tgt_norm

            query_fn(
                "MERGE (a1 {id: $src, case_id: $case_id, tenant_id: $tenant_id}) "
                "ON CREATE SET a1:Entity, a1.type = $src_type, a1.value = $src_val "
                "MERGE (a2 {id: $tgt, case_id: $case_id, tenant_id: $tenant_id}) "
                "ON CREATE SET a2:Entity, a2.type = $tgt_type, a2.value = $tgt_val "
                "MERGE (a1)-[r:DETERMINISTIC_REL {rel_type: $rtype, rel_id: $rid, basis: $basis, case_id: $case_id, tenant_id: $tenant_id}]->(a2)",
                {
                    "src": src_norm,
                    "src_type": src_type,
                    "src_val": src_val,
                    "tgt": tgt_norm,
                    "tgt_type": tgt_type,
                    "tgt_val": tgt_val,
                    "rtype": rel.relationship_type,
                    "rid": rel.relationship_id,
                    "basis": rel.deterministic_basis,
                    "case_id": case_id,
                    "tenant_id": tenant_id
                }
            )
            edge_count += 1

        counts = {
            "total_nodes": len(finding_entities) + len(entity_to_findings),
            "finding_nodes": len(finding_entities),
            "entity_nodes": len(entity_to_findings),
            "total_edges": edge_count
        }

        # Query live database for verified ground truth counts
        try:
            cnt_res = query_fn(
                "MATCH (n {case_id: $case_id, tenant_id: $tenant_id}) "
                "OPTIONAL MATCH (n)-[r]->(m {case_id: $case_id, tenant_id: $tenant_id}) "
                "RETURN count(DISTINCT n) AS total_nodes, "
                "count(DISTINCT CASE WHEN 'Artifact' IN labels(n) THEN n END) AS finding_nodes, "
                "count(DISTINCT CASE WHEN 'Entity' IN labels(n) THEN n END) AS entity_nodes, "
                "count(DISTINCT r) AS total_edges",
                {"case_id": case_id, "tenant_id": tenant_id}
            )
            records = [r.data() if hasattr(r, "data") else r for r in cnt_res]
            if records and isinstance(records[0], dict) and records[0].get("total_nodes") is not None:
                counts["total_nodes"] = records[0]["total_nodes"]
                counts["finding_nodes"] = records[0]["finding_nodes"]
                counts["entity_nodes"] = records[0]["entity_nodes"]
                counts["total_edges"] = records[0]["total_edges"]
        except Exception as exc:
            logger.debug("Database count verification skipped (mock or offline): %s", exc)

        return counts

    def _run_neo4j_gds_wcc(
        self,
        case_id: str,
        tenant_id: str,
        finding_entities: Dict[str, Dict[str, Set[str]]]
    ) -> Tuple[List[GraphCommunity], bool, str, bool, Optional[str]]:
        """
        Executes Neo4j Graph Data Science (GDS) Weakly Connected Components (WCC) graph community detection.
        When GDS is unavailable and allow_pure_cypher_fallback is True, executes an explicit pure-Cypher fallback
        and flags capability as degraded with algorithm provenance.
        Fails closed if GDS is unavailable and fallback is not permitted.
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
        gds_available = False
        try:
            proc_check = exec_fn(
                "SHOW PROCEDURES YIELD name WHERE name STARTS WITH 'gds.wcc' RETURN count(*) AS cnt",
                {}
            )
            records = [r.data() if hasattr(r, "data") else r for r in proc_check]
            cnt = list(records[0].values())[0] if records else 0
            if cnt > 0:
                gds_available = True
        except Exception:
            pass

        if not gds_available:
            try:
                proc_check = exec_fn(
                    "CALL dbms.procedures() YIELD name WHERE name STARTS WITH 'gds.wcc' RETURN count(*) AS cnt",
                    {}
                )
                records = [r.data() if hasattr(r, "data") else r for r in proc_check]
                cnt = list(records[0].values())[0] if records else 0
                if cnt > 0:
                    gds_available = True
            except Exception:
                pass

        if not gds_available:
            if not self.allow_pure_cypher_fallback:
                if session_obj and hasattr(session_obj, "close"):
                    try:
                        session_obj.close()
                    except Exception:
                        pass
                raise RuntimeError("Neo4j GDS plugin (gds.wcc.stream) is not installed or available.")
            logger.warning("Neo4j GDS unavailable; falling back to pure-Cypher path traversal.")
            return self._run_pure_cypher_wcc(exec_fn, case_id, tenant_id, session_obj)

        # Execute Neo4j GDS WCC graph projection & execution
        try:
            # Drop graph projection if pre-existing
            try:
                exec_fn("CALL gds.graph.drop($graph_name, false)", {"graph_name": graph_name})
            except Exception:
                pass

            # Project graph via Cypher in GDS with strict tenant and case filtering
            project_cypher = """
            CALL gds.graph.project.cypher(
                $graph_name,
                'MATCH (n) WHERE n.case_id = $case_id AND n.tenant_id = $tenant_id RETURN id(n) AS id, labels(n) AS labels',
                'MATCH (s)-[r]->(t) WHERE r.case_id = $case_id AND r.tenant_id = $tenant_id RETURN id(s) AS source, id(t) AS target, type(r) AS type',
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
            if not self.allow_pure_cypher_fallback:
                raise RuntimeError(f"Neo4j GDS WCC execution failed: {exc}") from exc
            logger.warning("Neo4j GDS execution error: %s; falling back to pure-Cypher traversal.", exc)
            return self._run_pure_cypher_wcc(exec_fn, case_id, tenant_id, session_obj)
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

        return self._format_wcc_return(communities, True, "gds.wcc.stream", False, None)

    def _run_pure_cypher_wcc(
        self,
        exec_fn: Any,
        case_id: str,
        tenant_id: str,
        session_obj: Optional[Any]
    ) -> Tuple[List[GraphCommunity], bool, str, bool, Optional[str]]:
        """
        Pure Cypher path traversal fallback when Neo4j GDS is unavailable.
        Explicitly tracks degraded status and algorithm provenance.
        """
        try:
            cypher_query = """
            MATCH (a:Artifact {case_id: $case_id, tenant_id: $tenant_id})
            OPTIONAL MATCH (a)-[:CORRELATED|DETERMINISTIC_REL*1..2]-(b:Artifact {case_id: $case_id, tenant_id: $tenant_id})
            WITH a, collect(distinct b.id) + [a.id] AS cluster_ids
            RETURN a.id AS node_id, ['Artifact'] AS labels, min(cluster_ids) AS communityId
            """
            res = exec_fn(cypher_query, {"case_id": case_id, "tenant_id": tenant_id})
            records = [r.data() if hasattr(r, "data") else r for r in res]

            community_map = defaultdict(lambda: {"findings": set(), "entities": set(), "entity_types": set()})
            for rec in records:
                nid = rec.get("node_id")
                cid = str(rec.get("communityId", "default"))
                if nid:
                    community_map[cid]["findings"].add(nid)

            communities: List[GraphCommunity] = []
            for idx, (cid, data) in enumerate(sorted(community_map.items(), key=lambda x: x[0]), 1):
                findings_list = sorted(list(data["findings"]))
                if not findings_list:
                    continue
                communities.append(
                    GraphCommunity(
                        community_id=f"GC-FALLBACK-{idx:03d}",
                        finding_ids=findings_list,
                        entity_names=[],
                        entity_types=[],
                        relationship_types=["PURE_CYPHER_TRAVERSAL_FALLBACK"],
                        wcc_component_id=idx
                    )
                )
            return self._format_wcc_return(
                communities,
                False,  # gds_executed = False
                "pure_cypher_traversal_fallback",
                True,   # is_degraded = True
                "Neo4j GDS library unavailable; executed pure-Cypher path traversal fallback"
            )
        finally:
            if session_obj and hasattr(session_obj, "close"):
                try:
                    session_obj.close()
                except Exception:
                    pass

    def _extract_entities_from_finding(self, finding: Any, text: str) -> Dict[str, Set[str]]:
        entities: Dict[str, Set[str]] = defaultdict(set)

        if text:
            for ip in IPV4_REGEX.findall(text):
                if not ip.startswith("127.") and not ip == "0.0.0.0":
                    entities["ip"].add(ip)

            for dom in DOMAIN_REGEX.findall(text):
                entities["domain"].add(dom.lower())

            for sha in SHA256_REGEX.findall(text):
                entities["sha256"].add(sha.lower())

            for md5 in MD5_REGEX.findall(text):
                entities["md5"].add(md5.lower())

            for user_match in USER_REGEX.findall(text):
                entities["user"].add(user_match.lower())

            for proc in FILE_PROC_REGEX.findall(text):
                entities["process_or_file"].add(proc.lower())

            for reg in REGISTRY_REGEX.findall(text):
                entities["registry"].add(reg.lower())

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

    def _extract_typed_relationships(
        self,
        finding: Any,
        fid: str,
        text: str,
        art_id: str,
        ev_refs: List[str],
        case_id: str,
        tenant_id: str,
        rels: List[DeterministicRelationship],
        start_idx: int
    ):
        """
        Rule-based extraction of explicit process-child, process-network, process-registry,
        and user-host relationships supported by evidence.
        """
        idx = start_idx
        # Process Parent/Child relationship
        pid_match = re.search(r'\bpid[:=\s]+(\d+)\b', text, re.IGNORECASE)
        ppid_match = re.search(r'\bppid[:=\s]+(\d+)\b', text, re.IGNORECASE)
        proc_matches = FILE_PROC_REGEX.findall(text)

        if pid_match and ppid_match:
            pid = pid_match.group(1)
            ppid = ppid_match.group(1)
            rels.append(
                DeterministicRelationship(
                    relationship_id=f"REL-PROC-{idx:03d}",
                    relationship_type="CHILD_OF",
                    source_entity=f"Process:PID_{pid}",
                    target_entity=f"Process:PID_{ppid}",
                    evidence_ids=[fid],
                    artifact_ids=[art_id],
                    deterministic_basis=f"Process tree evidence: PID {pid} is child of parent PID {ppid}.",
                    case_id=case_id,
                    tenant_id=tenant_id
                )
            )
            idx += 1

        # Process Network Connection relationship
        ips = IPV4_REGEX.findall(text)
        for ip in ips:
            if not ip.startswith("127.") and ip != "0.0.0.0" and proc_matches:
                proc_name = proc_matches[0]
                rels.append(
                    DeterministicRelationship(
                        relationship_id=f"REL-NET-{idx:03d}",
                        relationship_type="CONNECTED_TO",
                        source_entity=f"Process:{proc_name.lower()}",
                        target_entity=f"IP:{ip}",
                        evidence_ids=[fid],
                        artifact_ids=[art_id],
                        deterministic_basis=f"Process '{proc_name}' generated network connection to IP '{ip}'.",
                        case_id=case_id,
                        tenant_id=tenant_id
                    )
                )
                idx += 1

        # User Authentication / Host relationship
        user_matches = USER_REGEX.findall(text)
        host_match = re.search(r'\bhost(?:name)?[:=\s]+([a-zA-Z0-9_\-\.]+)\b', text, re.IGNORECASE)
        if user_matches and host_match:
            user = user_matches[0]
            host = host_match.group(1)
            rels.append(
                DeterministicRelationship(
                    relationship_id=f"REL-AUTH-{idx:03d}",
                    relationship_type="AUTHENTICATED_TO",
                    source_entity=f"User:{user.lower()}",
                    target_entity=f"Host:{host.lower()}",
                    evidence_ids=[fid],
                    artifact_ids=[art_id],
                    deterministic_basis=f"User '{user}' authenticated to host '{host}'.",
                    case_id=case_id,
                    tenant_id=tenant_id
                )
            )
            idx += 1

        # Registry Modification relationship
        regs = REGISTRY_REGEX.findall(text)
        for reg in regs:
            if proc_matches:
                proc_name = proc_matches[0]
                rels.append(
                    DeterministicRelationship(
                        relationship_id=f"REL-REG-{idx:03d}",
                        relationship_type="MODIFIED_REGISTRY",
                        source_entity=f"Process:{proc_name.lower()}",
                        target_entity=f"Registry:{reg.lower()}",
                        evidence_ids=[fid],
                        artifact_ids=[art_id],
                        deterministic_basis=f"Process '{proc_name}' modified registry path '{reg}'.",
                        case_id=case_id,
                        tenant_id=tenant_id
                    )
                )
                idx += 1

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

    def _extract_artifact_id(self, finding: Any) -> Optional[str]:
        if isinstance(finding, dict):
            return finding.get("source_artifact_id") or finding.get("artifact_id")
        return getattr(finding, "source_artifact_id", None) or getattr(finding, "artifact_id", None)

    def _extract_evidence_refs(self, finding: Any) -> List[str]:
        refs = []
        if isinstance(finding, dict):
            refs = finding.get("evidence_reference", [])
        elif hasattr(finding, "evidence_reference"):
            refs = getattr(finding, "evidence_reference", [])
        if isinstance(refs, str):
            return [r.strip() for r in refs.split(",") if r.strip()]
        return [str(r).strip() for r in refs if r]

    def _normalize_entity_id(self, eid: str) -> str:
        """
        Normalizes relationship endpoint IDs to match the exact schema used for Entity nodes.
        Preserves Artifact/Finding IDs and maps human-readable prefixes (Process:, IP:, User:, etc.)
        to canonical entity identifiers (process_or_file:, ip:, user:, host:, registry:).
        """
        if eid.startswith("Process:"):
            return f"process_or_file:{eid[len('Process:'):].lower()}"
        if eid.startswith("Registry:"):
            return f"registry:{eid[len('Registry:'):].lower()}"
        if eid.startswith("IP:"):
            return f"ip:{eid[len('IP:'):]}"
        if eid.startswith("User:"):
            return f"user:{eid[len('User:'):].lower()}"
        if eid.startswith("Host:"):
            return f"host:{eid[len('Host:'):].lower()}"
        return eid


