"""
Agent 5b — Case Behavioral Signature Builder
============================================
Extracts, aggregates, and structures findings from Agent 3, Agent 4, and Agent 5a
into a unified CaseBehavioralSignature before vector encoding and Qdrant retrieval.

Enforces:
- Authoritative case_id and tenant_id inheritance and mismatch detection
- Accurate mapping of behavior to supporting evidence IDs
- Synthetic / Documentation IP handling (RFC 5737)
"""

from typing import Dict, Any, List, Optional, Set
import re
import logging
from agents.agent5b_campaign_similarity.schemas import (
    CaseBehavioralSignature,
    MalwareBehaviorSignature,
    AttackPatternSignature,
    ThreatIntelligenceSignature,
    YaraSignature
)

logger = logging.getLogger(__name__)

# RFC 5737 Documentation & Synthetic Prefix Patterns
SYNTHETIC_IP_PATTERNS = [
    re.compile(r"^192\.0\.2\."),       # TEST-NET-1
    re.compile(r"^198\.51\.100\."),    # TEST-NET-2
    re.compile(r"^203\.0\.113\."),     # TEST-NET-3
    re.compile(r"^127\."),             # Loopback
]
SYNTHETIC_DOMAIN_PATTERNS = [
    re.compile(r"\bexample\.(com|org|net)\b", re.IGNORECASE),
    re.compile(r"\blocalhost\b", re.IGNORECASE)
]


class CaseSignatureBuilder:
    """
    Builds structured CaseBehavioralSignature from upstream agent payloads.
    Validates case and tenant consistency and maps supporting evidence IDs.
    """

    @classmethod
    def build(
        cls,
        case_id: str,
        tenant_id: str = "default",
        agent3_output: Optional[Dict[str, Any]] = None,
        agent4_output: Optional[Dict[str, Any]] = None,
        agent5a_output: Optional[Dict[str, Any]] = None,
        agent2_output: Optional[Dict[str, Any]] = None,
        evidence_ids: Optional[List[str]] = None
    ) -> CaseBehavioralSignature:
        validation_warnings: List[str] = []
        mismatched_records: List[Dict[str, Any]] = []

        if agent3_output is not None and not isinstance(agent3_output, dict):
            validation_warnings.append("Agent 3 output is malformed (expected dict)")
            agent3_data = {}
        else:
            agent3_data = agent3_output or {}

        if agent4_output is not None and not isinstance(agent4_output, dict):
            validation_warnings.append("Agent 4 output is malformed (expected dict)")
            agent4_data = {}
        else:
            agent4_data = agent4_output or {}

        if agent5a_output is not None and not isinstance(agent5a_output, dict):
            validation_warnings.append("Agent 5a output is malformed (expected dict)")
            agent5a_data = {}
        else:
            agent5a_data = agent5a_output or {}

        if agent2_output is not None and not isinstance(agent2_output, dict):
            validation_warnings.append("Agent 2 output is malformed (expected dict)")
            agent2_data = {}
        else:
            agent2_data = agent2_output or {}

        # 1. Validate Case ID and Tenant ID consistency across inputs
        cls._validate_metadata(
            "Agent 3", agent3_data, case_id, tenant_id, validation_warnings, mismatched_records
        )
        cls._validate_metadata(
            "Agent 4", agent4_data, case_id, tenant_id, validation_warnings, mismatched_records
        )
        cls._validate_metadata(
            "Agent 5a", agent5a_data, case_id, tenant_id, validation_warnings, mismatched_records
        )
        if agent2_data:
            cls._validate_metadata(
                "Agent 2", agent2_data, case_id, tenant_id, validation_warnings, mismatched_records
            )

        # 2. Build Malware Behavior Signature from Agent 4
        malware_behavior = cls._build_malware_behavior(agent4_data)

        # 3. Build Attack Pattern Signature from Agent 3
        attack_pattern = cls._build_attack_pattern(agent3_data)

        # 4. Build Threat Intelligence Signature from Agent 5a
        threat_intel = cls._build_threat_intel(agent5a_data)

        # 5. Build YARA Signature from Agent 4 / Agent 2
        yara = cls._build_yara(agent4_data, agent2_data)

        # 6. Collect valid evidence IDs
        all_eids = set(evidence_ids or [])
        for src in [agent2_data, agent3_data, agent4_data, agent5a_data]:
            if "evidence_ids" in src and isinstance(src["evidence_ids"], list):
                for item in src["evidence_ids"]:
                    if isinstance(item, str) and item.strip():
                        all_eids.add(item.strip())
            if "evidence_references" in src and isinstance(src["evidence_references"], list):
                for item in src["evidence_references"]:
                    if isinstance(item, str) and item.strip():
                        all_eids.add(item.strip())
                    elif isinstance(item, dict):
                        val = item.get("finding_id") or item.get("evidence_id") or item.get("id")
                        if isinstance(val, str) and val.strip():
                            all_eids.add(val.strip())

        return CaseBehavioralSignature(
            case_id=case_id,
            tenant_id=tenant_id,
            malware_behavior=malware_behavior,
            attack_pattern=attack_pattern,
            threat_intelligence=threat_intel,
            yara=yara,
            evidence_ids=sorted(list(all_eids)),
            validation_warnings=validation_warnings,
            mismatched_records=mismatched_records
        )

    @classmethod
    def _validate_metadata(
        cls,
        source_name: str,
        data: Dict[str, Any],
        expected_case_id: str,
        expected_tenant_id: str,
        warnings: List[str],
        mismatches: List[Dict[str, Any]]
    ):
        if not data or not isinstance(data, dict):
            return

        src_case_id = data.get("case_id")
        if src_case_id and str(src_case_id).strip() != expected_case_id.strip():
            msg = f"{source_name} case_id mismatch: expected '{expected_case_id}', found '{src_case_id}'"
            warnings.append(msg)
            mismatches.append({
                "source": source_name,
                "field": "case_id",
                "expected": expected_case_id,
                "found": src_case_id
            })

        src_tenant_id = data.get("tenant_id")
        if src_tenant_id and str(src_tenant_id).strip() != expected_tenant_id.strip():
            msg = f"{source_name} tenant_id mismatch: expected '{expected_tenant_id}', found '{src_tenant_id}'"
            warnings.append(msg)
            mismatches.append({
                "source": source_name,
                "field": "tenant_id",
                "expected": expected_tenant_id,
                "found": src_tenant_id
            })

    @classmethod
    def _build_malware_behavior(cls, a4: Dict[str, Any]) -> MalwareBehaviorSignature:
        fp = a4.get("behavior_fingerprint") or {}
        if hasattr(fp, "model_dump"):
            fp = fp.model_dump()

        cap = a4.get("capability_profile") or {}
        if hasattr(cap, "model_dump"):
            cap = cap.model_dump()

        categories = [
            "execution", "persistence", "credential_access", "privilege_escalation",
            "defense_evasion", "discovery", "collection", "command_and_control",
            "exfiltration", "impact"
        ]

        data: Dict[str, List[str]] = {}
        evidence_map: Dict[str, List[str]] = {}

        # Fallback evidence from Agent 4 claims or observations
        observations = a4.get("behavior_observations", [])
        claims = a4.get("claims", [])

        # Index observation evidence
        obs_eids: Dict[str, Set[str]] = {}
        for obs in observations:
            b_name = obs.get("behavior") if isinstance(obs, dict) else getattr(obs, "behavior", "")
            eids = obs.get("cited_evidence_ids") or obs.get("evidence_ids") if isinstance(obs, dict) else getattr(obs, "cited_evidence_ids", [])
            if b_name:
                obs_eids.setdefault(b_name.strip(), set()).update(eids or [])

        # Global evidence IDs from a4 as baseline
        global_eids = a4.get("evidence_ids") or []

        for cat in categories:
            items = set()
            for item in fp.get(cat, []):
                s_item = str(item).strip()
                if s_item:
                    items.add(s_item)
                    # Associate evidence IDs
                    if s_item in obs_eids:
                        evidence_map[s_item] = sorted(list(obs_eids[s_item]))
                    elif global_eids:
                        evidence_map[s_item] = sorted(list(global_eids))

            for item in cap.get(cat, []):
                s_item = str(item).strip()
                if s_item:
                    items.add(s_item)
                    if s_item not in evidence_map and global_eids:
                        evidence_map[s_item] = sorted(list(global_eids))

            for obs in observations:
                obs_cat = obs.get("category", "") if isinstance(obs, dict) else getattr(obs, "category", "")
                if obs_cat.lower() == cat:
                    beh = obs.get("behavior", "") if isinstance(obs, dict) else getattr(obs, "behavior", "")
                    if beh:
                        beh_s = beh.strip()
                        items.add(beh_s)
                        if beh_s in obs_eids:
                            evidence_map[beh_s] = sorted(list(obs_eids[beh_s]))

            data[cat] = sorted(list(items))

        return MalwareBehaviorSignature(**data, behavior_evidence_map=evidence_map)

    @classmethod
    def _build_attack_pattern(cls, a3: Dict[str, Any]) -> AttackPatternSignature:
        stages = a3.get("attack_stages") or a3.get("stages") or []
        path = a3.get("attack_path") or a3.get("path") or []
        kill_chain = a3.get("kill_chain_steps") or a3.get("kill_chain") or []
        infection_source = a3.get("infection_source")

        tactics = a3.get("tactics") or {}
        if hasattr(tactics, "model_dump"):
            tactics = tactics.model_dump()

        stage_evidence_map: Dict[str, List[str]] = {}
        eids = a3.get("evidence_ids") or []
        for s in (stages if isinstance(stages, list) else [stages]):
            if s and eids:
                stage_evidence_map[str(s)] = sorted(list(eids))

        return AttackPatternSignature(
            initial_access=cls._extract_list(tactics.get("initial_access", a3.get("initial_access", []))),
            execution=cls._extract_list(tactics.get("execution", a3.get("execution", []))),
            persistence=cls._extract_list(tactics.get("persistence", a3.get("persistence", []))),
            credential_access=cls._extract_list(tactics.get("credential_access", a3.get("credential_access", []))),
            lateral_movement=cls._extract_list(tactics.get("lateral_movement", a3.get("lateral_movement", []))),
            command_and_control=cls._extract_list(tactics.get("command_and_control", a3.get("command_and_control", []))),
            exfiltration=cls._extract_list(tactics.get("exfiltration", a3.get("exfiltration", []))),
            infection_source=str(infection_source) if infection_source else None,
            attack_path=[str(p) for p in path] if isinstance(path, list) else ([str(path)] if path else []),
            attack_stages=[str(s) for s in stages] if isinstance(stages, list) else ([str(stages)] if stages else []),
            kill_chain_steps=[str(k) for k in kill_chain] if isinstance(kill_chain, list) else ([str(kill_chain)] if kill_chain else []),
            stage_evidence_map=stage_evidence_map
        )

    @classmethod
    def _build_threat_intel(cls, a5a: Dict[str, Any]) -> ThreatIntelligenceSignature:
        ti = a5a.get("threat_intelligence") or a5a

        families = ti.get("candidate_malware_families") or ti.get("candidate_families") or []
        raw_iocs = ti.get("ioc_matches") or []
        mitre = ti.get("mitre_techniques") or []
        cves = ti.get("cve_references") or ti.get("cves") or []
        reports = ti.get("threat_reports") or []
        quality = ti.get("source_quality") or []
        freshness = ti.get("freshness") or []
        conf = float(ti.get("confidence", 0.8))
        conflicts = ti.get("intelligence_conflicts") or []
        limitations = ti.get("limitations") or []

        # Tag synthetic / documentation-only indicators
        processed_iocs: List[Dict[str, Any]] = []
        for ioc in raw_iocs:
            ioc_dict = ioc if isinstance(ioc, dict) else {"indicator": str(ioc)}
            ind = str(ioc_dict.get("indicator", ""))

            is_synthetic = any(p.search(ind) for p in SYNTHETIC_IP_PATTERNS) or any(p.search(ind) for p in SYNTHETIC_DOMAIN_PATTERNS)
            if is_synthetic:
                ioc_dict = dict(ioc_dict)
                ioc_dict["is_synthetic_documentation_indicator"] = True
                ioc_dict["test_data_note"] = "RFC 5737 documentation prefix or example domain; not verified live malicious infrastructure."

            processed_iocs.append(ioc_dict)

        return ThreatIntelligenceSignature(
            candidate_malware_families=[str(f) for f in families],
            ioc_matches=processed_iocs,
            mitre_techniques=[str(m) for m in mitre],
            cve_references=[str(c) for c in cves],
            threat_reports=[r if isinstance(r, dict) else {"title": str(r)} for r in reports],
            source_quality=[q if isinstance(q, dict) else {"source": str(q)} for q in quality],
            freshness=[f if isinstance(f, dict) else {"source": str(f)} for f in freshness],
            confidence=conf,
            intelligence_conflicts=[c if isinstance(c, dict) else {"conflict": str(c)} for c in conflicts],
            limitations=[str(l) for l in limitations]
        )

    @classmethod
    def _build_yara(cls, a4: Dict[str, Any], a2: Optional[Dict[str, Any]] = None) -> YaraSignature:
        yara_matches = list(a4.get("yara_matches") or [])
        if a2 and "yara_matches" in a2:
            yara_matches.extend(a2.get("yara_matches") or [])
        rules = set()
        categories = set()
        eids = set()

        for y in yara_matches:
            if isinstance(y, dict):
                rule = y.get("rule") or y.get("rule_name")
                if rule:
                    rules.add(rule)
                cat = y.get("category")
                if cat:
                    categories.add(cat)
                eid = y.get("evidence_id")
                if eid:
                    eids.add(eid)
            elif isinstance(y, str):
                rules.add(y)

        return YaraSignature(
            matched_rules=sorted(list(rules)),
            rule_categories=sorted(list(categories)),
            supporting_evidence_references=sorted(list(eids))
        )

    @staticmethod
    def _extract_list(val: Any) -> List[str]:
        if isinstance(val, list):
            return [str(v).strip() for v in val if v]
        elif isinstance(val, str) and val.strip():
            return [val.strip()]
        return []
