"""
Agent 5b — Multi-Dimensional Similarity Engine
==============================================
Calculates:
- Behavioral similarity score
- Attack-pattern similarity score (structural stage alignment, path sequence, infection source)
- Threat-intelligence similarity score
- Composite similarity score (single deterministic formula with documented weights)
- Similarity breakdown (exact values reused across JSON, explanations, claims)
- Similar malware families (with explicit non-attribution caveats)
- Similar campaigns (overlapping techniques & infrastructure)
- Possible threat actor context (with strict profiling caveats)
- Grounded confidence score (strictly separated from similarity, computed from evidence coverage,
  threat intel reliability, feed freshness, and absence of conflicts)
"""

from typing import List, Dict, Any, Tuple, Optional
import math
import re
import logging
from agents.agent5b_campaign_similarity.schemas import (
    CaseBehavioralSignature,
    AttackPatternSignature,
    RetrievedHistoricalCase,
    SimilarMalwareFamily,
    SimilarCampaign,
    ThreatActorContext,
    SimilarityBreakdown
)

logger = logging.getLogger(__name__)


class SimilarityEngine:
    """
    Computes multi-dimensional similarity, family/campaign/actor associations,
    and grounded confidence scores.
    """

    # Configurable dimension weights (must sum to 1.0)
    DEFAULT_WEIGHT_BEHAVIOR = 0.40
    DEFAULT_WEIGHT_ATTACK = 0.35
    DEFAULT_WEIGHT_THREAT_INTEL = 0.25

    @classmethod
    def compute_scores(
        cls,
        retrieved_cases: List[RetrievedHistoricalCase],
        current_sig: Optional[CaseBehavioralSignature] = None,
        custom_weights: Optional[Dict[str, float]] = None
    ) -> Tuple[float, float, float, float, SimilarityBreakdown]:
        """
        Computes (behavior_sim, attack_sim, ti_sim, composite_sim, breakdown) for top retrieved case.
        Calculated ONCE deterministically. Reused verbatim across outputs, claims, and explanations.
        """
        if not retrieved_cases:
            zero_bd = SimilarityBreakdown(
                behavior_similarity=0.0,
                attack_similarity=0.0,
                intelligence_similarity=0.0,
                composite_similarity=0.0,
                weights_used={"behavior": 0.40, "attack": 0.35, "threat_intel": 0.25},
                formula="composite = 0.40*behavior + 0.35*attack + 0.25*threat_intel (No historical matches retrieved)"
            )
            return 0.0, 0.0, 0.0, 0.0, zero_bd

        top = retrieved_cases[0]
        b_sim = cls._sanitize_score(top.behavior_similarity)
        raw_a_sim = cls._sanitize_score(top.attack_similarity)
        ti_sim = cls._sanitize_score(top.intelligence_similarity)

        # Refine attack similarity using structural alignment if current_sig is provided
        if current_sig and top.case_data.attack_pattern:
            a_sim = cls.calculate_attack_similarity(
                current_ap=current_sig.attack_pattern,
                historical_ap=top.case_data.attack_pattern,
                vector_sim=raw_a_sim
            )
        else:
            a_sim = raw_a_sim

        # Base weights
        weights = custom_weights or {
            "behavior": cls.DEFAULT_WEIGHT_BEHAVIOR,
            "attack": cls.DEFAULT_WEIGHT_ATTACK,
            "threat_intel": cls.DEFAULT_WEIGHT_THREAT_INTEL
        }

        w_b = weights.get("behavior", 0.40)
        w_a = weights.get("attack", 0.35)
        w_ti = weights.get("threat_intel", 0.25)

        if current_sig:
            mb = current_sig.malware_behavior
            has_b = any(getattr(mb, c, []) for c in [
                "execution", "persistence", "credential_access", "privilege_escalation",
                "defense_evasion", "discovery", "collection", "command_and_control",
                "exfiltration", "impact"
            ])
            ap = current_sig.attack_pattern
            has_a = bool(ap.attack_path or ap.attack_stages or ap.kill_chain_steps or ap.infection_source or ap.lateral_movement)
            ti = current_sig.threat_intelligence
            has_ti = bool(ti.candidate_malware_families or ti.mitre_techniques or ti.cve_references or ti.ioc_matches)

            if not has_b:
                w_b = 0.0
            if not has_a:
                w_a = 0.0
            if not has_ti:
                w_ti = 0.0

            total_w = w_b + w_a + w_ti
            if total_w > 0:
                w_b /= total_w
                w_a /= total_w
                w_ti /= total_w
            else:
                w_b, w_a, w_ti = 0.40, 0.35, 0.25

        composite = (w_b * b_sim) + (w_a * a_sim) + (w_ti * ti_sim)
        composite = cls._sanitize_score(composite)

        formula_str = (
            f"composite = ({w_b:.2f} * {b_sim:.4f}) + ({w_a:.2f} * {a_sim:.4f}) + ({w_ti:.2f} * {ti_sim:.4f}) = {composite:.4f}"
        )

        breakdown = SimilarityBreakdown(
            behavior_similarity=b_sim,
            attack_similarity=a_sim,
            intelligence_similarity=ti_sim,
            composite_similarity=composite,
            weights_used={"behavior": round(w_b, 4), "attack": round(w_a, 4), "threat_intel": round(w_ti, 4)},
            formula=formula_str
        )

        return (
            round(b_sim, 4),
            round(a_sim, 4),
            round(ti_sim, 4),
            round(composite, 4),
            breakdown
        )

    @classmethod
    def calculate_attack_similarity(
        cls,
        current_ap: AttackPatternSignature,
        historical_ap: Dict[str, Any],
        vector_sim: float = 0.0
    ) -> float:
        """
        Calculates attack-pattern similarity from actual Agent 3 output and historical records.
        Evaluates:
        1. Attack stages overlap (Jaccard similarity)
        2. Attack path sequence alignment
        3. Infection source match
        Penalizes incomplete or missing information.
        A score of 1.0 is awarded ONLY if stages, path, and infection source are ALL
        non-empty and match completely.
        """
        curr_stages = [s.strip().lower() for s in (current_ap.attack_stages or []) if s]
        hist_stages = [s.strip().lower() for s in (historical_ap.get("stages", []) or []) if s]

        curr_path = [p.strip().lower() for p in (current_ap.attack_path or []) if p]
        hist_path = [p.strip().lower() for p in (historical_ap.get("path", []) or []) if p]

        curr_src = (current_ap.infection_source or "").strip().lower()
        hist_src = str(historical_ap.get("infection_source", "") or "").strip().lower()

        if not curr_stages and not curr_path and not curr_src:
            return 0.0

        # 1. Stages overlap
        if curr_stages and hist_stages:
            set_c = set(curr_stages)
            set_h = set(hist_stages)
            jaccard_stages = len(set_c & set_h) / len(set_c | set_h)
            order_match = (curr_stages == hist_stages)
            stage_score = jaccard_stages if not order_match else 1.0
        elif not curr_stages and not hist_stages:
            stage_score = 0.5
        else:
            stage_score = 0.0

        # 2. Path alignment
        if curr_path and hist_path:
            curr_hops = set()
            for p in curr_path:
                curr_hops.update(h.strip() for h in re.split(r'->|>', p) if h.strip())
            hist_hops = set()
            for p in hist_path:
                hist_hops.update(h.strip() for h in re.split(r'->|>', p) if h.strip())

            if curr_hops and hist_hops:
                path_score = len(curr_hops & hist_hops) / max(len(curr_hops), len(hist_hops))
            else:
                path_score = 0.0
            if curr_path == hist_path:
                path_score = 1.0
        elif not curr_path and not hist_path:
            path_score = 0.5
        else:
            path_score = 0.0

        # 3. Infection source match
        if curr_src and hist_src:
            if curr_src == hist_src:
                src_score = 1.0
            else:
                c_toks = set(re.findall(r'[a-z0-9]+', curr_src))
                h_toks = set(re.findall(r'[a-z0-9]+', hist_src))
                overlap = c_toks & h_toks
                if overlap:
                    src_score = len(overlap) / max(len(c_toks), len(h_toks))
                else:
                    src_score = 0.0
        elif not curr_src and not hist_src:
            src_score = 0.5
        else:
            src_score = 0.0

        # Strict criteria for 1.0 (perfect score)
        is_perfect = (
            bool(curr_stages and hist_stages and curr_stages == hist_stages) and
            bool(curr_path and hist_path and curr_path == hist_path) and
            bool(curr_src and hist_src and curr_src == hist_src)
        )
        if is_perfect:
            return 1.0

        # Structural combination
        raw_structural = (0.45 * stage_score) + (0.35 * path_score) + (0.20 * src_score)

        if vector_sim > 0.0:
            combined = 0.60 * raw_structural + 0.40 * vector_sim
        else:
            combined = raw_structural

        # Cap strictly below 1.0 if any component is incomplete or divergent
        return min(0.95, cls._sanitize_score(combined))

    @classmethod
    def identify_malware_families(
        cls,
        current_sig: CaseBehavioralSignature,
        retrieved_cases: List[RetrievedHistoricalCase],
        min_similarity: float = 0.40
    ) -> List[SimilarMalwareFamily]:
        """
        Ranks malware families associated with retrieved validated cases.
        Enforces: Similarity != Identification.
        """
        families: List[SimilarMalwareFamily] = []
        seen = set()

        for case in retrieved_cases:
            fam_name = case.case_data.malware_identity.family
            if not fam_name or fam_name.lower() in ["unknown", "unclassified", "none"]:
                continue
            if fam_name in seen:
                continue

            sim = case.behavior_similarity if case.behavior_similarity > 0 else case.similarity_score
            if sim >= min_similarity:
                seen.add(fam_name)

                fp = case.case_data.malware_behavior_fingerprint or {}
                supporting = []
                for cat, items in fp.items():
                    curr_items = getattr(current_sig.malware_behavior, cat, [])
                    for ci in curr_items:
                        if any(ci.lower() in hi.lower() or hi.lower() in ci.lower() for hi in items):
                            supporting.append(f"{cat}: {ci}")

                families.append(SimilarMalwareFamily(
                    family_name=fam_name,
                    historical_case_id=case.case_id,
                    similarity_score=round(sim, 4),
                    supporting_behaviors=supporting[:5],
                    caveat=(
                        f"Current investigation exhibits behavioral similarity to Case {case.case_id} ({fam_name}). "
                        "This is contextual reference only, not proof of malware identity (does not prove current malware identity)."
                    )
                ))

        return families

    @classmethod
    def identify_campaigns(
        cls,
        current_sig: CaseBehavioralSignature,
        retrieved_cases: List[RetrievedHistoricalCase],
        min_similarity: float = 0.45
    ) -> List[SimilarCampaign]:
        """
        Identifies campaigns associated with similar historical cases with strict contextual caveat.
        """
        campaigns: List[SimilarCampaign] = []
        seen = set()

        for case in retrieved_cases:
            camps = case.case_data.associated_campaigns or []
            for c_name in camps:
                if c_name in seen:
                    continue
                seen.add(c_name)

                curr_mitre = set(current_sig.threat_intelligence.mitre_techniques)
                hist_mitre = set(case.case_data.threat_intelligence.get("mitre_techniques", []))
                overlap_tech = sorted(list(curr_mitre & hist_mitre))

                curr_iocs = set(str(i.get("indicator", i)) for i in current_sig.threat_intelligence.ioc_matches)
                hist_iocs = set(case.case_data.threat_intelligence.get("iocs", []))
                raw_overlap = sorted(list(curr_iocs & hist_iocs))

                # Identify and tag synthetic test indicators (RFC 5737 and example domains)
                synth_patterns = [
                    re.compile(r"^192\.0\.2\."),
                    re.compile(r"^198\.51\.100\."),
                    re.compile(r"^203\.0\.113\."),
                    re.compile(r"^127\."),
                    re.compile(r"\bexample\.(com|org|net)\b", re.IGNORECASE)
                ]
                overlap_infra = []
                for ind in raw_overlap:
                    if any(p.search(ind) for p in synth_patterns):
                        overlap_infra.append(f"{ind} [SYNTHETIC TEST INDICATOR - NOT LIVE C2]")
                    else:
                        overlap_infra.append(ind)

                campaigns.append(SimilarCampaign(
                    campaign_name=c_name,
                    historical_case_id=case.case_id,
                    similarity_score=round(case.similarity_score, 4),
                    overlapping_techniques=overlap_tech,
                    overlapping_infrastructure=overlap_infra
                ))

        return campaigns

    @classmethod
    def identify_threat_actors(
        cls,
        current_sig: CaseBehavioralSignature,
        retrieved_cases: List[RetrievedHistoricalCase],
        min_similarity: float = 0.50
    ) -> List[ThreatActorContext]:
        """
        Extracts threat actor context from similar historical cases with strict profiling caveat.
        """
        actors: List[ThreatActorContext] = []
        seen = set()

        for case in retrieved_cases:
            actor = case.case_data.threat_actor
            if not actor or actor.lower() in ["unknown", "unattributed", "none"]:
                continue
            if actor in seen:
                continue

            sim = case.similarity_score
            if sim >= min_similarity:
                seen.add(actor)
                matches = []
                stages = current_sig.attack_pattern.attack_stages
                h_stages = case.case_data.attack_pattern.get("stages", [])
                for st in stages:
                    if st in h_stages:
                        matches.append(f"Attack Stage: {st}")

                if not matches and case.case_data.malware_identity.family:
                    matches.append(f"Associated Family: {case.case_data.malware_identity.family}")

                actors.append(ThreatActorContext(
                    actor_name=actor,
                    historical_case_id=case.case_id,
                    similarity_score=round(sim, 4),
                    matching_characteristics=matches,
                    attribution_caveat=(
                        f"Contextual profiling only. Behavioral similarity to historical Case {case.case_id} "
                        f"does not assert that the current attack was conducted by '{actor}'."
                    )
                ))

        return actors

    @classmethod
    def compute_grounded_confidence(
        cls,
        current_sig: CaseBehavioralSignature,
        agent3_present: bool = True,
        agent4_present: bool = True,
        agent5a_present: bool = True
    ) -> Tuple[float, str]:
        """
        Calculates grounded investigative confidence score strictly separated from similarity.
        High similarity != High confidence.
        Confidence is grounded in:
        1. Current evidence coverage & quality (number of active behavioral categories and valid evidence count).
        2. Upstream input completeness (presence of Agent 3, Agent 4, and Agent 5a).
        3. Threat intelligence reliability (Agent 5a confidence and feed freshness).
        4. Absence of intelligence conflicts and case/tenant mismatches.

        Zero mathematical dependence on composite_similarity or retrieval ranking.
        Returns: (confidence, methodology_explanation)
        """
        mb = current_sig.malware_behavior
        active_cats = sum(1 for c in [
            "execution", "persistence", "credential_access", "privilege_escalation",
            "defense_evasion", "discovery", "collection", "command_and_control",
            "exfiltration", "impact"
        ] if getattr(mb, c, []))

        total_curr_behaviors = sum(len(getattr(mb, c, [])) for c in [
            "execution", "persistence", "credential_access", "privilege_escalation",
            "defense_evasion", "discovery", "collection", "command_and_control",
            "exfiltration", "impact"
        ])

        if total_curr_behaviors == 0 and not current_sig.evidence_ids:
            return 0.0, "Investigative confidence 0.0: No forensic behaviors or evidence IDs established in current case."

        # 1. Evidence Quality & Coverage (weight: 0.45)
        cat_ratio = min(1.0, active_cats / 4.0)
        evid_count = len(current_sig.evidence_ids)
        evid_ratio = min(1.0, evid_count / 3.0) if evid_count > 0 else 0.0
        c_coverage = (0.55 * cat_ratio) + (0.45 * evid_ratio)

        # 2. Upstream Input Completeness (weight: 0.30)
        c_upstream = 0.0
        if agent4_present and total_curr_behaviors > 0:
            c_upstream += 0.40
        if agent3_present and (current_sig.attack_pattern.attack_stages or current_sig.attack_pattern.attack_path):
            c_upstream += 0.35
        if agent5a_present and (current_sig.threat_intelligence.candidate_malware_families or current_sig.threat_intelligence.ioc_matches or current_sig.threat_intelligence.mitre_techniques):
            c_upstream += 0.25

        # 3. Threat Intelligence Reliability (weight: 0.25)
        a5a_conf = current_sig.threat_intelligence.confidence
        freshness_list = current_sig.threat_intelligence.freshness
        freshness_mult = 0.85
        if freshness_list:
            statuses = [str(f.get("freshness_status", f.get("status", ""))).upper() for f in freshness_list if isinstance(f, dict)]
            if any("CURRENT" in s for s in statuses):
                freshness_mult = 1.0
            elif any("STALE" in s for s in statuses):
                freshness_mult = 0.60

        c_ti = min(1.0, a5a_conf * freshness_mult)

        base_conf = (0.45 * c_coverage) + (0.30 * c_upstream) + (0.25 * c_ti)

        methodology_steps = [
            f"Coverage factor: {c_coverage:.2f} ({active_cats} active categories, {evid_count} evidence IDs)",
            f"Upstream completeness: {c_upstream:.2f} (Agents 3, 4, 5a presence)",
            f"Threat intel reliability: {c_ti:.2f} (5A confidence: {a5a_conf:.2f}, freshness multiplier: {freshness_mult:.2f})"
        ]

        # 4. Penalties
        conflicts = current_sig.threat_intelligence.intelligence_conflicts
        if conflicts:
            conflict_penalty = min(0.35, len(conflicts) * 0.15)
            base_conf -= conflict_penalty
            methodology_steps.append(f"Conflict penalty: -{conflict_penalty:.2f} ({len(conflicts)} unresolved threat feed conflict(s))")

        if current_sig.mismatched_records:
            mismatch_penalty = 0.30
            base_conf -= mismatch_penalty
            methodology_steps.append(f"Metadata mismatch penalty: -{mismatch_penalty:.2f} ({len(current_sig.mismatched_records)} mismatched record(s))")

        final_conf = cls._sanitize_score(base_conf)
        methodology_text = "; ".join(methodology_steps)

        return round(final_conf, 4), methodology_text

    @staticmethod
    def _sanitize_score(val: Any) -> float:
        """
        Validates score numbers against NaN, infinity, and out-of-bound values.
        Clamps to [0.0, 1.0].
        """
        if val is None:
            return 0.0
        try:
            f = float(val)
            if math.isnan(f) or math.isinf(f):
                return 0.0
            return max(0.0, min(1.0, f))
        except (ValueError, TypeError):
            return 0.0
