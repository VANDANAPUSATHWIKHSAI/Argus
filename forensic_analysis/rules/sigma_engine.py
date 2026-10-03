"""
Sigma Rule Engine — Pure-Python Deterministic Log/Telemetry Matcher
====================================================================
Evaluates a documented subset of the Sigma specification against Argus
Artifact objects (normalized_fields + raw_fields). Produces standard
forensic_analysis.schemas.Finding objects.

Supported Sigma subset: see SUPPORTED_SIGMA_SUBSET.md

ARCHITECTURAL DECISIONS:
1. NO external transpilation (no pySigma / Elasticsearch / Splunk backend).
2. Confidence is derived from rule level, NOT hardcoded to 0.90.
3. MITRE tags from rules are advisory metadata hints, NOT authoritative mappings.
4. Field resolution: normalized_fields → raw_fields → common casing variants.
5. This is a SUB-ANALYZER: it is called from existing engine orchestrators
   (LogEngine, EndpointEngine, etc.), NOT directly from the orchestrator.

SECURITY: Rules are YAML data files. No rule content is ever executed.
"""

from __future__ import annotations

import os
import re
import logging
from glob import glob
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple, Set

import yaml

from forensic_analysis.schemas import Finding
from preprocessing.schemas import Artifact

logger = logging.getLogger(__name__)

# ── Confidence mapping from Sigma level → Finding confidence ─────────────────
# NOT hardcoded to 0.90. Each level maps to a calibrated confidence reflecting
# the inherent precision of that rule severity tier.
LEVEL_TO_CONFIDENCE: Dict[str, float] = {
    "critical": 0.95,
    "high": 0.88,
    "medium": 0.75,
    "low": 0.60,
    "informational": 0.50,
}

# Common EVTX/Sysmon casing variants for field name resolution fallback
FIELD_CASING_VARIANTS: Dict[str, List[str]] = {
    "process_name": ["ProcessName", "NewProcessName", "Image", "process_name"],
    "process_command_line": ["CommandLine", "command_line", "ScriptBlockText"],
    "parent_process_name": ["ParentProcessName", "ParentImage", "parent_process_name"],
    "user": ["User", "SubjectUserName", "TargetUserName", "user"],
    "host": ["Computer", "Hostname", "host", "host_id"],
    "src_ip": ["SourceAddress", "src_ip", "IpAddress"],
    "dst_ip": ["DestAddress", "dst_ip", "DestinationAddress"],
    "src_port": ["SourcePort", "src_port"],
    "dst_port": ["DestPort", "dst_port", "DestinationPort"],
    "file_path": ["TargetFilename", "file_path", "ObjectName"],
    "file_name": ["file_name", "FileName"],
    "registry_key": ["TargetObject", "registry_key", "ObjectName"],
    "registry_value": ["Details", "registry_value", "NewValue"],
    "domain": ["QueryName", "domain", "DestinationHostname"],
    "url": ["url", "RequestUrl", "cs-uri-stem"],
    "hash": ["Hashes", "hash", "SHA256", "MD5"],
    "rule_name": ["RuleTitle", "rule_name", "RuleName"],
    "severity": ["Level", "level", "severity"],
}


class SigmaRule:
    """
    Parsed in-memory representation of a single Sigma YAML rule.
    Stores only the fields used by the supported subset.
    """

    def __init__(self, rule_data: Dict[str, Any], source_path: str):
        self.title: str = rule_data.get("title", "Unnamed Sigma Rule")
        self.rule_id: str = rule_data.get("id", "unknown")
        self.description: str = rule_data.get("description", "")
        self.level: str = str(rule_data.get("level", "medium")).lower()
        self.author: str = rule_data.get("author", "")
        self.date: str = str(rule_data.get("date", ""))
        self.status: str = rule_data.get("status", "experimental")
        self.source_path: str = source_path

        # Detection block
        detection = rule_data.get("detection", {})
        self.condition: str = str(detection.get("condition", "")).strip()
        self.detection_blocks: Dict[str, Any] = {
            k: v for k, v in detection.items() if k != "condition"
        }

        # MITRE tags — advisory metadata ONLY, not authoritative
        raw_tags = rule_data.get("tags", [])
        self.mitre_tags: List[str] = []
        for tag in raw_tags:
            tag_str = str(tag).lower()
            # Extract MITRE technique IDs from tags like "attack.t1059.001"
            if tag_str.startswith("attack.t") and len(tag_str) > 9:
                technique = tag_str.replace("attack.", "").upper()
                self.mitre_tags.append(technique)

        self.falsepositives: List[str] = rule_data.get("falsepositives", [])

        # Logsource metadata (used for documentation, not for routing)
        logsource = rule_data.get("logsource", {})
        self.logsource_category: str = logsource.get("category", "")
        self.logsource_product: str = logsource.get("product", "")

    @property
    def mitre_hint(self) -> Optional[str]:
        """First MITRE tag as advisory hint, or None."""
        return self.mitre_tags[0] if self.mitre_tags else None

    @property
    def confidence(self) -> float:
        """Confidence derived from rule level — never hardcoded."""
        return LEVEL_TO_CONFIDENCE.get(self.level, 0.70)


def _resolve_field_value(artifact: Artifact, field_name: str) -> Optional[str]:
    """
    Resolves a Sigma field name to a string value from the Artifact.

    Resolution order:
    1. artifact.normalized_fields.<field_name> (Pydantic attribute)
    2. artifact.raw_fields[field_name]
    3. artifact.raw_fields[<CasingVariant>] for known EVTX/Sysmon variants

    Returns None if the field cannot be resolved (condition evaluates to no-match).
    """
    norm = artifact.normalized_fields

    # 1. Try normalized_fields attribute
    val = getattr(norm, field_name, None)
    if val is not None:
        return str(val)

    # 2. Try raw_fields exact key
    raw = artifact.raw_fields or {}
    if field_name in raw and raw[field_name] is not None:
        return str(raw[field_name])

    # 3. Try known casing variants
    variants = FIELD_CASING_VARIANTS.get(field_name, [])
    for variant in variants:
        if variant in raw and raw[variant] is not None:
            return str(raw[variant])

    return None


def _match_value(field_val: str, match_spec: Any, modifiers: List[str]) -> bool:
    """
    Evaluates a single field value against a match specification with modifiers.

    Supports: (none), contains, endswith, startswith, re, all
    """
    if field_val is None:
        return False

    field_lower = field_val.lower()

    # If match_spec is a list, handle based on modifiers
    if isinstance(match_spec, list):
        if "all" in modifiers:
            # ALL items must match
            return all(_match_single(field_val, field_lower, item, modifiers) for item in match_spec)
        else:
            # ANY item matches (OR semantics — default for lists)
            return any(_match_single(field_val, field_lower, item, modifiers) for item in match_spec)

    return _match_single(field_val, field_lower, match_spec, modifiers)


def _match_single(field_val: str, field_lower: str, pattern: Any, modifiers: List[str]) -> bool:
    """Evaluates one value against one pattern with modifiers."""
    if pattern is None:
        return field_val is None

    pattern_str = str(pattern)
    pattern_lower = pattern_str.lower()

    if "re" in modifiers:
        try:
            return bool(re.search(pattern_str, field_val, re.IGNORECASE))
        except re.error:
            logger.warning("SigmaEngine: Invalid regex pattern '%s' in rule", pattern_str)
            return False

    if "contains" in modifiers:
        return pattern_lower in field_lower

    if "endswith" in modifiers:
        return field_lower.endswith(pattern_lower)

    if "startswith" in modifiers:
        return field_lower.startswith(pattern_lower)

    # Default: exact case-insensitive equality
    return field_lower == pattern_lower


def _parse_field_and_modifiers(field_key: str) -> Tuple[str, List[str]]:
    """
    Parses a Sigma detection field key into (field_name, [modifiers]).
    Example: 'command_line|contains|all' → ('command_line', ['contains', 'all'])
    """
    parts = field_key.split("|")
    return parts[0], parts[1:]


def _evaluate_block(block: Dict[str, Any], artifact: Artifact) -> bool:
    """
    Evaluates a single Sigma detection block (AND semantics across fields).
    All field conditions within a block must match for the block to match.
    """
    if not block or not isinstance(block, dict):
        return False

    for field_key, match_spec in block.items():
        field_name, modifiers = _parse_field_and_modifiers(field_key)
        field_val = _resolve_field_value(artifact, field_name)

        if not _match_value(field_val, match_spec, modifiers):
            return False

    return True


def _evaluate_condition(
    condition: str,
    detection_blocks: Dict[str, Any],
    artifact: Artifact
) -> bool:
    """
    Evaluates the Sigma condition expression against named detection blocks.

    Supported patterns:
    - 'selection'
    - 'selection and not filter'
    - '(selection1 or selection2) and not filter'
    - '1 of selection*'
    - 'all of selection*'
    """
    cond = condition.strip()

    # Strip outer parentheses if the entire string is wrapped in parens
    while cond.startswith("(") and cond.endswith(")"):
        depth = 0
        matching_outer = True
        for char in cond[:-1]:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    matching_outer = False
                    break
        if matching_outer:
            cond = cond[1:-1].strip()
        else:
            break

    # Helper to evaluate single atom/block reference or wildcard pattern
    def _eval_atom(atom: str) -> bool:
        atom_clean = atom.strip()
        if not atom_clean:
            return False

        if atom_clean.startswith("(") and atom_clean.endswith(")"):
            return _evaluate_condition(atom_clean[1:-1], detection_blocks, artifact)

        one_of = re.match(r"^1\s+of\s+(\w+)\*$", atom_clean, re.IGNORECASE)
        if one_of:
            prefix = one_of.group(1)
            matching_blocks = {k: v for k, v in detection_blocks.items() if k.startswith(prefix)}
            return any(_evaluate_block(block, artifact) for block in matching_blocks.values())

        all_of = re.match(r"^all\s+of\s+(\w+)\*$", atom_clean, re.IGNORECASE)
        if all_of:
            prefix = all_of.group(1)
            matching_blocks = {k: v for k, v in detection_blocks.items() if k.startswith(prefix)}
            if not matching_blocks:
                return False
            return all(_evaluate_block(block, artifact) for block in matching_blocks.values())

        block = detection_blocks.get(atom_clean, {})
        return _evaluate_block(block, artifact)

    # 1. Evaluate 'and not'
    if " and not " in cond.lower():
        parts = re.split(r"\s+and\s+not\s+", cond, flags=re.IGNORECASE, maxsplit=1)
        if len(parts) == 2:
            return _evaluate_condition(parts[0], detection_blocks, artifact) and not _evaluate_condition(parts[1], detection_blocks, artifact)

    # 2. Evaluate 'and'
    if " and " in cond.lower():
        parts = re.split(r"\s+and\s+", cond, flags=re.IGNORECASE, maxsplit=1)
        if len(parts) == 2:
            return _evaluate_condition(parts[0], detection_blocks, artifact) and _evaluate_condition(parts[1], detection_blocks, artifact)

    # 3. Evaluate 'or'
    if " or " in cond.lower():
        parts = re.split(r"\s+or\s+", cond, flags=re.IGNORECASE, maxsplit=1)
        if len(parts) == 2:
            return _evaluate_condition(parts[0], detection_blocks, artifact) or _evaluate_condition(parts[1], detection_blocks, artifact)

    return _eval_atom(cond)


class SigmaRuleEngine:
    """
    Loads and evaluates Sigma YAML rules against Artifact objects.

    Usage:
        engine = SigmaRuleEngine()  # loads from default rules/sigma/ directory
        findings = engine.evaluate(case_id, artifacts, fcr_ref)
    """

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules_dir = rules_dir or os.path.join(os.path.dirname(__file__), "sigma")
        self.rules: List[SigmaRule] = []
        self._load_rules()

    def _load_rules(self) -> None:
        """Loads all .yml files from the sigma rules directory tree."""
        if not os.path.isdir(self.rules_dir):
            logger.warning(
                "SigmaRuleEngine: Rules directory '%s' not found. Sigma detection disabled.",
                self.rules_dir
            )
            return

        yml_files = glob(os.path.join(self.rules_dir, "**", "*.yml"), recursive=True)
        loaded = 0
        for yml_path in yml_files:
            try:
                with open(yml_path, "r", encoding="utf-8") as f:
                    rule_data = yaml.safe_load(f)

                if not isinstance(rule_data, dict):
                    logger.warning("SigmaRuleEngine: Skipping non-dict YAML '%s'", yml_path)
                    continue

                if "detection" not in rule_data:
                    logger.warning("SigmaRuleEngine: Skipping rule without 'detection' block: '%s'", yml_path)
                    continue

                rule = SigmaRule(rule_data, source_path=yml_path)
                self.rules.append(rule)
                loaded += 1
            except Exception as e:
                logger.warning("SigmaRuleEngine: Failed to load rule '%s': %s", yml_path, e)

        logger.info(
            "SigmaRuleEngine: Loaded %d Sigma rules from '%s'",
            loaded, self.rules_dir
        )

    def evaluate(
        self,
        case_id: str,
        artifacts: List[Artifact],
        fcr_ref: str
    ) -> List[Finding]:
        """
        Evaluates all loaded Sigma rules against a list of Artifacts.
        Returns a list of Finding objects for each (rule, artifact) match.

        Each matched Finding:
        - confidence: derived from rule level (NOT hardcoded)
        - mitre_mapping: advisory hint from rule tags (NOT authoritative)
        - layer: 'sigma.<rule_id>' for full provenance traceability
        - metadata: includes rule_id, rule_title, matched_fields, rule_source
        """
        if not self.rules:
            return []

        findings: List[Finding] = []

        for artifact in artifacts:
            for rule in self.rules:
                if not rule.condition or not rule.detection_blocks:
                    continue

                try:
                    matched = _evaluate_condition(
                        rule.condition,
                        rule.detection_blocks,
                        artifact
                    )
                except Exception as e:
                    logger.warning(
                        "SigmaRuleEngine: Error evaluating rule '%s' on artifact '%s': %s",
                        rule.title, artifact.artifact_id, e
                    )
                    continue

                if matched:
                    # Collect which fields actually matched for provenance
                    matched_fields = _collect_matched_fields(rule, artifact)

                    fact_msg = (
                        f"Sigma rule '{rule.title}' matched on artifact "
                        f"(type={artifact.artifact_type}, source={artifact.source_tool}): "
                        f"{rule.description or 'No description'}"
                    )

                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=rule.confidence,
                        severity=rule.level if rule.level in (
                            "informational", "low", "medium", "high", "critical"
                        ) else "medium",
                        mitre_mapping=rule.mitre_hint,
                        timestamp=artifact.timestamp,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer=f"sigma.{rule.rule_id}",
                        metadata={
                            "rule_id": rule.rule_id,
                            "rule_title": rule.title,
                            "rule_author": rule.author,
                            "rule_level": rule.level,
                            "rule_source": rule.source_path,
                            "matched_fields": matched_fields,
                            "mitre_tags_advisory": rule.mitre_tags,
                            "falsepositives": rule.falsepositives,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

        return findings


def _collect_matched_fields(rule: SigmaRule, artifact: Artifact) -> Dict[str, str]:
    """
    For provenance: collects the actual field values from the artifact
    that the rule's detection blocks reference.
    """
    matched: Dict[str, str] = {}
    for block_name, block in rule.detection_blocks.items():
        if isinstance(block, dict):
            for field_key in block:
                field_name, _ = _parse_field_and_modifiers(field_key)
                val = _resolve_field_value(artifact, field_name)
                if val is not None:
                    # Truncate long values for metadata
                    matched[field_name] = val[:200] if len(val) > 200 else val
    return matched
