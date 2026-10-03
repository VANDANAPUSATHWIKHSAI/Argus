"""
YARA Rule Engine — Deterministic Binary/File Pattern Matcher
============================================================
Evaluates compiled YARA rules against binary byte streams, memory dumps, or discrete file artifacts.
Produces standard forensic_analysis.schemas.Finding objects.

ARCHITECTURAL DECISIONS:
1. Scans actual file bytes / binary memory buffers, NOT arbitrary textual log output.
2. DISK SAFETY GUARD: Refuses to scan unpartitioned disk images (.dd, .raw, .vmdk, .e01, .iso)
   or files exceeding safety limits (>500MB default) without explicit override.
3. Confidence is derived from YARA rule metadata/severity (NOT hardcoded to 0.90 across all rules).
4. MITRE ATT&CK tags from rule metadata/tags are advisory hints, NOT authoritative mappings.
5. This is a SUB-ANALYZER: called from MemoryAnalysisEngine, FileAnalysis, or EndpointEngine.

SECURITY: Uses native compiled YARA pattern matching engine safely.
"""

from __future__ import annotations

import os
import uuid
import logging
from glob import glob
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple, Set

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    yara = None
    YARA_AVAILABLE = False

from forensic_analysis.schemas import Finding
from preprocessing.schemas import Artifact

logger = logging.getLogger(__name__)

# Severity to confidence mapping for YARA detections
SEVERITY_TO_CONFIDENCE: Dict[str, float] = {
    "critical": 0.95,
    "high": 0.90,
    "medium": 0.75,
    "low": 0.60,
    "informational": 0.50,
}

# Raw disk image extensions to block from blind YARA scanning
BLOCKED_DISK_EXTENSIONS: Set[str] = {
    ".dd", ".raw", ".vmdk", ".vhdx", ".vhd", ".e01", ".iso", ".img", ".qcow2", ".dmp_huge"
}

# Default maximum file size to scan (500 MB)
DEFAULT_MAX_FILE_SIZE_BYTES: int = 500 * 1024 * 1024


class YaraRuleEngine:
    """
    Deterministic YARA pattern scanning engine.
    Loads and compiles YARA rule sets (.yar / .yara) and scans byte buffers or files.
    """

    def __init__(
        self,
        rules_dir: Optional[str] = None,
        max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
    ):
        self.rules_dir = rules_dir or os.path.join(os.path.dirname(__file__), "yara")
        self.max_file_size_bytes = max_file_size_bytes
        self.compiled_rules: Optional[Any] = None
        self.rule_filepaths: List[str] = []
        self.raw_rules: Dict[str, str] = {}
        self._load_and_compile_rules()

    def _load_and_compile_rules(self) -> None:
        """Loads all .yar/.yara rules from the rules_dir tree and compiles them."""
        if not YARA_AVAILABLE:
            logger.warning(
                "YaraRuleEngine: 'yara-python' package is not installed. "
                "YARA rule compilation and scanning disabled."
            )
            return

        if not os.path.isdir(self.rules_dir):
            logger.warning(
                "YaraRuleEngine: Rules directory '%s' not found. YARA detection disabled.",
                self.rules_dir
            )
            return

        yar_files = (
            glob(os.path.join(self.rules_dir, "**", "*.yar"), recursive=True) +
            glob(os.path.join(self.rules_dir, "**", "*.yara"), recursive=True)
        )

        if not yar_files:
            logger.info("YaraRuleEngine: No .yar/.yara rule files found in '%s'", self.rules_dir)
            return

        filepaths_dict: Dict[str, str] = {}
        for idx, path in enumerate(yar_files):
            rule_key = f"rule_{idx}_{os.path.basename(path)}"
            filepaths_dict[rule_key] = path
            self.rule_filepaths.append(path)

        try:
            self.compiled_rules = yara.compile(filepaths=filepaths_dict)
            logger.info(
                "YaraRuleEngine: Successfully compiled %d YARA rule files from '%s'",
                len(yar_files), self.rules_dir
            )
        except Exception as e:
            logger.error("YaraRuleEngine: Failed to compile YARA rules from '%s': %s", self.rules_dir, e)
            self.compiled_rules = None

    def add_rule_string(self, rule_str: str, identifier: str = "custom_rule") -> bool:
        """Dynamically compiles and adds a YARA rule string."""
        if not YARA_AVAILABLE:
            logger.warning("YaraRuleEngine: Cannot add rule string; yara-python not installed.")
            return False

        try:
            compiled = yara.compile(source=rule_str)
            self.raw_rules[identifier] = rule_str
            if self.compiled_rules is None:
                self.compiled_rules = compiled
            else:
                # Merge source rules
                all_sources = dict(self.raw_rules)
                for idx, path in enumerate(self.rule_filepaths):
                    all_sources[f"file_{idx}"] = path
                self.compiled_rules = yara.compile(sources=all_sources)
            logger.info("YaraRuleEngine: Successfully added rule '%s'", identifier)
            return True
        except Exception as e:
            logger.error("YaraRuleEngine: Error compiling rule string '%s': %s", identifier, e)
            return False

    def evaluate_bytes(
        self,
        case_id: str,
        artifact_id: str,
        data: bytes,
        evidence_ref: str,
        source_name: Optional[str] = None
    ) -> List[Finding]:
        """
        Evaluates compiled YARA rules against a raw byte buffer.
        """
        if not YARA_AVAILABLE or self.compiled_rules is None or not data:
            return []

        try:
            matches = self.compiled_rules.match(data=data)
        except Exception as e:
            logger.warning("YaraRuleEngine: Error during byte array scan: %s", e)
            return []

        return self._matches_to_findings(
            matches=matches,
            case_id=case_id,
            artifact_id=artifact_id,
            evidence_ref=evidence_ref,
            source_name=source_name or "in_memory_bytes"
        )

    def evaluate_file(
        self,
        case_id: str,
        artifact_id: str,
        file_path: str,
        evidence_ref: str
    ) -> List[Finding]:
        """
        Evaluates compiled YARA rules against a file path on disk.
        Includes guard against full disk image scanning and giant file sizes.
        """
        if not YARA_AVAILABLE or self.compiled_rules is None or not file_path:
            return []

        if not os.path.isfile(file_path):
            logger.warning("YaraRuleEngine: Target file path '%s' does not exist.", file_path)
            return []

        # DISK SAFETY CHECK: Extension check
        ext = os.path.splitext(file_path)[1].lower()
        if ext in BLOCKED_DISK_EXTENSIONS:
            logger.warning(
                "YaraRuleEngine: Refusing to scan raw disk image file '%s' (ext=%s) directly.",
                file_path, ext
            )
            return []

        # DISK SAFETY CHECK: File size check
        try:
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size_bytes:
                logger.warning(
                    "YaraRuleEngine: File '%s' size (%d MB) exceeds max scan threshold (%d MB). Skipping scan.",
                    file_path, file_size // (1024 * 1024), self.max_file_size_bytes // (1024 * 1024)
                )
                return []
        except Exception as e:
            logger.warning("YaraRuleEngine: Failed to check file size for '%s': %s", file_path, e)
            return []

        try:
            matches = self.compiled_rules.match(filepath=file_path)
        except Exception as e:
            logger.warning("YaraRuleEngine: Error scanning file '%s': %s", file_path, e)
            return []

        return self._matches_to_findings(
            matches=matches,
            case_id=case_id,
            artifact_id=artifact_id,
            evidence_ref=evidence_ref,
            source_name=os.path.basename(file_path)
        )

    def evaluate_artifacts(
        self,
        case_id: str,
        artifacts: List[Artifact],
        fcr_ref: str
    ) -> List[Finding]:
        """
        Evaluates YARA rules against Artifact objects containing raw byte payload
        or targeting file paths referenced within raw_fields/normalized_fields.
        """
        if not YARA_AVAILABLE or self.compiled_rules is None:
            return []

        findings: List[Finding] = []

        for artifact in artifacts:
            # 1. Check for raw byte data inside artifact
            raw_bytes = None
            if hasattr(artifact, "raw_data") and isinstance(artifact.raw_data, bytes):
                raw_bytes = artifact.raw_data
            elif isinstance(artifact.raw_fields, dict):
                bytes_field = artifact.raw_fields.get("raw_bytes") or artifact.raw_fields.get("payload_bytes")
                if isinstance(bytes_field, bytes):
                    raw_bytes = bytes_field
                elif isinstance(bytes_field, str):
                    try:
                        raw_bytes = bytes_field.encode("utf-8")
                    except Exception:
                        pass

            if raw_bytes:
                bytes_findings = self.evaluate_bytes(
                    case_id=case_id,
                    artifact_id=artifact.artifact_id,
                    data=raw_bytes,
                    evidence_ref=fcr_ref,
                    source_name=f"artifact_{artifact.artifact_type}"
                )
                findings.extend(bytes_findings)

            # 2. Check for target file path referenced in artifact
            target_path = None
            if isinstance(artifact.raw_fields, dict):
                target_path = (
                    artifact.raw_fields.get("file_path") or
                    artifact.raw_fields.get("target_path") or
                    artifact.raw_fields.get("binary_path")
                )
            if not target_path and isinstance(artifact.normalized_fields, dict):
                target_path = artifact.normalized_fields.get("file_path")

            if target_path and isinstance(target_path, str) and os.path.isfile(target_path):
                file_findings = self.evaluate_file(
                    case_id=case_id,
                    artifact_id=artifact.artifact_id,
                    file_path=target_path,
                    evidence_ref=fcr_ref
                )
                findings.extend(file_findings)

        return findings

    def _matches_to_findings(
        self,
        matches: List[Any],
        case_id: str,
        artifact_id: str,
        evidence_ref: str,
        source_name: str
    ) -> List[Finding]:
        """Converts YARA Match objects into standard Finding models."""
        findings: List[Finding] = []

        for match in matches:
            rule_name = getattr(match, "rule", "unknown_yara_rule")
            meta = getattr(match, "meta", {}) or {}
            tags = getattr(match, "tags", []) or []

            # 1. Derive Severity & Confidence (NOT hardcoded 0.90)
            raw_severity = str(meta.get("severity", meta.get("level", "high"))).lower()
            severity = raw_severity if raw_severity in SEVERITY_TO_CONFIDENCE else "high"
            
            # Check meta for explicit confidence float override, otherwise derive from severity
            meta_conf = meta.get("confidence")
            if isinstance(meta_conf, (int, float)) and 0.0 <= meta_conf <= 1.0:
                confidence = float(meta_conf)
            elif isinstance(meta_conf, str):
                try:
                    parsed_conf = float(meta_conf.strip())
                    if 0.0 <= parsed_conf <= 1.0:
                        confidence = parsed_conf
                    else:
                        confidence = SEVERITY_TO_CONFIDENCE.get(severity, 0.85)
                except ValueError:
                    confidence = SEVERITY_TO_CONFIDENCE.get(severity, 0.85)
            else:
                confidence = SEVERITY_TO_CONFIDENCE.get(severity, 0.85)

            # 2. Extract MITRE ATT&CK Advisory Tags
            mitre_tags = []
            mitre_hint = None
            if "mitre_attack" in meta:
                mitre_tags.append(str(meta["mitre_attack"]))
            for tag in tags:
                tag_lower = tag.lower()
                if tag_lower.startswith("attack.") or tag_lower.startswith("t1"):
                    mitre_tags.append(tag)
            if mitre_tags:
                mitre_hint = mitre_tags[0]

            # 3. Format matched string details safely
            string_matches = []
            raw_strings = getattr(match, "strings", []) or []
            for item in raw_strings[:10]: # Limit to first 10 string matches
                try:
                    # YARA string tuple format: (offset, string_identifier, matched_data)
                    offset, str_id, str_data = item[0], item[1], item[2]
                    if isinstance(str_data, bytes):
                        # Safe ascii/utf-8 representation
                        preview = str_data.decode("utf-8", errors="replace")
                    else:
                        preview = str(str_data)
                    if len(preview) > 100:
                        preview = preview[:100] + "..."
                    string_matches.append({
                        "offset": offset,
                        "string_id": str_id,
                        "preview": preview
                    })
                except Exception:
                    pass

            rule_desc = meta.get("description", meta.get("author", "YARA Rule Detections"))

            fact_msg = (
                f"YARA rule '{rule_name}' matched on '{source_name}': {rule_desc}. "
                f"Matched {len(raw_strings)} string instance(s)."
            )

            findings.append(Finding(
                case_id=case_id,
                fact=fact_msg,
                confidence=confidence,
                severity=severity,
                mitre_mapping=mitre_hint,
                timestamp=datetime.now(timezone.utc),
                evidence_reference=evidence_ref or artifact_id,
                source_artifact_id=artifact_id,
                layer=f"yara.{rule_name}",
                metadata={
                    "rule_name": rule_name,
                    "rule_tags": tags,
                    "rule_meta": meta,
                    "matched_strings": string_matches,
                    "total_string_matches": len(raw_strings),
                    "source_name": source_name,
                    "mitre_tags_advisory": mitre_tags,
                }
            ))

        return findings
