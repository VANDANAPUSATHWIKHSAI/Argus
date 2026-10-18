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
6. Rigorous scan outcome semantics: guarantees distinct representation for clean zero-matches,
   missing rules, invalid syntax, unsupported evidence types, resource limits, and execution failures.

SECURITY: Uses native compiled YARA pattern matching engine safely.
"""

from __future__ import annotations

import os
import uuid
import hashlib
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
from forensic_analysis.rules.scan_outcome import ScanStatus, ScanExecutionRecord

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
        self.engine_version: str = getattr(yara, "__version__", "4.5.1-native") if YARA_AVAILABLE else "unavailable"
        self.compiled_rules: Optional[Any] = None
        self.rule_filepaths: List[str] = []
        self.rule_identifiers: List[str] = []
        self.raw_rules: Dict[str, str] = {}
        self.rules_hash: Optional[str] = None
        self.init_status: ScanStatus = ScanStatus.ZERO_MATCHES
        self.init_error: Optional[str] = None
        self.last_scan_record: Optional[ScanExecutionRecord] = None
        self._load_and_compile_rules()

    def _load_and_compile_rules(self) -> None:
        """Loads all .yar/.yara rules from the rules_dir tree and compiles them."""
        if not YARA_AVAILABLE:
            self.init_status = ScanStatus.ENGINE_UNAVAILABLE
            self.init_error = "'yara-python' package is not installed."
            logger.warning("YaraRuleEngine: %s", self.init_error)
            return

        if not os.path.isdir(self.rules_dir):
            self.init_status = ScanStatus.MISSING_RULE_CONFIG
            self.init_error = f"Rules directory '{self.rules_dir}' not found."
            logger.warning("YaraRuleEngine: %s", self.init_error)
            return

        yar_files = (
            glob(os.path.join(self.rules_dir, "**", "*.yar"), recursive=True) +
            glob(os.path.join(self.rules_dir, "**", "*.yara"), recursive=True)
        )

        if not yar_files:
            self.init_status = ScanStatus.MISSING_RULE_CONFIG
            self.init_error = f"No .yar/.yara rule files found in '{self.rules_dir}'"
            logger.info("YaraRuleEngine: %s", self.init_error)
            return

        filepaths_dict: Dict[str, str] = {}
        contents_for_hash: List[str] = []
        for idx, path in enumerate(sorted(yar_files)):
            rule_key = f"rule_{idx}_{os.path.basename(path)}"
            filepaths_dict[rule_key] = path
            self.rule_filepaths.append(path)
            self.rule_identifiers.append(os.path.basename(path))
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    contents_for_hash.append(f.read())
            except Exception as e:
                logger.warning("Could not read rule file for hash: %s", e)

        if contents_for_hash:
            self.rules_hash = hashlib.sha256("".join(contents_for_hash).encode("utf-8")).hexdigest()

        try:
            self.compiled_rules = yara.compile(filepaths=filepaths_dict)
            self.init_status = ScanStatus.ZERO_MATCHES
            logger.info(
                "YaraRuleEngine: Successfully compiled %d YARA rule files from '%s'",
                len(yar_files), self.rules_dir
            )
        except Exception as e:
            self.init_status = ScanStatus.INVALID_RULE_SYNTAX
            self.init_error = f"Failed to compile YARA rules from '{self.rules_dir}': {e}"
            logger.error("YaraRuleEngine: %s", self.init_error)
            self.compiled_rules = None

    def add_rule_string(self, rule_str: str, identifier: str = "custom_rule") -> bool:
        """Dynamically compiles and adds a YARA rule string."""
        if not YARA_AVAILABLE:
            logger.warning("YaraRuleEngine: Cannot add rule string; yara-python not installed.")
            return False

        try:
            compiled = yara.compile(source=rule_str)
            self.raw_rules[identifier] = rule_str
            if identifier not in self.rule_identifiers:
                self.rule_identifiers.append(identifier)

            # Re-hash rule set
            all_str = "".join([rule_str] + list(self.raw_rules.values()))
            self.rules_hash = hashlib.sha256(all_str.encode("utf-8")).hexdigest()

            if self.compiled_rules is None:
                self.compiled_rules = compiled
            else:
                # Merge source rules
                all_sources = dict(self.raw_rules)
                for idx, path in enumerate(self.rule_filepaths):
                    all_sources[f"file_{idx}"] = path
                self.compiled_rules = yara.compile(sources=all_sources)

            self.init_status = ScanStatus.ZERO_MATCHES
            self.init_error = None
            logger.info("YaraRuleEngine: Successfully added rule '%s'", identifier)
            return True
        except Exception as e:
            self.init_status = ScanStatus.INVALID_RULE_SYNTAX
            self.init_error = f"Error compiling rule string '{identifier}': {e}"
            logger.error("YaraRuleEngine: %s", self.init_error)
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
        source_evidence_ids = [evidence_ref] if evidence_ref else ([artifact_id] if artifact_id else [])

        # 1. Check engine availability
        if not YARA_AVAILABLE:
            self.last_scan_record = ScanExecutionRecord(
                engine_name="yara",
                status=ScanStatus.ENGINE_UNAVAILABLE,
                engine_version=self.engine_version,
                source_evidence_ids=source_evidence_ids,
                artifact_id=artifact_id,
                error_message="'yara-python' package is not installed."
            )
            return []

        # 2. Check rule initialization state
        if self.init_status in (ScanStatus.MISSING_RULE_CONFIG, ScanStatus.INVALID_RULE_SYNTAX):
            self.last_scan_record = ScanExecutionRecord(
                engine_name="yara",
                status=self.init_status,
                rule_count=len(self.rule_identifiers),
                rule_identifiers=self.rule_identifiers,
                rules_hash=self.rules_hash,
                engine_version=self.engine_version,
                source_evidence_ids=source_evidence_ids,
                artifact_id=artifact_id,
                error_message=self.init_error
            )
            return []

        if self.compiled_rules is None:
            self.last_scan_record = ScanExecutionRecord(
                engine_name="yara",
                status=ScanStatus.MISSING_RULE_CONFIG,
                engine_version=self.engine_version,
                source_evidence_ids=source_evidence_ids,
                artifact_id=artifact_id,
                error_message="No compiled YARA rules available."
            )
            return []

        # 3. Check evidence type
        if data is None or not isinstance(data, (bytes, bytearray)):
            self.last_scan_record = ScanExecutionRecord(
                engine_name="yara",
                status=ScanStatus.UNSUPPORTED_EVIDENCE_TYPE,
                rule_count=len(self.rule_identifiers),
                rule_identifiers=self.rule_identifiers,
                rules_hash=self.rules_hash,
                engine_version=self.engine_version,
                source_evidence_ids=source_evidence_ids,
                artifact_id=artifact_id,
                error_message=f"Expected bytes or bytearray, got {type(data).__name__}"
            )
            return []

        if len(data) == 0:
            self.last_scan_record = ScanExecutionRecord(
                engine_name="yara",
                status=ScanStatus.ZERO_MATCHES,
                rule_count=len(self.rule_identifiers),
                rule_identifiers=self.rule_identifiers,
                rules_hash=self.rules_hash,
                engine_version=self.engine_version,
                source_evidence_ids=source_evidence_ids,
                artifact_id=artifact_id,
                matches_count=0
            )
            return []

        # 4. Check safety resource limit
        if len(data) > self.max_file_size_bytes:
            self.last_scan_record = ScanExecutionRecord(
                engine_name="yara",
                status=ScanStatus.RESOURCE_LIMIT_EXCEEDED,
                rule_count=len(self.rule_identifiers),
                rule_identifiers=self.rule_identifiers,
                rules_hash=self.rules_hash,
                engine_version=self.engine_version,
                source_evidence_ids=source_evidence_ids,
                artifact_id=artifact_id,
                error_message=f"Data buffer size ({len(data)} bytes) exceeds safety threshold ({self.max_file_size_bytes} bytes)."
            )
            return []

        # 5. Execute scan
        try:
            matches = self.compiled_rules.match(data=data)
        except Exception as e:
            self.last_scan_record = ScanExecutionRecord(
                engine_name="yara",
                status=ScanStatus.EXECUTION_FAILURE,
                rule_count=len(self.rule_identifiers),
                rule_identifiers=self.rule_identifiers,
                rules_hash=self.rules_hash,
                engine_version=self.engine_version,
                source_evidence_ids=source_evidence_ids,
                artifact_id=artifact_id,
                error_message=f"Yara match exception: {e}"
            )
            logger.warning("YaraRuleEngine: Error during byte array scan: %s", e)
            return []

        findings = self._matches_to_findings(
            matches=matches,
            case_id=case_id,
            artifact_id=artifact_id,
            evidence_ref=evidence_ref,
            source_name=source_name or "in_memory_bytes"
        )

        final_status = ScanStatus.MATCHES_FOUND if findings else ScanStatus.ZERO_MATCHES
        self.last_scan_record = ScanExecutionRecord(
            engine_name="yara",
            status=final_status,
            rule_count=len(self.rule_identifiers),
            rule_identifiers=self.rule_identifiers,
            rules_hash=self.rules_hash,
            engine_version=self.engine_version,
            source_evidence_ids=source_evidence_ids,
            artifact_id=artifact_id,
            matches_count=len(findings)
        )
        return findings

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
        source_evidence_ids = [evidence_ref] if evidence_ref else ([artifact_id] if artifact_id else [])

        if not YARA_AVAILABLE:
            self.last_scan_record = ScanExecutionRecord(
                engine_name="yara",
                status=ScanStatus.ENGINE_UNAVAILABLE,
                engine_version=self.engine_version,
                source_evidence_ids=source_evidence_ids,
                artifact_id=artifact_id,
                error_message="'yara-python' package is not installed."
            )
            return []

        if self.init_status in (ScanStatus.MISSING_RULE_CONFIG, ScanStatus.INVALID_RULE_SYNTAX):
            self.last_scan_record = ScanExecutionRecord(
                engine_name="yara",
                status=self.init_status,
                rule_count=len(self.rule_identifiers),
                rule_identifiers=self.rule_identifiers,
                rules_hash=self.rules_hash,
                engine_version=self.engine_version,
                source_evidence_ids=source_evidence_ids,
                artifact_id=artifact_id,
                error_message=self.init_error
            )
            return []

        if self.compiled_rules is None:
            self.last_scan_record = ScanExecutionRecord(
                engine_name="yara",
                status=ScanStatus.MISSING_RULE_CONFIG,
                engine_version=self.engine_version,
                source_evidence_ids=source_evidence_ids,
                artifact_id=artifact_id,
                error_message="No compiled YARA rules available."
            )
            return []

        if not file_path or not isinstance(file_path, str):
            self.last_scan_record = ScanExecutionRecord(
                engine_name="yara",
                status=ScanStatus.UNSUPPORTED_EVIDENCE_TYPE,
                source_evidence_ids=source_evidence_ids,
                artifact_id=artifact_id,
                error_message="File path must be a non-empty string."
            )
            return []

        if not os.path.isfile(file_path):
            self.last_scan_record = ScanExecutionRecord(
                engine_name="yara",
                status=ScanStatus.EXECUTION_FAILURE,
                source_evidence_ids=source_evidence_ids,
                artifact_id=artifact_id,
                error_message=f"Target file path '{file_path}' does not exist."
            )
            logger.warning("YaraRuleEngine: Target file path '%s' does not exist.", file_path)
            return []

        # DISK SAFETY CHECK: Extension check
        ext = os.path.splitext(file_path)[1].lower()
        if ext in BLOCKED_DISK_EXTENSIONS:
            self.last_scan_record = ScanExecutionRecord(
                engine_name="yara",
                status=ScanStatus.RESOURCE_LIMIT_EXCEEDED,
                rule_count=len(self.rule_identifiers),
                rule_identifiers=self.rule_identifiers,
                rules_hash=self.rules_hash,
                engine_version=self.engine_version,
                source_evidence_ids=source_evidence_ids,
                artifact_id=artifact_id,
                error_message=f"Refusing to scan raw disk image '{file_path}' (ext={ext}) directly."
            )
            logger.warning(
                "YaraRuleEngine: Refusing to scan raw disk image file '%s' (ext=%s) directly.",
                file_path, ext
            )
            return []

        # DISK SAFETY CHECK: File size check
        try:
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size_bytes:
                self.last_scan_record = ScanExecutionRecord(
                    engine_name="yara",
                    status=ScanStatus.RESOURCE_LIMIT_EXCEEDED,
                    rule_count=len(self.rule_identifiers),
                    rule_identifiers=self.rule_identifiers,
                    rules_hash=self.rules_hash,
                    engine_version=self.engine_version,
                    source_evidence_ids=source_evidence_ids,
                    artifact_id=artifact_id,
                    error_message=f"File '{file_path}' size ({file_size // (1024 * 1024)} MB) exceeds max scan threshold ({self.max_file_size_bytes // (1024 * 1024)} MB)."
                )
                logger.warning(
                    "YaraRuleEngine: File '%s' size (%d MB) exceeds max scan threshold (%d MB). Skipping scan.",
                    file_path, file_size // (1024 * 1024), self.max_file_size_bytes // (1024 * 1024)
                )
                return []
        except Exception as e:
            self.last_scan_record = ScanExecutionRecord(
                engine_name="yara",
                status=ScanStatus.EXECUTION_FAILURE,
                source_evidence_ids=source_evidence_ids,
                artifact_id=artifact_id,
                error_message=f"Failed to check file size for '{file_path}': {e}"
            )
            logger.warning("YaraRuleEngine: Failed to check file size for '%s': %s", file_path, e)
            return []

        try:
            matches = self.compiled_rules.match(filepath=file_path)
        except Exception as e:
            self.last_scan_record = ScanExecutionRecord(
                engine_name="yara",
                status=ScanStatus.EXECUTION_FAILURE,
                rule_count=len(self.rule_identifiers),
                rule_identifiers=self.rule_identifiers,
                rules_hash=self.rules_hash,
                engine_version=self.engine_version,
                source_evidence_ids=source_evidence_ids,
                artifact_id=artifact_id,
                error_message=f"Error scanning file '{file_path}': {e}"
            )
            logger.warning("YaraRuleEngine: Error scanning file '%s': %s", file_path, e)
            return []

        findings = self._matches_to_findings(
            matches=matches,
            case_id=case_id,
            artifact_id=artifact_id,
            evidence_ref=evidence_ref,
            source_name=os.path.basename(file_path)
        )

        final_status = ScanStatus.MATCHES_FOUND if findings else ScanStatus.ZERO_MATCHES
        self.last_scan_record = ScanExecutionRecord(
            engine_name="yara",
            status=final_status,
            rule_count=len(self.rule_identifiers),
            rule_identifiers=self.rule_identifiers,
            rules_hash=self.rules_hash,
            engine_version=self.engine_version,
            source_evidence_ids=source_evidence_ids,
            artifact_id=artifact_id,
            matches_count=len(findings)
        )
        return findings

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
        source_evidence_ids = [fcr_ref] if fcr_ref else []

        if not YARA_AVAILABLE:
            self.last_scan_record = ScanExecutionRecord(
                engine_name="yara",
                status=ScanStatus.ENGINE_UNAVAILABLE,
                engine_version=self.engine_version,
                source_evidence_ids=source_evidence_ids,
                error_message="'yara-python' package is not installed."
            )
            return []

        if self.init_status in (ScanStatus.MISSING_RULE_CONFIG, ScanStatus.INVALID_RULE_SYNTAX):
            self.last_scan_record = ScanExecutionRecord(
                engine_name="yara",
                status=self.init_status,
                rule_count=len(self.rule_identifiers),
                rule_identifiers=self.rule_identifiers,
                rules_hash=self.rules_hash,
                engine_version=self.engine_version,
                source_evidence_ids=source_evidence_ids,
                error_message=self.init_error
            )
            return []

        if self.compiled_rules is None:
            self.last_scan_record = ScanExecutionRecord(
                engine_name="yara",
                status=ScanStatus.MISSING_RULE_CONFIG,
                engine_version=self.engine_version,
                source_evidence_ids=source_evidence_ids,
                error_message="No compiled YARA rules available."
            )
            return []

        findings: List[Finding] = []
        any_evaluated = False

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

            if raw_bytes is not None:
                any_evaluated = True
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
                any_evaluated = True
                file_findings = self.evaluate_file(
                    case_id=case_id,
                    artifact_id=artifact.artifact_id,
                    file_path=target_path,
                    evidence_ref=fcr_ref
                )
                findings.extend(file_findings)

        if not any_evaluated and artifacts:
            # Artifacts were provided but none contained binary data or valid file targets
            self.last_scan_record = ScanExecutionRecord(
                engine_name="yara",
                status=ScanStatus.UNSUPPORTED_EVIDENCE_TYPE,
                rule_count=len(self.rule_identifiers),
                rule_identifiers=self.rule_identifiers,
                rules_hash=self.rules_hash,
                engine_version=self.engine_version,
                source_evidence_ids=source_evidence_ids,
                error_message=f"Provided artifacts ({len(artifacts)}) contained no byte payload or referenced binary file paths."
            )
            return []

        final_status = ScanStatus.MATCHES_FOUND if findings else ScanStatus.ZERO_MATCHES
        self.last_scan_record = ScanExecutionRecord(
            engine_name="yara",
            status=final_status,
            rule_count=len(self.rule_identifiers),
            rule_identifiers=self.rule_identifiers,
            rules_hash=self.rules_hash,
            engine_version=self.engine_version,
            source_evidence_ids=source_evidence_ids,
            matches_count=len(findings)
        )
        return findings

    def evaluate_with_report(
        self,
        case_id: str,
        artifact_id: str,
        data: bytes,
        evidence_ref: str,
        source_name: Optional[str] = None
    ) -> Tuple[List[Finding], ScanExecutionRecord]:
        """Evaluates byte data and returns both findings and the full ScanExecutionRecord."""
        findings = self.evaluate_bytes(
            case_id=case_id,
            artifact_id=artifact_id,
            data=data,
            evidence_ref=evidence_ref,
            source_name=source_name
        )
        return findings, self.last_scan_record

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
                    "engine_version": self.engine_version,
                    "rules_hash": self.rules_hash,
                    "scan_status": ScanStatus.MATCHES_FOUND.value,
                }
            ))

        return findings
