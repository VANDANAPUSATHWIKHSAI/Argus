"""
Artifact Extraction — Deterministic ioc-finder + YaraScanner + CyNER NER
========================================================================
Extracts IOCs, file hashes, IPs, domains, URLs, email addresses, CVEs,
YARA matches, and NER-extracted threat actors/malware from forensic artifacts.
"""

from __future__ import annotations

import logging
import os
import threading
import uuid
import base64
import re
import ipaddress
import hashlib
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple, Set


import torch
import tldextract
import ioc_finder
import yara
from transformers import pipeline, AutoTokenizer, AutoModelForTokenClassification

from preprocessing.schemas import Artifact, NormalizedFields, ExtractedEntity
from preprocessing.artifact_extractor.resolver import CommandLineSpanResolver
from preprocessing.artifact_extractor.registry import SystemObjectRegistry

logger = logging.getLogger(__name__)

# Pinned model configurations
NER_MODEL_ID = "PranavaKailash/CyNER-2.0-DeBERTa-v3-base"
NER_REVISION = "main"

# Model Lifecycle States
MODEL_AVAILABLE = "MODEL_AVAILABLE"
MODEL_LOADING = "MODEL_LOADING"
MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
MODEL_FAILED = "MODEL_FAILED"

CYNER_LABEL_MAP = {
    "threat_group": "threat-actor",
    "threat_actor": "threat-actor",
    "threat-actor": "threat-actor",
    "malware": "malware",
    "malware_candidate": "malware",
    "indicator": "command-line",
    "system": "system_process",
    "organization": "organization",
    "vulnerability": "vulnerability"
}

# ═══════════════════════════════════════════════════════════════════════════════
# 1. DETERMINISTIC IOC FINDER SPAN UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def make_defang_regex(normalized_val: str, ioc_type: str) -> str:
    """Construct a regex that matches normalized IOC and its defanged variants."""
    escaped = re.escape(normalized_val)
    parts = escaped.split(r'\.')
    dot_pattern = r'(?:\.|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\))'
    pattern = dot_pattern.join(parts)
    if ioc_type == "url":
        pattern = pattern.replace('http', r'h[xt][xt]p')
        pattern = pattern.replace('https', r'h[xt][xt]ps')
    if ioc_type in ("ipv4", "ipv6", "md5", "sha1", "sha256", "cve_id", "bitcoin_address", "mac_address"):
        return r'\b' + pattern + r'\b'
    return pattern

def find_raw_spans(normalized_val: str, text: str, ioc_type: str) -> List[Tuple[str, int, int]]:
    """Find all raw/defanged occurrences of a normalized IOC value in text."""
    regex_str = make_defang_regex(normalized_val, ioc_type)
    try:
        pattern = re.compile(regex_str, re.IGNORECASE)
        matches = list(pattern.finditer(text))
        return [(m.group(), m.start(), m.end()) for m in matches]
    except Exception:
        # Fallback to simple substring find if regex error
        idx = text.lower().find(normalized_val.lower())
        if idx != -1:
            return [(text[idx:idx+len(normalized_val)], idx, idx+len(normalized_val))]
        return []

def map_category_to_type(cat: str) -> Optional[str]:
    """Map ioc-finder categories to schema ioc types."""
    mapping = {
        "ipv4s": "ipv4",
        "ipv6s": "ipv6",
        "urls": "url",
        "domains": "domain",
        "md5s": "md5",
        "sha1s": "sha1",
        "sha256s": "sha256",
        "email_addresses": "email",
        "cves": "cve_id",
        "bitcoin_addresses": "bitcoin_address",
        "mac_addresses": "mac_address",
    }
    return mapping.get(cat)

# ═══════════════════════════════════════════════════════════════════════════════
# 2. YARA SCANNER COMPONENT
# ═══════════════════════════════════════════════════════════════════════════════

class YaraScanner:
    """Compiles and executes YARA rules against raw binary content."""

    def __init__(self, rule_filepath: Optional[str] = None):
        if not rule_filepath:
            rule_filepath = str(Path(__file__).resolve().parent / "rules" / "signature_base_rules.yar")
        
        self.rule_filepath = rule_filepath
        try:
            self.rules = yara.compile(filepath=self.rule_filepath)
            logger.info(f"YARA rules compiled successfully from {self.rule_filepath}")
        except Exception as e:
            raise RuntimeError(f"YARA compilation failed for {self.rule_filepath}: {e}") from e

    def scan_binary(self, data: bytes, source_artifact_id: str, evidence_id: str) -> List[Artifact]:
        """Runs the compiled rules against binary data and returns yara_match artifacts."""
        artifacts = []
        try:
            matches = self.rules.match(data=data)
            for m in matches:
                matched_strings = []
                for s in m.strings:
                    for inst in s.instances:
                        offset = inst.offset
                        string_id = s.identifier
                        string_data = inst.matched_data
                        try:
                            str_val = string_data.decode('utf-8', errors='replace')
                        except Exception:
                            str_val = string_data.hex()
                        matched_strings.append(f"{string_id} at {offset}: {str_val}")

                # Create yara_match artifact
                art = Artifact(
                    evidence_id=evidence_id,
                    source_tool="yara",
                    artifact_type="yara_match",
                    raw_fields={
                        "rule_name": m.rule,
                        "matched_strings": matched_strings,
                        "source_artifact_id": source_artifact_id,
                        "normalized_value": m.rule,
                    }
                )
                artifacts.append(art)

                # Extract IOCs from matched strings
                for s in m.strings:
                    for inst in s.instances:
                        string_id = s.identifier
                        string_data = inst.matched_data
                        try:
                            str_val = string_data.decode('utf-8', errors='replace')
                        except Exception:
                            continue
                        
                        found = ioc_finder.find_iocs(str_val)
                        for cat, val_list in found.items():
                            ioc_type = map_category_to_type(cat)
                            if not ioc_type or not val_list:
                                continue
                            for val in val_list:
                                spans = find_raw_spans(val, str_val, ioc_type)
                                for raw_match, start, end in spans:
                                    ioc_art = Artifact(
                                        evidence_id=evidence_id,
                                        source_tool="yara",
                                        artifact_type="extracted_ioc",
                                        raw_fields={
                                            "ioc_type": ioc_type,
                                            "raw_value": raw_match,
                                            "normalized_value": val,
                                            "defanged": raw_match.lower() != val.lower(),
                                            "source_artifact_id": source_artifact_id,
                                            "source_field": f"yara_match.{m.rule}.{string_id}",
                                            "char_start": start,
                                            "char_end": end,
                                        }
                                    )
                                    artifacts.append(ioc_art)
        except Exception as e:
            logger.error(f"YARA matching failed: {e}")
        return artifacts

# ═══════════════════════════════════════════════════════════════════════════════
# 3. MAIN ARTIFACT EXTRACTOR CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class ArtifactExtractor:
    """Unified Preprocessing Artifact Extractor."""

    def __init__(self, threshold: float = 0.5):
        self._threshold = threshold
        self._model = None
        self._tokenizer = None
        self._pipeline = None
        self._model_revision = NER_REVISION
        self._lock = threading.Lock()
        self._cmd_resolver = CommandLineSpanResolver()
        self._sys_registry = SystemObjectRegistry()
        self._degraded = False
        self._degraded_reason: str | None = None
        self._model_state = MODEL_LOADING
        self._extractor_version = "1.0.0"
        self._model_name = NER_MODEL_ID

        # Telemetry
        self._rejected_prediction_count = 0
        self._rejected_predictions: List[dict] = []
        
        # Versions
        self._gliner_version = None
        self._transformers_version = None
        self._pytorch_version = None
        self._schema_version = "1.0.0"
        
        # YaraScanner instantiation
        try:
            self._yara_scanner = YaraScanner()
        except Exception as e:
            logger.error(f"YaraScanner initialization failed: {e}")
            self._yara_scanner = None

        # Load CyNER model
        self._load_model()

    def get_model_state(self) -> str:
        return self._model_state

    def health_check(self) -> bool:
        return self._model_state == MODEL_AVAILABLE

    def _load_model(self) -> None:
        self._model_state = MODEL_LOADING
        try:
            import transformers
            import torch
            from huggingface_hub import hf_hub_download
            
            self._transformers_version = getattr(transformers, "__version__", "unknown")
            self._pytorch_version = getattr(torch, "__version__", "unknown")
            
            device = 0 if torch.cuda.is_available() else -1
            
            # File integrity verification
            required_hashes = {
                "model.safetensors": "097d42dda461f69ed32bbc99a59c3175ec5626b80280aca5eef10996d73308fa",
                "config.json": "fb0341635cf5a236eaff5bf77728c563a000f8ce846abf314808c1448bf612ed",
                "tokenizer.json": "9313554f1d10f9e6addc02ea82c727f7e646d9cfb153d2cb62560b9268dd4ca4",
                "tokenizer_config.json": "bbdee0f89bf77971bc593224c513496e4ec34aecc199b60e64d2b45ac7aa61ff",
                "spm.model": "c679fbf93643d19aab7ee10c0b99e460bdbc02fedf34b92b05af343b4af586fd",
                "added_tokens.json": "a4b6bfe668f2b3cf6f0cd535e98a0663d2d0d4a4a15f13075ad3597d33985a23",
                "special_tokens_map.json": "b70b72bbc44ed96ae896e1b26d2d269d40a58709c9de1428c9bbfa872fe7f7ce"
            }
            
            # Offline hash checks
            for filename, expected_hash in required_hashes.items():
                try:
                    local_path_str = hf_hub_download(
                        repo_id=NER_MODEL_ID,
                        filename=filename,
                        revision=NER_REVISION,
                        local_files_only=True
                    )
                except Exception as e:
                    self._degraded = True
                    self._model_state = MODEL_UNAVAILABLE
                    self._degraded_reason = f"CyNER model file {filename} not pre-provisioned/cached locally: {e}"
                    logger.error(self._degraded_reason)
                    return

                local_path = Path(local_path_str)
                if not local_path.exists():
                    self._degraded = True
                    self._model_state = MODEL_UNAVAILABLE
                    self._degraded_reason = f"CyNER model file {filename} path does not exist: {local_path}"
                    logger.error(self._degraded_reason)
                    return

                # Calculate SHA-256 hash of the file
                h = hashlib.sha256()
                with open(local_path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        h.update(chunk)
                actual_hash = h.hexdigest()

                if actual_hash != expected_hash:
                    self._degraded = True
                    self._model_state = MODEL_FAILED
                    self._degraded_reason = f"Integrity check failed for {filename}. Expected: {expected_hash}, Actual: {actual_hash}"
                    logger.error(self._degraded_reason)
                    return

            # Load model and tokenizer
            self._tokenizer = AutoTokenizer.from_pretrained(
                NER_MODEL_ID,
                revision=NER_REVISION,
                local_files_only=True
            )
            self._model = AutoModelForTokenClassification.from_pretrained(
                NER_MODEL_ID,
                revision=NER_REVISION,
                local_files_only=True
            )
            try:
                self._pipeline = pipeline(
                    "token-classification",
                    model=self._model,
                    tokenizer=self._tokenizer,
                    aggregation_strategy="simple",
                    device=device
                )
            except ValueError as val_e:
                if "accelerate" in str(val_e) or "device" in str(val_e):
                    logger.info("Discarding device argument for accelerate-managed model pipeline.")
                    self._pipeline = pipeline(
                        "token-classification",
                        model=self._model,
                        tokenizer=self._tokenizer,
                        aggregation_strategy="simple"
                    )
                else:
                    raise val_e
            self._model_state = MODEL_AVAILABLE
            logger.info(f"CyNER model loaded successfully: {NER_MODEL_ID}")
        except Exception as e:
            self._degraded = True
            err_msg = str(e)
            if "local_files_only" in err_msg or "offline" in err_msg or "not found" in err_msg.lower():
                self._model_state = MODEL_UNAVAILABLE
                self._degraded_reason = f"CyNER model not pre-provisioned/cached locally: {err_msg}"
            else:
                self._model_state = MODEL_FAILED
                self._degraded_reason = f"CyNER model initialization failed: {err_msg}"
            logger.error(f"CyNER model failed to load: {self._degraded_reason}")

    def _estimate_token_count(self, text: str) -> int:
        if self._tokenizer is not None:
            return len(self._tokenizer.encode(text, add_special_tokens=False))
        return max(1, len(text) // 4)

    def _chunk_text(self, text: str) -> List[Tuple[str, int]]:
        max_seq_tokens = 384
        overlap_tokens = 50
        est_tokens = self._estimate_token_count(text)
        if est_tokens <= max_seq_tokens:
            return [(text, 0)]

        chunks: List[Tuple[str, int]] = []
        if self._tokenizer is not None:
            encoding = self._tokenizer(
                text,
                add_special_tokens=False,
                return_offsets_mapping=True,
            )
            offsets = encoding["offset_mapping"]
            token_ids = encoding["input_ids"]
            n_tokens = len(token_ids)

            stride = max_seq_tokens - overlap_tokens
            start_tok = 0
            while start_tok < n_tokens:
                end_tok = min(start_tok + max_seq_tokens, n_tokens)
                char_start = offsets[start_tok][0]
                char_end = offsets[end_tok - 1][1]
                chunk_text = text[char_start:char_end]
                chunks.append((chunk_text, char_start))
                if end_tok >= n_tokens:
                    break
                start_tok += stride
        else:
            words = text.split()
            words_per_chunk = max(1, int(max_seq_tokens / 1.3))
            overlap_words = max(1, int(overlap_tokens / 1.3))
            stride = words_per_chunk - overlap_words

            char_pos = 0
            word_idx = 0
            while word_idx < len(words):
                chunk_words = words[word_idx:word_idx + words_per_chunk]
                chunk_str = " ".join(chunk_words)
                chunk_start = text.find(chunk_words[0], char_pos)
                if chunk_start == -1:
                    chunk_start = char_pos
                chunks.append((chunk_str, chunk_start))
                if word_idx + words_per_chunk >= len(words):
                    break
                word_idx += stride
                char_pos = chunk_start + len(chunk_str) - len(" ".join(chunk_words[-overlap_words:]))
        return chunks

    def _predict_gliner(self, texts: List[str]) -> List[List[dict]]:
        """Mock/compat method that performs CyNER prediction but returns in the legacy format."""
        model = getattr(self, "_model", None)
        pipeline_obj = getattr(self, "_pipeline", None)
        if model is None:
            return None
        if pipeline_obj is None and not hasattr(model, "predict_entities"):
            return None
        lock_obj = getattr(self, "_lock", None)
        # Handle cases where _lock was not initialized due to __new__
        if lock_obj is None:
            import threading
            self._lock = threading.Lock()
            lock_obj = self._lock
        with lock_obj:
            try:
                if hasattr(self._model, "predict_entities"):
                    results = []
                    for text in texts:
                        res = self._model.predict_entities(text, GLINER_LABELS)
                        results.append(res)
                    return results

                results = []
                for text in texts:
                    res = self._pipeline(text)
                    entities = []
                    for ent in res:
                        ent_group = ent.get("entity_group", "").lower()
                        mapped_label = CYNER_LABEL_MAP.get(ent_group, ent_group)
                        entities.append({
                            "text": ent.get("word", ""),
                            "label": mapped_label,
                            "start": ent.get("start", 0),
                            "end": ent.get("end", 0),
                            "score": float(ent.get("score", 0.0))
                        })
                    results.append(entities)
                return results
            except Exception as e:
                logger.warning(f"CyNER batch inference failed: {e}")
                raise e

    @staticmethod
    def get_field_extraction_policy(field_name: str) -> str:
        parts = field_name.split(".", 1)
        name = parts[-1].lower().strip() if len(parts) > 1 else field_name.lower().strip()

        neither_keywords = {
            "id", "artifact_id", "evidence_id", "tenant_id", "created_at", "updated_at",
            "timestamp", "time", "date", "status", "deleted", "size", "size_bytes", 
            "size_val", "lineno", "channel", "event_id", "event_record_id", "computer", 
            "severity", "log_level", "level", "version", "tool_version", "case_id",
            "sequence", "counter", "internal_id"
        }
        neither_suffixes = (
            "_id", "_time", "_date", "_bytes", "_size", "_at", "_status", "_level"
        )
        if name in neither_keywords or name.endswith(neither_suffixes):
            return "neither"

        regex_keywords = {
            "md5", "sha1", "sha256", "sha512", "hash", "file_hash", "ip", "ipv4", "ipv6", "src_ip", "dst_ip", 
            "destination_ip", "source_ip", "port", "src_port", "dest_port", "mac", 
            "host", "hostname", "domain", "dns", "sender", "recipients", "from", 
            "to", "cc", "bcc", "msg_id", "message_id", "device_serial", "serial"
        }
        if name in regex_keywords or any(k in name for k in ["_ip", "ip_", "_port", "port_"]):
            return "regex"

        gliner_keywords = [
            "analyst_notes", "threat_intel", "summary", "text", "payload", 
            "prose", "story", "writeup", "narrative", "analysis"
        ]
        if any(k in name for k in gliner_keywords):
            return "gliner"

        both_keywords = [
            "process", "process_name", "parent_process", "parent_process_name", "command", "command_line", "cmdline", "commandline", 
            "image", "image_path", "parent_image", "event_data", "event_message", 
            "msg", "message", "description", "detail", "details", "rule", "rule_name", 
            "comment", "comments", "notes", "unstructured", "body", "message_body", "subject", 
            "headers", "plugin_text", "raw_text", "raw_message", "file_path", 
            "path", "filepath", "file_name", "filename", "registry_key", "registry_value", "registry_data", "key_path", 
            "value_name", "value_data", "url", "title", "history", "download", 
            "cookie", "friendly_name"
        ]
        if any(k in name for k in both_keywords):
            return "both"

        return "regex"

    def _extract_base64_substrings(self, text: str, max_attempts: int = 5) -> List[Tuple[str, str]]:
        """Identify base64 patterns in text, decode them and return (raw, decoded) list."""
        pattern = re.compile(r'\b[A-Za-z0-9+/]{21,}={0,2}\b')
        matches = pattern.findall(text)
        valid_decodes = []
        attempts = 0
        for match in matches:
            if attempts >= max_attempts:
                break
            try:
                padded_match = match
                missing_padding = len(padded_match) % 4
                if missing_padding:
                    padded_match += '=' * (4 - missing_padding)
                decoded_bytes = base64.b64decode(padded_match, validate=True)
                decoded_text = decoded_bytes.decode('utf-8')
                if decoded_text.isprintable() or all(c in '\r\n\t' or c.isprintable() for c in decoded_text):
                    if decoded_text.strip():
                        valid_decodes.append((match, decoded_text))
                        attempts += 1
            except Exception:
                continue
        return valid_decodes

    def get_binary_content(self, artifact: Artifact) -> Optional[bytes]:
        """Resolve raw binary content from artifact data/fields or path attachments."""
        if artifact.artifact_type in (
            "email_header", "dns_query", "http_request", "tls_session", 
            "ids_alert", "network_flow", "browser_history", "browser_cookie",
            "auth_event", "evasion_indicator"
        ):
            return None

        # Check binary keys
        for key in ("binary_content", "raw_bytes", "data"):
            val = artifact.raw_fields.get(key)
            if isinstance(val, bytes):
                return val
            elif isinstance(val, str):
                try:
                    return base64.b64decode(val)
                except Exception:
                    return val.encode('utf-8')

        # Check path values
        for key in ("attachment_path", "file_path", "filepath", "path"):
            val = artifact.raw_fields.get(key)
            if not val and artifact.normalized_fields:
                val = getattr(artifact.normalized_fields, "file_path", None)
            if val and isinstance(val, str):
                try:
                    p = Path(val)
                    if p.is_file():
                        return p.read_bytes()
                except Exception:
                    pass
        return None

    def extract_artifacts(self, artifacts: List[Artifact], evidence_id: str) -> List[Artifact]:
        """
        Strengthened extraction pipeline returning a unified list of new Artifact entries.
        Includes Decode-and-Rescan, ioc-finder, YARA, CyNER NER, validation, dedup and confidence scoring.
        """
        all_extracted: List[Artifact] = []

        # 1. Decode-and-Rescan Preprocessing Pass
        scanned_artifacts = list(artifacts)
        for art in artifacts:
            decode_count = 0
            for k, v in list(art.raw_fields.items()):
                if isinstance(v, str) and len(v) > 20:
                    decodes = self._extract_base64_substrings(v, max_attempts=5 - decode_count)
                    for raw_b64, decoded_str in decodes:
                        # Create decoded child artifact to rescan
                        child_art = Artifact(
                            evidence_id=evidence_id,
                            source_tool=art.source_tool,
                            artifact_type=art.artifact_type,
                            timestamp=art.timestamp,
                            raw_fields={
                                "decoded_content": decoded_str,
                                "decoded_from": raw_b64,
                                "source_artifact_id": art.artifact_id,
                                "source_field": f"raw_fields.{k}"
                            }
                        )
                        scanned_artifacts.append(child_art)
                        decode_count += 1

        # 2. Stage 1 & 1.75 - ioc-finder & YARA scanning
        for art in scanned_artifacts:
            # A. Free-text ioc-finder scans
            for k, v in art.raw_fields.items():
                if isinstance(v, str) and len(v) > 3:
                    # Check field policy
                    field_path = f"raw_fields.{k}"
                    policy = self.get_field_extraction_policy(field_path)
                    if policy == "neither":
                        continue

                    # Run ioc-finder
                    found = ioc_finder.find_iocs(v)
                    for cat, val_list in found.items():
                        ioc_type = map_category_to_type(cat)
                        if not ioc_type or not val_list:
                            continue
                        for val in val_list:
                            spans = find_raw_spans(val, v, ioc_type)
                            for raw_match, start, end in spans:
                                # Validation Layer (Stage 1.5)
                                valid = True
                                is_private = False
                                
                                if ioc_type in ("ipv4", "ipv6"):
                                    try:
                                        ip = ipaddress.ip_address(val)
                                        is_private = ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local or ip.is_multicast
                                    except ValueError:
                                        logger.info(f"Dropping malformed IP match: {val} in field {k}")
                                        valid = False
                                
                                elif ioc_type == "domain":
                                    ext = tldextract.extract(val)
                                    if not ext.suffix:
                                        logger.info(f"Dropping domain with no valid TLD: {val} in field {k}")
                                        valid = False

                                if not valid:
                                    continue

                                # Map normalized fields
                                nf = NormalizedFields()
                                if ioc_type in ("ipv4", "ipv6"):
                                    nf.src_ip = val
                                    nf.private_ip = is_private
                                    nf.ip_scope = "private" if is_private else "public"
                                elif ioc_type == "domain":
                                    nf.domain = val
                                elif ioc_type == "url":
                                    nf.url = val
                                elif ioc_type == "email":
                                    nf.sender = val

                                # Build extracted observable artifact
                                extracted_ioc = Artifact(
                                    evidence_id=evidence_id,
                                    source_tool="ioc_finder",
                                    artifact_type="extracted_ioc",
                                    timestamp=art.timestamp,
                                    raw_fields={
                                        "ioc_type": ioc_type,
                                        "raw_value": raw_match,
                                        "normalized_value": val,
                                        "defanged": raw_match.lower() != val.lower(),
                                        "source_artifact_id": art.raw_fields.get("source_artifact_id") or art.artifact_id,
                                        "source_field": art.raw_fields.get("source_field", field_path),
                                        "char_start": start,
                                        "char_end": end,
                                    },
                                    normalized_fields=nf
                                )
                                for off_k in ("byte_offset", "byte_length", "line_number", "lineno"):
                                    if off_k in art.raw_fields and art.raw_fields[off_k] is not None:
                                        extracted_ioc.raw_fields[off_k] = art.raw_fields[off_k]
                                # Preserve decode traceback
                                if "decoded_from" in art.raw_fields:
                                    extracted_ioc.raw_fields["decoded_from"] = art.raw_fields["decoded_from"]

                                all_extracted.append(extracted_ioc)

                    # Run custom entities regex (registry key, file path)
                    custom_entities = self.find_custom_entities(v)
                    for custom_type, custom_val, c_start, c_end in custom_entities:
                        nf = NormalizedFields()
                        if custom_type == "file_path":
                            nf.file_path = custom_val
                        elif custom_type == "registry_key":
                            nf.registry_key = custom_val

                        custom_art = Artifact(
                            evidence_id=evidence_id,
                            source_tool=art.source_tool,
                            artifact_type="extracted_ioc",
                            timestamp=art.timestamp,
                            raw_fields={
                                "ioc_type": custom_type,
                                "raw_value": custom_val,
                                "normalized_value": custom_val,
                                "defanged": False,
                                "source_artifact_id": art.raw_fields.get("source_artifact_id") or art.artifact_id,
                                "source_field": art.raw_fields.get("source_field", field_path),
                                "char_start": c_start,
                                "char_end": c_end,
                            },
                            normalized_fields=nf
                        )
                        for off_k in ("byte_offset", "byte_length", "line_number", "lineno"):
                            if off_k in art.raw_fields and art.raw_fields[off_k] is not None:
                                custom_art.raw_fields[off_k] = art.raw_fields[off_k]
                        if "decoded_from" in art.raw_fields:
                            custom_art.raw_fields["decoded_from"] = art.raw_fields["decoded_from"]
                        all_extracted.append(custom_art)

            # B. Stage 1.75 YARA execution
            yara_scanner = getattr(self, "_yara_scanner", None)
            if yara_scanner:
                content = self.get_binary_content(art)
                if content:
                    yara_arts = yara_scanner.scan_binary(
                        content,
                        art.raw_fields.get("source_artifact_id", art.artifact_id),
                        evidence_id
                    )
                    for ya in yara_arts:
                        if "decoded_from" in art.raw_fields:
                            ya.raw_fields["decoded_from"] = art.raw_fields["decoded_from"]
                        all_extracted.append(ya)

        # 3. Stage 2 - CyNER NER execution
        # Collect unstructured texts
        ner_targets = []
        pipeline_obj = getattr(self, "_pipeline", None)
        model_obj = getattr(self, "_model", None)
        for art in scanned_artifacts:
            for k, v in art.raw_fields.items():
                if isinstance(v, str) and len(v) > 3:
                    field_path = f"raw_fields.{k}"
                    policy = self.get_field_extraction_policy(field_path)
                    if policy in ("gliner", "both") and (pipeline_obj is not None or model_obj is not None):
                        ner_targets.append((art, field_path, v))

        if ner_targets and (pipeline_obj is not None or model_obj is not None):
            # Precise token chunking & batch execution
            chunked_texts = []
            chunk_meta = []
            for art, field, text in ner_targets:
                chunks = self._chunk_text(text)
                for chunk_str, offset in chunks:
                    chunked_texts.append(chunk_str)
                    chunk_meta.append((art, field, text, offset))

            try:
                batch_res = self._predict_gliner(chunked_texts)
            except Exception as e:
                logger.warning(f"CyNER batch inference failed: {e}")
                batch_res = None
                self._degraded = True
                self._degraded_reason = f"Inference failure: {e}"

            if batch_res is not None:
                for idx, entities in enumerate(batch_res):
                    art, field, original_text, offset = chunk_meta[idx]
                    for ent in entities:
                        val = ent["text"]
                        lbl = ent["label"]
                        start = ent["start"] + offset
                        end = ent["end"] + offset
                        score = ent["score"]

                        # Check labels
                        if lbl not in CYNER_LABEL_MAP.values():
                            self._rejected_prediction_count += 1
                            self._rejected_predictions.append({
                                "rejected_label": lbl,
                                "artifact_id": art.artifact_id,
                                "evidence_id": evidence_id,
                            })
                            continue

                        # Build extracted entity artifact
                        nf = NormalizedFields()
                        if lbl == "malware":
                            nf.process = val
                        elif lbl == "threat-actor":
                            nf.user = val
                        elif lbl == "command-line":
                            nf.friendly_name = val

                        ent_art = Artifact(
                            evidence_id=evidence_id,
                            source_tool="cyner",
                            artifact_type="extracted_entity",
                            timestamp=art.timestamp,
                            raw_fields={
                                "entity_type": lbl,
                                "value": val,
                                "normalized_value": val,
                                "source_artifact_id": art.raw_fields.get("source_artifact_id") or art.artifact_id,
                                "source_field": art.raw_fields.get("source_field", field),
                                "char_start": start,
                                "char_end": end,
                                "confidence": score,
                            },
                            normalized_fields=nf
                        )
                        for off_k in ("byte_offset", "byte_length", "line_number", "lineno"):
                            if off_k in art.raw_fields and art.raw_fields[off_k] is not None:
                                ent_art.raw_fields[off_k] = art.raw_fields[off_k]
                        if "decoded_from" in art.raw_fields:
                            ent_art.raw_fields["decoded_from"] = art.raw_fields["decoded_from"]
                        all_extracted.append(ent_art)

        # 4. Dedup + Provenance Merge Pass
        # We group extracted_ioc and yara_match artifacts by (artifact_type, normalized_value)
        groups: Dict[Tuple[str, str], List[Artifact]] = {}
        ner_entities: List[Artifact] = []

        for art in all_extracted:
            if art.artifact_type in ("extracted_ioc", "yara_match"):
                norm_val = art.raw_fields.get("normalized_value", "").lower()
                key = (art.artifact_type, norm_val)
                groups.setdefault(key, []).append(art)
            else:
                ner_entities.append(art)

        merged_artifacts: List[Artifact] = []
        for key, group in groups.items():
            art_type, norm_val = key
            first = group[0]
            
            # Combine tools and occurrences
            unique_tools = {art.source_tool for art in group}
            occurrences = []
            for art in group:
                occ = {
                    "raw_value": art.raw_fields.get("raw_value", art.raw_fields.get("rule_name")),
                    "source_artifact_id": art.raw_fields.get("source_artifact_id"),
                    "source_field": art.raw_fields.get("source_field"),
                    "char_start": art.raw_fields.get("char_start", 0),
                    "char_end": art.raw_fields.get("char_end", 0),
                    "defanged": art.raw_fields.get("defanged", False),
                    "byte_offset": art.raw_fields.get("byte_offset"),
                    "byte_length": art.raw_fields.get("byte_length"),
                    "line_number": art.raw_fields.get("line_number") or art.raw_fields.get("lineno"),
                }
                if "decoded_from" in art.raw_fields:
                    occ["decoded_from"] = art.raw_fields["decoded_from"]
                occurrences.append(occ)

            # Build merged artifact
            merged_art = Artifact(
                artifact_id=first.artifact_id,
                evidence_id=evidence_id,
                source_tool="ioc_finder" if len(unique_tools) == 1 and "ioc_finder" in unique_tools else "+".join(sorted(unique_tools)),
                artifact_type=art_type,
                timestamp=first.timestamp,
                raw_fields={
                    "ioc_type": first.raw_fields.get("ioc_type"),
                    "rule_name": first.raw_fields.get("rule_name"),
                    "raw_value": first.raw_fields.get("raw_value"),
                    "normalized_value": first.raw_fields.get("normalized_value"),
                    "defanged": first.raw_fields.get("defanged", False),
                    "found_by": list(unique_tools),
                    "occurrences": occurrences,
                },
                normalized_fields=first.normalized_fields
            )
            # Retain decoded_from trace in root
            decoded_from_vals = {occ["decoded_from"] for occ in occurrences if "decoded_from" in occ}
            if decoded_from_vals:
                merged_art.raw_fields["decoded_from"] = list(decoded_from_vals)[0]

            merged_artifacts.append(merged_art)

        # Re-include NER entities
        all_final = merged_artifacts + ner_entities

        # 5. Confidence Scoring Layer
        for art in all_final:
            base_score = 0.0
            found_by = art.raw_fields.get("found_by", [art.source_tool])
            
            if art.artifact_type == "yara_match":
                base_score = 0.9
            elif art.artifact_type == "extracted_ioc":
                # Private range checks
                if art.normalized_fields and art.normalized_fields.private_ip:
                    base_score = 0.3
                else:
                    base_score = 0.7
            elif art.artifact_type == "extracted_entity":
                # NER Entity confidence is model's reported score directly (range 0.0-1.0)
                base_score = art.raw_fields.get("confidence", 0.5)

            # Boost for multiple detection methods
            if len(found_by) > 1:
                base_score += 0.15

            art.confidence_score = min(1.0, max(0.0, base_score))

        return all_final

    def find_custom_entities(self, text: str) -> List[Tuple[str, str, int, int]]:
        """
        Finds custom entities (registry_key, file_path) in text.
        Returns list of (entity_type, value, start_char, end_char).
        """
        results = []
        
        # 1. Quoted Windows Paths (with drive letter or UNC)
        quoted_win = re.finditer(r'(["\'])([a-zA-Z]:\\[^"\']+)\1', text)
        for m in quoted_win:
            val = m.group(2)
            results.append(("file_path", val, m.start(2), m.end(2)))
            
        quoted_unc = re.finditer(r'(["\'])(\\\\[^"\']+)\1', text)
        for m in quoted_unc:
            val = m.group(2)
            results.append(("file_path", val, m.start(2), m.end(2)))

        # 2. Unquoted Windows Drive Paths
        win_drive = re.finditer(r'\b([a-zA-Z]:\\(?:[a-zA-Z0-9_\-\.\(\)\s]+\\)*[a-zA-Z0-9_\-\.\(\)]+)\b', text)
        for m in win_drive:
            val = m.group(1).rstrip()
            start, end = m.start(1), m.end(1)
            # Avoid overlapping with quoted matches
            if not any(r[2] <= start and end <= r[3] for r in results):
                results.append(("file_path", val, start, end))

        # 3. UNC Paths
        unc_path = re.finditer(r'(?<![a-zA-Z0-9_\\])(\\\\[a-zA-Z0-9_\-\.]+\\(?:[a-zA-Z0-9_\-\$\s\.\(\)]+\\)*[a-zA-Z0-9_\-\$\.\(\)]+)(?![a-zA-Z0-9_\-\\])', text)
        for m in unc_path:
            val = m.group(1).rstrip()
            start, end = m.start(1), m.end(1)
            if not any(r[2] <= start and end <= r[3] for r in results):
                results.append(("file_path", val, start, end))

        # 4. Linux Paths (absolute paths under standard Unix directories)
        linux_path = re.finditer(r'(?<![a-zA-Z0-9_\/])(\/(?:bin|boot|dev|etc|home|lib|lib64|media|mnt|opt|proc|root|run|sbin|srv|sys|tmp|usr|var)(?:\/[a-zA-Z0-9_\-\.\(\)]+)+)(?![a-zA-Z0-9_\/])', text)
        for m in linux_path:
            val = m.group(1).rstrip()
            start, end = m.start(1), m.end(1)
            results.append(("file_path", val, start, end))

        # 5. Registry Keys (HKLM, HKCU, etc.)
        reg_key = re.finditer(r'\b((?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_USERS|HKU|HKEY_CLASSES_ROOT|HKCR|HKEY_CURRENT_CONFIG)(\\[a-zA-Z0-9_\-\s\{\}\(\)\.\+]+)+)\b', text)
        for m in reg_key:
            val = m.group(1).rstrip()
            results.append(("registry_key", val, m.start(1), m.end(1)))

        return results

    def extract(self, artifacts: List[Artifact], evidence_id: str, include_suppressed: bool = False) -> List[ExtractedEntity]:
        """Unified extraction interface returning ExtractedEntity objects with complete provenance."""
        extracted_artifacts = self.extract_artifacts(artifacts, evidence_id)
        
        # Build mapping from original artifact_id to parent Artifact instance
        art_map = {a.artifact_id: a for a in artifacts}
        
        entities: List[ExtractedEntity] = []
        for art in extracted_artifacts:
            # Resolve parent artifact for case_id/source_tool inheritance
            parent_id = art.raw_fields.get("source_artifact_id")
            if not parent_id:
                occs = art.raw_fields.get("occurrences", [])
                if occs:
                    parent_id = occs[0].get("source_artifact_id")
            if not parent_id:
                parent_id = art.artifact_id
                
            parent_art = art_map.get(parent_id)
            case_id = parent_art.case_id if parent_art else getattr(art, "case_id", "")
            src_tool = parent_art.source_tool if parent_art else art.source_tool
            
            # Map Artifact back to ExtractedEntity structure
            if art.artifact_type == "extracted_ioc":
                # Handle merged occurrences
                occs = art.raw_fields.get("occurrences", [art.raw_fields])
                for occ in occs:
                    raw_val = occ.get("raw_value", art.raw_fields.get("normalized_value"))
                    ent = ExtractedEntity(
                        artifact_id=occ.get("source_artifact_id", art.artifact_id),
                        evidence_id=evidence_id,
                        case_id=case_id,
                        entity_type=art.raw_fields.get("ioc_type", "extracted_ioc"),
                        value=occ.get("raw_value", art.raw_fields.get("normalized_value")),
                        source_field=occ.get("source_field", "raw_fields"),
                        char_start=occ.get("char_start", 0),
                        char_end=occ.get("char_end", 0),
                        extraction_method="regex:" + art.raw_fields.get("ioc_type", "extracted_ioc"),
                        confidence=art.confidence_score or 1.0,
                        degraded_mode=getattr(self, "_degraded", False),
                        degraded_reason=getattr(self, "_degraded_reason", None),
                        source_tool=src_tool,
                        original_value=raw_val,
                        start_offset=occ.get("char_start", 0),
                        end_offset=occ.get("char_end", 0),
                        byte_offset=occ.get("byte_offset", art.raw_fields.get("byte_offset")),
                        byte_length=occ.get("byte_length", art.raw_fields.get("byte_length")),
                        line_number=occ.get("line_number", art.raw_fields.get("line_number") or art.raw_fields.get("lineno"))
                    )
                    ent.extractor_version = getattr(self, "_extractor_version", "1.0.0")
                    ent.model_name = getattr(self, "_model_name", "PranavaKailash/CyNER-2.0-DeBERTa-v3-base")
                    ent.model_revision = getattr(self, "_model_revision", "main")
                    entities.append(ent)
            
            elif art.artifact_type == "yara_match":
                rule_name = art.raw_fields.get("rule_name")
                ent = ExtractedEntity(
                    artifact_id=art.raw_fields.get("source_artifact_id", art.artifact_id),
                    evidence_id=evidence_id,
                    case_id=case_id,
                    entity_type="yara_match",
                    value=rule_name,
                    source_field="binary_content",
                    char_start=0,
                    char_end=0,
                    extraction_method="yara",
                    confidence=art.confidence_score or 0.9,
                    degraded_mode=getattr(self, "_degraded", False),
                    degraded_reason=getattr(self, "_degraded_reason", None),
                    source_tool=src_tool,
                    original_value=rule_name,
                    byte_offset=art.raw_fields.get("byte_offset"),
                    byte_length=art.raw_fields.get("byte_length"),
                    line_number=art.raw_fields.get("line_number") or art.raw_fields.get("lineno")
                )
                ent.extractor_version = getattr(self, "_extractor_version", "1.0.0")
                entities.append(ent)

            elif art.artifact_type == "extracted_entity":
                val = art.raw_fields.get("value")
                ent = ExtractedEntity(
                    artifact_id=art.raw_fields.get("source_artifact_id", art.artifact_id),
                    evidence_id=evidence_id,
                    case_id=case_id,
                    entity_type=art.raw_fields.get("entity_type"),
                    value=val,
                    source_field=art.raw_fields.get("source_field"),
                    char_start=art.raw_fields.get("char_start", 0),
                    char_end=art.raw_fields.get("char_end", 0),
                    extraction_method="gliner",
                    confidence=art.confidence_score or art.raw_fields.get("confidence", 0.5),
                    degraded_mode=getattr(self, "_degraded", False),
                    degraded_reason=getattr(self, "_degraded_reason", None),
                    source_tool=src_tool,
                    original_value=val,
                    start_offset=art.raw_fields.get("char_start", 0),
                    end_offset=art.raw_fields.get("char_end", 0),
                    byte_offset=art.raw_fields.get("byte_offset"),
                    byte_length=art.raw_fields.get("byte_length"),
                    line_number=art.raw_fields.get("line_number") or art.raw_fields.get("lineno")
                )
                ent.extractor_version = getattr(self, "_extractor_version", "1.0.0")
                ent.model_name = getattr(self, "_model_name", "PranavaKailash/CyNER-2.0-DeBERTa-v3-base")
                ent.model_revision = getattr(self, "_model_revision", "main")
                entities.append(ent)

        # Extract structured metadata fields from original artifacts list
        for art in artifacts:
            norm = art.normalized_fields
            case_id = getattr(art, "case_id", "")
            
            def add_meta_ent(etype: str, val: Any, field_name: str):
                if val is None or str(val).strip() == "":
                    return
                val_str = str(val)
                ent = ExtractedEntity(
                    artifact_id=art.artifact_id,
                    evidence_id=evidence_id,
                    case_id=case_id,
                    entity_type=etype,
                    value=val_str,
                    source_field=f"normalized_fields.{field_name}",
                    char_start=0,
                    char_end=len(val_str),
                    extraction_method=f"metadata:{field_name}",
                    confidence=art.confidence or 1.0,
                    degraded_mode=self._degraded,
                    degraded_reason=self._degraded_reason,
                    source_tool=art.source_tool,
                    original_value=val_str,
                    byte_offset=art.raw_fields.get("byte_offset"),
                    byte_length=art.raw_fields.get("byte_length"),
                    line_number=art.raw_fields.get("line_number") or art.raw_fields.get("lineno")
                )
                ent.extractor_version = getattr(self, "_extractor_version", "1.0.0")
                entities.append(ent)

            # Core normalized properties
            add_meta_ent("host", norm.host, "host")
            add_meta_ent("user", norm.user, "user")
            add_meta_ent("process_id", norm.process_id, "process_id")
            add_meta_ent("parent_process_id", norm.parent_process_id, "parent_process_id")
            add_meta_ent("process_name", norm.process_name, "process_name")
            if norm.process_command_line:
                add_meta_ent("command_line", norm.process_command_line, "process_command_line")

            if norm.src_ip:
                add_meta_ent("ipv6" if ":" in norm.src_ip else "ipv4", norm.src_ip, "src_ip")
            if norm.dst_ip:
                add_meta_ent("ipv6" if ":" in norm.dst_ip else "ipv4", norm.dst_ip, "dst_ip")

            add_meta_ent("network_port", norm.src_port, "src_port")
            add_meta_ent("network_port", norm.dst_port, "dst_port")
            add_meta_ent("file_path", norm.file_path, "file_path")
            add_meta_ent("file_name", norm.file_name, "file_name")

            if norm.hash:
                h_len = len(norm.hash.strip())
                htype = "sha256" if h_len == 64 else ("sha1" if h_len == 40 else "md5")
                add_meta_ent(htype, norm.hash, "hash")

            add_meta_ent("domain", norm.domain, "domain")
            add_meta_ent("url", norm.url, "url")
            add_meta_ent("registry_key", norm.registry_key, "registry_key")
            add_meta_ent("registry_value", norm.registry_value, "registry_value")
            add_meta_ent("usb_serial_number", norm.usb_serial_number, "usb_serial_number")

            # Specialized USB device extractions
            if art.artifact_type == "usb_device" or "usb" in art.source_tool.lower():
                raw = art.raw_fields
                dev_id = raw.get("device_id") or raw.get("device_identifier") or raw.get("device_instance_id")
                if dev_id:
                    add_meta_ent("device_identifier", dev_id, "device_id")
                dl = raw.get("drive_letter") or raw.get("drive")
                if dl:
                    add_meta_ent("drive_letter", dl, "drive_letter")
                vp = raw.get("vendor_product") or raw.get("vendor_product_info") or raw.get("product")
                if vp:
                    add_meta_ent("vendor_product_info", vp, "vendor_product")

        art_map = {a.artifact_id: a for a in artifacts}
        
        # Group entities by (artifact_id, source_field) to preserve context grouping
        groups: Dict[Tuple[str, str], List[ExtractedEntity]] = {}
        for e in entities:
            groups.setdefault((e.artifact_id, e.source_field), []).append(e)
            
        processed_entities: List[ExtractedEntity] = []
        for (art_id, src_field), group_ents in groups.items():
            art = art_map.get(art_id)
            field_text = ""
            if art:
                if src_field.startswith("raw_fields."):
                    field_name = src_field.split(".", 1)[-1]
                    field_text = art.raw_fields.get(field_name, "")
                elif src_field.startswith("normalized_fields."):
                    field_name = src_field.split(".", 1)[-1]
                    field_text = str(getattr(art.normalized_fields, field_name, ""))
            
            processed = self._post_process_entities(group_ents, field_text)
            processed_entities.extend(processed)
        
        if not include_suppressed:
            processed_entities = [e for e in processed_entities if e.validation_status != "suppressed"]

        return processed_entities

    def _is_valid_filler(self, s: str) -> bool:
        s_clean = s.strip().lower()
        if not s_clean:
            return True
        for c in ",.-:;":
            s_clean = s_clean.replace(c, " ")
        words = s_clean.split()
        filler_words = {"the", "of", "a", "an", "at", "organization", "group", "campaign", "is", "was", "published", "by", "against"}
        return all(w in filler_words for w in words)

    def _classify_command_line_or_executable(self, value: str) -> str:
        val_stripped = value.strip()
        if " " in val_stripped:
            parts = val_stripped.split()
            if len(parts) > 1 and any(p.startswith(("-", "/", "\\", "$")) or p.lower() in ["delete", "shadows", "run", "start"] for p in parts[1:]):
                return "command_line"
        return "executable"

    def _is_followed_by_command_arguments(self, text: str, end_idx: int) -> bool:
        remaining = text[end_idx:].strip()
        if not remaining:
            return False
        parts = remaining.split(None, 1)
        first_word = parts[0] if parts else ""
        first_word_clean = first_word.rstrip(".,;:!?")
        if first_word_clean.startswith(("-", "/", "\\", "$")):
            return True
        if first_word_clean.lower() in ["delete", "shadows", "run", "start", "stop", "create", "add", "set", "get", "query"]:
            return True
        return False

    def _is_valid_command_syntax(self, value: str, text: str = "") -> bool:
        val = value.strip()
        if not val:
            return False
            
        # Ignore trivial single punctuation/characters
        if len(val) <= 2 and not val.isalnum():
            return False
            
        # Split into tokens
        parts = val.split()
        if not parts:
            return False
            
        first_word = parts[0].lower().rstrip(".,;:!?").strip("'\"")
        
        # 1. Known shell commands & system binaries
        known_cmds = {
            "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
            "bash", "sh", "wscript", "wscript.exe", "cscript", "cscript.exe",
            "schtasks", "schtasks.exe", "reg", "reg.exe", "whoami", "whoami.exe",
            "ping", "sc", "sc.exe", "net", "net.exe", "ipconfig", "arp", "route",
            "rundll32", "rundll32.exe", "regsvr32", "regsvr32.exe", "certutil", "certutil.exe",
            "mshta", "mshta.exe", "bitsadmin", "bitsadmin.exe", "vssadmin", "vssadmin.exe",
            "powershell_ise", "powershell_ise.exe", "nslookup", "tasklist", "taskkill", "ssh"
        }
        
        # Known executable extensions
        exe_exts = (".exe", ".bat", ".cmd", ".ps1", ".sh", ".vbs", ".js", ".scr")
        
        # Check if first word is a known command or ends with an executable extension
        is_exec_start = first_word in known_cmds or first_word.endswith(exe_exts) or first_word.startswith((".", "..", "/", "\\"))
        
        # 2. Check for flag-like tokens anywhere in the string (after the command name)
        has_flags = any(p.startswith(("-", "/", "--")) for p in parts[1:])
        
        # 3. Check for shell operators
        shell_ops = {"|", ">", "<", "&", "&&", ";"}
        has_ops = any(op in val for op in shell_ops)
        
        # Single-word validation
        if len(parts) == 1:
            if first_word in known_cmds:
                return True
            if first_word.endswith(exe_exts) and text:
                sentence_has_execution = any(verb in text.lower() for verb in ["executed", "spawned", "launched", "executing"])
                if sentence_has_execution:
                    return True
            return False
            
        # Multi-word validation: must start with an executable/command, OR contain flags, OR contain shell operators
        return is_exec_start or has_flags or has_ops

    def _post_process_entities(self, entities: List[ExtractedEntity], text: str) -> List[ExtractedEntity]:
        """
        Runs CommandLineSpanResolver, SystemObjectRegistry checks, maps entities to
        normalized candidate concepts, and populates verification tracking fields.
        """
        cmd_resolver = getattr(self, "_cmd_resolver", None)
        if cmd_resolver is None:
            from preprocessing.artifact_extractor.resolver import CommandLineSpanResolver
            cmd_resolver = CommandLineSpanResolver()
            
        sys_registry = getattr(self, "_sys_registry", None)
        if sys_registry is None:
            from preprocessing.artifact_extractor.registry import SystemObjectRegistry
            sys_registry = SystemObjectRegistry()

        # Safely fall back to default configurations if instantiated via __new__ in test environments
        generic_terms = getattr(self, "_generic_category_terms", {
            "threat actor", "attacker", "malware", "system process"
        })
        persona_negative = getattr(self, "_persona_negative_indicators", {
            "security researcher", "threat researcher", "researcher",
            "security analyst", "analyst", "system administrator", "administrator",
            "developer", "engineer", "employee", "operator"
        })
        persona_positive = getattr(self, "_persona_positive_indicators", {
            "threat actor", "attacker", "operator of the campaign",
            "member of the threat group", "launched the campaign",
            "deployed malware", "conducted the intrusion",
            "launched campaign", "deployed the malware"
        })
        context_before = getattr(self, "_context_before_len", 50)
        context_after = getattr(self, "_context_after_len", 50)

        processed = []
        for e in entities:
            # 0. Preserve original model prediction
            e.predicted_type = e.entity_type
            e.validation_status = "candidate"
            e.suppression_reason = None

            # 1. Expand command line spans if target executable and followed by arguments/execution context
            if e.entity_type in ("command-line", "command_line"):
                has_space = " " in e.value.strip()
                followed_by_args = self._is_followed_by_command_arguments(text, e.char_end)
                sentence_has_execution = any(verb in text.lower() for verb in ["executed", "spawned", "launched", "executing"])
                
                if has_space or followed_by_args or sentence_has_execution:
                    start, end, val = cmd_resolver.resolve_command_line(text, e.char_start, e.char_end, e.value)
                    e.char_start = start
                    e.char_end = end
                    e.value = val

                # Extract standalone executable from command line start if present
                cmd_stripped = e.value.strip()
                if cmd_stripped:
                    parts = cmd_stripped.split(None, 1)
                    first_tok = parts[0].strip("'\"")
                    first_tok_clean = first_tok.rstrip(".,;:!?")
                    exe_exts = (".exe", ".ps1", ".bat", ".cmd", ".sh", ".py", ".pl", ".vbs", ".js", ".scr", ".bin", ".dll")
                    known_execs = {"cmd", "powershell", "pwsh", "wscript", "cscript", "schtasks", "reg", "vssadmin", "rundll32", "regsvr32", "whoami", "net", "sc"}
                    
                    if first_tok_clean.lower() in known_execs or any(first_tok_clean.lower().endswith(ext) for ext in exe_exts) or "\\" in first_tok_clean or "/" in first_tok_clean:
                        exec_val = first_tok_clean
                        rel_start = e.value.find(first_tok_clean)
                        if rel_start != -1:
                            exec_start = e.char_start + rel_start
                            exec_end = exec_start + len(exec_val)
                            exec_ent = ExtractedEntity(
                                artifact_id=e.artifact_id,
                                evidence_id=e.evidence_id,
                                case_id=e.case_id,
                                entity_type="executable",
                                value=exec_val,
                                source_field=e.source_field,
                                char_start=exec_start,
                                char_end=exec_end,
                                extraction_method=e.extraction_method,
                                confidence=e.confidence,
                                degraded_mode=e.degraded_mode,
                                degraded_reason=e.degraded_reason,
                                source_tool=e.source_tool,
                                original_value=exec_val,
                                start_offset=exec_start,
                                end_offset=exec_end,
                                byte_offset=e.byte_offset,
                                byte_length=e.byte_length,
                                line_number=e.line_number
                            )
                            processed.append(exec_ent)

            # 2. Phase 1 – Generic Term Suppression
            norm_val = " ".join(e.value.lower().split())
            if norm_val in generic_terms:
                e.validation_status = "suppressed"
                e.suppression_reason = "generic_category_term"

            # 3. Phase 4 & 5 – Defensive Software & OS Processes Normalization
            val_lower = e.value.lower().strip()
            if val_lower == "windows defender":
                e.entity_type = "software"
            elif val_lower == "microsoft":
                e.entity_type = "organization"
            elif sys_registry.is_system_object(e.value):
                e.entity_type = "system_process"
            else:
                # 4. Normalized candidate concepts mapping
                if e.entity_type == "malware":
                    e.entity_type = "malware_candidate"
                elif e.entity_type == "threat-actor":
                    e.entity_type = "threat_actor"
                elif e.entity_type in ("command-line", "command_line"):
                    if not self._is_valid_command_syntax(e.value, text):
                        e.validation_status = "suppressed"
                        e.suppression_reason = "invalid_command_syntax"
                    else:
                        e.entity_type = self._classify_command_line_or_executable(e.value)

            # 5. Phase 2 – Persona-Aware Threat-Actor Validation
            if e.entity_type in ["threat_actor", "threat-actor"]:
                val_clean = e.value.lower().strip()
                if val_clean in persona_negative:
                    e.entity_type = "unconfirmed_person"
                    e.validation_status = "downgraded"
                    e.suppression_reason = "negative_persona_indicator"
                
                if e.validation_status != "downgraded":
                    nearest_pos_dist = 999.0
                    nearest_neg_dist = 999.0

                    prefix = text[max(0, e.char_start - context_before):e.char_start]
                    suffix = text[e.char_end:min(len(text), e.char_end + context_after)]

                    import re

                    prefix_lower = prefix.lower()
                    for ind in persona_positive:
                        pattern = re.compile(r'\b' + re.escape(ind.lower()) + r'\b')
                        matches = list(pattern.finditer(prefix_lower))
                        if matches:
                            match = matches[-1]
                            filler = prefix_lower[match.end():]
                            if self._is_valid_filler(filler):
                                dist = float(len(prefix_lower) - match.end())
                                if dist < nearest_pos_dist:
                                    nearest_pos_dist = dist
                                    
                    for ind in persona_negative:
                        pattern = re.compile(r'\b' + re.escape(ind.lower()) + r'\b')
                        matches = list(pattern.finditer(prefix_lower))
                        if matches:
                            match = matches[-1]
                            filler = prefix_lower[match.end():]
                            if self._is_valid_filler(filler):
                                dist = float(len(prefix_lower) - match.end())
                                if dist < nearest_neg_dist:
                                    nearest_neg_dist = dist

                    suffix_lower = suffix.lower()
                    for ind in persona_positive:
                        pattern = re.compile(r'\b' + re.escape(ind.lower()) + r'\b')
                        matches = list(pattern.finditer(suffix_lower))
                        if matches:
                            match = matches[0]
                            filler = suffix_lower[:match.start()]
                            if self._is_valid_filler(filler):
                                dist = float(match.start())
                                if dist < nearest_pos_dist:
                                    nearest_pos_dist = dist
                                    
                    for ind in persona_negative:
                        pattern = re.compile(r'\b' + re.escape(ind.lower()) + r'\b')
                        matches = list(pattern.finditer(suffix_lower))
                        if matches:
                            match = matches[0]
                            filler = suffix_lower[:match.start()]
                            if self._is_valid_filler(filler):
                                dist = float(match.start())
                                if dist < nearest_neg_dist:
                                    nearest_neg_dist = dist

                    if nearest_neg_dist < 999:
                        if nearest_pos_dist < 999 or nearest_neg_dist <= nearest_pos_dist:
                            e.entity_type = "unconfirmed_person"
                            e.validation_status = "downgraded"
                            e.suppression_reason = "negative_persona_indicator"

            e.normalized_type = e.entity_type
            e.model_confidence = e.confidence
            e.extraction_confidence = e.confidence
            if e.entity_type in ["malware_candidate", "executable"]:
                e.forensic_relevance = 0.5
            else:
                e.forensic_relevance = 0.8
            e.validated = False
            processed.append(e)

        return self._filter_contained_entities(processed)

    def _filter_contained_entities(self, entities: List[ExtractedEntity]) -> List[ExtractedEntity]:
        if not entities:
            return entities

        # 1. Sort entities by length descending, and then by char_start ascending
        sorted_ents = sorted(entities, key=lambda x: (x.char_end - x.char_start, -x.char_start), reverse=True)
        keep: List[ExtractedEntity] = []

        atomic_iocs = {
            "ipv4", "ipv6", "url", "domain", "file_path", "registry_key",
            "email", "md5", "sha1", "sha256", "cve_id", "usb_serial_number",
            "device_identifier", "drive_letter", "vendor_product_info",
            "process_id", "parent_process_id", "process_name", "host", "user"
        }
        ner_containers = {
            "command_line", "command-line", "executable", "system_process", "system-process",
            "malware_candidate", "malware", "threat_actor", "threat-actor",
            "organization", "software", "unconfirmed_person", "yara_match"
        }

        for e in sorted_ents:
            overlap_discard = False
            norm_e_type = e.entity_type.replace("-", "_")

            for parent in keep:
                if e.artifact_id != parent.artifact_id or e.source_field != parent.source_field:
                    continue

                norm_parent_type = parent.entity_type.replace("-", "_")

                # Check if e and parent overlap
                if max(e.char_start, parent.char_start) < min(e.char_end, parent.char_end):
                    # We have an overlap!
                    # Case 1: Same normalized type -> keep only the larger one
                    if norm_e_type == norm_parent_type:
                        overlap_discard = True
                        break

                    # Case 2: Hash types overlap (e.g. md5/sha1/sha256 nested inside each other)
                    hash_types = {"md5", "sha1", "sha256"}
                    if norm_e_type in hash_types and norm_parent_type in hash_types:
                        overlap_discard = True
                        break

                    # Case 3: Same family path types overlap (e.g. file_path nested inside longer file_path)
                    path_types = {"file_path", "filepath", "registry_key"}
                    if norm_e_type in path_types and norm_parent_type in path_types:
                        overlap_discard = True
                        break

                    # Case 4: Allowed cross-category overlaps/nestings
                    if norm_parent_type in {t.replace("-", "_") for t in ner_containers} and norm_e_type in atomic_iocs:
                        continue
                    if norm_e_type in {t.replace("-", "_") for t in ner_containers} and norm_parent_type in atomic_iocs:
                        continue
                    if norm_parent_type == "url" and norm_e_type in ("domain", "ipv4", "ipv6", "file_path"):
                        continue
                    if norm_parent_type in ("command_line", "executable") and norm_e_type in ("executable", "file_path", "url", "domain", "ipv4", "ipv6", "email", "sha256", "md5", "sha1"):
                        continue
                    if norm_parent_type == "file_path" and norm_e_type in ("file_name", "filename"):
                        continue

                    # For all other overlapping cases, discard the smaller (e)
                    overlap_discard = True
                    break

            if not overlap_discard:
                keep.append(e)

        # 2. Sort back by start offset for deterministic output
        resolved = sorted(keep, key=lambda x: (x.char_start, x.char_end))

        # 3. Deduplicate exact duplicates (same artifact, same type, same value)
        seen = set()
        unique_entities = []
        for e in resolved:
            key = (e.artifact_id, e.entity_type, e.value)
            if key not in seen:
                seen.add(key)
                unique_entities.append(e)

        return unique_entities

    def _merge_chunk_boundary_entities(self, entities: List[ExtractedEntity]) -> List[ExtractedEntity]:
        if not entities:
            return entities
        groups: Dict[tuple, List[ExtractedEntity]] = {}
        for e in entities:
            key = (e.artifact_id, e.source_field, e.entity_type, e.value)
            groups.setdefault(key, []).append(e)
        merged: List[ExtractedEntity] = []
        for key, group in groups.items():
            if len(group) == 1:
                merged.append(group[0])
            else:
                best = max(group, key=lambda x: x.confidence)
                best.char_start = min(e.char_start for e in group)
                best.char_end = max(e.char_end for e in group)
                merged.append(best)
        return merged

    def _cross_layer_dedup(self, regex_entities: List[ExtractedEntity], gliner_entities: List[ExtractedEntity]) -> List[ExtractedEntity]:
        gliner_index: Dict[tuple, ExtractedEntity] = {}
        for e in gliner_entities:
            key = (e.artifact_id, e.source_field, e.value, e.char_start, e.char_end)
            if key not in gliner_index or e.confidence > gliner_index[key].confidence:
                gliner_index[key] = e
        consumed_gliner_keys = set()
        merged = []
        for re_ent in regex_entities:
            key = (re_ent.artifact_id, re_ent.source_field, re_ent.value, re_ent.char_start, re_ent.char_end)
            if key in gliner_index:
                gl_ent = gliner_index[key]
                best_conf = max(re_ent.confidence, gl_ent.confidence)
                merged.append(ExtractedEntity(
                    artifact_id=re_ent.artifact_id,
                    evidence_id=re_ent.evidence_id,
                    entity_type=re_ent.entity_type,
                    value=re_ent.value,
                    source_field=re_ent.source_field,
                    char_start=re_ent.char_start,
                    char_end=re_ent.char_end,
                    extraction_method=f"{re_ent.extraction_method}+gliner",
                    confidence=best_conf,
                    degraded_mode=re_ent.degraded_mode,
                    degraded_reason=re_ent.degraded_reason or gl_ent.degraded_reason,
                    model_revision=gl_ent.model_revision or re_ent.model_revision,
                    extractor_version=re_ent.extractor_version or gl_ent.extractor_version,
                    model_name=re_ent.model_name or gl_ent.model_name
                ))
                consumed_gliner_keys.add(key)
            else:
                merged.append(re_ent)
        for key, gl_ent in gliner_index.items():
            if key not in consumed_gliner_keys:
                merged.append(gl_ent)
        return merged


# Legacy compatibility aliases and helper functions for unit tests
GLINER_LABELS = [
    "malware",
    "threat-actor",
    "command-line",
    "malware_candidate",
    "threat_actor",
    "command_line",
    "executable",
    "system_process",
    "process_candidate",
]
GLINER_MODEL_ID = NER_MODEL_ID
GLINER_REVISION = NER_REVISION
MAX_SEQ_TOKENS = 384
OVERLAP_TOKENS = 50

# Regexes kept specifically for path, registry key, and MITRE compatibility in tests
_COMPAT_PATTERNS = [
    ("registry_key", "registry_key", re.compile(
        r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT"
        r"|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)"
        r"(?:\\[A-Za-z0-9_\-. ]+)*(?:\\[A-Za-z0-9_\-.]+)", re.IGNORECASE
    )),
    ("windows_path", "file_path", re.compile(
        r"[A-Za-z]:\\(?:[A-Za-z0-9_\-. ]+\\)*[A-Za-z0-9_\-.]+", re.IGNORECASE
    )),
    ("unix_path", "file_path", re.compile(
        r"(?:/[A-Za-z0-9_\-\.]+){2,}", re.IGNORECASE
    )),
    ("mitre_attack", "mitre_attack", re.compile(
        r"\b(?:T[0-9]{4}(?:\.[0-9]{3})?)\b", re.IGNORECASE
    ))
]

def is_ipv4_version_number(text: str, start_offset: int) -> bool:
    if start_offset > 0 and text[start_offset - 1].lower() == 'v':
        return True
    preceding = text[max(0, start_offset - 15):start_offset].lower()
    words = preceding.split()
    if any(w in ("ver", "version", "release") for w in words) or any(w.startswith("v.") for w in words):
        return True
    return False

def extract_regex(text: str, source_field: str, artifact_id: str, evidence_id: str) -> List[ExtractedEntity]:
    """Compatible wrapper running both ioc-finder and the legacy path/registry patterns."""
    entities = []
    
    # 1. ioc-finder categories
    found = ioc_finder.find_iocs(text)
    for cat, val_list in found.items():
        ioc_type = map_category_to_type(cat)
        if not ioc_type or not val_list:
            continue
        for val in val_list:
            # Check version number for IPv4
            spans = find_raw_spans(val, text, ioc_type)
            for raw_match, start, end in spans:
                if ioc_type == "ipv4" and is_ipv4_version_number(text, start):
                    continue
                entities.append(ExtractedEntity(
                    artifact_id=artifact_id,
                    evidence_id=evidence_id,
                    entity_type=ioc_type,
                    value=raw_match,
                    source_field=source_field,
                    char_start=start,
                    char_end=end,
                    extraction_method="regex:" + ioc_type,
                    confidence=1.0,
                ))

    # 2. Compatibility regexes (paths, registry keys, MITRE codes)
    for name, entity_type, compiled in _COMPAT_PATTERNS:
        for m in compiled.finditer(text):
            entities.append(ExtractedEntity(
                artifact_id=artifact_id,
                evidence_id=evidence_id,
                entity_type=entity_type,
                value=m.group(),
                source_field=source_field,
                char_start=m.start(),
                char_end=m.end(),
                extraction_method=f"regex:{name}",
                confidence=1.0,
            ))
    return entities

