"""
Evidence Sanitization Gateway
=============================
The central boundary where untrusted free-text fields (e.g., email bodies, log messages)
cross from deterministic storage into any LLM prompt.
Applies:
  1. PII & Secrets Redaction (scrubs credit cards, Aadhaar, email, phone numbers, addresses, credentials, and system artifacts).
  2. Homoglyph Normalization and Zero-width character stripping.
  3. Base64, Hex, and ROT13 payload scans and decoders.
  4. HTML/Markdown comment quarantining.
  5. Structural separation using escaped XML tags.
  6. Active scrubbing/redaction of detected prompt injection attempts.
  7. Fail-closed security architecture.
  8. Logging to a persistent audit trail.
"""

from __future__ import annotations

import re
import json
import codecs
import base64
import html
import unicodedata
from pathlib import Path
from datetime import datetime, timezone
from typing import Tuple, Dict, List, Any, Optional
from pydantic import BaseModel, Field

from sanitization.injection_detector import InjectionDetector
from sanitization.pii_redactor import PIIRedactor


class SanitizedAgentContext(BaseModel):
    """
    Immutable, safe context returned by SanitizationGateway for LLM AI Agents.
    Preserves forensic metadata, evidence references, and provenance.
    """
    finding_id: str
    case_id: str
    tenant_id: str
    source_artifact_id: Optional[str] = None
    evidence_reference: List[str]
    contributing_correlation_ids: List[str] = Field(default_factory=list)
    timestamp: datetime
    severity: str
    confidence: float
    layer: str
    mitre_mapping: Optional[str] = None
    sanitized_fact: str
    xml_evidence_block: str
    injection_flagged: bool = False
    injection_score: float = 0.0
    sanitization_actions: List[str] = Field(default_factory=list)
    redaction_metadata: Dict[str, Any] = Field(default_factory=dict)


class SanitizationGateway:
    """
    Sanitizes untrusted inputs to prevent prompt injection attacks and protect
    user privacy (PII & Credentials Redaction) before feeding data to downstream agents.
    """

    UNSTRUCTURED_FIELD_KEYWORDS = {
        "body", "subject", "message", "chat", "email", "comment", "description",
        "raw_text", "unstructured", "fact"
    }

    def __init__(self):
        self.detector = InjectionDetector()
        self.pii_redactor = PIIRedactor()

    def redact_pii(self, text: str) -> str:
        """
        Scrubs PII and credentials, replacing them with safe placeholder tokens.
        """
        redacted_text, _ = self.pii_redactor.redact(text)
        return redacted_text

    def log_sanitization_event(self, field_name: str, layer: str, reason: str, details: dict):
        """
        Logs blocked injection attempts to a persistent JSON-lines audit trail file.
        Logs safe metadata without leaking raw secrets or raw payloads.
        """
        log_path = Path(__file__).parent.parent / "data" / "sanitization_audit.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        safe_details = {k: v for k, v in details.items() if k not in ("raw_payload", "secret", "password")}

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "field_name": field_name,
            "layer": layer,
            "reason": reason,
            "details": safe_details
        }
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            print(f"  [GATEWAY ERROR] Failed to write to audit log: {e}")

    def blocked_placeholder(self, field_name: str, layer: str, reason: str) -> str:
        """
        Returns the safe blocked placeholder wrapped in strict XML tags with escaped text.
        """
        scrubbed_text = f"[SANITISED: Potential prompt injection blocked. Layer: {layer}, Reason: {reason}]"
        print(f"  [GATEWAY WARNING] Injection blocked in field '{field_name}'! Layer: {layer}, Reason: {reason}")
        return (
            f'<evidence_data field="{field_name}">\n'
            f'{html.escape(scrubbed_text, quote=False)}\n'
            f'</evidence_data>'
        )

    def sanitize(self, text: str, field_name: str) -> str:
        """
        Sanitizes raw text:
          1. Normalizes homoglyphs (NFKC) and strips zero-width chars and control bytes.
          2. Redacts user PII, credentials, and internal prompt traces.
          3. Decodes and checks obfuscated payloads (Base64/Hex/ROT13).
          4. Checks Markdown and HTML comments.
          5. Checks and defuses prompt injection in the main text.
          6. Entity-escapes XML characters and wraps in strict XML delimiters.
          7. Fails closed on error without returning raw text.
        """
        try:
            if not text:
                return f'<evidence_data field="{field_name}" empty="true" />'

            # ── 1. Basic cleaning & Normalization ─────────────────────
            cleaned_text = "".join(ch for ch in text if ch >= " " or ch in "\t\n\r")
            cleaned_text = re.sub(r'[\u200b-\u200d\ufeff\u200e\u200f\u202a-\u202e]', '', cleaned_text)
            normalized_text = unicodedata.normalize('NFKC', cleaned_text)

            # ── 2. Privacy Layer: Redact user PII, Credentials, Prompts ──
            privacy_safe_text = self.redact_pii(normalized_text)

            # ── 3. Determine field characteristics ────────────────────
            field_lower = field_name.lower()
            is_unstructured = any(kw in field_lower for kw in self.UNSTRUCTURED_FIELD_KEYWORDS)

            # ── 4. HTML/Markdown Comment Scanning ─────────────────────
            comment_pattern = re.compile(r'<!--(.*?)-->', re.DOTALL)
            for comment in comment_pattern.findall(privacy_safe_text):
                comment_clean = comment.strip()
                if comment_clean:
                    is_malicious, details = self.detector.is_injection(comment_clean, is_unstructured=is_unstructured)
                    if is_malicious:
                        details["layer"] = "markdown_comment"
                        self.log_sanitization_event(field_name, "markdown_comment", details.get("reason"), details)
                        return self.blocked_placeholder(field_name, "markdown_comment", details.get("reason"))

            # ── 5. Payload Scan & Obfuscation Decoding ───────────────────
            # Base64 scan
            b64_pattern = re.compile(r'(?<!\w)[A-Za-z0-9+/]{16,}={0,2}(?!\w)')
            for candidate in b64_pattern.findall(privacy_safe_text):
                try:
                    candidate_clean = candidate.strip()
                    missing_padding = len(candidate_clean) % 4
                    if missing_padding:
                        candidate_clean += '=' * (4 - missing_padding)
                    decoded_bytes = base64.b64decode(candidate_clean)
                    decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                    if len(decoded_str.strip()) >= 8:
                        is_malicious, details = self.detector.is_injection(decoded_str, is_unstructured=is_unstructured)
                        if is_malicious:
                            details["layer"] = "base64_payload"
                            self.log_sanitization_event(field_name, "base64_payload", details.get("reason"), details)
                            return self.blocked_placeholder(field_name, "base64_payload", details.get("reason"))
                except Exception:
                    pass

            # Hex scan
            hex_pattern = re.compile(r'(?<!\w)[0-9a-fA-F]{16,}(?!\w)')
            for candidate in hex_pattern.findall(privacy_safe_text):
                try:
                    decoded_bytes = bytes.fromhex(candidate)
                    decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                    if len(decoded_str.strip()) >= 8:
                        is_malicious, details = self.detector.is_injection(decoded_str, is_unstructured=is_unstructured)
                        if is_malicious:
                            details["layer"] = "hex_payload"
                            self.log_sanitization_event(field_name, "hex_payload", details.get("reason"), details)
                            return self.blocked_placeholder(field_name, "hex_payload", details.get("reason"))
                except Exception:
                    pass

            # ROT13 scan — check if ROT13 decoding reveals explicit injection overrides
            try:
                rot13_text = codecs.encode(privacy_safe_text, 'rot_13')
                if any(kw in rot13_text.lower() for kw in ("ignore previous instructions", "disregard all instructions", "system message:", "jailbreak", "system prompt override")):
                    is_malicious, details = self.detector.is_injection(rot13_text, is_unstructured=False)
                    if is_malicious:
                        details["layer"] = "rot13_payload"
                        self.log_sanitization_event(field_name, "rot13_payload", details.get("reason"), details)
                        return self.blocked_placeholder(field_name, "rot13_payload", details.get("reason"))
            except Exception:
                pass

            # ── 6. Run layered injection detection on final text ─────────
            is_malicious, details = self.detector.is_injection(privacy_safe_text, is_unstructured=is_unstructured)
            if is_malicious:
                self.log_sanitization_event(field_name, details.get("layer"), details.get("reason"), details)
                return self.blocked_placeholder(field_name, details.get("layer"), details.get("reason"))

            scrubbed_text = privacy_safe_text

            # ── 7. Entity-escape XML characters & wrap in XML delimiters ──
            escaped_text = html.escape(scrubbed_text, quote=False)
            delimited = (
                f'<evidence_data field="{field_name}">\n'
                f'{escaped_text}\n'
                f'</evidence_data>'
            )
            return delimited

        except Exception as exc:
            # Fail closed on unexpected exception
            print(f"  [GATEWAY FAIL-CLOSED ERROR] Exception in sanitize(): {exc}")
            return self.blocked_placeholder(field_name, "fail_closed", "sanitization_exception")

    def sanitize_finding(self, finding: Any) -> SanitizedAgentContext:
        """
        Consumes an authoritative FIRFinding (or Finding), performs immutability-preserving
        sanitization on finding.fact / sanitized_fact, escapes XML entities, detects prompt injections,
        and returns a safe SanitizedAgentContext object for AI agent consumption.
        Fails closed on processing error without exposing raw evidence downstream.
        """
        try:
            finding_id = getattr(finding, "finding_id", "UNKNOWN")
            case_id = getattr(finding, "case_id", "UNKNOWN")
            tenant_id = getattr(finding, "tenant_id", "default")
            source_artifact_id = getattr(finding, "source_artifact_id", None)
            
            ev_ref = getattr(finding, "evidence_reference", [])
            if isinstance(ev_ref, str):
                ev_ref = [ev_ref]
            elif not isinstance(ev_ref, list):
                ev_ref = [str(ev_ref)]

            contrib_ids = getattr(finding, "contributing_correlation_ids", None)
            if contrib_ids is None:
                contrib_ids = list(ev_ref)

            fact_raw = getattr(finding, "sanitized_fact", None) or getattr(finding, "fact", "") or ""
            
            xml_block = self.sanitize(fact_raw, field_name="fact")
            
            # Check injection gate result
            gate_res = self.detector.is_injection(fact_raw, is_unstructured=True)
            inj_flagged = getattr(finding, "injection_flagged", False) or gate_res[0]
            inj_score = getattr(finding, "injection_score", 0.0)
            if gate_res[0]:
                inj_score = max(inj_score, gate_res[1].get("confidence", 1.0))

            actions = []
            if inj_flagged:
                actions.append("prompt_injection_blocked")
            
            redacted_text, _, redactions = self.pii_redactor.redact_with_details(fact_raw)
            if redactions:
                actions.append("pii_secret_redacted")

            return SanitizedAgentContext(
                finding_id=finding_id,
                case_id=case_id,
                tenant_id=tenant_id,
                source_artifact_id=source_artifact_id,
                evidence_reference=ev_ref,
                contributing_correlation_ids=contrib_ids,
                timestamp=getattr(finding, "timestamp", datetime.now(timezone.utc)),
                severity=getattr(finding, "severity", "informational"),
                confidence=getattr(finding, "confidence", 1.0),
                layer=getattr(finding, "layer", "unknown"),
                mitre_mapping=getattr(finding, "mitre_mapping", None),
                sanitized_fact=redacted_text,
                xml_evidence_block=xml_block,
                injection_flagged=inj_flagged,
                injection_score=inj_score,
                sanitization_actions=actions,
                redaction_metadata=redaction_metadata if (redaction_metadata := redactions) else {},
            )
        except Exception as exc:
            print(f"  [GATEWAY FAIL-CLOSED ERROR] Exception during sanitize_finding: {exc}")
            # Fail closed: return safe quarantined placeholder context
            return SanitizedAgentContext(
                finding_id=getattr(finding, "finding_id", "UNKNOWN"),
                case_id=getattr(finding, "case_id", "UNKNOWN"),
                tenant_id=getattr(finding, "tenant_id", "default"),
                source_artifact_id=getattr(finding, "source_artifact_id", None),
                evidence_reference=getattr(finding, "evidence_reference", []),
                timestamp=getattr(finding, "timestamp", datetime.now(timezone.utc)),
                severity="high",
                confidence=0.0,
                layer=getattr(finding, "layer", "unknown"),
                sanitized_fact="[SANITISED: Quarantined due to sanitization processing error]",
                xml_evidence_block='<evidence_data field="fact">\n[SANITISED: Quarantined due to sanitization processing error]\n</evidence_data>',
                injection_flagged=True,
                injection_score=1.0,
                sanitization_actions=["fail_closed_quarantine"],
                redaction_metadata={"error": "fail_closed_quarantine"}
            )
