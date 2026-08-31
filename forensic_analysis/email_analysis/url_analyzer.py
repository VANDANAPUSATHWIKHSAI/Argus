"""
Email Analysis Engine — URL Analyzer
=====================================
Deterministically analyzes URLs extracted from email headers and body text
without network fetching, DNS resolution, or external requests.
"""

from __future__ import annotations

import re
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from urllib.parse import urlparse

from forensic_analysis.schemas import Finding
from preprocessing.schemas import Artifact

logger = logging.getLogger(__name__)

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".zip", ".gq", ".cf", ".ml", ".ga", ".work",
    ".click", ".link", ".buzz", ".monster", ".country"
}

URL_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "tiny.cc"
}

URL_REGEX = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
IP_LITERAL_REGEX = re.compile(r'^https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/.*)?$', re.IGNORECASE)


class URLAnalyzer:
    """
    Analyzes URLs extracted from email evidence strictly in-memory without
    making network or DNS calls.
    """

    def analyze(
        self,
        artifact: Artifact,
        correlation_ids: List[str]
    ) -> List[Finding]:
        art_type = getattr(artifact, "artifact_type", "")
        if art_type not in ("email", "email_header", "email.header", "email.body", "email_message"):
            return []

        findings: List[Finding] = []
        raw = getattr(artifact, "raw_fields", {}) or {}
        norm = getattr(artifact, "normalized_fields", None)

        urls: set[str] = set()

        # Collect URLs from normalized fields and raw fields
        if norm and getattr(norm, "url", None):
            urls.add(str(norm.url).strip())

        raw_urls = raw.get("urls") or raw.get("urls_extracted") or []
        if isinstance(raw_urls, list):
            for u in raw_urls:
                if isinstance(u, str) and u.strip():
                    urls.add(u.strip())

        # Extract URLs from body text/html using regex if not explicitly extracted
        body_text = raw.get("body_text") or raw.get("body") or raw.get("body_html") or ""
        if isinstance(body_text, str) and body_text:
            found_urls = URL_REGEX.findall(body_text)
            for fu in found_urls:
                urls.add(fu.rstrip(".,;!"))

        for url_str in urls:
            if not url_str.startswith(("http://", "https://")):
                continue

            try:
                parsed = urlparse(url_str)
            except Exception:
                continue

            hostname = (parsed.hostname or "").lower()
            port = parsed.port
            netloc = (parsed.netloc or "").lower()

            # 1. IP-Literal URL Detection
            if IP_LITERAL_REGEX.match(url_str) or re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', hostname):
                fact_msg = f"IP-literal URL observed in email content: '{url_str}'"
                findings.append(Finding(
                    case_id=artifact.case_id,
                    tenant_id=getattr(artifact, "tenant_id", "default"),
                    fact=fact_msg,
                    confidence=0.85,
                    severity="high",
                    mitre_mapping="T1566.002",
                    timestamp=artifact.timestamp or datetime.now(timezone.utc),
                    evidence_reference=correlation_ids[0] if correlation_ids else artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="email.url_analyzer",
                    contributing_correlation_ids=list(correlation_ids),
                    metadata={"url": url_str, "domain": hostname}
                ))

            # 2. Punycode / IDN Domain Detection
            if "xn--" in hostname:
                fact_msg = f"Punycode encoded domain observed in email URL: '{hostname}' (URL: '{url_str}')"
                findings.append(Finding(
                    case_id=artifact.case_id,
                    tenant_id=getattr(artifact, "tenant_id", "default"),
                    fact=fact_msg,
                    confidence=0.90,
                    severity="high",
                    mitre_mapping="T1566.002",
                    timestamp=artifact.timestamp or datetime.now(timezone.utc),
                    evidence_reference=correlation_ids[0] if correlation_ids else artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="email.url_analyzer",
                    contributing_correlation_ids=list(correlation_ids),
                    metadata={"url": url_str, "domain": hostname}
                ))

            # 3. URL Shortening Service Detection
            if hostname in URL_SHORTENER_DOMAINS:
                fact_msg = f"URL shortening service domain observed in email: '{hostname}' (URL: '{url_str}')"
                findings.append(Finding(
                    case_id=artifact.case_id,
                    tenant_id=getattr(artifact, "tenant_id", "default"),
                    fact=fact_msg,
                    confidence=0.75,
                    severity="medium",
                    mitre_mapping="T1566.002",
                    timestamp=artifact.timestamp or datetime.now(timezone.utc),
                    evidence_reference=correlation_ids[0] if correlation_ids else artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="email.url_analyzer",
                    contributing_correlation_ids=list(correlation_ids),
                    metadata={"url": url_str, "domain": hostname}
                ))

            # 4. Suspicious TLD Detection
            for tld in SUSPICIOUS_TLDS:
                if hostname.endswith(tld):
                    fact_msg = f"Suspicious TLD '{tld}' observed in email URL: '{url_str}'"
                    findings.append(Finding(
                        case_id=artifact.case_id,
                        tenant_id=getattr(artifact, "tenant_id", "default"),
                        fact=fact_msg,
                        confidence=0.80,
                        severity="medium",
                        mitre_mapping="T1566.002",
                        timestamp=artifact.timestamp or datetime.now(timezone.utc),
                        evidence_reference=correlation_ids[0] if correlation_ids else artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="email.url_analyzer",
                        contributing_correlation_ids=list(correlation_ids),
                        metadata={"url": url_str, "domain": hostname, "tld": tld}
                    ))
                    break

            # 5. Embedded Credentials Detection
            if "@" in netloc and not netloc.startswith("http"):
                fact_msg = f"Embedded user credentials observed in email URL structure: '{url_str}'"
                findings.append(Finding(
                    case_id=artifact.case_id,
                    tenant_id=getattr(artifact, "tenant_id", "default"),
                    fact=fact_msg,
                    confidence=0.85,
                    severity="high",
                    mitre_mapping="T1566.002",
                    timestamp=artifact.timestamp or datetime.now(timezone.utc),
                    evidence_reference=correlation_ids[0] if correlation_ids else artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="email.url_analyzer",
                    contributing_correlation_ids=list(correlation_ids),
                    metadata={"url": url_str, "domain": hostname}
                ))

            # 6. Non-Standard Port Detection
            if port and port not in (80, 443):
                fact_msg = f"Unusual non-standard port :{port} observed in email URL: '{url_str}'"
                findings.append(Finding(
                    case_id=artifact.case_id,
                    tenant_id=getattr(artifact, "tenant_id", "default"),
                    fact=fact_msg,
                    confidence=0.75,
                    severity="medium",
                    mitre_mapping="T1566.002",
                    timestamp=artifact.timestamp or datetime.now(timezone.utc),
                    evidence_reference=correlation_ids[0] if correlation_ids else artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="email.url_analyzer",
                    contributing_correlation_ids=list(correlation_ids),
                    metadata={"url": url_str, "port": port}
                ))

        return findings
