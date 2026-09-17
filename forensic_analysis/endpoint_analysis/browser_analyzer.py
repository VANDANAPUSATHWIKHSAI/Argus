"""
Endpoint Analysis — Browser Artifact Analyzer
===============================================
Analyzes Chrome and Firefox browser history and download artifacts.

Strictly enforces semantic boundaries:
- VISITED != EXECUTED
- DOWNLOADED != EXECUTED
- URL OBSERVED != COMPROMISE
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from preprocessing.schemas import Artifact
from forensic_analysis.schemas import Finding

logger = logging.getLogger(__name__)

SUSPICIOUS_TLDS = (".xyz", ".top", ".tk", ".zip", ".cc", ".biz", ".work")
SUSPICIOUS_DYNDNS = ("duckdns.org", "ngrok.io", "loca.lt", "serveo.net", "portmap.host")
EXECUTABLE_EXTENSIONS = (".exe", ".dll", ".bat", ".ps1", ".vbs", ".iso", ".zip", ".msi", ".scr", ".hta")


class BrowserAnalyzer:
    """
    Deterministic analyzer for browser history and download artifacts.
    """

    def analyze(
        self,
        artifacts: List[Artifact],
        case_id: str,
        fcr_ref: Optional[str] = None
    ) -> List[Finding]:
        findings: List[Finding] = []

        for artifact in artifacts:
            art_type = (artifact.artifact_type or "").lower()
            norm = artifact.normalized_fields
            raw = artifact.raw_fields or {}
            ts = artifact.timestamp or datetime.now(timezone.utc)

            # 1. Browser History Visits
            if art_type in ("browser_history", "endpoint.browser_history"):
                url = norm.url or str(raw.get("url", "")) or str(raw.get("URL", ""))
                domain = norm.domain or str(raw.get("domain", "")) or str(raw.get("host", ""))
                title = str(raw.get("title", "")) or str(raw.get("name", ""))
                if not domain and url:
                    parsed = urlparse(url)
                    domain = parsed.netloc or url

                if url or domain:
                    domain_clean = domain.lower()
                    is_susp_tld = any(domain_clean.endswith(tld) for tld in SUSPICIOUS_TLDS)
                    is_susp_dyndns = any(dyndns in domain_clean for dyndns in SUSPICIOUS_DYNDNS)

                    if is_susp_tld or is_susp_dyndns:
                        fact_msg = (
                            f"Web page visit recorded in browser history to suspicious domain/dynamic DNS: "
                            f"URL '{url or domain}' (domain: '{domain_clean}'). "
                            f"Note: Web history confirms page navigation/visit, NOT malicious execution."
                        )
                        findings.append(Finding(
                            case_id=case_id,
                            fact=fact_msg,
                            confidence=0.88,
                            severity="medium",
                            mitre_mapping="T1071.001",
                            timestamp=ts,
                            evidence_reference=fcr_ref or artifact.artifact_id,
                            source_artifact_id=artifact.artifact_id,
                            layer="endpoint.browser_analyzer",
                            metadata={
                                "url": url,
                                "domain": domain_clean,
                                "is_susp_tld": is_susp_tld,
                                "is_susp_dyndns": is_susp_dyndns,
                                "artifact_id": artifact.artifact_id,
                            }
                        ))

            # 2. Browser Downloads
            elif art_type in ("browser_download", "endpoint.browser_download"):
                filename = norm.file_name or str(raw.get("file_name", "")) or str(raw.get("target_path", ""))
                url = norm.url or str(raw.get("url", "")) or str(raw.get("referrer", ""))

                if filename:
                    fname_clean = filename.lower()
                    is_exe_download = any(fname_clean.endswith(ext) for ext in EXECUTABLE_EXTENSIONS)

                    if is_exe_download:
                        fact_msg = (
                            f"Executable/script file download recorded in browser history: file '{filename}' "
                            f"downloaded from URL '{url or 'N/A'}'. "
                            f"Note: Browser history confirms file download to disk, NOT execution."
                        )
                        findings.append(Finding(
                            case_id=case_id,
                            fact=fact_msg,
                            confidence=0.92,
                            severity="high",
                            mitre_mapping="T1204.002",
                            timestamp=ts,
                            evidence_reference=fcr_ref or artifact.artifact_id,
                            source_artifact_id=artifact.artifact_id,
                            layer="endpoint.browser_analyzer",
                            metadata={
                                "file_name": filename,
                                "url": url,
                                "artifact_id": artifact.artifact_id,
                            }
                        ))

            # 3. Installed Extensions
            elif art_type in ("browser_extension", "endpoint.browser_extension") or "extension" in str(raw.get("row_type", "")).lower():
                ext_name = str(raw.get("name", "")) or str(raw.get("title", "")) or norm.rule_name or "Unknown Extension"
                ext_id = str(raw.get("url", "")) or str(raw.get("value", ""))
                fact_msg = (
                    f"Browser extension recorded in profile: '{ext_name}' (ID/Path: '{ext_id}'). "
                    f"Note: Browser profile confirms extension installation/configuration."
                )
                findings.append(Finding(
                    case_id=case_id,
                    fact=fact_msg,
                    confidence=0.85,
                    severity="informational",
                    mitre_mapping="T1176",
                    timestamp=ts,
                    evidence_reference=fcr_ref or artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="endpoint.browser_analyzer",
                    metadata={
                        "extension_name": ext_name,
                        "extension_id": ext_id,
                        "artifact_id": artifact.artifact_id,
                    }
                ))

            # 4. Cookies & Site Settings
            elif art_type in ("browser_cookie", "endpoint.browser_cookie"):
                c_domain = norm.domain or str(raw.get("host_key", "")) or str(raw.get("domain", ""))
                c_name = str(raw.get("name", ""))
                if c_domain or c_name:
                    fact_msg = (
                        f"Browser cookie record observed: name '{c_name}' for domain '{c_domain}'. "
                        f"Note: Confirms site session state/access."
                    )
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.80,
                        severity="informational",
                        mitre_mapping="T1539",
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="endpoint.browser_analyzer",
                        metadata={
                            "domain": c_domain,
                            "cookie_name": c_name,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

        return findings
