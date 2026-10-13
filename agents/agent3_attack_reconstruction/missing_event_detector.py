"""
Agent 3 — Deterministic Missing Expected Event Detector
=========================================================
Identifies missing expected forensic events (e.g. expected logon after credential dump,
expected file download prior to execution, missing DNS resolution prior to external IP connection)
based on deterministic rules over FIR evidence findings.
"""

import re
import logging
from typing import List, Dict, Any, Set
from agents.agent3_attack_reconstruction.schemas import MissingExpectedEvent

logger = logging.getLogger(__name__)


class MissingEventDetector:
    """
    Deterministic rule engine to detect expected forensic events that are missing from evidence.
    """

    def detect_missing_events(self, findings: List[Any]) -> List[MissingExpectedEvent]:
        missing_events: List[MissingExpectedEvent] = []
        
        # Combine finding text facts for rule scanning
        all_facts = []
        for f in findings:
            fact = self._get_val(f, "fact") or self._get_val(f, "event_summary") or ""
            all_facts.append(str(fact).lower())
            
        full_corpus_text = " ".join(all_facts)

        # 1. Rule 1: Credential Access without subsequent successful auth log
        if any(term in full_corpus_text for term in ["lsass", "mimikatz", "vault", "sam_hive", "credential_dump"]):
            if not any(term in full_corpus_text for term in ["event id 4624", "successful logon", "session established"]):
                missing_events.append(
                    MissingExpectedEvent(
                        event="Expected Successful Authentication / Interactive Session Log",
                        reason="Credential dumping / LSASS access was observed, but no subsequent successful logon (Event ID 4624) or remote session creation log was recorded.",
                        status="NOT_OBSERVED"
                    )
                )

        # 2. Rule 2: Execution from Temp/AppData without recorded file download/write
        if any(term in full_corpus_text for term in ["appdata", "temp", "tmp", "public\\"]) and any(term in full_corpus_text for term in [".exe", ".bat", ".ps1", ".vbs"]):
            if not any(term in full_corpus_text for term in ["download", "file_created", "file_write", "http", "attachment"]):
                missing_events.append(
                    MissingExpectedEvent(
                        event="Expected File Creation / Ingress Download Log",
                        reason="Script/binary execution observed from temporary directory, but no prior file write or browser/email download artifact was recorded.",
                        status="NOT_OBSERVED"
                    )
                )

        # 3. Rule 3: Outbound IP connection without prior DNS resolution
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', full_corpus_text)
        external_ips = [ip for ip in ips if not ip.startswith("127.") and not ip.startswith("192.168.") and not ip.startswith("10.") and ip != "0.0.0.0"]
        if external_ips:
            if not any(term in full_corpus_text for term in ["dns", "query", "domain_resolution"]):
                missing_events.append(
                    MissingExpectedEvent(
                        event="Expected DNS Query Resolution Log",
                        reason=f"Direct socket connection to external IP ({external_ips[0]}) was observed, but corresponding DNS query resolution log was not captured.",
                        status="NOT_OBSERVED"
                    )
                )

        # 4. Rule 4: Multiple Failed Logon events without Account Lockout Event
        failed_count = sum(1 for text in all_facts if "4625" in text or "failed logon" in text or "logon failure" in text)
        if failed_count >= 3:
            if not any(term in full_corpus_text for term in ["4740", "account lockout", "lockout_event"]):
                missing_events.append(
                    MissingExpectedEvent(
                        event="Expected Account Lockout Event ID 4740 Log",
                        reason=f"Multiple failed authentication attempts ({failed_count} events) were observed, but no Event ID 4740 (Account Lockout) was present in audit logs.",
                        status="NOT_OBSERVED"
                    )
                )

        return missing_events

    def _get_val(self, obj: Any, key: str, default: Any = None) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)
