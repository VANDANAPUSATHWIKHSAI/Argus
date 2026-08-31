"""
Forensic Analysis Layer — FCR Router
====================================
Determines which forensic analysis engines should process a given Forensic Correlation Record (FCR).

Routing is explicit, deterministic, order-independent, and duplicate-free.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Any
from preprocessing.fcr_engine.schemas import CorrelationRecord
from preprocessing.schemas import Artifact

logger = logging.getLogger(__name__)

# ARCHITECTURAL DECISION & COMPATIBILITY NOTE:
# The dual namespace (e.g., 'network.conn', 'endpoint.process') and canonical-name
# (e.g., 'dns_query', 'http_request', 'process_event', 'auth_event') mapping below
# exists to accommodate inconsistent artifact_type naming across existing parsers.
# Dot-namespace (e.g., 'network.dns', 'endpoint.process', 'log.auth') is the preferred
# convention going forward for any new parser.

ARTIFACT_TYPE_TO_ENGINE: Dict[str, str] = {
    # ── Network Domain ────────────────────────────────────────────────────────
    "network.conn":         "network",
    "network.dns":          "network",
    "network.http":         "network",
    "network.tls":          "network",
    "network_connection":   "network",
    "dns_query":            "network",
    "http_request":         "network",
    "tls_session":          "network",
    "ssl_handshake":        "network",
    "ids_alert":            "network",
    "network_flow":         "network",
    "file_transfer":        "network",
    "network_anomaly":      "network",
    "firewall_log":         "network",

    # ── Log Domain ────────────────────────────────────────────────────────────
    "log.auth":             "log",
    "log.process":          "log",
    "log.powershell":       "log",
    "log.hayabusa":         "log",
    "auth_event":           "log",
    "process_event":        "log",
    "powershell_event":     "log",
    "powershell_history":   "log",
    "hayabusa_triage":      "log",
    "evtx_record":          "log",
    "sysmon_event":         "log",
    "threat_detection":     "log",
    "windows_event":        "log",

    # ── Endpoint / Registry / Disk Domain ─────────────────────────────────────
    "endpoint.process":     "endpoint",
    "endpoint.file":        "endpoint",
    "endpoint.dll":         "endpoint",
    "registry.userassist":  "endpoint",
    "registry.amcache":     "endpoint",
    "registry_key":         "endpoint",
    "usb_device":           "endpoint",
    "file_record":          "endpoint",
    "dll_load":             "endpoint",
    "evasion_indicator":    "endpoint",
    "mft_entry":            "endpoint",
    "prefetch":             "endpoint",
    "prefetch_entry":       "endpoint",
    "lnk":                  "endpoint",
    "lnk_shortcut":         "endpoint",
    "jumplist":             "endpoint",
    "jumplist_entry":       "endpoint",
    "recycle_bin":          "endpoint",
    "recycle_bin_entry":    "endpoint",
    "amcache_entry":        "endpoint",
    "srum":                 "endpoint",
    "srum_entry":           "endpoint",
    "filesystem_entry":     "endpoint",
    "usn_entry":            "endpoint",
    "shimcache":            "endpoint",
    "shimcache_entry":      "endpoint",
    "scheduled_task":       "endpoint",
    "shellbags":            "endpoint",
    "shellbag_entry":       "endpoint",
    "wmi_persistence":      "endpoint",
    "wmi_event_consumer":   "endpoint",
    "timeline":             "endpoint",
    "timeline_activity":    "endpoint",
    "windows_search":       "endpoint",
    "search_history":       "endpoint",
    "sticky_notes":         "endpoint",
    "sticky_note":          "endpoint",
    "notification_db":      "endpoint",
    "notification":         "endpoint",
    "wer_report":           "endpoint",
    "windows_update":       "endpoint",
    "gpo_event":            "endpoint",
    "group_policy":         "endpoint",
    "vss_snapshot":         "endpoint",
    "dpapi_blob":           "endpoint",
    "defender_log":         "endpoint",

    # ── Email Domain ──────────────────────────────────────────────────────────
    "email":                "email",
    "email.header":         "email",
    "email.body":           "email",
    "email_header":         "email",
    "email_message":        "email",

    # ── Memory Domain ─────────────────────────────────────────────────────────
    "memory.pslist":            "memory",
    "memory.psscan":            "memory",
    "memory.pstree":            "memory",
    "memory.cmdline":           "memory",
    "process_record":           "memory",
    "process_tree_record":      "memory",
    "unlinked_process_record":  "memory",
    "command_line_record":      "memory",
    "memory.dlllist":           "memory",
    "memory.ldrmodules":        "memory",
    "memory.modules":           "memory",
    "dll_record":               "memory",
    "memory.netscan":           "memory",
    "memory.netstat":           "memory",
    "memory.malfind":           "memory",
    "memory.vadinfo":           "memory",
    "memory.vaddump":           "memory",
    "injection_indicator":      "memory",
    "memory.rootkit":           "memory",
    "hidden_modules":           "memory",
    "memory.lsass":             "memory",
    "memory.credentials":       "memory",
    "memory.hashdump":          "memory",
    "memory.lsadump":          "memory",
    "memory.timeline":          "memory",

    # ── Browser Domain (routes to endpoint) ───────────────────────────────────
    "browser_history":      "endpoint",
    "browser_download":     "endpoint",
    "browser_cookie":       "endpoint",
    "browser_formhistory":  "endpoint",

    # ── Derived Artifact Domain (ArtifactExtractor Stage-2 outputs) ──────────
    "extracted_ioc":        "endpoint",
    "extracted_entity":     "endpoint",
    "text_record":          "endpoint",
}


def route_fcr(
    fcr: CorrelationRecord,
    artifacts_by_id: Dict[str, Artifact]
) -> List[str]:
    """
    Inspects fcr.artifact_ids, resolves each referenced Artifact from artifacts_by_id,
    and maps artifact types to producing analysis engine names.

    Returns a sorted, unique list of required engine names.
    Logs a warning for any unmatched artifact_type.
    Does not crash on empty artifact lists or unknown artifact types.
    """
    if not fcr or not getattr(fcr, "artifact_ids", None):
        return []

    target_engines: set[str] = set()

    for art_id in fcr.artifact_ids:
        artifact = artifacts_by_id.get(art_id)
        if artifact is None:
            logger.warning(
                "Router: Referenced artifact_id '%s' in FCR '%s' not found in artifacts_by_id store.",
                art_id, getattr(fcr, "correlation_id", "UNKNOWN")
            )
            continue

        art_type = artifact.artifact_type
        
        # Dynamic routing for derived extracted observables
        if art_type == "extracted_ioc":
            ioc_type = (artifact.raw_fields.get("ioc_type") or "").lower()
            if ioc_type in ("ipv4", "ipv6", "domain", "url"):
                target_engines.add("network")
            else:
                target_engines.add("endpoint")
        elif art_type == "extracted_entity":
            entity_type = (artifact.raw_fields.get("entity_type") or "").lower()
            if entity_type in ("command-line", "indicator"):
                target_engines.add("log")
            else:
                target_engines.add("endpoint")
        else:
            engine = ARTIFACT_TYPE_TO_ENGINE.get(art_type)

            if engine is not None:
                target_engines.add(engine)
                # Special volatility3 memory routing for generic artifact types
                if getattr(artifact, "source_tool", None) == "volatility3" and art_type in ("network_connection", "process_event", "dll_load"):
                    target_engines.add("memory")
            else:
                logger.warning(
                    "Router: Unmatched artifact_type '%s' for artifact_id '%s' in FCR '%s'. Excluding from routing.",
                    art_type, art_id, getattr(fcr, "correlation_id", "UNKNOWN")
                )

    return sorted(list(target_engines))
