"""
ARGUS — Dynamic Case Evidence & Findings Profiler
===================================================
Analyzes the genuine evidence artifacts and multi-agent findings for any given case,
dynamically profiling its modalities (Network, Registry, Memory, Logs, Disk, Multimodal),
extracting observed telemetry (IPs, domains, registry keys, hashes, MITRE mappings),
and providing consistent, evidence-grounded contexts for both report generation and AI chat.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


def profile_case_evidence(raw_evidence: Optional[List[Any]] = None, raw_findings: Optional[List[Any]] = None) -> Dict[str, Any]:
    evidence = raw_evidence or []
    findings = raw_findings or []

    # 1. Normalize and extract evidence files
    ev_files: List[str] = []
    ev_hashes: Dict[str, str] = {}
    ev_exts: Set[str] = set()

    for e in evidence:
        fn = ""
        sha = ""
        if isinstance(e, dict):
            fn = str(e.get("filename") or e.get("name") or "").strip()
            sha = str(e.get("sha256") or e.get("hash") or "").strip()
        else:
            fn = str(getattr(e, "filename", None) or getattr(e, "name", "") or "").strip()
            sha = str(getattr(e, "sha256", None) or getattr(e, "hash", "") or "").strip()

        if fn:
            ev_files.append(fn)
            ext = Path(fn).suffix.lower()
            if ext:
                ev_exts.add(ext)
            if sha:
                ev_hashes[fn] = sha

    # 2. Normalize and extract findings
    finding_records: List[Dict[str, Any]] = []
    finding_facts: List[str] = []
    mitre_techniques: List[str] = []
    severity_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}

    for f in findings:
        fact = ""
        sev = "informational"
        mitre = ""
        fid = ""
        if isinstance(f, dict):
            fact = str(f.get("sanitized_fact") or f.get("fact") or "").strip()
            sev = str(f.get("severity") or "informational").lower().strip()
            mitre = str(f.get("mitre_mapping") or f.get("mitre") or "").strip()
            fid = str(f.get("finding_id") or f.get("id") or "")
        else:
            fact = str(getattr(f, "sanitized_fact", None) or getattr(f, "fact", "") or "").strip()
            sev = str(getattr(f, "severity", "informational") or "informational").lower().strip()
            mitre = str(getattr(f, "mitre_mapping", None) or getattr(f, "mitre", "") or "").strip()
            fid = str(getattr(f, "finding_id", None) or getattr(f, "id", "") or "")

        if fact:
            finding_facts.append(fact)
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["informational"] += 1

            if mitre and mitre != "None" and mitre not in mitre_techniques:
                mitre_techniques.append(mitre)

            finding_records.append({
                "id": fid,
                "fact": fact,
                "severity": sev,
                "mitre": mitre
            })

    # Combined text for regex extraction
    corpus = " ".join(finding_facts + ev_files)

    # 3. Extract IP addresses (distinguishing RFC1918 internal from external)
    all_ips = list(dict.fromkeys(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', corpus)))
    internal_ips = [
        ip for ip in all_ips
        if ip.startswith("192.168.") or ip.startswith("10.") or (ip.startswith("172.") and any(ip.startswith(f"172.{o}.") for o in range(16, 32)))
    ]
    external_ips = [
        ip for ip in all_ips
        if ip not in internal_ips and not ip.startswith("127.") and not ip.startswith("0.") and not ip.startswith("255.")
    ]

    # 4. Extract domain names
    raw_domains = list(dict.fromkeys(re.findall(r'\b[a-zA-Z0-9_\-\.]+\.(?:com|cfd|top|xyz|net|org|io|ru|cn|cc|info)\b', corpus, re.IGNORECASE)))
    clean_domains = [
        d for d in raw_domains
        if not d.lower().endswith(('.pki.goog', '.google.com', '.microsoft.com', '.local', '.lan', '.internal'))
    ]

    # 5. Extract Registry keys / values
    registry_keys = list(dict.fromkeys(re.findall(r'\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[a-zA-Z0-9_\\\-]+', corpus, re.IGNORECASE)))
    if any(k in corpus.lower() for k in ("mru", "mrulistex", "recentdocs")):
        registry_keys.append(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\MRUListEx")
    registry_keys = list(dict.fromkeys(registry_keys))

    # 6. Detect Evidence Modalities
    has_pcap = any(ext in ('.pcap', '.pcapng', '.cap') for ext in ev_exts) or any("pcap" in fn.lower() for fn in ev_files) or bool(external_ips or clean_domains)
    has_registry = (
        any(any(k in fn.upper() for k in ("SYSTEM", "NTUSER", "SOFTWARE", "SAM", "SECURITY", ".REG")) for fn in ev_files)
        or any(k in corpus.lower() for k in ("mru", "registry", "mrulistex", "recentdocs", "run key", "userassist"))
    )
    has_memory = (
        any(ext in ('.raw', '.dmp', '.vmem', '.mem') for ext in ev_exts)
        or any(k in corpus.lower() for k in ("volatility", "vad", "malfind", "hollow", "injected dll", "process dump", "lsass"))
    )
    has_evtx = (
        any(ext in ('.evtx', '.log') for ext in ev_exts)
        or any(k in corpus.lower() for k in ("sysmon", "event id", "eid 4624", "eid 4688", "security.evtx"))
    )
    has_disk = (
        any(ext in ('.dd', '.e01', '.vmdk', '.mft') for ext in ev_exts)
        or any(k in corpus.lower() for k in ("$mft", "usnjrnl", "prefetch", "shellbags", "lnk file"))
    )
    has_binary = any(ext in ('.exe', '.dll', '.bin', '.elf', '.ps1', '.bat') for ext in ev_exts)

    active_modalities: List[str] = []
    if has_registry: active_modalities.append("REGISTRY")
    if has_pcap: active_modalities.append("NETWORK")
    if has_memory: active_modalities.append("MEMORY")
    if has_evtx: active_modalities.append("LOGS")
    if has_disk: active_modalities.append("DISK")
    if has_binary: active_modalities.append("BINARY")

    if len(active_modalities) > 1:
        primary_category = "MULTIMODAL"
    elif active_modalities:
        primary_category = active_modalities[0]
    else:
        primary_category = "GENERIC"

    # 7. Descriptive Contexts
    victim_node = internal_ips[0] if internal_ips else ("Workstation Endpoint (Local Host)" if has_registry or has_memory or has_evtx else "Internal System")
    adversary_node = clean_domains[0] if clean_domains else (external_ips[0] if external_ips else "No External C2 Detected")

    if primary_category == "REGISTRY":
        summary_title = "Host Endpoint & Windows Registry Forensics"
    elif primary_category == "NETWORK":
        summary_title = "Network Traffic & Command-and-Control (C2) Analysis" if clean_domains or external_ips else "Network Packet Capture Forensics"
    elif primary_category == "MEMORY":
        summary_title = "Volatile Host Memory & Process Injection Analysis"
    elif primary_category == "LOGS":
        summary_title = "Security Event Log & Audit Telemetry Analysis"
    elif primary_category == "MULTIMODAL":
        summary_title = f"Multi-Source Unified Forensics ({' + '.join(active_modalities)})"
    else:
        summary_title = "Digital Forensic Evidence Triage"

    return {
        "category": primary_category,
        "modalities": active_modalities,
        "is_registry": has_registry,
        "is_pcap": has_pcap,
        "is_memory": has_memory,
        "is_evtx": has_evtx,
        "is_disk": has_disk,
        "is_binary": has_binary,
        "evidence_files": ev_files,
        "evidence_hashes": ev_hashes,
        "findings": finding_records,
        "finding_facts": finding_facts,
        "mitre_techniques": mitre_techniques,
        "severity_counts": severity_counts,
        "internal_ips": internal_ips,
        "external_ips": external_ips,
        "domains": clean_domains,
        "registry_keys": registry_keys,
        "victim_node": victim_node,
        "adversary_node": adversary_node,
        "summary_title": summary_title,
        "finding_count": len(finding_records),
        "evidence_count": len(ev_files),
    }

