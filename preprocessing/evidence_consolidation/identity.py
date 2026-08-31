"""
Deterministic Evidence Identity Resolution
==========================================
Implements type-specific deterministic identity rules per forensic artifact type.
Enforces FALSE MERGE > FALSE SPLIT ("When in doubt, DO NOT MERGE").

Separates:
- EVENT_IDENTITY: Specific forensic event (e.g. process launch, network connection, log entry).
- IOC_ENTITY_IDENTITY: Shared atomic IOC (e.g. SHA-256 hash, URL, Domain, IP address).

Enforces strict case_id and tenant_id isolation in all identity keys.
"""

from __future__ import annotations

import re
import hashlib
from typing import Optional, Tuple
from urllib.parse import urlparse

from preprocessing.schemas import Artifact, NormalizedFields


def resolve_identity(
    artifact: Artifact,
    tenant_id: Optional[str] = None
) -> Tuple[str, str, str, str, str, str]:
    """
    Resolve deterministic identity tuple for a given Artifact.

    Args:
        artifact: Valid Artifact object.
        tenant_id: Tenant identifier for isolation (defaults to artifact.raw_fields or "default_tenant").

    Returns:
        Tuple of (canonical_type, canonical_value, identity_category, identity_method, identity_key, unified_artifact_id)
    """
    t_id = (tenant_id or artifact.raw_fields.get("tenant_id") or "default_tenant").strip()
    c_id = artifact.case_id.strip()
    nf: NormalizedFields = artifact.normalized_fields or NormalizedFields()
    atype = (artifact.artifact_type or "").strip().lower()

    host = (nf.host or "").strip().lower()

    # Rule 1: File Artifacts (Hash vs Event)
    if nf.hash:
        clean_hash = nf.hash.strip().lower()
        can_type = "file"
        can_val = clean_hash
        cat = "IOC_ENTITY_IDENTITY"
        method = "SHA256_EXACT_MATCH"
    elif nf.file_path and "file" in atype:
        clean_path = nf.file_path.strip().lower()
        can_type = "file_event"
        can_val = f"{host}:{clean_path}" if host else clean_path
        cat = "EVENT_IDENTITY"
        method = "FILE_PATH_EVENT_CONTEXT"

    # Rule 2: URL Artifacts
    elif nf.url:
        clean_url = _normalize_url(nf.url)
        can_type = "url"
        can_val = clean_url
        cat = "IOC_ENTITY_IDENTITY"
        method = "CANONICAL_URL"

    # Rule 3: Domain Artifacts
    elif nf.domain:
        clean_dom = nf.domain.strip().lower()
        can_type = "domain"
        can_val = clean_dom
        cat = "IOC_ENTITY_IDENTITY"
        method = "CANONICAL_DOMAIN"

    # Rule 4: Process Events (PID alone is NEVER sufficient!)
    elif "process" in atype or (nf.process_id is not None and nf.process_name):
        pid = nf.process_id if nf.process_id is not None else "nopid"
        pname = (nf.process_name or "nopname").strip().lower()
        cmd = (nf.process_command_line or "").strip()
        # Process identity MUST include host + pid + process_name to prevent false cross-host/time merges
        can_type = "process_event"
        can_val = f"{host}:{pid}:{pname}:{cmd}"
        cat = "EVENT_IDENTITY"
        method = "PROCESS_HOST_PID_TIME_CONTEXT"

    # Rule 5: Standalone IP IOC vs Network Connection Event
    elif atype in ("ip", "ip_address", "ioc") and (nf.dst_ip or nf.src_ip):
        ip_val = (nf.dst_ip or nf.src_ip or "").strip()
        can_type = "ip"
        can_val = ip_val
        cat = "IOC_ENTITY_IDENTITY"
        method = "CANONICAL_IP"

    elif nf.src_ip or nf.dst_ip or "network" in atype:
        src = (nf.src_ip or "*").strip()
        dst = (nf.dst_ip or "*").strip()
        sport = nf.src_port if nf.src_port is not None else "*"
        dport = nf.dst_port if nf.dst_port is not None else "*"
        can_type = "network_event"
        can_val = f"{host}:{src}:{sport}:{dst}:{dport}"
        cat = "EVENT_IDENTITY"
        method = "NETWORK_EVENT_CONTEXT"

    # Rule 6: Registry Keys
    elif nf.registry_key:
        clean_reg = _normalize_registry_key(nf.registry_key)
        can_type = "registry_key"
        can_val = f"{host}:{clean_reg}" if host else clean_reg
        cat = "EVENT_IDENTITY"
        method = "CANONICAL_REGISTRY_PATH"

    # Rule 7: Emails
    elif nf.sender or nf.subject or "email" in atype:
        msg_id = artifact.raw_fields.get("message_id")
        if msg_id:
            can_type = "email"
            can_val = str(msg_id).strip()
            cat = "IOC_ENTITY_IDENTITY"
            method = "EMAIL_MESSAGE_ID_HEADER"
        else:
            snd = (nf.sender or "").strip().lower()
            sbj = (nf.subject or "").strip()
            can_type = "email_event"
            can_val = f"{snd}:{sbj}"
            cat = "EVENT_IDENTITY"
            method = "EMAIL_HEADER_EVENT_CONTEXT"

    # Rule 8: USB Devices
    elif "usb" in atype or artifact.raw_fields.get("serial_number"):
        serial = str(artifact.raw_fields.get("serial_number") or "").strip()
        vid = str(artifact.raw_fields.get("vendor_id") or "").strip()
        pid = str(artifact.raw_fields.get("product_id") or "").strip()
        if serial:
            can_type = "usb_device"
            can_val = f"{vid}:{pid}:{serial}"
            cat = "IOC_ENTITY_IDENTITY"
            method = "USB_DEVICE_SERIAL"
        else:
            can_type = "usb_event"
            can_val = f"{host}:{artifact.artifact_id}"
            cat = "EVENT_IDENTITY"
            method = "USB_EVENT_CONTEXT"

    # Default Conservative Fallback: Keep separate!
    else:
        can_type = atype or "generic_artifact"
        can_val = f"{c_id}:{artifact.artifact_id}"
        cat = "EVENT_IDENTITY"
        method = "STRICT_ARTIFACT_FALLBACK"

    # Compute deterministic identity key incorporating tenant_id and case_id
    seed = f"{t_id}:{c_id}:{can_type}:{can_val}"
    id_key = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    num_val = int(id_key[:8], 16) % 1000000
    uai_id = f"UAI-{num_val:06d}"

    return can_type, can_val, cat, method, id_key, uai_id


def _normalize_url(url_str: str) -> str:
    """Normalize URL string safely while preserving query parameters."""
    url_clean = url_str.strip()
    try:
        parsed = urlparse(url_clean)
        scheme = (parsed.scheme or "http").lower()
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{netloc}{path}{query}"
    except Exception:
        return url_clean.lower()


def _normalize_registry_key(key_str: str) -> str:
    """Normalize registry key path (e.g. HKLM -> HKEY_LOCAL_MACHINE)."""
    k = key_str.strip()
    k_upper = k.upper()
    replacements = [
        ("HKLM\\", "HKEY_LOCAL_MACHINE\\"),
        ("HKCU\\", "HKEY_CURRENT_USER\\"),
        ("HKU\\", "HKEY_USERS\\"),
        ("HKCR\\", "HKEY_CLASSES_ROOT\\"),
    ]
    for short_form, full_form in replacements:
        if k_upper.startswith(short_form):
            return full_form + k[len(short_form):]
    return k
