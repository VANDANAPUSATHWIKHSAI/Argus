"""
Preprocessing Layer — Shared Schema
====================================
Defines the single Artifact model that every parser in preprocessing/parsers/
returns a list of, regardless of the originating forensic tool.

Pattern mirrors infrastructure/schemas.py — one shared contract, no per-tool
shapes scattered across the codebase.

Tool → source_tool string conventions (keep consistent across parsers):
  "hayabusa"       — Windows Event Log (EVTX) parser
  "volatility3"    — Memory dump analysis
  "zeek"           — PCAP / network connection logs
  "suricata"       — IDS / EVE JSON alerts and flows
  "regripper"      — Windows Registry (and USB artefacts via registry)
  "hindsight"      — Browser history, cookies, downloads
  "python_email"   — .eml / .msg parsed via Python's built-in email library
  "tsk"            — File-system / disk image via The Sleuth Kit

artifact_type string conventions:
  "process_event"       — running/terminated process (Volatility pslist, Hayabusa)
  "network_connection"  — TCP/UDP connection (Zeek conn.log, Volatility netscan)
  "dns_query"           — DNS query + response (Zeek dns.log, Suricata dns)
  "http_request"        — HTTP transaction (Zeek http.log, Suricata http)
  "tls_session"         — TLS/SSL handshake info (Zeek ssl.log)
  "ids_alert"           — Suricata signature match (event_type=alert)
  "network_flow"        — Suricata flow summary (event_type=flow)
  "registry_key"        — Registry key/value record (RegRipper)
  "usb_device"          — USB connection artefact (RegRipper usbstor)
  "browser_history"     — Browser URL visit (Hindsight)
  "browser_download"    — File downloaded via browser (Hindsight)
  "browser_cookie"      — Cookie record (Hindsight)
  "email_header"        — Parsed email headers/body/attachments (python_email)
  "file_record"         — File-system entry / timeline row (TSK fls / mactime)
  "auth_event"          — Authentication / logon event (Hayabusa Security channel)
  "dll_load"            — DLL / module loaded into a process (Volatility dlllist)
  "file_transfer"       — File observed in network traffic (Zeek files.log)
  "evasion_indicator"   — Anti-forensic / timestomping indicator detected during
                          post-parse heuristic checks.  raw_fields["indicator"]
                          names the specific pattern; raw_fields["note"] explains
                          the finding.  Always includes a disclaimer that this is
                          a heuristic indicator, not a guarantee of tampering.
                          Possible indicator values:
                            audit_log_cleared                        (evtx_parser)
                            event_record_id_gap                      (evtx_parser)
                            timestamp_creation_after_modification    (registry_parser)
                            all_timestamps_identical                 (registry_parser)
                            all_process_create_times_identical       (memory_parser)
                            dll_load_time_before_process_create_time (memory_parser)
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field
import uuid


from datetime import datetime, timezone
from typing import Optional, Any
from pydantic import BaseModel, Field, model_validator
import uuid


class NormalizedFields(BaseModel):
    """
    Correlation-friendly subset of fields extracted from raw_fields across all 42 sources.

    Populate only fields meaningful for the given artifact_type — leave others as None.
    Supports property aliases for backwards compatibility (pid/process_id, ppid/parent_process_id,
    process/process_name, device_serial/usb_serial_number).
    """
    host:                  Optional[str] = None   # hostname / computer name / host_id
    user:                  Optional[str] = None   # account / username involved
    process_id:            Optional[int] = None   # process ID (pid)
    parent_process_id:     Optional[int] = None   # parent process ID (ppid)
    process_name:          Optional[str] = None   # process name / image path (process)
    process_command_line:  Optional[str] = None   # process command line string
    src_ip:                Optional[str] = None   # source IP address (IPv4 or IPv6)
    dst_ip:                Optional[str] = None   # destination IP address
    src_port:              Optional[int] = None   # source TCP/UDP port
    dst_port:              Optional[int] = None   # destination TCP/UDP port
    file_path:             Optional[str] = None   # full file path or registry key display path
    file_name:             Optional[str] = None   # basename of file
    hash:                  Optional[str] = None   # file or payload hash (SHA256, MD5, SHA1)
    domain:                Optional[str] = None   # DNS domain queried or email domain
    url:                   Optional[str] = None   # full URL (HTTP requests, browser history)
    registry_key:          Optional[str] = None   # Registry key path
    registry_value:        Optional[str] = None   # Registry value name
    registry_value_data:   Optional[str] = None   # Registry value data
    usb_serial_number:     Optional[str] = None   # USB device serial number (device_serial)
    rule_name:             Optional[str] = None   # detection rule / Sigma rule name
    severity:              Optional[str] = None   # alert severity level (informational, low, medium, high, critical)

    # Secondary / specialized artifact fields
    first_connected:       Optional[str] = None   # USB first connection timestamp
    last_connected:        Optional[str] = None   # USB last connection timestamp
    friendly_name:         Optional[str] = None   # USB friendly name / description
    sender:                Optional[str] = None   # Email sender (From)
    recipients:            Optional[str] = None   # Email recipients (To, CC, BCC, comma-separated)
    subject:               Optional[str] = None   # Email subject
    mtime:                 Optional[str] = None   # Filesystem modified time
    atime:                 Optional[str] = None   # Filesystem accessed time
    ctime:                 Optional[str] = None   # Filesystem metadata change time
    deleted:               Optional[bool] = None  # Filesystem deleted flag
    private_ip:            Optional[bool] = None  # Tag private/reserved range IP address
    ip_scope:              Optional[str] = None   # "private", "reserved", "public" scope

    # ── Property Aliases for Backwards Compatibility ──────────────────────
    @property
    def pid(self) -> Optional[int]:
        return self.process_id

    @pid.setter
    def pid(self, val: Optional[int]) -> None:
        self.process_id = val

    @property
    def ppid(self) -> Optional[int]:
        return self.parent_process_id

    @ppid.setter
    def ppid(self, val: Optional[int]) -> None:
        self.parent_process_id = val

    @property
    def process(self) -> Optional[str]:
        return self.process_name

    @process.setter
    def process(self, val: Optional[str]) -> None:
        self.process_name = val

    @property
    def device_serial(self) -> Optional[str]:
        return self.usb_serial_number

    @device_serial.setter
    def device_serial(self, val: Optional[str]) -> None:
        self.usb_serial_number = val

    @model_validator(mode="before")
    @classmethod
    def _sync_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Sync pid / process_id
            if "pid" in data and "process_id" not in data:
                data["process_id"] = data.pop("pid")
            if "ppid" in data and "parent_process_id" not in data:
                data["parent_process_id"] = data.pop("ppid")
            if "process" in data and "process_name" not in data:
                data["process_name"] = data.pop("process")
            if "device_serial" in data and "usb_serial_number" not in data:
                data["usb_serial_number"] = data.pop("device_serial")

            # Coerce numeric fields (process_id, parent_process_id, src_port, dst_port) to int or None
            for key in ("process_id", "parent_process_id", "src_port", "dst_port"):
                if key in data and data[key] is not None:
                    try:
                        v_str = str(data[key]).strip()
                        data[key] = int(float(v_str)) if v_str else None
                    except (ValueError, TypeError, OverflowError):
                        data[key] = None
        return data


class Artifact(BaseModel):
    """
    One atomic forensic finding produced by a parser.

    Every parser in preprocessing/parsers/ returns list[Artifact].
    Satisfies the Authoritative ARGUS Layer 2 Normalized Evidence contract.
    """
    artifact_id:       str                = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id:           str                = ""                      # FK → CaseSession.case_id
    evidence_id:       str                                          # FK → infrastructure.Evidence.evidence_id
    source_tool:       str                                          # e.g. "hayabusa", "volatility3", "zeek"
    artifact_type:     str                                          # e.g. "process_event", "dns_query"
    host_id:           Optional[str]      = None                    # Host identifier / computer name
    timestamp:         Optional[datetime] = None                    # Nullable event timestamp
    timestamp_type:    Optional[str]      = "event"                 # Timestamp semantics: created, modified, accessed, event, etc.
    event_summary:     Optional[str]      = None                    # Deterministic human-readable event summary
    raw_fields:        dict               = Field(default_factory=dict) # Tool's native output, preserved intact
    normalized_fields: NormalizedFields   = Field(default_factory=NormalizedFields)
    confidence:        Optional[float]    = 1.0                     # Deterministic parser confidence score
    ingested_at:       datetime           = Field(default_factory=lambda: datetime.now(timezone.utc))
    parser_version:    str                = "1.0.0"                 # Version of parser tool/wrapper
    schema_version:    str                = "2.0.0"                 # Version of normalized schema contract

    # Backwards compatibility alias for confidence_score
    @property
    def confidence_score(self) -> Optional[float]:
        return self.confidence

    @confidence_score.setter
    def confidence_score(self, val: Optional[float]) -> None:
        self.confidence = val

    @model_validator(mode="before")
    @classmethod
    def _sync_confidence_and_host(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "confidence_score" in data and "confidence" not in data:
                data["confidence"] = data.pop("confidence_score")
            # Sync host_id from host if not provided
            if "host_id" not in data or data["host_id"] is None:
                norm = data.get("normalized_fields")
                if isinstance(norm, dict) and norm.get("host"):
                    data["host_id"] = norm.get("host")
                elif isinstance(norm, NormalizedFields) and norm.host:
                    data["host_id"] = norm.host
        return data


class ExtractedEntity(BaseModel):
    """
    One atomic entity extracted from a forensic artifact's text fields.

    Produced by ArtifactExtractor using deterministic regex (google-re2) and/or
    GLiNER zero-shot NER.  Every entity carries full provenance: which field it
    came from, its character offsets, how it was found, and whether the extraction
    ran in degraded (regex-only) mode.
    """
    entity_id:          str            = Field(default_factory=lambda: str(uuid.uuid4()))
    artifact_id:        str            # FK → Artifact.artifact_id
    evidence_id:        str            # FK → infrastructure.Evidence.evidence_id
    entity_type:        str            # e.g. "ipv4", "sha256", "malware", "threat-actor"
    value:              str            # the extracted text span
    source_field:       str            # which field the entity was found in
    char_start:         int            # character offset (inclusive) in source_field text
    char_end:           int            # character offset (exclusive) in source_field text
    extraction_method:  str            # "regex:<pattern_name>", "gliner", or "regex:<name>+gliner"
    confidence:         float          # 1.0 for regex, model score for GLiNER
    degraded_mode:      bool  = False  # True when GLiNER was unavailable and regex-only ran
    degraded_reason:    Optional[str] = None  # Explanation of degraded mode
    model_revision:     Optional[str] = None  # exact HF commit hash for reproducibility
    extractor_version:  Optional[str] = "1.0.0"  # Version of the extraction engine
    model_name:         Optional[str] = None  # Pinned Hugging Face model ID
    model_confidence:   Optional[float] = None # raw model output score
    extraction_confidence: Optional[float] = None # confidence of extraction process
    forensic_relevance: Optional[float] = None # relevance of entity to target threat investigation
    validated:          bool = False # whether entity has been validated downstream
    predicted_type:     Optional[str] = None # original model type prediction
    normalized_type:    Optional[str] = None # type prediction after normalization and post-processing
    validation_status:  Optional[str] = "candidate" # "candidate", "suppressed", or "downgraded"
    suppression_reason: Optional[str] = None # details on why entity was suppressed or downgraded
    
    # Forensic Provenance Extension Fields
    case_id:            Optional[str] = ""     # FK -> CaseSession.case_id
    host_id:            Optional[str] = None   # Host identifier
    timestamp:          Optional[datetime] = None # Optional event timestamp
    byte_offset:        Optional[int] = None   # byte offset in original stream
    start_offset:       Optional[int] = None   # start offset
    end_offset:         Optional[int] = None   # end offset
    byte_length:        Optional[int] = None   # length of entity in bytes
    line_number:        Optional[int] = None   # line number if available from parser
    source_tool:        Optional[str] = None   # source tool
    original_value:     Optional[str] = None   # raw un-normalized match
    raw_fields:         dict = Field(default_factory=dict)
    normalized_fields:  NormalizedFields = Field(default_factory=NormalizedFields)

    @property
    def artifact_type(self) -> str:
        return "extracted_entity"


