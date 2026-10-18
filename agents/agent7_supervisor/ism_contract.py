"""
Agent 7 — Future Investigation State Machine (ISM) Integration Contract
========================================================================
STATUS: IMPLEMENTED (Aligned with ism/state_machine.py)

Defines the clean boundary contract for the future Investigation State Machine (ISM).
Agent 7 implements this contract to expose execution state, idempotency keys, and
error categories WITHOUT implementing cross-agent scheduling, global checkpointing,
or system-wide lifecycle transitions.
"""

from __future__ import annotations

from enum import Enum
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field


class ISMExecutionStatus(str, Enum):
    """Execution status emitted by Agent 7 to the future ISM controller."""
    PENDING     = "PENDING"
    RUNNING     = "RUNNING"
    COMPLETED   = "COMPLETED"
    FAILED      = "FAILED"
    WAITING_FOR_REVIEW = "WAITING_FOR_REVIEW"


class ISMErrorCategory(str, Enum):
    """Error categories for ISM failure analysis and retry decisions."""
    NONE                     = "NONE"
    TRANSIENT_NETWORK        = "TRANSIENT_NETWORK"       # Retryable (e.g. timeout)
    MODEL_UNAVAILABLE        = "MODEL_UNAVAILABLE"       # Retryable with backoff
    INPUT_VALIDATION_ERROR   = "INPUT_VALIDATION_ERROR"  # Non-retryable
    AUTHENTICATION_ERROR     = "AUTHENTICATION_ERROR"    # Non-retryable
    CROSS_TENANT_VIOLATION   = "CROSS_TENANT_VIOLATION"  # Security incident, non-retryable
    FATAL_INTERNAL_ERROR     = "FATAL_INTERNAL_ERROR"    # Non-retryable


class ISMAgent7ExecutionRecord(BaseModel):
    """
    Contract record emitted by Agent 7 for ingestion by the future ISM module.
    """
    # 1. Identifiers & Multi-Tenancy
    case_id: str = Field(description="Investigation case identifier")
    tenant_id: str = Field(default="default", description="Authoritative tenant isolation identifier")
    agent_id: str = Field(default="agent7_supervisor", description="Agent identifier")
    execution_id: str = Field(description="Unique Agent 7 run execution identifier, e.g. EXEC-A7-...")
    idempotency_key: str = Field(description="Deduplication key: sha256(case_id:tenant_id:input_version:evidence_count)")

    # 2. Schema Versions
    input_schema_version: str = Field(default="v2.0", description="Input contract schema version")
    output_schema_version: str = Field(default="v2.0", description="Output contract schema version")

    # 3. Execution Lifecycle Status & Timestamps
    status: ISMExecutionStatus = ISMExecutionStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # 4. Error Handling & Retryability
    error_category: ISMErrorCategory = ISMErrorCategory.NONE
    error_message: Optional[str] = None
    is_retryable: bool = False

    # 5. Result Reference & Audit Correlation
    audit_correlation_id: str = Field(description="Audit trail correlation identifier")
    result_reference: Optional[str] = Field(default=None, description="Pointer to structured report in DB or MinIO")
    review_level_required: Optional[str] = Field(default=None, description="ROUTINE or MANDATORY_SENIOR_DUAL")


def build_ism_idempotency_key(case_id: str, tenant_id: str, evidence_ids: List[str]) -> str:
    """Helper to generate deterministic idempotency key for ISM deduplication."""
    import hashlib
    raw = f"{case_id}:{tenant_id}:{','.join(sorted(evidence_ids))}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
