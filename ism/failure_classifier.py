"""
ISM Failure Classification Engine
=================================
Classifies failures across all forensic pipeline stages:
  - Infrastructure crashes (PostgreSQL, Redis, MinIO, Neo4j, Qdrant)
  - Parser errors (malformed file, syntax error, format unroutable)
  - AI Agent failures (LLM connection failure, timeout, context limit, JSON parse error)
  - Security violations (tenant mismatch, prompt injection attempt, path traversal)
  - Transient timeouts (network timeout, rate limit)
  - Validation errors (missing ID, bad schema)

Provides deterministic classification and retryability decisions for the ISM RetryHandler.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict, Any

logger = logging.getLogger("ArgusISM.FailureClassifier")


class FailureType(str, Enum):
    INFRA_CRASH = "infra_crash"
    PARSER_ERROR = "parser_error"
    AI_AGENT_FAILURE = "ai_agent_failure"
    TIMEOUT = "timeout"
    SECURITY_VIOLATION = "security_violation"
    VALIDATION_ERROR = "validation_error"
    UNKNOWN = "unknown"


@dataclass
class FailureClassificationResult:
    failure_type: FailureType
    is_retryable: bool
    recommended_backoff_seconds: float
    description: str
    error_class: str


class FailureClassifier:
    """
    Evaluates exceptions occurring during forensic pipeline and agent execution.
    Determines failure category, retryability, and backoff policy.
    """

    # Retryable transient network / connection error patterns
    TRANSIENT_PATTERNS = [
        "connection refused",
        "connection reset",
        "connection timed out",
        "timed out",
        "timeout",
        "temporary failure",
        "too many requests",
        "rate limit",
        "server disconnected",
        "broken pipe",
        "503 service unavailable",
        "502 bad gateway",
        "504 gateway timeout",
        "deadlock detected",
    ]

    # Non-retryable fatal patterns
    FATAL_PATTERNS = [
        "immutability violation",
        "cross-tenant",
        "tenant access denied",
        "null-byte injection",
        "unsafe path traversal",
        "syntaxerror",
        "attributeerror",
        "keyerror",
        "typeerror",
        "filenotfounderror",
        "permission denied",
        "authentication failed",
    ]

    def classify_detailed(self, error: Exception) -> FailureClassificationResult:
        """
        Performs in-depth inspection of error type, hierarchy, and message text.
        """
        err_cls = error.__class__.__name__
        err_msg = str(error).lower()
        err_module = getattr(error.__class__, "__module__", "")

        # 1. Security & Isolation Violations (Strictly Non-Retryable)
        if any(pat in err_msg for pat in ["tenant access denied", "cross-tenant", "immutability violation", "null-byte", "path traversal"]):
            return FailureClassificationResult(
                failure_type=FailureType.SECURITY_VIOLATION,
                is_retryable=False,
                recommended_backoff_seconds=0.0,
                description=f"Security/Integrity violation: {error}",
                error_class=err_cls,
            )

        # 2. Timeouts (Retryable)
        if isinstance(error, TimeoutError) or "timeout" in err_cls.lower() or "timed out" in err_msg:
            return FailureClassificationResult(
                failure_type=FailureType.TIMEOUT,
                is_retryable=True,
                recommended_backoff_seconds=2.0,
                description=f"Operation timed out: {error}",
                error_class=err_cls,
            )

        # 3. Infrastructure Crashes (PostgreSQL, Redis, MinIO, Neo4j, Qdrant)
        is_infra = False
        if any(db in err_module for db in ["psycopg2", "redis", "minio", "neo4j", "qdrant_client"]):
            is_infra = True
        elif any(db_err in err_cls for db_err in ["OperationalError", "ConnectionError", "DatabaseError", "ServiceUnavailable"]):
            is_infra = True

        if is_infra:
            is_transient = any(pat in err_msg for pat in self.TRANSIENT_PATTERNS) or "closed" in err_msg
            # Auth errors are not transient
            if "password authentication failed" in err_msg or "access denied" in err_msg:
                is_transient = False

            return FailureClassificationResult(
                failure_type=FailureType.INFRA_CRASH,
                is_retryable=is_transient,
                recommended_backoff_seconds=3.0 if is_transient else 0.0,
                description=f"Infrastructure service failure ({err_cls}): {error}",
                error_class=err_cls,
            )

        # 4. Parser & Extraction Errors
        if any(p_term in err_cls.lower() or p_term in err_module or p_term in err_msg for p_term in ["parser", "evtx", "pcap", "hayabusa", "scapy", "zip"]):
            return FailureClassificationResult(
                failure_type=FailureType.PARSER_ERROR,
                is_retryable=False,
                recommended_backoff_seconds=0.0,
                description=f"Forensic parsing failure: {error}",
                error_class=err_cls,
            )

        # 5. AI Agent & LLM Failures
        if any(ai_term in err_msg or ai_term in err_module for ai_term in ["ollama", "qwen", "deberta", "huggingface", "model", "llm", "synthesis", "verification"]):
            is_transient = any(pat in err_msg for pat in self.TRANSIENT_PATTERNS) or "unavailable" in err_msg
            return FailureClassificationResult(
                failure_type=FailureType.AI_AGENT_FAILURE,
                is_retryable=is_transient,
                recommended_backoff_seconds=5.0 if is_transient else 0.0,
                description=f"AI Agent / Model failure: {error}",
                error_class=err_cls,
            )

        # 6. Input Validation Errors
        if isinstance(error, (ValueError, KeyError)) or "validation" in err_cls.lower():
            return FailureClassificationResult(
                failure_type=FailureType.VALIDATION_ERROR,
                is_retryable=False,
                recommended_backoff_seconds=0.0,
                description=f"Validation error: {error}",
                error_class=err_cls,
            )

        # 7. Generic Fallback
        is_transient = any(pat in err_msg for pat in self.TRANSIENT_PATTERNS)
        return FailureClassificationResult(
            failure_type=FailureType.UNKNOWN,
            is_retryable=is_transient,
            recommended_backoff_seconds=2.0 if is_transient else 0.0,
            description=f"Unclassified error ({err_cls}): {error}",
            error_class=err_cls,
        )

    def classify(self, error: Exception) -> str:
        """
        Public string classification method for backward compatibility.
        """
        res = self.classify_detailed(error)
        return res.failure_type.value
