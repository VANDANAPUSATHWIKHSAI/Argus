"""
Provenance Graph Lineage Implementation
========================================
Cross-cutting lineage graph tracking node and edge relationships across
the forensic lifecycle:
Original Evidence -> Artifact -> UnifiedArtifact -> FCR -> Evidence Consolidation -> FIR

Relationship Types:
- DERIVED_FROM
- REPRESENTS
- DUPLICATE_OF
- GROUPED_WITH
- SUPPORTED_BY
- CORRELATED_BY
- CONSOLIDATED_FROM
"""

from __future__ import annotations

import threading
import logging
from typing import Optional, Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


VALID_RELATIONSHIP_TYPES = {
    "DERIVED_FROM",
    "REPRESENTS",
    "DUPLICATE_OF",
    "GROUPED_WITH",
    "SUPPORTED_BY",
    "CORRELATED_BY",
    "CONSOLIDATED_FROM",
}


class ProvenanceNode:
    def __init__(self, node_id: str, node_type: str, metadata: Optional[dict[str, Any]] = None):
        self.node_id = node_id
        self.node_type = node_type
        self.metadata = metadata or {}
        self.created_at = datetime.now(timezone.utc)


class ProvenanceEdge:
    def __init__(
        self,
        source_id: str,
        target_id: str,
        relationship_type: str,
        case_id: str,
        tenant_id: str,
        reason: str = ""
    ):
        if relationship_type not in VALID_RELATIONSHIP_TYPES:
            raise ValueError(f"Invalid relationship_type '{relationship_type}'. Must be one of {VALID_RELATIONSHIP_TYPES}")

        self.source_id = source_id
        self.target_id = target_id
        self.relationship_type = relationship_type
        self.case_id = case_id
        self.tenant_id = tenant_id
        self.reason = reason
        self.timestamp = datetime.now(timezone.utc)


class ProvenanceGraph:
    """
    In-memory cross-cutting Provenance Graph.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._nodes: dict[str, ProvenanceNode] = {}
        self._edges: list[ProvenanceEdge] = []
        self._outgoing: dict[str, list[ProvenanceEdge]] = {}
        self._incoming: dict[str, list[ProvenanceEdge]] = {}

    def add_node(self, node_id: str, node_type: str, metadata: Optional[dict[str, Any]] = None) -> ProvenanceNode:
        """Register a node in the lineage graph."""
        with self._lock:
            if node_id not in self._nodes:
                node = ProvenanceNode(node_id, node_type, metadata)
                self._nodes[node_id] = node
                return node
            return self._nodes[node_id]

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relationship_type: str,
        case_id: str,
        tenant_id: str,
        reason: str = ""
    ) -> ProvenanceEdge:
        """Register a directed lineage edge from source_id to target_id."""
        with self._lock:
            edge = ProvenanceEdge(
                source_id=source_id,
                target_id=target_id,
                relationship_type=relationship_type,
                case_id=case_id,
                tenant_id=tenant_id,
                reason=reason
            )
            self._edges.append(edge)
            self._outgoing.setdefault(source_id, []).append(edge)
            self._incoming.setdefault(target_id, []).append(edge)
            return edge

    def get_upstream(self, node_id: str) -> list[dict[str, Any]]:
        """Retrieve upstream lineage steps (nodes that point to target node_id)."""
        with self._lock:
            edges = self._incoming.get(node_id, [])
            return [
                {
                    "source_id": e.source_id,
                    "relationship_type": e.relationship_type,
                    "case_id": e.case_id,
                    "tenant_id": e.tenant_id,
                    "reason": e.reason,
                    "timestamp": e.timestamp.isoformat()
                }
                for e in edges
            ]

    def get_downstream(self, node_id: str) -> list[dict[str, Any]]:
        """Retrieve downstream lineage steps (nodes that target node_id points to)."""
        with self._lock:
            edges = self._outgoing.get(node_id, [])
            return [
                {
                    "target_id": e.target_id,
                    "relationship_type": e.relationship_type,
                    "case_id": e.case_id,
                    "tenant_id": e.tenant_id,
                    "reason": e.reason,
                    "timestamp": e.timestamp.isoformat()
                }
                for e in edges
            ]

    def get_lineage(self, node_id: str) -> dict[str, Any]:
        """Get full upstream and downstream lineage map for a given node_id."""
        with self._lock:
            node = self._nodes.get(node_id)
            return {
                "node_id": node_id,
                "node_type": node.node_type if node else "UNKNOWN",
                "metadata": node.metadata if node else {},
                "upstream": self.get_upstream(node_id),
                "downstream": self.get_downstream(node_id)
            }
