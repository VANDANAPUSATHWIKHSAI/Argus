# Validated Case Repository
# Per-tenant vector index in Qdrant (NOT shared index with filter —
# filter-based isolation is 'one bug away' from cross-tenant leak).
# Periodically re-audited (MITRE mappings go stale).
# Feeds Agent 5b via RAG retrieval.
from typing import Optional, List, Dict, Any
from agents.agent5b_campaign_similarity.case_repository import ValidatedCaseRepository

__all__ = ["ValidatedCaseRepository"]
