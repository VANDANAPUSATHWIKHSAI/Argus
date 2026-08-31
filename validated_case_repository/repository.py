# Validated Case Repository
# Per-tenant vector index in Qdrant (NOT shared index with filter —
# filter-based isolation is 'one bug away' from cross-tenant leak).
# Periodically re-audited (MITRE mappings go stale).
# Feeds Agent 5b via RAG retrieval.
class ValidatedCaseRepository:
    def add_case(self, case_id: str, tenant_id: str, embedding: list, metadata: dict): ...
    def search_similar(self, query_embedding: list, tenant_id: str, top_k: int = 5) -> list: ...
