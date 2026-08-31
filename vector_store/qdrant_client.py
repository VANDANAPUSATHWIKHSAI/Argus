# Qdrant vector store client
# Used by: Agent 5b (RAG against Validated Case Repository)
# Qdrant Cloud free tier for dev; self-hosted for production
from qdrant_client import QdrantClient as _QdrantClient

class VectorStore:
    def __init__(self, url: str, api_key: str = None):
        self.client = _QdrantClient(url=url, api_key=api_key)

    def upsert(self, collection: str, vectors: list, payloads: list): ...
    def search(self, collection: str, query_vector: list, top_k: int = 5) -> list: ...
