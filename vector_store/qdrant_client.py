# Qdrant vector store client
# Used by: Agent 5b (RAG against Validated Case Repository)
# Qdrant Cloud free tier for dev; self-hosted for production
from typing import Optional, List, Dict, Any
import logging

logger = logging.getLogger(__name__)

try:
    from qdrant_client import QdrantClient as _QdrantClient, models
    QDRANT_INSTALLED = True
except ImportError:
    QDRANT_INSTALLED = False
    _QdrantClient = None
    models = None


class VectorStore:
    def __init__(self, url: str = "http://localhost:6333", api_key: Optional[str] = None):
        if not QDRANT_INSTALLED:
            self.client = None
            return

        if url == ":memory:":
            self.client = _QdrantClient(":memory:")
        else:
            try:
                self.client = _QdrantClient(url=url, api_key=api_key)
            except Exception as e:
                logger.warning(f"Could not connect to Qdrant at {url}: {e}. Falling back to in-memory.")
                self.client = _QdrantClient(":memory:")

    def upsert(self, collection: str, points: list):
        if self.client:
            return self.client.upsert(collection_name=collection, points=points)

    def search(self, collection: str, query_vector: list, top_k: int = 5) -> list:
        if not self.client:
            return []
        if hasattr(self.client, "query_points"):
            res = self.client.query_points(collection_name=collection, query=query_vector, limit=top_k)
            return res.points if res else []
        elif hasattr(self.client, "search"):
            return self.client.search(collection_name=collection, query_vector=query_vector, limit=top_k)
        return []
