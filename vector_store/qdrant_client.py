# Qdrant vector store client
# Used by: Agent 5b (RAG against Validated Case Repository)
# Qdrant Cloud or authenticated self-hosted cluster for production
from typing import Optional, List, Dict, Any
import logging

from config.settings import settings

logger = logging.getLogger(__name__)

try:
    from qdrant_client import QdrantClient as _QdrantClient, models
    QDRANT_INSTALLED = True
except ImportError:
    QDRANT_INSTALLED = False
    _QdrantClient = None
    models = None


class VectorStore:
    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_tls: Optional[bool] = None,
        tls_cert_path: Optional[str] = None,
        timeout: float = 10.0,
    ):
        if not QDRANT_INSTALLED:
            self.client = None
            return

        target_url = url or getattr(settings, "qdrant_url", "http://localhost:6333")
        target_key = api_key or getattr(settings, "qdrant_api_key", None)
        target_verify = getattr(settings, "qdrant_verify_tls", True) if verify_tls is None else verify_tls
        cert_path = tls_cert_path or getattr(settings, "qdrant_tls_cert_path", None)

        if target_url == ":memory:":
            self.client = _QdrantClient(":memory:")
            return

        is_prod = getattr(settings, "app_env", "development") == "production"
        is_remote = not ("localhost" in target_url or "127.0.0.1" in target_url)

        # Enforce HTTPS for remote connections in production
        if is_prod and is_remote and target_url.startswith("http://"):
            logger.warning("Upgrading plaintext Qdrant URL to https:// for production security: %s", target_url)
            target_url = target_url.replace("http://", "https://", 1)

        https_mode = target_url.startswith("https://")

        client_kwargs: Dict[str, Any] = {
            "url": target_url,
            "api_key": target_key,
            "timeout": timeout,
            "https": https_mode,
        }

        # If custom TLS certificate or verification settings provided
        if https_mode:
            if not target_verify:
                client_kwargs["verify"] = False
            elif cert_path:
                client_kwargs["verify"] = cert_path

        try:
            self.client = _QdrantClient(**client_kwargs)
            logger.debug("Initialized Qdrant client with url=%s, https=%s", target_url, https_mode)
        except Exception as e:
            logger.warning("Could not connect to Qdrant at %s: %s. Falling back to in-memory.", target_url, e)
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
