"""
Embedding Loader Module
=======================
Loads embedding models for similarity matching (Agent 5a / 5b / Qdrant RAG).
"""

from typing import List
from sentence_transformers import SentenceTransformer
from config.settings import settings


class EmbeddingLoader:
    """
    Embedding model loader with explicit fallback provenance and production fail-closed support.
    """

    def __init__(self):
        self.target_model_name = settings.embedding_model
        self.model_name = self.target_model_name
        self.is_fallback = False
        self.fallback_reason = None
        self._model = None

        is_prod = getattr(settings, "app_env", "development") == "production"

        # Check if requested model requires fallback in lightweight/dev environments
        if "Qwen" in self.target_model_name:
            if is_prod:
                # In production, must load the designated target embedding model
                self.model_name = self.target_model_name
            else:
                # In dev/test: explicit MiniLM fallback with documented provenance
                self.model_name = "sentence-transformers/all-MiniLM-L6-v2"
                self.is_fallback = True
                self.fallback_reason = (
                    f"Designated target '{self.target_model_name}' substituted with "
                    f"'{self.model_name}' for local execution."
                )

    def load(self) -> SentenceTransformer:
        """Loads the embedding model or fails closed in production."""
        if not self._model:
            is_prod = getattr(settings, "app_env", "development") == "production"
            try:
                print(f"[Embeddings] Loading {self.model_name}...")
                self._model = SentenceTransformer(self.model_name)
            except Exception as e:
                if is_prod:
                    raise RuntimeError(
                        f"CRITICAL: Failed to load designated embedding model '{self.model_name}' in production: {e}"
                    ) from e
                # Fallback to MiniLM in dev if target model load fails
                print(f"[Embeddings] Target model '{self.model_name}' load failed: {e}. Falling back to MiniLM.")
                self.model_name = "sentence-transformers/all-MiniLM-L6-v2"
                self.is_fallback = True
                self.fallback_reason = f"Load failure for target model: {e}"
                self._model = SentenceTransformer(self.model_name)
        return self._model

    def encode(self, texts: List[str]) -> List[List[float]]:
        """Encodes texts into list of vector embeddings."""
        model = self.load()
        embeddings = model.encode(texts, show_progress_bar=False)
        return embeddings.tolist()
