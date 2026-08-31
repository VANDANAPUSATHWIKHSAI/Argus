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
    Embedding model loader.
    """

    def __init__(self):
        # Dev fallback: all-MiniLM-L6-v2 (highly optimized and fast)
        self.model_name = settings.embedding_model
        if "Qwen" in self.model_name:
            # Fallback to MiniLM for easy local execution without GPU
            self.model_name = "sentence-transformers/all-MiniLM-L6-v2"
        self._model = None

    def load(self) -> SentenceTransformer:
        """Loads the embedding model."""
        if not self._model:
            print(f"[Embeddings] Loading {self.model_name}...")
            self._model = SentenceTransformer(self.model_name)
        return self._model

    def encode(self, texts: List[str]) -> List[List[float]]:
        """Encodes texts into list of vector embeddings."""
        model = self.load()
        embeddings = model.encode(texts, show_progress_bar=False)
        return embeddings.tolist()
