# Qdrant vector store client
# Used by: Agent 5b (RAG against Validated Case Repository)
# Qdrant Cloud free tier for dev; self-hosted for production
from qdrant_client import QdrantClient as _QdrantClient
from qdrant_client.models import FieldCondition, Filter, MatchValue, PointStruct

class VectorStore:
    def __init__(self, url: str, api_key: str = None):
        self.client = _QdrantClient(url=url, api_key=api_key)

    def upsert(self, collection: str, vectors: list, payloads: list, ids: list | None = None):
        if len(vectors) != len(payloads):
            raise ValueError("vectors and payloads must have the same length")
        point_ids = ids or list(range(len(vectors)))
        if len(point_ids) != len(vectors):
            raise ValueError("ids must have the same length as vectors")
        points = [
            PointStruct(id=point_id, vector=vector, payload=payload)
            for point_id, vector, payload in zip(point_ids, vectors, payloads)
        ]
        return self.client.upsert(collection_name=collection, points=points)

    def search(
        self,
        collection: str,
        query_vector: list,
        top_k: int = 5,
        filters: dict | None = None,
    ) -> list:
        query_filter = None
        if filters:
            conditions = [
                FieldCondition(key=key, match=MatchValue(value=value))
                for key, value in filters.items()
            ]
            query_filter = Filter(must=conditions)
        return self.client.search(
            collection_name=collection,
            query_vector=query_vector,
            query_filter=query_filter,
            limit=top_k,
        )
