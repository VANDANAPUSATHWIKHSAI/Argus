# ──────────────────────────────────────────────────────────────
# Redis Client — Workflow State, Queues, Checkpoints
# ──────────────────────────────────────────────────────────────
import logging
from typing import Optional, Any
from config.settings import settings

logger = logging.getLogger(__name__)


class RedisClient:
    """
    Redis client interface for workflow state management, task queuing,
    and execution checkpoints.
    Does not interfere with forensic reasoning logic.
    """

    def __init__(self):
        self._client: Optional[Any] = None

    def connect(self):
        """Lazy initialization of redis client connection."""
        if self._client is None:
            try:
                import redis
                self._client = redis.Redis.from_url(
                    settings.redis_url,
                    decode_responses=True,
                    socket_timeout=5
                )
            except Exception as e:
                logger.warning(f"Redis client initialization deferred/failed: {e}")

    def get_client(self) -> Optional[Any]:
        if self._client is None:
            self.connect()
        return self._client

    def set_checkpoint(self, case_id: str, stage: str, data: str, ttl: int = 86400) -> bool:
        """Stores a workflow checkpoint for a case stage."""
        try:
            client = self.get_client()
            if client:
                key = f"checkpoint:{case_id}:{stage}"
                return bool(client.set(key, data, ex=ttl))
        except Exception as exc:
            logger.warning(f"Redis set_checkpoint failed: {exc}")
        return False

    def get_checkpoint(self, case_id: str, stage: str) -> Optional[str]:
        """Retrieves a workflow checkpoint for a case stage."""
        try:
            client = self.get_client()
            if client:
                key = f"checkpoint:{case_id}:{stage}"
                return client.get(key)
        except Exception as exc:
            logger.warning(f"Redis get_checkpoint failed: {exc}")
        return None


# Singleton instance
redis_client = RedisClient()
