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

    def set_checkpoint(
        self,
        case_id: str,
        stage: str,
        data: str,
        ttl: Optional[int] = 86400,
        persist: bool = False,
    ) -> bool:
        """Stores a workflow checkpoint for a case stage with safe persistence."""
        try:
            client = self.get_client()
            if client:
                key = f"checkpoint:{case_id}:{stage}"
                if persist or ttl is None:
                    return bool(client.set(key, data))
                return bool(client.set(key, data, ex=ttl))
        except Exception as exc:
            logger.warning(f"Redis set_checkpoint failed: {exc}")
        return False

    def persist_checkpoint(self, case_id: str, stage: str) -> bool:
        """Removes expiration from an existing checkpoint key, making it persistent."""
        try:
            client = self.get_client()
            if client:
                key = f"checkpoint:{case_id}:{stage}"
                return bool(client.persist(key))
        except Exception as exc:
            logger.warning(f"Redis persist_checkpoint failed: {exc}")
        return False

    def get_eviction_policy(self) -> dict[str, str]:
        """Queries Redis memory and persistence settings to verify checkpoint safety."""
        info = {}
        try:
            client = self.get_client()
            if client:
                cfg = client.config_get("maxmemory-policy")
                info["maxmemory_policy"] = cfg.get("maxmemory-policy", "unknown")
                save_cfg = client.config_get("save")
                info["rdb_save"] = save_cfg.get("save", "unknown")
        except Exception as exc:
            logger.warning(f"Failed to query Redis eviction policy: {exc}")
            info["error"] = str(exc)
        return info

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
