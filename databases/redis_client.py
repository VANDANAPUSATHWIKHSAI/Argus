# ──────────────────────────────────────────────────────────────
# Redis Client — Workflow State, Queues, Checkpoints
# ──────────────────────────────────────────────────────────────
import logging
import time
from typing import Optional, Any
from config.settings import settings

logger = logging.getLogger(__name__)


class RedisClient:
    """
    Redis client interface for workflow state management, task queuing,
    and execution checkpoints.
    Features fast failover and circuit breaker to prevent blocking when Redis is offline.
    """

    def __init__(self):
        self._client: Optional[Any] = None
        self._circuit_broken_until: float = 0.0

    def connect(self):
        """Lazy initialization of redis client connection with short connect timeout."""
        if time.monotonic() < self._circuit_broken_until:
            return
        if self._client is None:
            try:
                import redis
                self._client = redis.Redis.from_url(
                    settings.redis_url,
                    decode_responses=True,
                    socket_connect_timeout=0.2,
                    socket_timeout=0.5
                )
                # Quick healthcheck ping
                self._client.ping()
            except Exception as e:
                logger.debug(f"Redis unavailable; activating circuit breaker for 30s: {e}")
                self._client = None
                self._circuit_broken_until = time.monotonic() + 30.0

    def get_client(self) -> Optional[Any]:
        if time.monotonic() < self._circuit_broken_until:
            return None
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
            self._client = None
            self._circuit_broken_until = time.monotonic() + 30.0
            logger.debug(f"Redis set_checkpoint failed: {exc}")
        return False

    def persist_checkpoint(self, case_id: str, stage: str) -> bool:
        """Removes expiration from an existing checkpoint key, making it persistent."""
        try:
            client = self.get_client()
            if client:
                key = f"checkpoint:{case_id}:{stage}"
                return bool(client.persist(key))
        except Exception as exc:
            self._client = None
            self._circuit_broken_until = time.monotonic() + 30.0
            logger.debug(f"Redis persist_checkpoint failed: {exc}")
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
            self._client = None
            self._circuit_broken_until = time.monotonic() + 30.0
            logger.debug(f"Failed to query Redis eviction policy: {exc}")
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
            self._client = None
            self._circuit_broken_until = time.monotonic() + 30.0
            logger.debug(f"Redis get_checkpoint failed: {exc}")
        return None


# Singleton instance
redis_client = RedisClient()
