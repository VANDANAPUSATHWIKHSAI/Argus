"""
ARGUS Celery Task Queue Configuration
====================================
Configures Celery application using Redis as message broker and result backend.
Includes automatic availability detection and fallback helpers.
"""

import logging
from celery import Celery
from config.settings import settings

logger = logging.getLogger(__name__)

# Initialize Celery app
celery_app = Celery(
    "argus_celery",
    broker=getattr(settings, "redis_url", "redis://localhost:6379/0"),
    backend=getattr(settings, "redis_url", "redis://localhost:6379/0"),
    include=["tasks.forensic_tasks"]
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,             # 1 hour hard limit for heavy disk/memory dumps
    task_soft_time_limit=3300,        # 55 minute soft limit
    broker_connection_retry_on_startup=True,
    task_acks_late=True,              # Only ack task once completed so crashes retry
    worker_prefetch_multiplier=1,      # One heavy forensic job per worker process
)


_celery_available_cache = None
_celery_available_cache_time = 0.0

def is_celery_broker_available(timeout_sec: float = 0.5) -> bool:
    """
    Check if the Redis broker is reachable AND at least one Celery worker is actively running.
    Used by FastAPI to choose between Celery async dispatch and thread pool fallback.
    """
    import time
    global _celery_available_cache, _celery_available_cache_time
    now = time.time()
    if _celery_available_cache is not None and (now - _celery_available_cache_time < 5.0):
        return _celery_available_cache

    try:
        import redis
        host = getattr(settings, "redis_host", "127.0.0.1")
        port = int(getattr(settings, "redis_port", 6379))
        password = getattr(settings, "redis_password", None)
        r = redis.Redis(
            host=host,
            port=port,
            password=password,
            socket_timeout=timeout_sec,
            socket_connect_timeout=timeout_sec
        )
        if not r.ping():
            _celery_available_cache = False
            _celery_available_cache_time = now
            return False

        # Verify active Celery worker is responding
        workers = celery_app.control.ping(timeout=timeout_sec)
        is_ready = bool(workers and len(workers) > 0)
        _celery_available_cache = is_ready
        _celery_available_cache_time = now
        return is_ready
    except Exception as e:
        logger.debug(f"Celery check: offline or unreachable ({e})")
        _celery_available_cache = False
        _celery_available_cache_time = now
        return False
