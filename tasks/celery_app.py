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


def is_celery_broker_available(timeout_sec: float = 1.0) -> bool:
    """
    Check if the Redis broker is reachable.
    Used by FastAPI to choose between Celery async dispatch and thread pool fallback.
    """
    try:
        import redis
        host = getattr(settings, "redis_host", "localhost")
        port = int(getattr(settings, "redis_port", 6379))
        password = getattr(settings, "redis_password", None)
        r = redis.Redis(
            host=host,
            port=port,
            password=password,
            socket_timeout=timeout_sec,
            socket_connect_timeout=timeout_sec
        )
        return bool(r.ping())
    except Exception as e:
        logger.debug(f"Celery Redis broker check: offline or unreachable ({e})")
        return False
