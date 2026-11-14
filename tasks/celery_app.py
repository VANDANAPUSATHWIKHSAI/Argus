"""
ARGUS Celery Task Queue Configuration
====================================
Configures Celery application using Redis as message broker and result backend.
Includes automatic availability detection and fallback helpers.
"""

import logging
try:
    from celery import Celery
except ImportError:
    import sys
    from unittest.mock import MagicMock
    celery_mock = MagicMock()
    class Celery:
        def __init__(self, *args, **kwargs):
            class _Conf:
                def __init__(self):
                    self.task_serializer = "json"
                    self.result_serializer = "json"
                    self.timezone = "UTC"
                    self.task_acks_late = True
                def update(self, **kw):
                    pass
            self.conf = _Conf()
            class _Control:
                def ping(self, timeout=None):
                    return []
            self.control = _Control()
            self.task = lambda *a, **k: (lambda f: f)
    celery_mock.Celery = Celery
    sys.modules["celery"] = celery_mock
    sys.modules["celery.result"] = celery_mock.result

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

def is_celery_broker_available(timeout_sec: float = 0.2) -> bool:
    """
    Check if the Redis broker is reachable AND at least one Celery worker is actively running.
    Used by FastAPI to choose between Celery async dispatch and thread pool fallback.
    """
    import time
    global _celery_available_cache, _celery_available_cache_time
    now = time.time()
    if _celery_available_cache is not None and (now - _celery_available_cache_time < 30.0):
        return _celery_available_cache

    try:
        from databases.redis_client import redis_client
        if not redis_client.is_available():
            _celery_available_cache = False
            _celery_available_cache_time = now
            return False

        r = redis_client.get_client()
        if not r or not r.ping():
            _celery_available_cache = False
            _celery_available_cache_time = now
            return False

        # Verify active Celery worker is responding with bounded tight timeout
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
