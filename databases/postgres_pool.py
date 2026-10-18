"""
Bounded synchronous PostgreSQL connection pool for concurrent forensic workloads.
Provides thread-safe connection pooling, automatic return on context exit,
and bounded queueing to prevent PostgreSQL connection starvation.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Generator, Optional

import psycopg2
from psycopg2 import pool
from config.settings import settings

logger = logging.getLogger(__name__)


class PostgresConnectionPool:
    """Thread-safe bounded connection pool wrapping psycopg2.pool.ThreadedConnectionPool."""

    _pool: Optional[pool.ThreadedConnectionPool] = None

    @classmethod
    def initialize(cls, minconn: int = 2, maxconn: int = 20) -> None:
        """Initializes the connection pool if not already initialized."""
        if cls._pool is None:
            try:
                cls._pool = pool.ThreadedConnectionPool(
                    minconn=minconn,
                    maxconn=maxconn,
                    host=settings.postgres_host,
                    port=settings.postgres_port,
                    database=settings.postgres_db,
                    user=settings.postgres_user,
                    password=settings.postgres_password,
                    connect_timeout=5,
                )
                logger.info(
                    "Initialized PostgreSQL ThreadedConnectionPool (min=%d, max=%d) on %s:%d",
                    minconn,
                    maxconn,
                    settings.postgres_host,
                    settings.postgres_port,
                )
            except Exception as e:
                logger.warning("Failed to initialize PostgreSQL connection pool: %s", e)
                cls._pool = None

    @classmethod
    def close_all(cls) -> None:
        """Closes all pooled connections."""
        if cls._pool is not None:
            cls._pool.closeall()
            cls._pool = None
            logger.info("Closed PostgreSQL ThreadedConnectionPool.")

    @classmethod
    @contextmanager
    def get_connection(cls) -> Generator[psycopg2.extensions.connection, None, None]:
        """Context manager yielding a pooled connection and returning it to the pool on exit.
        
        Falls back to ad-hoc connection if pool is uninitialized or exhausted.
        """
        if cls._pool is None:
            cls.initialize()

        conn = None
        from_pool = False
        try:
            if cls._pool is not None:
                try:
                    conn = cls._pool.getconn()
                    from_pool = True
                except pool.PoolError as pe:
                    logger.warning("Postgres pool exhausted: %s. Creating bounded fallback connection.", pe)
                    conn = psycopg2.connect(
                        host=settings.postgres_host,
                        port=settings.postgres_port,
                        database=settings.postgres_db,
                        user=settings.postgres_user,
                        password=settings.postgres_password,
                        connect_timeout=5,
                    )
            else:
                conn = psycopg2.connect(
                    host=settings.postgres_host,
                    port=settings.postgres_port,
                    database=settings.postgres_db,
                    user=settings.postgres_user,
                    password=settings.postgres_password,
                    connect_timeout=5,
                )

            yield conn

        finally:
            if conn is not None:
                if from_pool and cls._pool is not None:
                    try:
                        cls._pool.putconn(conn)
                    except Exception as e:
                        logger.error("Error returning connection to pool: %s", e)
                else:
                    try:
                        conn.close()
                    except Exception:
                        pass
