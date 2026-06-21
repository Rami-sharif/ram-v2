"""PostgreSQL connection pool for the semantic memory layer.

We pass/read vectors as text literals with an explicit ::vector cast, so no
extra vector adapter is required. The pool is created lazily so the service
(and /health) starts even if Postgres is briefly unavailable.
"""
import logging
import threading

from psycopg_pool import ConnectionPool

from .config import get_settings

logger = logging.getLogger(__name__)

_pool: ConnectionPool | None = None
_lock = threading.Lock()


def get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        with _lock:
            if _pool is None:
                dsn = get_settings().postgres_dsn
                logger.info("Opening Postgres connection pool")
                _pool = ConnectionPool(
                    conninfo=dsn,
                    min_size=1,
                    max_size=5,
                    max_idle=300,
                    kwargs={"connect_timeout": 5},
                    open=True,
                )
    return _pool


def vector_literal(vec: list[float]) -> str:
    """Format a float vector as a pgvector text literal, full float precision."""
    return "[" + ",".join(repr(float(x)) for x in vec) + "]"
