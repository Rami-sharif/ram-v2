"""PostgreSQL connection pool for the semantic memory layer.

A "connection pool" keeps a small set of open database connections ready to reuse.
Opening a fresh DB connection is slow, so instead of connecting per query we borrow a
connection from the pool and return it when done — much faster under load.

We pass/read vectors as text literals with an explicit ::vector cast, so no
extra vector adapter is required. The pool is created lazily (only on first real use)
so the service — and its /health check — can start even if Postgres is briefly
unavailable at boot.
"""
# For logging pool lifecycle events (e.g. when it's opened).
import logging
# threading + a Lock let us safely build the pool exactly once even if several requests
# arrive at the same instant (the "double-checked locking" pattern used below).
import threading

# psycopg is the PostgreSQL driver for Python; ConnectionPool is its pooling helper.
from psycopg_pool import ConnectionPool

# Settings accessor, used to read the Postgres DSN.
from .config import get_settings

# Module-level logger, named after this module's dotted path.
logger = logging.getLogger(__name__)

# The single shared pool for the whole process ("singleton"). It's None until the first
# call creates it — that's what "lazy initialization" means. The `| None` type says it
# may hold either a ConnectionPool or None.
_pool: ConnectionPool | None = None
# A lock so that if two threads reach get_pool() together, only one actually builds the
# pool while the other waits, instead of both creating one.
_lock = threading.Lock()


# Returns the shared connection pool, creating it on first call (thread-safe, lazy).
def get_pool() -> ConnectionPool:
    # `global` lets us REASSIGN the module-level _pool variable from inside this function
    # (without it, _pool = ... would create a new local variable instead).
    global _pool
    # Fast path: once the pool exists, just return it without paying for locking.
    if _pool is None:
        # `with _lock:` acquires the lock (and releases it on exit). Only one thread is
        # inside this block at a time; any others wait here.
        with _lock:
            # Check _pool AGAIN now that we hold the lock: another thread may have built it
            # while we were waiting to enter. This second check is the "double-check".
            if _pool is None:
                # Fetch the Postgres connection string from settings (env-derived).
                dsn = get_settings().postgres_dsn
                # Log once, at creation time, so pool lifecycle is visible in logs.
                logger.info("Opening Postgres connection pool")
                # Build the pool: keep at least 1 connection warm, cap at 5, recycle
                # idle connections after 300s, and time out new connections after 5s
                # so the service (and /health) doesn't hang if Postgres is unreachable.
                _pool = ConnectionPool(
                    conninfo=dsn,
                    min_size=1,
                    max_size=5,
                    max_idle=300,
                    kwargs={"connect_timeout": 5},
                    open=True,
                )
    # Return the (now guaranteed-initialized) pool.
    return _pool


def vector_literal(vec: list[float]) -> str:
    """Format a float vector as a pgvector text literal, full float precision."""
    # An embedding is a list of floats. pgvector (the Postgres extension that stores
    # vectors) accepts them written as the text "[v1,v2,...]", which SQL then casts with
    # ::vector. repr() is used instead of str() because it prints the float with full
    # precision, so no accuracy is lost in the round-trip to the database.
    return "[" + ",".join(repr(float(x)) for x in vec) + "]"
