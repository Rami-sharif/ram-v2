"""Lightweight in-process operational counters, surfaced on /health.

"In-process" means these counts live in this running program's memory only — plain
integers in a dict, nothing written to disk. They are operational signals (e.g.
console-record failures), NOT a system of record: they reset to zero on every restart.
The audit_log and the DB tables remain the source of truth. Use these to spot trouble
quickly, then reconcile against the DB (console.store.reconcile_counts) for the
authoritative number.
"""
# A web server handles many requests at once on different threads. threading.Lock lets us
# make counter updates thread-safe so two simultaneous updates can't corrupt the count.
import threading

# One lock guarding every read/write of _counters below.
_lock = threading.Lock()
# The actual counters: a name -> integer dict. We pre-create the one counter we know about
# at 0 so /health always shows it even before the first failure occurs.
_counters: dict[str, int] = {
    "console_record_failures": 0,
}


# Adds `amount` (default 1) to the named counter, creating it at 0 first if new.
def increment(name: str, amount: int = 1) -> None:
    # `x = x + 1` is really three steps (read, add, write). Without the lock, two threads
    # could both read the old value and one increment would be lost. The lock forces them
    # to take turns so no update is missed.
    with _lock:
        # .get(name, 0) returns the current value, or 0 if this name hasn't been seen yet.
        _counters[name] = _counters.get(name, 0) + amount


# Returns a point-in-time copy of all counters, safe to hand to callers (e.g. /health).
def snapshot() -> dict[str, int]:
    # Copy under the lock so the snapshot is internally consistent (no counter changing mid-copy).
    with _lock:
        # dict(_counters) is a fresh copy, so the caller can't accidentally mutate our
        # private store by editing what they receive.
        return dict(_counters)
