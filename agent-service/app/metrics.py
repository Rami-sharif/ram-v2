"""Lightweight in-process operational counters, surfaced on /health.

These are operational signals (e.g. console-record failures), NOT a system of
record — they reset on restart and are not durable. The audit_log and the DB
tables remain the source of truth. Use them to spot trouble, then reconcile
against the DB (see console.store.reconcile_counts) for the authoritative answer.
"""
import threading

_lock = threading.Lock()
_counters: dict[str, int] = {
    "console_record_failures": 0,
}


def increment(name: str, amount: int = 1) -> None:
    with _lock:
        _counters[name] = _counters.get(name, 0) + amount


def snapshot() -> dict[str, int]:
    with _lock:
        return dict(_counters)
