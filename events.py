from collections import Counter
from threading import Lock
from typing import Dict

_events: Counter = Counter()
_lock: Lock = Lock()


def hit(event_name: str) -> None:
    """Increment a named event counter in a thread-safe manner."""
    if not event_name:
        return
    with _lock:
        _events[event_name] += 1


def snapshot() -> Dict[str, int]:
    """Return a shallow copy of current event counters."""
    with _lock:
        return dict(_events)


def reset_events() -> None:
    """Clear all recorded events."""
    with _lock:
        _events.clear()
