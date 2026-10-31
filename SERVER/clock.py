"""Strictly increasing timestamps.

The policy engine compares times ("was this PC already shared before the
block?"). Windows' system clock can repeat a value within ~15 ms, so every
timestamp stored in the database comes from here and is guaranteed to be later
than the previous one."""
import threading
import time

_lock = threading.Lock()
_last = 0.0


def now() -> float:
    global _last
    with _lock:
        _last = max(time.time(), _last + 1e-6)
        return _last
