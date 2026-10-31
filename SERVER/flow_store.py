"""Short-lived server-side state for multi-step ceremonies (registration, login,
new-device enrolment). Kept in memory: a server restart simply cancels any
half-finished ceremony."""
import secrets
import threading
import time

from errors import PimError


class FlowStore:
    def __init__(self, lifetime_seconds: int):
        self._lifetime = lifetime_seconds
        self._flows = {}
        self._lock = threading.Lock()

    def create(self, kind: str, **data):
        flow_id = secrets.token_urlsafe(18)
        flow = {"kind": kind, "expires_at": time.time() + self._lifetime, **data}
        with self._lock:
            now = time.time()
            for key in [k for k, v in self._flows.items() if v["expires_at"] < now]:
                del self._flows[key]
            self._flows[flow_id] = flow
        return flow_id, flow

    def get(self, flow_id: str, kind: str) -> dict:
        with self._lock:
            flow = self._flows.get(flow_id or "")
        if not flow or flow["kind"] != kind:
            raise PimError(400, "This step is no longer valid. Please start again.")
        if flow["expires_at"] < time.time():
            self.delete(flow_id)
            raise PimError(400, "This step has expired. Please start again.")
        return flow

    def delete(self, flow_id: str):
        with self._lock:
            self._flows.pop(flow_id, None)
