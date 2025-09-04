
from __future__ import annotations

from collections import deque

from ..api.models import PolicyDoc
from ..settings import settings
from .store import set_policy


class CircuitBreaker:
    def __init__(self):
        self.window: deque[bool] = deque(maxlen=settings.cb_window_size)

    def add_outcome(self, success: bool) -> None:
        self.window.append(success)

    def should_trip(self) -> bool:
        if len(self.window) < settings.cb_min_events:
            return False
        failures = sum(1 for ok in self.window if not ok)
        rate = failures / len(self.window)
        return rate >= settings.cb_error_rate_threshold

    def maybe_trip(self, current: PolicyDoc, signer_sk: bytes):
        if not self.should_trip():
            return None
        # Simple policy downgrade: prefer hybrid if stricter
        target_mode = "hybrid" if current.mode == "pqc" else "classical"
        new = PolicyDoc(
            version=f"{current.version}-cb",
            allow_groups=current.allow_groups,
            deny_groups=current.deny_groups,
            mode=target_mode,
            description=f"circuit-breaker from {current.mode}"
        )
        return set_policy(new, signer_sk)
