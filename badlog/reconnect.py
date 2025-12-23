from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ReconnectState(str, Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    STREAMING = "streaming"


@dataclass
class ReconnectController:
    base_delay: float = 2.0
    max_delay: float = 30.0
    attempt: int = 0
    state: ReconnectState = ReconnectState.DISCONNECTED

    def connected(self) -> None:
        self.state = ReconnectState.STREAMING
        self.attempt = 0

    def disconnected(self) -> float:
        self.state = ReconnectState.DISCONNECTED
        delay = min(self.base_delay * (2**self.attempt), self.max_delay)
        self.attempt += 1
        return delay
