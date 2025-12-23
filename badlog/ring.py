from __future__ import annotations

from collections import deque
from typing import Deque, Iterable


class RingBuffer:
    def __init__(self, max_lines: int) -> None:
        if max_lines <= 0:
            raise ValueError("max_lines must be positive")
        self._buffer: Deque[str] = deque(maxlen=max_lines)

    def append(self, line: str) -> None:
        self._buffer.append(line)

    def snapshot(self) -> list[str]:
        return list(self._buffer)

    def tail(self, count: int) -> list[str]:
        if count <= 0:
            return []
        return list(self._buffer)[-count:]

    def extend(self, lines: Iterable[str]) -> None:
        for line in lines:
            self.append(line)
