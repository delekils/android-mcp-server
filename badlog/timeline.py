from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable

from badlog.timeutils import parse_device_timestamp


DMESG_TIMESTAMP = re.compile(r"^\[(?P<seconds>\d+\.\d+)\]\s+(?P<message>.*)$")


def build_timeline(events: Iterable[dict], dmesg_text: str | None) -> list[dict[str, str]]:
    entries: list[tuple[datetime | None, str]] = []
    for event in events:
        device_ts = parse_device_timestamp(event.get("device_timestamp"))
        label = f"{event.get('rule_name')}"
        entries.append((device_ts, label))

    if dmesg_text:
        for line in dmesg_text.splitlines():
            match = DMESG_TIMESTAMP.match(line.strip())
            if not match:
                continue
            message = match.group("message")
            if _is_signal_dmesg(message):
                entries.append((None, f"dmesg: {message}"))

    entries_sorted = sorted(entries, key=lambda item: (item[0] is None, item[0]))
    if not entries_sorted:
        return []

    last_time = max((ts for ts, _ in entries_sorted if ts is not None), default=None)
    timeline: list[dict[str, str]] = []
    for ts, label in entries_sorted:
        offset = _format_offset(ts, last_time)
        timeline.append({"offset": offset, "event": label})
    return timeline


def _is_signal_dmesg(message: str) -> bool:
    lowered = message.lower()
    signals = ["watchdog", "panic", "rcu", "thermal", "ufs", "mmc", "hang"]
    return any(signal in lowered for signal in signals)


def _format_offset(timestamp: datetime | None, anchor: datetime | None) -> str:
    if timestamp is None or anchor is None:
        return "T+?"
    delta = (timestamp - anchor).total_seconds()
    if delta <= 0:
        return f"T{int(delta)}s"
    return f"T+{int(delta)}s"
