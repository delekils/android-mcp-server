from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class ResetReason(str, Enum):
    WATCHDOG = "WATCHDOG"
    KERNEL_PANIC = "KERNEL_PANIC"
    POWER_LOSS = "POWER_LOSS"
    THERMAL = "THERMAL"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ResetReasonResult:
    normalized: ResetReason
    evidence: list[str]
    hints: dict[str, str]


RESET_PATTERNS: list[tuple[ResetReason, re.Pattern[str]]] = [
    (ResetReason.WATCHDOG, re.compile(r"watchdog|wdt|dog bark", re.IGNORECASE)),
    (ResetReason.KERNEL_PANIC, re.compile(r"panic|kernel panic|oops", re.IGNORECASE)),
    (ResetReason.THERMAL, re.compile(r"thermal|overheat", re.IGNORECASE)),
    (ResetReason.POWER_LOSS, re.compile(r"power loss|brownout|cold boot", re.IGNORECASE)),
]


def normalize_reset_reason(hints: dict[str, str], dmesg_text: str | None) -> ResetReasonResult:
    evidence: list[str] = []
    normalized = ResetReason.UNKNOWN
    for key, value in hints.items():
        blob = f"{key}={value}".strip()
        for reason, pattern in RESET_PATTERNS:
            if pattern.search(blob):
                evidence.append(blob)
                normalized = _prefer_reason(normalized, reason)
    if dmesg_text:
        for line in dmesg_text.splitlines():
            for reason, pattern in RESET_PATTERNS:
                if pattern.search(line):
                    evidence.append(line.strip())
                    normalized = _prefer_reason(normalized, reason)
    if not evidence:
        evidence.append("no reset hints detected")
    return ResetReasonResult(normalized=normalized, evidence=evidence, hints=hints)


def _prefer_reason(current: ResetReason, candidate: ResetReason) -> ResetReason:
    priority = {
        ResetReason.WATCHDOG: 4,
        ResetReason.KERNEL_PANIC: 3,
        ResetReason.THERMAL: 2,
        ResetReason.POWER_LOSS: 1,
        ResetReason.UNKNOWN: 0,
    }
    return candidate if priority[candidate] >= priority[current] else current
