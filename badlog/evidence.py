from __future__ import annotations

import re
from typing import Iterable

from badlog.classification import EvidenceContribution, FailureClass


ARTIFACT_PATTERNS: list[tuple[FailureClass, float, re.Pattern[str], str]] = [
    (FailureClass.WATCHDOG_RESET, 0.6, re.compile(r"watchdog|wdt|dog bark", re.IGNORECASE), "artifact: watchdog"),
    (FailureClass.MEMORY_CORRUPTION, 0.5, re.compile(r"oops|stack corruption|bad page state", re.IGNORECASE), "artifact: memory corruption"),
    (FailureClass.STORAGE_TIMEOUT, 0.6, re.compile(r"ufs|mmc|I/O error|timeout", re.IGNORECASE), "artifact: storage timeout"),
    (FailureClass.THERMAL_SHUTDOWN, 0.6, re.compile(r"thermal|overheat", re.IGNORECASE), "artifact: thermal"),
    (FailureClass.POWER_CUT, 0.5, re.compile(r"power loss|brownout|cold boot", re.IGNORECASE), "artifact: power loss"),
]


def contributions_from_artifacts(texts: Iterable[str]) -> list[EvidenceContribution]:
    contributions: list[EvidenceContribution] = []
    for text in texts:
        for failure_class, weight, pattern, label in ARTIFACT_PATTERNS:
            if pattern.search(text):
                contributions.append(EvidenceContribution(failure_class, weight, label))
    return contributions
