from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from badlog.reset_reason import ResetReason


class FailureClass(str, Enum):
    EXECUTION_STALL = "EXECUTION_STALL"
    WATCHDOG_RESET = "WATCHDOG_RESET"
    MEMORY_CORRUPTION = "MEMORY_CORRUPTION"
    POWER_CUT = "POWER_CUT"
    THERMAL_SHUTDOWN = "THERMAL_SHUTDOWN"
    STORAGE_TIMEOUT = "STORAGE_TIMEOUT"
    FRAMEWORK_FATAL = "FRAMEWORK_FATAL"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class EvidenceContribution:
    failure_class: FailureClass
    weight: float
    label: str


@dataclass(frozen=True)
class ClassificationResult:
    failure_class: FailureClass
    confidence: float
    evidence: list[str]


def classify_incident(
    contributions: Iterable[EvidenceContribution],
    reset_reason: ResetReason,
) -> ClassificationResult:
    scores: dict[FailureClass, float] = {}
    evidence_map: dict[FailureClass, list[str]] = {}
    for contribution in contributions:
        scores[contribution.failure_class] = scores.get(contribution.failure_class, 0.0) + contribution.weight
        evidence_map.setdefault(contribution.failure_class, []).append(contribution.label)

    if reset_reason == ResetReason.WATCHDOG:
        scores[FailureClass.WATCHDOG_RESET] = scores.get(FailureClass.WATCHDOG_RESET, 0.0) + 0.6
        evidence_map.setdefault(FailureClass.WATCHDOG_RESET, []).append("reset_reason=WATCHDOG")
    elif reset_reason == ResetReason.KERNEL_PANIC:
        scores[FailureClass.EXECUTION_STALL] = scores.get(FailureClass.EXECUTION_STALL, 0.0) + 0.4
        scores[FailureClass.MEMORY_CORRUPTION] = scores.get(FailureClass.MEMORY_CORRUPTION, 0.0) + 0.4
        evidence_map.setdefault(FailureClass.EXECUTION_STALL, []).append("reset_reason=KERNEL_PANIC")
    elif reset_reason == ResetReason.THERMAL:
        scores[FailureClass.THERMAL_SHUTDOWN] = scores.get(FailureClass.THERMAL_SHUTDOWN, 0.0) + 0.6
        evidence_map.setdefault(FailureClass.THERMAL_SHUTDOWN, []).append("reset_reason=THERMAL")
    elif reset_reason == ResetReason.POWER_LOSS:
        scores[FailureClass.POWER_CUT] = scores.get(FailureClass.POWER_CUT, 0.0) + 0.6
        evidence_map.setdefault(FailureClass.POWER_CUT, []).append("reset_reason=POWER_LOSS")

    if not scores:
        return ClassificationResult(FailureClass.UNKNOWN, 0.0, ["no evidence"])

    best_class = max(scores, key=scores.get)
    total_score = sum(scores.values())
    confidence = round(scores[best_class] / total_score, 2) if total_score else 0.0
    evidence = sorted(set(evidence_map.get(best_class, [])))
    return ClassificationResult(best_class, confidence, evidence)
