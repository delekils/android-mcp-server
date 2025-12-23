from badlog.classification import EvidenceContribution, FailureClass, classify_incident
from badlog.reset_reason import ResetReason


def test_classification_scores_and_confidence() -> None:
    contributions = [
        EvidenceContribution(FailureClass.EXECUTION_STALL, 0.6, "soft lockup"),
        EvidenceContribution(FailureClass.WATCHDOG_RESET, 0.4, "watchdog"),
    ]
    result = classify_incident(contributions, ResetReason.WATCHDOG)
    assert result.failure_class == FailureClass.WATCHDOG_RESET
    assert result.confidence >= 0.5
    assert "reset_reason=WATCHDOG" in result.evidence
