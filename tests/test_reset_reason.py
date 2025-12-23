from badlog.reset_reason import ResetReason, normalize_reset_reason


def test_normalize_reset_reason_from_hints() -> None:
    hints = {"ro.boot.bootreason": "watchdog"}
    result = normalize_reset_reason(hints, None)
    assert result.normalized == ResetReason.WATCHDOG
    assert any("watchdog" in item for item in result.evidence)
