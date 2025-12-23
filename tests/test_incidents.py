from badlog.events import EventRecord
from badlog.incidents import IncidentManager


def _event(timestamp: str) -> EventRecord:
    return EventRecord(
        event_id="evt",
        type="event",
        timestamp_utc="2000-01-01T00:00:00Z",
        device_timestamp=timestamp,
        rule_name="demo",
        severity="HIGH",
        category="KERNEL",
        rationale=None,
        domains=[],
        line="hit",
        pre_context=[],
        post_context=[],
        device_props={},
        incident_id=None,
        reset_reason=None,
    )


def test_incident_grouping_window() -> None:
    manager = IncidentManager(window_seconds=10, id_factory=lambda: "incident")
    manager.add_event(_event("01-01 00:00:00.000"))
    closed = manager.add_event(_event("01-01 00:00:05.000"))
    assert closed == []
    closed = manager.add_event(_event("01-01 00:00:20.000"))
    assert len(closed) == 1
    assert closed[0].incident_id == "incident"
