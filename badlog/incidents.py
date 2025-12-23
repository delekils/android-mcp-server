from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable

from badlog.classification import ClassificationResult, EvidenceContribution, classify_incident
from badlog.events import EventRecord, IncidentRecord
from badlog.reset_reason import ResetReasonResult
from badlog.timeutils import parse_device_timestamp, utc_now
from badlog.timeline import build_timeline


@dataclass
class IncidentState:
    incident_id: str
    start_time: datetime
    end_time: datetime
    device_start_time: str | None
    device_end_time: str | None
    events: list[EventRecord] = field(default_factory=list)


class IncidentManager:
    def __init__(self, window_seconds: int, id_factory) -> None:
        self.window = timedelta(seconds=window_seconds)
        self.current: IncidentState | None = None
        self._id_factory = id_factory

    def add_event(self, event: EventRecord) -> list[IncidentState]:
        event_time = self._event_time(event)
        closed: list[IncidentState] = []
        if self.current is None:
            self.current = self._start_incident(event, event_time)
            return closed
        if event_time - self.current.end_time > self.window:
            closed.append(self.current)
            self.current = self._start_incident(event, event_time)
        else:
            self.current.end_time = event_time
            self.current.device_end_time = event.device_timestamp
            event.incident_id = self.current.incident_id
            self.current.events.append(event)
        return closed

    def close_current(self) -> IncidentState | None:
        if not self.current:
            return None
        incident = self.current
        self.current = None
        return incident

    def _start_incident(self, event: EventRecord, event_time: datetime) -> IncidentState:
        incident_id = event.incident_id or self._id_factory()
        event.incident_id = incident_id
        return IncidentState(
            incident_id=incident_id,
            start_time=event_time,
            end_time=event_time,
            device_start_time=event.device_timestamp,
            device_end_time=event.device_timestamp,
            events=[event],
        )

    def _event_time(self, event: EventRecord) -> datetime:
        device_time = parse_device_timestamp(event.device_timestamp)
        if device_time:
            return device_time
        return datetime.utcnow()


def build_incident_record(
    incident: IncidentState,
    reason: str,
    artifacts: list[str],
    reset_reason: ResetReasonResult,
    contributions: Iterable[EvidenceContribution],
    dmesg_text: str | None,
) -> IncidentRecord:
    classification: ClassificationResult = classify_incident(contributions, reset_reason.normalized)
    timeline = build_timeline([event.to_dict() for event in incident.events], dmesg_text)
    return IncidentRecord(
        type="incident",
        incident_id=incident.incident_id,
        timestamp_utc=utc_now(),
        reason=reason,
        start_time_utc=incident.start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        end_time_utc=incident.end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        device_start_time=incident.device_start_time,
        device_end_time=incident.device_end_time,
        failure_class=classification.failure_class.value,
        confidence=classification.confidence,
        evidence=classification.evidence,
        reset_reason=reset_reason.normalized.value,
        reset_reason_details=reset_reason.hints,
        artifacts=artifacts,
        timeline=timeline,
        events=[event.to_dict() for event in incident.events],
    )
