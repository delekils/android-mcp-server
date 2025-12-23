from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class EventRecord:
    event_id: str
    type: str
    timestamp_utc: str
    device_timestamp: str | None
    rule_name: str
    severity: str
    category: str
    rationale: str | None
    domains: list[str]
    line: str
    pre_context: list[str]
    post_context: list[str]
    device_props: dict[str, str]
    incident_id: str | None
    reset_reason: str | None
    artifacts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "type": self.type,
            "timestamp_utc": self.timestamp_utc,
            "device_timestamp": self.device_timestamp,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "category": self.category,
            "rationale": self.rationale,
            "domains": self.domains,
            "line": self.line,
            "pre_context": self.pre_context,
            "post_context": self.post_context,
            "device_props": self.device_props,
            "incident_id": self.incident_id,
            "reset_reason": self.reset_reason,
            "artifacts": self.artifacts,
        }


@dataclass
class IncidentRecord:
    type: str
    incident_id: str
    timestamp_utc: str
    reason: str
    start_time_utc: str
    end_time_utc: str
    device_start_time: str | None
    device_end_time: str | None
    failure_class: str
    confidence: float
    evidence: list[str]
    reset_reason: str
    reset_reason_details: dict[str, str]
    artifacts: list[str]
    timeline: list[dict[str, str]]
    events: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "incident_id": self.incident_id,
            "timestamp_utc": self.timestamp_utc,
            "reason": self.reason,
            "start_time_utc": self.start_time_utc,
            "end_time_utc": self.end_time_utc,
            "device_start_time": self.device_start_time,
            "device_end_time": self.device_end_time,
            "failure_class": self.failure_class,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "reset_reason": self.reset_reason,
            "reset_reason_details": self.reset_reason_details,
            "artifacts": self.artifacts,
            "timeline": self.timeline,
            "events": self.events,
        }


def utc_now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
