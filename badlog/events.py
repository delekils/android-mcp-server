from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class EventRecord:
    type: str
    timestamp_utc: str
    device_timestamp: str | None
    rule_name: str
    severity: str
    category: str
    line: str
    pre_context: list[str]
    post_context: list[str]
    device_props: dict[str, str]
    incident_id: str | None
    artifacts: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "timestamp_utc": self.timestamp_utc,
            "device_timestamp": self.device_timestamp,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "category": self.category,
            "line": self.line,
            "pre_context": self.pre_context,
            "post_context": self.post_context,
            "device_props": self.device_props,
            "incident_id": self.incident_id,
            "artifacts": self.artifacts,
        }


@dataclass
class IncidentRecord:
    type: str
    timestamp_utc: str
    reason: str
    artifacts: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "timestamp_utc": self.timestamp_utc,
            "reason": self.reason,
            "artifacts": self.artifacts,
        }


def utc_now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
