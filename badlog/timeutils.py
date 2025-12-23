from __future__ import annotations

from datetime import datetime


def parse_device_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        date_part, time_part = value.split(" ", 1)
        month, day = [int(part) for part in date_part.split("-")]
        hour, minute, second_millis = time_part.split(":", 2)
        second, millis = second_millis.split(".")
        return datetime(
            2000,
            month,
            day,
            int(hour),
            int(minute),
            int(second),
            int(millis) * 1000,
        )
    except ValueError:
        return None


def utc_now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
