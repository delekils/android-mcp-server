from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from badlog.adb import AdbRunner
from badlog.config import BadLogConfig
from badlog.events import EventRecord, IncidentRecord, utc_now
from badlog.reconnect import ReconnectController
from badlog.ring import RingBuffer
from badlog.rules import Rule


LOGGER = logging.getLogger(__name__)

LOGCAT_LINE = re.compile(
    r"(?P<date>\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<level>[VDIWEF])\s+"
    r"(?P<tag>[^:]+):\s+(?P<message>.*)"
)


@dataclass
class PendingEvent:
    record: EventRecord
    remaining_post: int


@dataclass
class RateLimiter:
    max_per_minute: int
    entries: dict[str, list[float]] = field(default_factory=dict)

    def allow(self, key: str) -> bool:
        if self.max_per_minute <= 0:
            return True
        now = time.time()
        window_start = now - 60.0
        bucket = self.entries.setdefault(key, [])
        bucket[:] = [ts for ts in bucket if ts >= window_start]
        if len(bucket) >= self.max_per_minute:
            return False
        bucket.append(now)
        return True


class LogRecorder:
    def __init__(self, config: BadLogConfig, rules: list[Rule], output_dir: Path) -> None:
        self.config = config
        self.rules = rules
        self.output_dir = output_dir
        self.ring = RingBuffer(config.capture.ring_size)
        self.pending: list[PendingEvent] = []
        self.rate_limiter = RateLimiter(config.suppression.rate_limit_per_minute)
        self.device_props: dict[str, str] = {}
        self.incident_id: str | None = None
        self.adb = AdbRunner(config.capture.device_serial)
        self.reconnect = ReconnectController()

    def run(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        event_path = self.output_dir / "events.jsonl"
        text_path = self.output_dir / "events.log"
        with event_path.open("a", encoding="utf-8") as event_file, text_path.open(
            "a", encoding="utf-8"
        ) as text_file:
            while True:
                try:
                    device = self.adb.resolve_device()
                    self.device_props = self._get_device_props()
                    LOGGER.info("Connected to device %s", device.serial)
                    self.reconnect.connected()
                    available_buffers = self._resolve_buffers()
                    logcat_proc = self.adb.stream(
                        [
                            "logcat",
                            *self._buffer_args(available_buffers),
                            "-v",
                            self.config.capture.format,
                        ]
                    )
                    for line in self._stream_lines(logcat_proc):
                        self._handle_line(line, event_file, text_file)
                    LOGGER.warning("Logcat stream ended; capturing incident artifacts")
                    self._capture_incident(event_file)
                except Exception as exc:  # noqa: BLE001
                    LOGGER.error("Recorder error: %s", exc)
                delay = self.reconnect.disconnected()
                LOGGER.info("Waiting for reconnect (%.1fs)", delay)
                time.sleep(delay)

    def _stream_lines(self, process) -> Iterable[str]:
        assert process.stdout is not None
        for line in process.stdout:
            yield line.rstrip("\n")

    def _buffer_args(self, buffers: list[str]) -> list[str]:
        args: list[str] = []
        for buffer_name in buffers:
            args.extend(["-b", buffer_name])
        return args

    def _resolve_buffers(self) -> list[str]:
        requested = self.config.capture.buffers
        if requested == ["all"]:
            candidates = ["main", "system", "crash", "kernel", "events", "radio"]
            available = self.adb.detect_logcat_buffers(candidates) or ["main"]
            LOGGER.info("Readable logcat buffers: %s", ", ".join(available))
            return available
        available = self.adb.detect_logcat_buffers(requested) or ["main"]
        LOGGER.info("Readable logcat buffers: %s", ", ".join(available))
        return available

    def _get_device_props(self) -> dict[str, str]:
        props = self.adb.getprop()
        keys = [
            "ro.product.model",
            "ro.build.fingerprint",
            "ro.hardware",
            "ro.build.version.sdk",
            "ro.build.version.release",
        ]
        return {key: props.get(key, "") for key in keys}

    def _handle_line(self, line: str, event_file, text_file) -> None:
        if not line:
            return
        if self._should_drop(line):
            return
        self._advance_pending(line, event_file, text_file)
        self.ring.append(line)
        for rule in self.rules:
            if not rule.regex.search(line):
                continue
            event = self._create_event(rule, line)
            pending = PendingEvent(record=event, remaining_post=self._post_context(rule))
            if pending.remaining_post <= 0:
                self._emit_event(pending.record, event_file, text_file)
            else:
                self.pending.append(pending)

    def _should_drop(self, line: str) -> bool:
        lower = line.lower()
        if self.config.suppression.drop_chatty and "chatty" in lower:
            return True
        tag = self._extract_tag(line)
        if tag and tag in self.config.suppression.drop_tags:
            return True
        signature = f"{tag}:{line}" if tag else line
        return not self.rate_limiter.allow(signature)

    def _advance_pending(self, line: str, event_file, text_file) -> None:
        completed: list[PendingEvent] = []
        for pending in self.pending:
            pending.record.post_context.append(line)
            pending.remaining_post -= 1
            if pending.remaining_post <= 0:
                completed.append(pending)
        for pending in completed:
            self.pending.remove(pending)
            self._emit_event(pending.record, event_file, text_file)

    def _create_event(self, rule: Rule, line: str) -> EventRecord:
        device_timestamp = self._extract_device_timestamp(line)
        pre_context = self.ring.tail(self._pre_context(rule))
        return EventRecord(
            type="event",
            timestamp_utc=utc_now(),
            device_timestamp=device_timestamp,
            rule_name=rule.name,
            severity=rule.severity,
            category=rule.category,
            line=line,
            pre_context=pre_context,
            post_context=[],
            device_props=self.device_props,
            incident_id=self.incident_id,
            artifacts=[],
        )

    def _emit_event(self, event: EventRecord, event_file, text_file) -> None:
        payload = event.to_dict()
        event_file.write(json.dumps(payload) + "\n")
        event_file.flush()
        text_file.write(self._format_text_event(event) + "\n")
        text_file.flush()

    def _format_text_event(self, event: EventRecord) -> str:
        header = f"[{event.timestamp_utc}] {event.severity} {event.category} {event.rule_name}"
        contexts = "\n".join(
            [
                "--- pre-context ---",
                *event.pre_context,
                "--- hit ---",
                event.line,
                "--- post-context ---",
                *event.post_context,
            ]
        )
        return f"{header}\n{contexts}\n"

    def _pre_context(self, rule: Rule) -> int:
        return self.config.capture.pre_context + rule.context_boost

    def _post_context(self, rule: Rule) -> int:
        return self.config.capture.post_context + rule.context_boost

    def _extract_device_timestamp(self, line: str) -> str | None:
        match = LOGCAT_LINE.match(line)
        if not match:
            return None
        return f"{match.group('date')} {match.group('time')}"

    def _extract_tag(self, line: str) -> str | None:
        match = LOGCAT_LINE.match(line)
        if not match:
            return None
        return match.group("tag").strip()

    def _capture_incident(self, event_file) -> None:
        self.incident_id = utc_now().replace(":", "").replace("-", "")
        incident_dir = self.output_dir / "incidents" / self.incident_id
        artifacts: list[str] = []
        self._capture_artifact(incident_dir, "dmesg.txt", "dmesg", artifacts)
        self._capture_artifact(incident_dir, "dropbox.txt", "dumpsys dropbox --print", artifacts)
        self._capture_pstore(incident_dir, artifacts)
        self._capture_reset_reasons(incident_dir, artifacts)
        record = IncidentRecord(
            type="incident",
            timestamp_utc=utc_now(),
            reason="logcat_stream_ended",
            artifacts=artifacts,
        )
        event_file.write(json.dumps(record.to_dict()) + "\n")
        event_file.flush()

    def _capture_artifact(
        self, incident_dir: Path, filename: str, command: str, artifacts: list[str]
    ) -> None:
        output = self.adb.capture_shell_output(command)
        if not output:
            LOGGER.info("Artifact unavailable or blocked: %s", command)
            return
        path = incident_dir / filename
        path.write_text(output, encoding="utf-8")
        artifacts.append(str(path))

    def _capture_pstore(self, incident_dir: Path, artifacts: list[str]) -> None:
        files = self.adb.list_files("/sys/fs/pstore")
        if not files:
            LOGGER.info("No pstore files available")
        for name in files:
            content = self.adb.read_file(f"/sys/fs/pstore/{name}")
            if content is None:
                LOGGER.info("Pstore file blocked: %s", name)
                continue
            path = incident_dir / "pstore" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            artifacts.append(str(path))

    def _capture_reset_reasons(self, incident_dir: Path, artifacts: list[str]) -> None:
        candidates = [
            "/proc/reset_reason",
            "/sys/devices/platform/reset_reason",
        ]
        for path in candidates:
            content = self.adb.read_file(path)
            if content:
                out = incident_dir / Path(path).name
                out.write_text(content, encoding="utf-8")
                artifacts.append(str(out))
            else:
                LOGGER.info("Reset reason unavailable: %s", path)
        props = self.adb.capture_shell_output("getprop | grep -i -E 'reboot|reset|panic|watchdog'")
        if props:
            out = incident_dir / "reset_props.txt"
            out.write_text(props, encoding="utf-8")
            artifacts.append(str(out))
        else:
            LOGGER.info("Reset properties not accessible")
