from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from badlog.adb import AdbRunner
from badlog.classification import EvidenceContribution, FailureClass
from badlog.config import BadLogConfig
from badlog.evidence import contributions_from_artifacts
from badlog.events import EventRecord
from badlog.incidents import IncidentManager, build_incident_record
from badlog.reconnect import ReconnectController
from badlog.reset_reason import ResetReason, ResetReasonResult, normalize_reset_reason
from badlog.ring import RingBuffer
from badlog.rules import Rule
from badlog.timeutils import utc_now


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
        self.adb = AdbRunner(config.capture.device_serial)
        self.reconnect = ReconnectController()
        self.incidents = IncidentManager(config.capture.incident_window_seconds, self._new_incident_id)
        self.event_counter = 0

    def run(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        incident_path = self.output_dir / "incidents.jsonl"
        text_path = self.output_dir / "incidents.log"
        with incident_path.open("a", encoding="utf-8") as incident_file, text_path.open(
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
                        self._handle_line(line, incident_file, text_file)
                    LOGGER.warning("Logcat stream ended; capturing incident artifacts")
                    self._flush_pending_events(incident_file, text_file)
                    self._capture_incident(incident_file, text_file)
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

    def _handle_line(self, line: str, incident_file, text_file) -> None:
        if not line:
            return
        if self._should_drop(line):
            return
        self._advance_pending(line, incident_file, text_file)
        self.ring.append(line)
        for rule in self.rules:
            if not rule.regex.search(line):
                continue
            event = self._create_event(rule, line)
            pending = PendingEvent(record=event, remaining_post=self._post_context(rule))
            if pending.remaining_post <= 0:
                self._record_event(pending.record, incident_file, text_file)
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

    def _advance_pending(self, line: str, incident_file, text_file) -> None:
        completed: list[PendingEvent] = []
        for pending in self.pending:
            pending.record.post_context.append(line)
            pending.remaining_post -= 1
            if pending.remaining_post <= 0:
                completed.append(pending)
        for pending in completed:
            self.pending.remove(pending)
            self._record_event(pending.record, incident_file, text_file)

    def _flush_pending_events(self, incident_file, text_file) -> None:
        for pending in list(self.pending):
            self.pending.remove(pending)
            self._record_event(pending.record, incident_file, text_file)

    def _create_event(self, rule: Rule, line: str) -> EventRecord:
        device_timestamp = self._extract_device_timestamp(line)
        pre_context = self.ring.tail(self._pre_context(rule))
        event_id = f"evt_{self.event_counter:06d}"
        self.event_counter += 1
        return EventRecord(
            event_id=event_id,
            type="event",
            timestamp_utc=utc_now(),
            device_timestamp=device_timestamp,
            rule_name=rule.name,
            severity=rule.severity,
            category=rule.category,
            rationale=rule.rationale,
            domains=rule.domains,
            line=line,
            pre_context=pre_context,
            post_context=[],
            device_props=self.device_props,
            incident_id=None,
            reset_reason=None,
        )

    def _record_event(self, event: EventRecord, incident_file, text_file) -> None:
        closed_incidents = self.incidents.add_event(event)
        for incident in closed_incidents:
            self._finalize_incident(
                incident_file,
                text_file,
                incident,
                reason="window_elapsed",
                artifacts=[],
                reset_reason=ResetReasonResult(ResetReason.UNKNOWN, ["no reset hints"], {}),
                artifact_texts=[],
                dmesg_text=None,
                include_disconnect_evidence=False,
            )

    def _finalize_incident(
        self,
        incident_file,
        text_file,
        incident,
        reason: str,
        artifacts: list[str],
        reset_reason: ResetReasonResult,
        artifact_texts: list[str],
        dmesg_text: str | None,
        include_disconnect_evidence: bool,
    ) -> None:
        contributions = self._build_contributions(
            incident.events, artifact_texts, include_disconnect_evidence
        )
        for event in incident.events:
            event.reset_reason = reset_reason.normalized.value
            event.incident_id = incident.incident_id
        record = build_incident_record(
            incident,
            reason,
            artifacts,
            reset_reason,
            contributions,
            dmesg_text,
        )
        incident_file.write(json.dumps(record.to_dict()) + "\n")
        incident_file.flush()
        text_file.write(self._format_text_incident(record) + "\n")
        text_file.flush()

    def _format_text_incident(self, record) -> str:
        header = (
            f"Incident {record.incident_id} [{record.start_time_utc} - {record.end_time_utc}] "
            f"{record.failure_class} ({record.confidence}) reset={record.reset_reason}"
        )
        lines = [header, f"Evidence: {', '.join(record.evidence)}"]
        lines.append("Timeline:")
        for entry in record.timeline:
            lines.append(f"  {entry['offset']}  {entry['event']}")
        lines.append("Events:")
        for event in record.events:
            lines.append(f"  - {event['rule_name']} :: {event['line']}")
        return "\n".join(lines) + "\n"

    def _build_contributions(
        self,
        events: list[EventRecord],
        artifact_texts: list[str],
        include_disconnect_evidence: bool,
    ) -> list[EvidenceContribution]:
        contributions: list[EvidenceContribution] = []
        for event in events:
            rule = next((rule for rule in self.rules if rule.name == event.rule_name), None)
            if not rule:
                continue
            for evidence in rule.evidence:
                try:
                    failure_class = FailureClass(evidence.failure_class)
                except ValueError:
                    continue
                contributions.append(EvidenceContribution(failure_class, evidence.weight, evidence.label))
        contributions.extend(contributions_from_artifacts(artifact_texts))
        if include_disconnect_evidence:
            contributions.append(
                EvidenceContribution(FailureClass.EXECUTION_STALL, 0.2, "logcat_stream_ended")
            )
        return contributions

    def _new_incident_id(self) -> str:
        return utc_now().replace(":", "").replace("-", "")

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

    def _capture_incident(self, incident_file, text_file) -> None:
        incident = self.incidents.close_current()
        incident_id = incident.incident_id if incident else self._new_incident_id()
        incident_dir = self.output_dir / "incidents" / incident_id
        artifacts: list[str] = []
        dmesg_text = self._capture_artifact(incident_dir, "dmesg.txt", "dmesg", artifacts)
        dropbox_text = self._capture_artifact(
            incident_dir,
            "dropbox.txt",
            "dumpsys dropbox --print",
            artifacts,
        )
        pstore_texts = self._capture_pstore(incident_dir, artifacts)
        reset_hints = self._capture_reset_reasons(incident_dir, artifacts)
        reset_hints["dropbox"] = dropbox_text or ""
        reset_result = normalize_reset_reason(reset_hints, dmesg_text)

        if incident is None:
            placeholder_event = EventRecord(
                event_id=f"evt_{self.event_counter:06d}",
                type="event",
                timestamp_utc=utc_now(),
                device_timestamp=None,
                rule_name="stream_disconnect",
                severity="MEDIUM",
                category="POWER",
                rationale="Logcat stream ended abruptly.",
                domains=["power"],
                line="logcat stream ended",
                pre_context=[],
                post_context=[],
                device_props=self.device_props,
                incident_id=incident_id,
                reset_reason=reset_result.normalized.value,
            )
            self.event_counter += 1
            self.incidents.add_event(placeholder_event)
            incident = self.incidents.close_current()
        incident.incident_id = incident_id
        for event in incident.events:
            event.incident_id = incident_id
        self._finalize_incident(
            incident_file,
            text_file,
            incident,
            reason="logcat_stream_ended",
            artifacts=artifacts,
            reset_reason=reset_result,
            artifact_texts=[text for text in [dmesg_text, dropbox_text, *pstore_texts] if text],
            dmesg_text=dmesg_text,
            include_disconnect_evidence=True,
        )

    def _capture_artifact(
        self, incident_dir: Path, filename: str, command: str, artifacts: list[str]
    ) -> str | None:
        output = self.adb.capture_shell_output(command)
        if not output:
            LOGGER.info("Artifact unavailable or blocked: %s", command)
            return None
        path = incident_dir / filename
        path.write_text(output, encoding="utf-8")
        artifacts.append(str(path))
        return output

    def _capture_pstore(self, incident_dir: Path, artifacts: list[str]) -> list[str]:
        files = self.adb.list_files("/sys/fs/pstore")
        texts: list[str] = []
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
            texts.append(content)
        return texts

    def _capture_reset_reasons(self, incident_dir: Path, artifacts: list[str]) -> dict[str, str]:
        hints: dict[str, str] = {}
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
                hints[path] = content.strip()
            else:
                LOGGER.info("Reset reason unavailable: %s", path)

        platform_entries = self.adb.list_files("/sys/devices/platform")
        for entry in platform_entries:
            candidate = f"/sys/devices/platform/{entry}/reset_reason"
            content = self.adb.read_file(candidate)
            if content:
                out = incident_dir / f"{entry}_reset_reason.txt"
                out.write_text(content, encoding="utf-8")
                artifacts.append(str(out))
                hints[candidate] = content.strip()

        props = self.adb.getprop()
        for key, value in props.items():
            lowered = key.lower()
            if lowered.startswith("ro.boot") or lowered.startswith("vendor.boot"):
                hints[key] = value
            if any(token in lowered for token in ["reboot", "reset", "panic", "watchdog", "bootreason"]):
                hints[key] = value

        if not hints:
            LOGGER.info("Reset properties not accessible")
        return hints
