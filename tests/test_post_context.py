import json
from pathlib import Path

from badlog.config import BadLogConfig
from badlog.recorder import LogRecorder
from badlog.reset_reason import ResetReason, ResetReasonResult
from badlog.rules import Rule


def test_post_context_collection(tmp_path: Path) -> None:
    config = BadLogConfig()
    config.capture.post_context = 1
    config.capture.pre_context = 1
    output_dir = tmp_path
    rule = Rule(
        name="demo",
        severity="HIGH",
        category="KERNEL",
        pattern="bad",
        context_boost=0,
        rationale=None,
        domains=[],
        evidence=[],
        regex=__import__("re").compile("bad", __import__("re").IGNORECASE),
    )
    recorder = LogRecorder(config, [rule], output_dir)
    recorder.device_props = {"ro.product.model": "demo"}
    incidents_path = output_dir / "incidents.jsonl"
    text_path = output_dir / "incidents.log"
    with incidents_path.open("a", encoding="utf-8") as incident_file, text_path.open(
        "a", encoding="utf-8"
    ) as text_file:
        recorder._handle_line("00-00 00:00:00.000  1 1 E tag: bad", incident_file, text_file)
        recorder._handle_line("00-00 00:00:00.001  1 1 I tag: after", incident_file, text_file)
        incident = recorder.incidents.close_current()
        assert incident is not None
        recorder._finalize_incident(
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
    data = [json.loads(line) for line in incidents_path.read_text(encoding="utf-8").splitlines()]
    assert len(data) == 1
    events = data[0]["events"]
    assert events[0]["post_context"] == ["00-00 00:00:00.001  1 1 I tag: after"]
