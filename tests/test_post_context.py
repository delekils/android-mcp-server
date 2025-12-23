import json
from pathlib import Path

from badlog.config import BadLogConfig
from badlog.recorder import LogRecorder
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
        regex=__import__("re").compile("bad", __import__("re").IGNORECASE),
    )
    recorder = LogRecorder(config, [rule], output_dir)
    recorder.device_props = {"ro.product.model": "demo"}
    events_path = output_dir / "events.jsonl"
    text_path = output_dir / "events.log"
    with events_path.open("a", encoding="utf-8") as event_file, text_path.open(
        "a", encoding="utf-8"
    ) as text_file:
        recorder._handle_line("00-00 00:00:00.000  1 1 E tag: bad", event_file, text_file)
        recorder._handle_line("00-00 00:00:00.001  1 1 I tag: after", event_file, text_file)
    data = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
    assert len(data) == 1
    assert data[0]["post_context"] == ["00-00 00:00:00.001  1 1 I tag: after"]
