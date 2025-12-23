from __future__ import annotations

import json
from pathlib import Path


def generate_html_report(output_dir: Path) -> Path:
    jsonl_path = output_dir / "events.jsonl"
    if not jsonl_path.exists():
        raise FileNotFoundError("events.jsonl not found")
    events = []
    with jsonl_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    html = _render_html(events)
    report_path = output_dir / "report.html"
    report_path.write_text(html, encoding="utf-8")
    return report_path


def _render_html(events: list[dict]) -> str:
    rows = []
    for event in events:
        if event.get("type") != "event":
            continue
        rows.append(
            f"<tr><td>{event.get('timestamp_utc')}</td>"
            f"<td>{event.get('severity')}</td>"
            f"<td>{event.get('category')}</td>"
            f"<td>{event.get('rule_name')}</td>"
            f"<td><pre>{_escape(event.get('line', ''))}</pre></td></tr>"
        )
    rows_html = "\n".join(rows) if rows else "<tr><td colspan='5'>No events</td></tr>"
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<style>body{font-family:Segoe UI,Arial}"
        "table{border-collapse:collapse;width:100%;}"
        "th,td{border:1px solid #ccc;padding:6px;}"
        "pre{margin:0;white-space:pre-wrap;}</style></head><body>"
        "<h1>BadLog Report</h1>"
        "<table><thead><tr><th>Timestamp</th><th>Severity</th><th>Category</th>"
        "<th>Rule</th><th>Line</th></tr></thead><tbody>"
        f"{rows_html}</tbody></table></body></html>"
    )


def _escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
