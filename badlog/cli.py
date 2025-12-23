from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import typer

from badlog.adb import AdbRunner
from badlog.config import BadLogConfig, load_config
from badlog.doctor import run_doctor
from badlog.recorder import LogRecorder
from badlog.report import generate_html_report
from badlog.rules import default_rules_path, load_ruleset
from badlog.tool_logging import setup_logging

app = typer.Typer(help="BadLog - Android log anomaly recorder")


def _build_config(
    config_path: Optional[Path],
    output_dir: Optional[Path],
    device: Optional[str],
    buffers: Optional[list[str]],
    format: Optional[str],
    ring_size: Optional[int],
    pre_context: Optional[int],
    post_context: Optional[int],
    rule_files: Optional[list[Path]],
    verbosity: int,
) -> BadLogConfig:
    base = load_config(config_path)
    if output_dir:
        base.output.directory = output_dir
    if device:
        base.capture.device_serial = device
    if buffers:
        base.capture.buffers = buffers
    if format:
        base.capture.format = format
    if ring_size:
        base.capture.ring_size = ring_size
    if pre_context:
        base.capture.pre_context = pre_context
    if post_context:
        base.capture.post_context = post_context
    if rule_files:
        base.rules.files = rule_files
    base.verbosity = verbosity
    return base


@app.command()
def devices() -> None:
    """List connected devices."""
    adb = AdbRunner()
    devices = adb.list_devices()
    if not devices:
        typer.echo("No devices found")
        raise typer.Exit(code=1)
    for device in devices:
        typer.echo(f"{device.serial}\t{device.state}\t{device.description}")


@app.command()
def run(
    config: Optional[Path] = typer.Option(None, "--config", help="Config file path"),
    output: Optional[Path] = typer.Option(None, "--output", help="Output directory"),
    device: Optional[str] = typer.Option(None, "--device", help="Device serial"),
    buffer: Optional[list[str]] = typer.Option(
        None, "--buffer", help="Logcat buffer(s)", show_default=False
    ),
    format: Optional[str] = typer.Option(None, "--format", help="Logcat format"),
    ring_size: Optional[int] = typer.Option(None, "--ring-size", help="Ring buffer size"),
    pre_context: Optional[int] = typer.Option(None, "--pre", help="Pre-context lines"),
    post_context: Optional[int] = typer.Option(None, "--post", help="Post-context lines"),
    rule_file: Optional[list[Path]] = typer.Option(
        None, "--rule", help="Custom rule file", show_default=False
    ),
    verbosity: int = typer.Option(0, "--verbose", count=True, help="Increase verbosity"),
) -> None:
    """Run the log recorder."""
    config_model = _build_config(
        config,
        output,
        device,
        buffer,
        format,
        ring_size,
        pre_context,
        post_context,
        rule_file,
        verbosity,
    )
    setup_logging(config_model.verbosity, config_model.capture.device_serial)
    logging.getLogger(__name__).info("Starting BadLog")
    ruleset = load_ruleset([default_rules_path()], config_model.rules.files)
    output_dir = config_model.output.directory / "runs" / _timestamp_dir()
    recorder = LogRecorder(config_model, ruleset, output_dir)
    recorder.run()


@app.command("test-rules")
def test_rules(rule_file: Path) -> None:
    """Validate a rule file."""
    ruleset = load_ruleset([default_rules_path()], [rule_file])
    typer.echo(f"Loaded {len(ruleset)} rules")


@app.command()
def report(output_dir: Path) -> None:
    """Generate an HTML report from an output directory."""
    report_path = generate_html_report(output_dir)
    typer.echo(f"Report written to {report_path}")


@app.command()
def incidents(output_dir: Path) -> None:
    """List incidents from an output directory."""
    incidents_path = output_dir / "incidents.jsonl"
    if not incidents_path.exists():
        typer.echo("incidents.jsonl not found")
        raise typer.Exit(code=1)
    with incidents_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            if record.get("type") != "incident":
                continue
            typer.echo(
                f"{record.get('incident_id')}\t{record.get('failure_class')}\t"
                f"{record.get('confidence')}\t{record.get('reset_reason')}"
            )


@app.command()
def explain(output_dir: Path, incident_id: str) -> None:
    """Explain how an incident was classified."""
    incidents_path = output_dir / "incidents.jsonl"
    if not incidents_path.exists():
        typer.echo("incidents.jsonl not found")
        raise typer.Exit(code=1)
    with incidents_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            if record.get("incident_id") != incident_id:
                continue
            typer.echo(f"Incident {incident_id}")
            typer.echo(f"Failure class: {record.get('failure_class')}")
            typer.echo(f"Confidence: {record.get('confidence')}")
            typer.echo(f"Reset reason: {record.get('reset_reason')}")
            typer.echo("Evidence:")
            for item in record.get("evidence", []):
                typer.echo(f"  - {item}")
            typer.echo("Timeline:")
            for entry in record.get("timeline", []):
                typer.echo(f"  {entry.get('offset')} {entry.get('event')}")
            return
    typer.echo("Incident not found")
    raise typer.Exit(code=1)


@app.command()
def doctor(device: Optional[str] = typer.Option(None, "--device", help="Device serial")) -> None:
    """Check ADB and data source accessibility."""
    report = run_doctor(device)
    if not report.adb_ok:
        typer.echo("ADB not ready or no devices found")
        raise typer.Exit(code=1)
    typer.echo(f"Device: {report.device_serial}")
    typer.echo(
        f"Readable buffers: {', '.join(report.buffers) if report.buffers else 'none'}"
    )
    typer.echo("Artifacts:")
    for key, value in report.artifacts.items():
        typer.echo(f"  {key}: {'ok' if value else 'blocked'}")


def _timestamp_dir() -> str:
    from datetime import datetime

    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


if __name__ == "__main__":
    app()
