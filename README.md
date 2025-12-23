# BadLog

BadLog is a Windows-first CLI for capturing **only** high-signal Android
anomalies ("bad stuff") from ADB logcat streams. It continuously monitors logs,
keeps a ring buffer for context, and emits structured events without dumping
full logs.

## Highlights

- Android 8–16 compatible via **feature detection** (no version hardcoding)
- No Android Studio required; only ADB in PATH
- Works without root, uses root only if available
- Survives disconnects/reboots and captures best-effort artifacts
- JSONL + human-readable text logs, optional HTML report

## Windows Installation

1. Install Python 3.11+.
2. Install ADB (Android platform-tools) and ensure `adb` is in `PATH`.
3. Install BadLog:

```bash
pip install -e .
```

## Quick Start

```bash
badlog devices
badlog run --output C:\badlog\out
```

### Configuration

BadLog accepts a YAML or JSON config file:

```yaml
output:
  directory: ./badlog-output
  emit_html: false
capture:
  device_serial:
  buffers: [all]
  format: threadtime
  ring_size: 400
  pre_context: 40
  post_context: 60
suppression:
  drop_chatty: true
  drop_tags: []
  rate_limit_per_minute: 0
rules:
  files: []
verbosity: 0
```

Run with:

```bash
badlog run --config badlog.yaml
```

## Supported Android Versions

BadLog supports Android 8–16 (API 26–36). It detects capabilities at runtime:

- Detects readable logcat buffers (`main`, `system`, `crash`, `kernel`, etc.)
- Attempts `dmesg`, pstore, and dropbox on reconnect
- Reports missing/denied artifacts cleanly

## Common Diagnostic Scenario

For intermittent freezes that end in watchdog reboot:

1. Start BadLog before testing.
2. Leave it running during soak tests.
3. When the device reboots, BadLog captures:
   - logcat context before the reboot
   - dmesg/pstore/dropbox/reset hints if available

## Rule Authoring

Rules are regex-based with metadata. Example:

```yaml
- name: watchdog_soft_lockup
  severity: CRITICAL
  category: WATCHDOG
  pattern: "soft lockup|watchdog timeout"
  context_boost: 20
```

Custom rules merge with defaults by name. Use:

```bash
badlog test-rules rules/custom.yaml
```

## Output

- `events.jsonl`: machine-readable events
- `events.log`: human-readable context
- `report.html`: optional summary report
- `incidents/`: reconnect artifacts (dmesg, pstore, reset hints)

## Security Note

Logs may contain PII. Consider redaction if sharing output with third parties.

## Commands

- `badlog run`
- `badlog devices`
- `badlog test-rules <file>`
- `badlog report <out_dir>`
