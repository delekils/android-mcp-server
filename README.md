# BadLog

BadLog is a Windows-first CLI for capturing **only** high-signal Android
anomalies ("bad stuff") from ADB logcat streams. It continuously monitors logs,
keeps a ring buffer for context, and emits **incident-centric** summaries with
classification, confidence scoring, and artifacts.

## Highlights

- Android 8–16 compatible via **feature detection** (no version hardcoding)
- No Android Studio required; only ADB in PATH
- Works without root, uses root only if available
- Survives disconnects/reboots and captures best-effort artifacts
- Incident-centric JSONL + text logs, optional HTML report

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
  incident_window_seconds: 30
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

## Failure Classes & Confidence

BadLog aggregates evidence into failure classes:

- **EXECUTION_STALL**: CPU stalls, scheduler/RCU lockups, hung tasks
- **WATCHDOG_RESET**: watchdog bite/bark, WDT resets
- **MEMORY_CORRUPTION**: DDR/ECC errors, panics tied to corruption
- **POWER_CUT**: PMIC resets, brownouts, power loss
- **THERMAL_SHUTDOWN**: thermal protection/overheat shutdowns
- **STORAGE_TIMEOUT**: UFS/eMMC timeouts, resets
- **FRAMEWORK_FATAL**: ANRs, tombstones, framework fatal errors

Confidence is deterministic: weighted evidence from logcat rules,
reconnect artifacts (dmesg/pstore/dropbox), and reset-reason normalization are
combined, then normalized by total evidence weight.

### EXECUTION_STALL vs POWER_CUT

- **EXECUTION_STALL** typically includes soft/hard lockups, RCU stalls,
  or hung-task indicators and aligns with watchdog resets.
- **POWER_CUT** is used when reset reasons or artifacts point to PMIC reset,
  brownout, or power loss without clear pre-crash kernel stall signatures.

## Rule Authoring

Rules are regex-based with metadata and evidence weights. Example:

```yaml
version: 2
rules:
  - name: watchdog_soft_lockup
    severity: CRITICAL
    category: WATCHDOG
    pattern: "soft lockup|watchdog timeout"
    context_boost: 20
    rationale: "Soft lockup suggests CPU execution stall without full reset."
    domains: [clock, scheduler]
    evidence:
      - failure_class: EXECUTION_STALL
        weight: 0.6
        label: "soft lockup"
```

Custom rules merge with defaults by name. Use:

```bash
badlog test-rules rules/custom.yaml
```

## Output (Incident-Centric)

- `incidents.jsonl`: machine-readable incident records
- `incidents.log`: human-readable incident summaries
- `report.html`: optional summary report
- `incidents/`: reconnect artifacts (dmesg, pstore, reset hints)

Incident records include:

- `incident_id`, `start_time_utc`, `end_time_utc`
- `failure_class`, `confidence`, `evidence`
- `reset_reason` (WATCHDOG, KERNEL_PANIC, POWER_LOSS, THERMAL, UNKNOWN)
- `timeline` (T-5s ... T+6s)
- full event list with context

## Reset Reason Normalization (Vendor Notes)

BadLog normalizes reset hints into a canonical enum:

- `WATCHDOG`, `KERNEL_PANIC`, `POWER_LOSS`, `THERMAL`, `UNKNOWN`

Vendor differences handled by pattern-based normalization:

- **Samsung**: `ro.boot.bootreason`, `sec_wdt`, `sec_wdt_reset` often map to `WATCHDOG`.
- **MTK**: AEE logs, `aee` warnings, and MTK-specific reset strings map to watchdog or kernel stall classes.
- **Generic**: `panic`, `kernel panic`, `thermal`, `brownout`, or `power loss` map to their respective classes.

## Commands

- `badlog run`
- `badlog devices`
- `badlog test-rules <file>`
- `badlog report <out_dir>`
- `badlog incidents <out_dir>`
- `badlog explain <out_dir> <incident_id>`
- `badlog doctor --device <serial>`

## Worked Example (freeze → watchdog reboot)

1. Start capture:
   ```bash
   badlog run --output C:\badlog\out
   ```
2. A freeze occurs and the device reboots.
3. BadLog emits an incident:

```json
{
  "incident_id": "20240210T114530Z",
  "failure_class": "WATCHDOG_RESET",
  "confidence": 0.82,
  "evidence": ["soft lockup", "RCU stall", "reset_reason=WATCHDOG"],
  "reset_reason": "WATCHDOG"
}
```

The timeline clarifies order:

```
T-5s  rcu_stall
T-2s  watchdog_soft_lockup
T+0s  reboot
T+6s  dmesg: watchdog bite
```

## Security Note

Logs may contain PII. Consider redaction if sharing output with third parties.
