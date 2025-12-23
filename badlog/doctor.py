from __future__ import annotations

from dataclasses import dataclass

from badlog.adb import AdbRunner


@dataclass
class DoctorReport:
    adb_ok: bool
    device_serial: str | None
    buffers: list[str]
    artifacts: dict[str, bool]


def run_doctor(serial: str | None) -> DoctorReport:
    adb = AdbRunner(serial)
    try:
        device = adb.resolve_device()
    except Exception:
        return DoctorReport(False, None, [], {})
    buffers = adb.detect_logcat_buffers(["main", "system", "crash", "kernel", "events", "radio"])
    artifacts = {
        "dmesg": adb.capture_shell_output("dmesg") is not None,
        "pstore": bool(adb.list_files("/sys/fs/pstore")),
        "dropbox": adb.capture_shell_output("dumpsys dropbox --print") is not None,
        "reset_reason": adb.read_file("/proc/reset_reason") is not None,
    }
    return DoctorReport(True, device.serial, buffers, artifacts)
