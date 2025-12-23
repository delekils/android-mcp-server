from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class Device:
    serial: str
    state: str
    description: str


class AdbError(RuntimeError):
    pass


class AdbRunner:
    def __init__(self, serial: str | None = None) -> None:
        self.serial = serial

    def _base_command(self) -> list[str]:
        cmd = ["adb"]
        if self.serial:
            cmd.extend(["-s", self.serial])
        return cmd

    def run(self, args: Iterable[str], timeout: int | None = None) -> subprocess.CompletedProcess[str]:
        cmd = [*self._base_command(), *args]
        LOGGER.debug("ADB run: %s", " ".join(cmd))
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    def stream(self, args: Iterable[str]) -> subprocess.Popen[str]:
        cmd = [*self._base_command(), *args]
        LOGGER.debug("ADB stream: %s", " ".join(cmd))
        return subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )

    def list_devices(self) -> list[Device]:
        result = self.run(["devices", "-l"])
        if result.returncode != 0:
            raise AdbError(result.stderr.strip() or "Failed to list devices")
        devices: list[Device] = []
        for line in result.stdout.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            serial = parts[0]
            state = parts[1] if len(parts) > 1 else "unknown"
            description = " ".join(parts[2:])
            devices.append(Device(serial=serial, state=state, description=description))
        return devices

    def resolve_device(self) -> Device:
        devices = [d for d in self.list_devices() if d.state == "device"]
        if self.serial:
            matches = [d for d in devices if d.serial == self.serial]
            if not matches:
                raise AdbError(f"Device {self.serial} not found")
            return matches[0]
        if len(devices) == 1:
            return devices[0]
        if not devices:
            raise AdbError("No connected devices found")
        raise AdbError("Multiple devices connected; specify --device")

    def detect_logcat_buffers(self, candidates: Iterable[str]) -> list[str]:
        available: list[str] = []
        for buffer_name in candidates:
            result = self.run(["logcat", "-b", buffer_name, "-d", "-t", "1"])
            if result.returncode != 0:
                continue
            stderr = result.stderr.lower()
            if "unknown" in stderr or "not exist" in stderr:
                continue
            available.append(buffer_name)
        return available

    def getprop(self) -> dict[str, str]:
        result = self.run(["shell", "getprop"])
        if result.returncode != 0:
            raise AdbError(result.stderr.strip() or "getprop failed")
        props: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if not line.startswith("["):
                continue
            try:
                key, value = line.split(":", 1)
                key = key.strip()[1:-1]
                value = value.strip().lstrip("[").rstrip("]")
                props[key] = value
            except ValueError:
                continue
        return props

    def read_file(self, path: str) -> str | None:
        result = self.run(["shell", "cat", path])
        if result.returncode != 0:
            return None
        return result.stdout

    def list_files(self, path: str) -> list[str]:
        result = self.run(["shell", "ls", path])
        if result.returncode != 0:
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def shell(self, command: str) -> subprocess.CompletedProcess[str]:
        return self.run(["shell", command])

    def capture_shell_output(self, command: str) -> str | None:
        result = self.shell(command)
        if result.returncode != 0:
            return None
        return result.stdout

    def write_output(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
