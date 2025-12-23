from __future__ import annotations

import logging


class ContextFilter(logging.Filter):
    def __init__(self, device_serial: str | None) -> None:
        super().__init__()
        self.device_serial = device_serial

    def filter(self, record: logging.LogRecord) -> bool:
        record.device_serial = self.device_serial or "auto"
        return True


def setup_logging(verbosity: int, device_serial: str | None) -> None:
    level = logging.INFO if verbosity == 0 else logging.DEBUG
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(device_serial)s] %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logging.basicConfig(level=level, handlers=[handler])
    logging.getLogger().addFilter(ContextFilter(device_serial))
