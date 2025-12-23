from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError


class OutputConfig(BaseModel):
    directory: Path = Field(default=Path("./badlog-output"))
    emit_html: bool = False


class CaptureConfig(BaseModel):
    device_serial: str | None = None
    buffers: list[str] = Field(default_factory=lambda: ["all"])
    format: str = "threadtime"
    ring_size: int = 400
    pre_context: int = 40
    post_context: int = 60


class SuppressionConfig(BaseModel):
    drop_chatty: bool = True
    drop_tags: list[str] = Field(default_factory=list)
    rate_limit_per_minute: int = 0


class RulesConfig(BaseModel):
    files: list[Path] = Field(default_factory=list)


class BadLogConfig(BaseModel):
    output: OutputConfig = Field(default_factory=OutputConfig)
    capture: CaptureConfig = Field(default_factory=CaptureConfig)
    suppression: SuppressionConfig = Field(default_factory=SuppressionConfig)
    rules: RulesConfig = Field(default_factory=RulesConfig)
    verbosity: int = 0


def load_config(path: Path | None) -> BadLogConfig:
    if path is None:
        return BadLogConfig()
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    content = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        data = yaml.safe_load(content) or {}
    else:
        data = json.loads(content)
    try:
        return BadLogConfig.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"Invalid config: {exc}") from exc


def merge_config(base: BadLogConfig, overrides: dict[str, Any]) -> BadLogConfig:
    payload = base.model_dump(mode="python")
    for key, value in overrides.items():
        if value is None:
            continue
        payload[key] = value
    return BadLogConfig.model_validate(payload)
