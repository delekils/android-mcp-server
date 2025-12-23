from pathlib import Path

from badlog.config import load_config


def test_load_config_yaml(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "output:\n  directory: ./out\n"
        "capture:\n  ring_size: 10\n"
        "suppression:\n  drop_chatty: false\n",
        encoding="utf-8",
    )
    config = load_config(config_path)
    assert config.output.directory.name == "out"
    assert config.capture.ring_size == 10
    assert config.suppression.drop_chatty is False
