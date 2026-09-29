"""Shared test fixtures."""

from pathlib import Path

import pytest


@pytest.fixture
def tmp_yaml(tmp_path: Path):
    def _write(content: str, name: str = "config.yaml") -> Path:
        p = tmp_path / name
        p.write_text(content, encoding="utf-8")
        return p

    return _write
