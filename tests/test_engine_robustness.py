"""Regression tests: the inputs that crashed the old prototype must NOT crash.

Every case here produced an unhandled 500 in the Flask app. The engine's
contract is that a bad file is reported as an error and the scan continues.
"""

from pathlib import Path

import pytest

from cloudnova.core.engine import Engine


@pytest.mark.parametrize(
    "content, name",
    [
        ("just a bare string", "scalar.yaml"),  # top-level not a dict -> was AttributeError
        ("session:\n  timeout: abc\n", "t.yaml"),  # non-numeric timeout -> was ValueError
        ("{ this is : : not json", "broken.json"),  # malformed JSON -> was JSONDecodeError
        (": : :", "broken.yaml"),  # malformed YAML
        ("", "empty.yaml"),  # empty file
    ],
)
def test_bad_files_never_crash(tmp_path: Path, content: str, name: str):
    (tmp_path / name).write_text(content, encoding="utf-8")
    result = Engine().scan_path(tmp_path)
    # No exception is the assertion; malformed inputs surface as errors, not crashes.
    assert isinstance(result.findings, list)


def test_unsupported_file_is_skipped(tmp_path: Path):
    (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")
    result = Engine().scan_path(tmp_path)
    assert result.files_scanned == 0
    assert result.findings == []


def test_missing_path_yields_empty(tmp_path: Path):
    result = Engine().scan_path(tmp_path / "does-not-exist")
    assert result.findings == []
