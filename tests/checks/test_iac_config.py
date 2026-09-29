from pathlib import Path

from cloudnova.core.engine import Engine


def _ids(root: Path) -> set[str]:
    return {f.check_id for f in Engine().scan_path(root).findings}


def test_public_access_flagged(tmp_yaml):
    p = tmp_yaml("access_control:\n  public: true\n")
    assert "IAC_ACCESS_PUBLIC" in _ids(p)


def test_public_access_false_not_flagged(tmp_yaml):
    p = tmp_yaml("access_control:\n  public: false\n")
    assert "IAC_ACCESS_PUBLIC" not in _ids(p)


def test_missing_password_key_not_flagged(tmp_yaml):
    # A missing key is not evidence of weakness -> no false positive.
    p = tmp_yaml("authentication: {}\n")
    assert "IAC_AUTH_NO_PASSWORD" not in _ids(p)


def test_password_disabled_flagged(tmp_yaml):
    p = tmp_yaml("authentication:\n  password_required: false\n")
    assert "IAC_AUTH_NO_PASSWORD" in _ids(p)


def test_zero_timeout_flagged(tmp_yaml):
    p = tmp_yaml("session:\n  timeout: 0\n")
    assert "IAC_SESSION_NO_TIMEOUT" in _ids(p)


def test_positive_timeout_not_flagged(tmp_yaml):
    p = tmp_yaml("session:\n  timeout: 15\n")
    assert "IAC_SESSION_NO_TIMEOUT" not in _ids(p)
