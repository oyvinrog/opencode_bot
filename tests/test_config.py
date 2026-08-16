import os
from pathlib import Path

import pytest

from matrix_opencode_bot.config import Settings, env_bool, env_positive_int


def configure(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    monkeypatch.setenv("MATRIX_HOMESERVER", "https://matrix.example/")
    monkeypatch.setenv("MATRIX_USER_ID", "@bot:example")
    monkeypatch.setenv("MATRIX_ALLOWED_ROOMS", "!one:example, !two:example")
    monkeypatch.setenv("MATRIX_ALLOWED_SENDERS", "@alice:example")
    monkeypatch.setenv("OPENCODE_DEFAULT_DIRECTORY", str(root))
    monkeypatch.setenv("OPENCODE_ALLOWED_ROOTS", str(root))


def test_settings_parse_required_values(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    configure(monkeypatch, tmp_path)
    settings = Settings.from_env()
    assert settings.homeserver == "https://matrix.example"
    assert settings.allowed_rooms == frozenset({"!one:example", "!two:example"})
    assert settings.allowed_senders == frozenset({"@alice:example"})
    assert settings.opencode_url == "http://127.0.0.1:4096"
    assert settings.show_reasoning is False
    assert settings.stuck_timeout_seconds == 900
    assert settings.pursuit_stuck_timeout_seconds == 180
    assert settings.pursuit_tool_timeout_seconds == 120
    assert settings.matrix_edit_interval_seconds == 5


def test_settings_can_enable_reasoning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    configure(monkeypatch, tmp_path)
    monkeypatch.setenv("MATRIX_SHOW_REASONING", "true")
    assert Settings.from_env().show_reasoning is True


@pytest.mark.parametrize("missing", ["MATRIX_ALLOWED_ROOMS", "MATRIX_ALLOWED_SENDERS"])
def test_security_allowlists_are_required(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, missing: str
) -> None:
    configure(monkeypatch, tmp_path)
    monkeypatch.delenv(missing)
    with pytest.raises(ValueError, match=missing):
        Settings.from_env()


def test_default_must_be_within_allowed_roots(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    default = tmp_path / "default"
    root = tmp_path / "root"
    default.mkdir()
    root.mkdir()
    configure(monkeypatch, default)
    monkeypatch.setenv("OPENCODE_ALLOWED_ROOTS", str(root))
    with pytest.raises(ValueError, match="must be inside"):
        Settings.from_env()


def test_resolve_relative_absolute_and_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    child = tmp_path / "project with spaces"
    child.mkdir()
    configure(monkeypatch, tmp_path)
    settings = Settings.from_env()
    assert settings.resolve_directory("project with spaces") == child.resolve()
    assert settings.resolve_directory(str(child)) == child.resolve()
    assert settings.resolve_directory(None) == tmp_path.resolve()


def test_resolve_rejects_traversal_and_symlink_escape(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    (allowed / "escape").symlink_to(outside, target_is_directory=True)
    configure(monkeypatch, allowed)
    settings = Settings.from_env()
    with pytest.raises(ValueError, match="outside"):
        settings.resolve_directory("../outside")
    with pytest.raises(ValueError, match="outside"):
        settings.resolve_directory("escape")


def test_roots_use_platform_path_separator(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    one = tmp_path / "one"
    two = tmp_path / "two"
    one.mkdir()
    two.mkdir()
    configure(monkeypatch, one)
    monkeypatch.setenv("OPENCODE_ALLOWED_ROOTS", os.pathsep.join((str(one), str(two))))
    assert Settings.from_env().allowed_roots == (one.resolve(), two.resolve())


def test_invalid_boolean(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BAD_BOOL", "perhaps")
    with pytest.raises(ValueError):
        env_bool("BAD_BOOL", True)


def test_stuck_timeout_must_be_positive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    configure(monkeypatch, tmp_path)
    monkeypatch.setenv("OPENCODE_STUCK_TIMEOUT_SECONDS", "120")
    assert Settings.from_env().stuck_timeout_seconds == 120
    for invalid in ("0", "-1", "soon"):
        monkeypatch.setenv("OPENCODE_STUCK_TIMEOUT_SECONDS", invalid)
        with pytest.raises(ValueError, match="positive integer"):
            Settings.from_env()


@pytest.mark.parametrize(
    "name,attribute",
    [
        ("OPENCODE_PURSUE_STUCK_TIMEOUT_SECONDS", "pursuit_stuck_timeout_seconds"),
        ("OPENCODE_PURSUE_TOOL_TIMEOUT_SECONDS", "pursuit_tool_timeout_seconds"),
    ],
)
def test_pursuit_timeouts_must_be_positive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str, attribute: str
) -> None:
    configure(monkeypatch, tmp_path)
    monkeypatch.setenv(name, "42")
    assert getattr(Settings.from_env(), attribute) == 42
    monkeypatch.setenv(name, "0")
    with pytest.raises(ValueError, match="positive integer"):
        Settings.from_env()


def test_matrix_edit_interval_must_be_positive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    configure(monkeypatch, tmp_path)
    monkeypatch.setenv("MATRIX_EDIT_INTERVAL_SECONDS", "8")
    assert Settings.from_env().matrix_edit_interval_seconds == 8
    monkeypatch.setenv("MATRIX_EDIT_INTERVAL_SECONDS", "0")
    with pytest.raises(ValueError, match="positive integer"):
        Settings.from_env()


def test_positive_int_uses_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("UNSET_POSITIVE_INT", raising=False)
    assert env_positive_int("UNSET_POSITIVE_INT", 7) == 7
