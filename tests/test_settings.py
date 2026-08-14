from pathlib import Path

import pytest

from matrix_eliza_bot.bot import Settings, env_bool


def test_settings_require_core_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MATRIX_HOMESERVER", raising=False)
    monkeypatch.delenv("MATRIX_USER_ID", raising=False)
    with pytest.raises(ValueError):
        Settings.from_env()


def test_settings_parse_rooms(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MATRIX_HOMESERVER", "https://matrix.example/")
    monkeypatch.setenv("MATRIX_USER_ID", "@eliza:example")
    monkeypatch.setenv("MATRIX_ALLOWED_ROOMS", "!one:example, !two:example")
    settings = Settings.from_env()
    assert settings.homeserver == "https://matrix.example"
    assert settings.allowed_rooms == frozenset({"!one:example", "!two:example"})
    assert settings.data_dir == Path("./data")


def test_invalid_boolean(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BAD_BOOL", "perhaps")
    with pytest.raises(ValueError):
        env_bool("BAD_BOOL", True)

