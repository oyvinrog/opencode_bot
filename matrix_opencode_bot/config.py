"""Environment configuration and workspace path policy."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    if value.lower() in {"1", "true", "yes", "on"}:
        return True
    if value.lower() in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be true or false")


def env_set(name: str) -> frozenset[str]:
    return frozenset(
        value.strip() for value in os.environ.get(name, "").split(",") if value.strip()
    )


def env_positive_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if parsed <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return parsed


@dataclass(frozen=True)
class Settings:
    homeserver: str
    user_id: str
    password: str | None
    data_dir: Path
    allowed_rooms: frozenset[str]
    allowed_senders: frozenset[str]
    auto_join: bool
    require_encryption: bool
    ignore_unverified_devices: bool
    opencode_url: str
    opencode_username: str
    opencode_password: str | None
    default_directory: Path
    allowed_roots: tuple[Path, ...]
    show_reasoning: bool = False
    stuck_timeout_seconds: int = 900
    pursuit_stuck_timeout_seconds: int = 180
    pursuit_tool_timeout_seconds: int = 120
    matrix_edit_interval_seconds: int = 5

    @classmethod
    def from_env(cls) -> "Settings":
        homeserver = os.environ.get("MATRIX_HOMESERVER", "").rstrip("/")
        user_id = os.environ.get("MATRIX_USER_ID", "")
        if not homeserver or not user_id:
            raise ValueError("MATRIX_HOMESERVER and MATRIX_USER_ID are required")

        rooms = env_set("MATRIX_ALLOWED_ROOMS")
        senders = env_set("MATRIX_ALLOWED_SENDERS")
        if not rooms:
            raise ValueError("MATRIX_ALLOWED_ROOMS must contain at least one room ID")
        if not senders:
            raise ValueError("MATRIX_ALLOWED_SENDERS must contain at least one Matrix user ID")

        default_value = os.environ.get("OPENCODE_DEFAULT_DIRECTORY", "")
        roots_value = os.environ.get("OPENCODE_ALLOWED_ROOTS", "")
        if not default_value:
            raise ValueError("OPENCODE_DEFAULT_DIRECTORY is required")
        if not roots_value:
            raise ValueError("OPENCODE_ALLOWED_ROOTS is required")

        default_directory = _existing_directory(Path(default_value), "OPENCODE_DEFAULT_DIRECTORY")
        roots = tuple(
            _existing_directory(Path(value.strip()), "OPENCODE_ALLOWED_ROOTS")
            for value in roots_value.split(os.pathsep)
            if value.strip()
        )
        if not roots:
            raise ValueError("OPENCODE_ALLOWED_ROOTS must contain at least one directory")
        if not any(default_directory.is_relative_to(root) for root in roots):
            raise ValueError("OPENCODE_DEFAULT_DIRECTORY must be inside OPENCODE_ALLOWED_ROOTS")

        data_value = os.environ.get("MATRIX_DATA_DIR") or os.environ.get("ELIZA_DATA_DIR", "./data")
        return cls(
            homeserver=homeserver,
            user_id=user_id,
            password=os.environ.get("MATRIX_PASSWORD"),
            data_dir=Path(data_value),
            allowed_rooms=rooms,
            allowed_senders=senders,
            auto_join=env_bool("MATRIX_AUTO_JOIN", False),
            require_encryption=env_bool("MATRIX_REQUIRE_ENCRYPTION", True),
            ignore_unverified_devices=env_bool("MATRIX_IGNORE_UNVERIFIED_DEVICES", False),
            opencode_url=os.environ.get("OPENCODE_URL", "http://127.0.0.1:4096").rstrip("/"),
            opencode_username=os.environ.get("OPENCODE_SERVER_USERNAME", "opencode"),
            opencode_password=os.environ.get("OPENCODE_SERVER_PASSWORD"),
            default_directory=default_directory,
            allowed_roots=roots,
            show_reasoning=env_bool("MATRIX_SHOW_REASONING", False),
            stuck_timeout_seconds=env_positive_int(
                "OPENCODE_STUCK_TIMEOUT_SECONDS", 900
            ),
            pursuit_stuck_timeout_seconds=env_positive_int(
                "OPENCODE_PURSUE_STUCK_TIMEOUT_SECONDS", 180
            ),
            pursuit_tool_timeout_seconds=env_positive_int(
                "OPENCODE_PURSUE_TOOL_TIMEOUT_SECONDS", 120
            ),
            matrix_edit_interval_seconds=env_positive_int(
                "MATRIX_EDIT_INTERVAL_SECONDS", 5
            ),
        )

    def resolve_directory(self, requested: str | None) -> Path:
        if not requested:
            candidate = self.default_directory
        else:
            path = Path(requested).expanduser()
            candidate = path if path.is_absolute() else self.default_directory / path
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise ValueError(f"Directory does not exist: {candidate}") from exc
        if not resolved.is_dir():
            raise ValueError(f"Not a directory: {resolved}")
        if not any(resolved.is_relative_to(root) for root in self.allowed_roots):
            raise ValueError("Directory is outside OPENCODE_ALLOWED_ROOTS")
        return resolved


def _existing_directory(path: Path, variable: str) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{variable} contains a directory that does not exist: {path}") from exc
    if not resolved.is_dir():
        raise ValueError(f"{variable} contains a non-directory path: {resolved}")
    return resolved
