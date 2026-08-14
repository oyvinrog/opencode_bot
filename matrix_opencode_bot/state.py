"""Persistent room-to-session state."""

from __future__ import annotations

import asyncio
import json
import os
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class PendingPermission:
    id: str
    title: str
    type: str
    pattern: str = ""
    created: int = 0


@dataclass
class RoomSession:
    session_id: str
    directory: str
    title: str = "OpenCode session"
    in_flight_event_id: str | None = None
    prompt_started_ms: int | None = None
    pending_permissions: list[PendingPermission] = field(default_factory=list)

    # Transient event aggregation fields are deliberately not persisted.
    text_parts: dict[str, str] = field(default_factory=dict, repr=False, compare=False)
    activity: str | None = field(default=None, repr=False, compare=False)
    stop_requested: bool = field(default=False, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "directory": self.directory,
            "title": self.title,
            "in_flight_event_id": self.in_flight_event_id,
            "prompt_started_ms": self.prompt_started_ms,
            "pending_permissions": [asdict(value) for value in self.pending_permissions],
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RoomSession":
        permissions = [
            PendingPermission(**item)
            for item in value.get("pending_permissions", [])
            if isinstance(item, dict) and item.get("id")
        ]
        return cls(
            session_id=str(value["session_id"]),
            directory=str(value["directory"]),
            title=str(value.get("title") or "OpenCode session"),
            in_flight_event_id=value.get("in_flight_event_id"),
            prompt_started_ms=value.get("prompt_started_ms"),
            pending_permissions=permissions,
        )


class StateStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.rooms: dict[str, RoomSession] = {}
        self._lock = asyncio.Lock()

    def load(self) -> None:
        if not self.path.exists():
            return
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        rooms = payload.get("rooms", {}) if isinstance(payload, dict) else {}
        if not isinstance(rooms, dict):
            raise ValueError("Invalid room mapping state")
        self.rooms = {
            str(room_id): RoomSession.from_dict(value)
            for room_id, value in rooms.items()
            if isinstance(value, dict)
        }

    async def save(self) -> None:
        async with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.parent.chmod(stat.S_IRWXU)
            temporary = self.path.with_suffix(self.path.suffix + ".tmp")
            payload = {"version": 1, "rooms": {k: v.to_dict() for k, v in self.rooms.items()}}
            temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            temporary.chmod(stat.S_IRUSR | stat.S_IWUSR)
            os.replace(temporary, self.path)

    async def set(self, room_id: str, state: RoomSession) -> None:
        self.rooms[room_id] = state
        await self.save()

    async def remove(self, room_id: str) -> RoomSession | None:
        value = self.rooms.pop(room_id, None)
        await self.save()
        return value
