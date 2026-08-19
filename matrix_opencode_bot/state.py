"""Persistent room-to-session state."""

from __future__ import annotations

import asyncio
import json
import os
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


PURSUIT_PROTOCOL_VERSION = 2


@dataclass
class PendingPermission:
    id: str
    title: str
    type: str
    pattern: str = ""
    created: int = 0
    session_id: str = ""


@dataclass
class RoomSession:
    session_id: str
    directory: str
    title: str = "OpenCode session"
    in_flight_event_id: str | None = None
    prompt_started_ms: int | None = None
    pending_permissions: list[PendingPermission] = field(default_factory=list)
    yolo_permissions: bool = False
    pending_pursuit_goal: str | None = None
    pending_pursuit_reuse_session: bool = False
    pending_pursuit_yolo_confirmation: bool = False
    pursuit_goal: str | None = None
    pursuit_extent: int = 1
    pursuit_phase: str | None = None
    pursuit_iteration: int = 0
    pursuit_protocol_version: int = PURSUIT_PROTOCOL_VERSION
    pursuit_worker_input_tokens: int = 0
    verifier_session_id: str | None = None
    acceptance_criteria: list[dict[str, str]] = field(default_factory=list)
    pursuit_criteria_status: dict[str, str] = field(default_factory=dict)
    pursuit_assumptions: list[str] = field(default_factory=list)
    pursuit_reflections: list[str] = field(default_factory=list)
    pursuit_evidence: list[dict[str, str]] = field(default_factory=list)
    pursuit_gap: str | None = None
    pursuit_stagnation_count: int = 0
    pursuit_signature: str | None = None
    pursuit_pending_question: str | None = None
    pursuit_protocol_failures: int = 0
    pursuit_retry_attempts: int = 0
    pursuit_last_worker_report: str | None = None
    bump_confirmation_session_id: str | None = None
    bump_confirmation_activity_ms: int | None = None
    manual_bump_pending: bool = False
    manual_bump_attempts: int = 0
    active_tools: dict[str, dict[str, Any]] = field(default_factory=dict)
    recovery_reason: str | None = None
    recovery_tool: str | None = None
    recovery_session_id: str | None = None
    watchdog_recovery_pending: bool = False
    watchdog_recovery_attempts: int = 0

    # Transient event aggregation fields are deliberately not persisted.
    text_parts: dict[str, str] = field(default_factory=dict, repr=False, compare=False)
    reasoning_parts: dict[str, str] = field(default_factory=dict, repr=False, compare=False)
    message_roles: dict[str, str] = field(default_factory=dict, repr=False, compare=False)
    part_message_ids: dict[str, str] = field(default_factory=dict, repr=False, compare=False)
    activity: str | None = field(default=None, repr=False, compare=False)
    activity_history: list[str] = field(default_factory=list, repr=False, compare=False)
    plan_items: list[tuple[str, str]] = field(default_factory=list, repr=False, compare=False)
    stop_requested: bool = field(default=False, repr=False, compare=False)
    last_activity_ms: int | None = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "directory": self.directory,
            "title": self.title,
            "in_flight_event_id": self.in_flight_event_id,
            "prompt_started_ms": self.prompt_started_ms,
            "pending_permissions": [asdict(value) for value in self.pending_permissions],
            "yolo_permissions": self.yolo_permissions,
            "pending_pursuit_goal": self.pending_pursuit_goal,
            "pending_pursuit_reuse_session": self.pending_pursuit_reuse_session,
            "pending_pursuit_yolo_confirmation": (
                self.pending_pursuit_yolo_confirmation
            ),
            "pursuit_goal": self.pursuit_goal,
            "pursuit_extent": self.pursuit_extent,
            "pursuit_phase": self.pursuit_phase,
            "pursuit_iteration": self.pursuit_iteration,
            "pursuit_protocol_version": self.pursuit_protocol_version,
            "pursuit_worker_input_tokens": self.pursuit_worker_input_tokens,
            "verifier_session_id": self.verifier_session_id,
            "acceptance_criteria": self.acceptance_criteria,
            "pursuit_criteria_status": self.pursuit_criteria_status,
            "pursuit_assumptions": self.pursuit_assumptions,
            "pursuit_reflections": self.pursuit_reflections,
            "pursuit_evidence": self.pursuit_evidence,
            "pursuit_gap": self.pursuit_gap,
            "pursuit_stagnation_count": self.pursuit_stagnation_count,
            "pursuit_signature": self.pursuit_signature,
            "pursuit_pending_question": self.pursuit_pending_question,
            "pursuit_protocol_failures": self.pursuit_protocol_failures,
            "pursuit_retry_attempts": self.pursuit_retry_attempts,
            "pursuit_last_worker_report": self.pursuit_last_worker_report,
            "bump_confirmation_session_id": self.bump_confirmation_session_id,
            "bump_confirmation_activity_ms": self.bump_confirmation_activity_ms,
            "manual_bump_pending": self.manual_bump_pending,
            "manual_bump_attempts": self.manual_bump_attempts,
            "active_tools": self.active_tools,
            "recovery_reason": self.recovery_reason,
            "recovery_tool": self.recovery_tool,
            "recovery_session_id": self.recovery_session_id,
            "watchdog_recovery_pending": self.watchdog_recovery_pending,
            "watchdog_recovery_attempts": self.watchdog_recovery_attempts,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RoomSession":
        permissions = [
            PendingPermission(**item)
            for item in value.get("pending_permissions", [])
            if isinstance(item, dict) and item.get("id")
        ]
        legacy_goal = value.get("obsess_goal")
        pursuit_goal = value.get("pursuit_goal") or legacy_goal
        pursuit_phase = value.get("pursuit_phase")
        if pursuit_goal and not pursuit_phase:
            # Resume old unconditional loops through the new verifier-backed workflow.
            pursuit_phase = "working" if value.get("in_flight_event_id") else "specifying"
        return cls(
            session_id=str(value["session_id"]),
            directory=str(value["directory"]),
            title=str(value.get("title") or "OpenCode session"),
            in_flight_event_id=value.get("in_flight_event_id"),
            prompt_started_ms=value.get("prompt_started_ms"),
            pending_permissions=permissions,
            yolo_permissions=bool(value.get("yolo_permissions", False)),
            pending_pursuit_goal=(
                str(value["pending_pursuit_goal"])
                if value.get("pending_pursuit_goal")
                else None
            ),
            pending_pursuit_reuse_session=bool(
                value.get("pending_pursuit_reuse_session", False)
            ),
            pending_pursuit_yolo_confirmation=bool(
                value.get("pending_pursuit_yolo_confirmation", False)
            ),
            pursuit_goal=str(pursuit_goal) if pursuit_goal else None,
            pursuit_extent=_pursuit_extent(value.get("pursuit_extent")),
            pursuit_phase=str(pursuit_phase) if pursuit_phase else None,
            pursuit_iteration=int(
                value.get("pursuit_iteration") or value.get("obsess_iteration") or 0
            ),
            pursuit_protocol_version=int(
                value.get("pursuit_protocol_version")
                or (1 if pursuit_goal else PURSUIT_PROTOCOL_VERSION)
            ),
            pursuit_worker_input_tokens=int(
                value.get("pursuit_worker_input_tokens") or 0
            ),
            verifier_session_id=(
                str(value["verifier_session_id"])
                if value.get("verifier_session_id")
                else None
            ),
            acceptance_criteria=_criteria(value.get("acceptance_criteria")),
            pursuit_criteria_status={
                str(key): str(status)
                for key, status in (value.get("pursuit_criteria_status") or {}).items()
                if status in {"pass", "fail", "unknown"}
            }
            if isinstance(value.get("pursuit_criteria_status"), dict)
            else {},
            pursuit_assumptions=_string_list(value.get("pursuit_assumptions")),
            pursuit_reflections=_string_list(value.get("pursuit_reflections")),
            pursuit_evidence=_evidence(value.get("pursuit_evidence")),
            pursuit_gap=str(value["pursuit_gap"]) if value.get("pursuit_gap") else None,
            pursuit_stagnation_count=int(value.get("pursuit_stagnation_count") or 0),
            pursuit_signature=(
                str(value["pursuit_signature"])
                if value.get("pursuit_signature")
                else None
            ),
            pursuit_pending_question=(
                str(value["pursuit_pending_question"])
                if value.get("pursuit_pending_question")
                else None
            ),
            pursuit_protocol_failures=int(value.get("pursuit_protocol_failures") or 0),
            pursuit_retry_attempts=int(value.get("pursuit_retry_attempts") or 0),
            pursuit_last_worker_report=(
                str(value["pursuit_last_worker_report"])
                if value.get("pursuit_last_worker_report")
                else None
            ),
            bump_confirmation_session_id=(
                str(value["bump_confirmation_session_id"])
                if value.get("bump_confirmation_session_id")
                else None
            ),
            bump_confirmation_activity_ms=value.get("bump_confirmation_activity_ms"),
            manual_bump_pending=bool(value.get("manual_bump_pending", False)),
            manual_bump_attempts=int(value.get("manual_bump_attempts") or 0),
            active_tools=_active_tools(value.get("active_tools")),
            recovery_reason=(
                str(value["recovery_reason"]) if value.get("recovery_reason") else None
            ),
            recovery_tool=(
                str(value["recovery_tool"]) if value.get("recovery_tool") else None
            ),
            recovery_session_id=(
                str(value["recovery_session_id"])
                if value.get("recovery_session_id")
                else None
            ),
            watchdog_recovery_pending=bool(
                value.get("watchdog_recovery_pending", False)
            ),
            watchdog_recovery_attempts=int(
                value.get("watchdog_recovery_attempts") or 0
            ),
        )


def _pursuit_extent(value: Any) -> int:
    try:
        extent = int(value or 1)
    except (TypeError, ValueError):
        return 1
    return extent if extent in {1, 2, 3} else 1


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
            payload = {"version": 3, "rooms": {k: v.to_dict() for k, v in self.rooms.items()}}
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


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _criteria(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        criterion_id = item.get("id")
        text = item.get("text")
        if (
            isinstance(criterion_id, str)
            and criterion_id.strip()
            and isinstance(text, str)
            and text.strip()
        ):
            result.append({"id": criterion_id.strip(), "text": text.strip()})
    return result


def _evidence(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        fields = {
            key: item.get(key)
            for key in ("criterion_id", "claim", "source", "verification")
        }
        if all(isinstance(field, str) and field.strip() for field in fields.values()):
            result.append({key: str(field).strip() for key, field in fields.items()})
    return result


def _active_tools(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for part_id, tool in value.items():
        if not isinstance(tool, dict) or not tool.get("name"):
            continue
        result[str(part_id)] = {
            "name": str(tool["name"]),
            "started_ms": int(tool.get("started_ms") or 0),
        }
    return result
