"""Encrypted Matrix bot that exposes OpenCode sessions to authorized rooms."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import difflib
import getpass
import json
import logging
import mimetypes
import os
import platform
import re
import stat
import tempfile
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from nio import (
    AsyncClient,
    AsyncClientConfig,
    InviteMemberEvent,
    LoginResponse,
    MatrixRoom,
    RoomMessageText,
)
from nio.exceptions import OlmUnverifiedDeviceError

from .config import Settings
from .opencode import OpenCodeClient, OpenCodeError
from .state import PURSUIT_PROTOCOL_VERSION, PendingPermission, RoomSession, StateStore

LOG = logging.getLogger("matrix_opencode")
MAX_MESSAGE_CHARS = 20_000
MAX_REASONING_CHARS = 8_000
WATCHDOG_POLL_SECONDS = 30.0
WATCHDOG_CONTINUATION = (
    "The previous turn was automatically interrupted because it produced no activity for "
    "the configured watchdog timeout. Continue the user's unfinished task from the existing "
    "session context. First inspect the current state, preserve completed work, and avoid "
    "repeating completed or side-effectful actions."
)
MANUAL_BUMP_CONTINUATION = (
    "The user manually interrupted the previous turn because it appeared stalled. Continue the "
    "unfinished task from the existing session context. First inspect the current state, preserve "
    "completed work, and avoid repeating completed or side-effectful actions."
)
CONTROL_PATTERN = re.compile(
    r"<pursuit-control>\s*(\{.*?\})\s*</pursuit-control>", re.DOTALL
)
VERIFIER_SYSTEM = """You are an independent, evidence-driven verifier. Do not edit files,
delegate work, or perform consequential actions. You may inspect files, run non-mutating checks,
and search/fetch the web. Prefer objective external evidence over the worker's assertions. For web
research, check identity, relevance, recency, authoritative or primary sources, claim coverage, and
contradictory evidence; one decisive primary source can be sufficient. For code, independently
inspect state and run applicable checks. For qualitative work, use the frozen rubric and distinguish
facts from inference. Difficulty is not a reason to stop. Return exactly one tagged JSON control
envelope in the requested schema and no text outside it."""
VERIFIER_TOOLS = {"write": False, "edit": False, "apply_patch": False, "task": False}
PURSUIT_WORKER_TOOLS = {"task": False}


def _pursuit_extent_instruction(extent: int) -> str:
    if extent == 3:
        return (
            "Exhaustive coverage. Build and maintain a systematic map of every plausible search "
            "space, interpretation, lead, alternative, and contradictory source. Do not accept a "
            "merely sufficient answer: continue until each plausible avenue is either checked or "
            "documented as inaccessible after concrete attempts. This mode may run for hours."
        )
    if extent == 2:
        return (
            "Broad coverage. Go beyond the first sufficient answer: investigate the main "
            "alternatives, likely edge cases, independent sources, and contradictory evidence. "
            "Complete only when the important plausible avenues have been checked."
        )
    return (
        "Goal-directed coverage. Satisfy every mandatory acceptance criterion with reliable "
        "evidence, then complete without requiring an unnecessary survey of marginal avenues."
    )


HELP = """Matrix–OpenCode commands:
!new [directory] — start a session
Ordinary messages — prompt the current session, creating one if needed
!pursue <goal> — choose permission mode and search depth, then pursue until verified or !stop
!status — show current activity
!diagnose — write a detailed DIAGNOSIS.txt in the session directory
!bump [confirm|cancel] — inspect inactivity and optionally restart a stalled turn
!send <filename> — find and send a file from the session directory
!yolo off — disable session-scoped automatic permission approval
!diff — show changed files
!stop — stop a pursuit and abort the current operation
!reset — discard the room-to-session mapping
!help — show this message"""

SESSION_REMINDER = (
    "Commands: !new [directory], !pursue <goal>, !status, !diagnose, !bump, !send, !diff, "
    "!yolo off, !stop, !reset, !help"
)
STARTUP_LOGO_PATH = Path(__file__).with_name("assets") / "openbot-logo.png"
STARTUP_LOGO_WIDTH = 1280
STARTUP_LOGO_HEIGHT = 720

DIAGNOSTIC_SECRET_KEY = re.compile(
    r"(^|[_-])(access[_-]?token|authorization|cookie|credential|password|secret|api[_-]?key)($|[_-])",
    re.IGNORECASE,
)
DIAGNOSTIC_SECRET_VALUE = re.compile(
    r"(?i)\b(password|token|secret|api[_-]?key|authorization)(\s*[:=]\s*)([^\s,;]+)"
)


class MatrixOpenCodeBot:
    def __init__(
        self,
        client: AsyncClient,
        settings: Settings,
        opencode: OpenCodeClient,
        store: StateStore,
    ) -> None:
        self.client = client
        self.settings = settings
        self.opencode = opencode
        self.store = store
        self.started_ms = int(time.time() * 1000)
        self.stop_events = asyncio.Event()
        self.room_locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self.edit_tasks: dict[str, asyncio.Task[None]] = {}
        self.retry_tasks: dict[str, asyncio.Task[None]] = {}
        self.last_edit: dict[str, float] = {}
        self.watchdog_task: asyncio.Task[None] | None = None
        self.diagnostic_events: defaultdict[str, deque[dict[str, Any]]] = defaultdict(
            lambda: deque(maxlen=200)
        )

    def room_allowed(self, room: MatrixRoom) -> bool:
        return room.room_id in self.settings.allowed_rooms

    async def on_invite(self, room: MatrixRoom, event: InviteMemberEvent) -> None:
        if event.state_key != self.client.user_id:
            return
        if not self.settings.auto_join:
            LOG.info("Invited to %s; auto-join is disabled", room.room_id)
            return
        if room.room_id not in self.settings.allowed_rooms:
            LOG.warning("Ignoring invite outside MATRIX_ALLOWED_ROOMS: %s", room.room_id)
            return
        response = await self.client.join(room.room_id)
        LOG.info("Join response for %s: %s", room.room_id, response)

    async def on_message(self, room: MatrixRoom, event: RoomMessageText) -> None:
        if event.sender == self.client.user_id or event.server_timestamp < self.started_ms:
            return
        if not self.room_allowed(room):
            return
        if event.sender not in self.settings.allowed_senders:
            LOG.warning("Ignoring unauthorized sender %s in %s", event.sender, room.room_id)
            return
        if self.settings.require_encryption and (not room.encrypted or not event.decrypted):
            LOG.warning("Ignoring unencrypted message in room %s", room.room_id)
            return

        body = event.body.strip()
        if not body:
            return
        async with self.room_locks[room.room_id]:
            await self._dispatch(room.room_id, body)

    async def _dispatch(self, room_id: str, body: str) -> None:
        command, _, argument = body.partition(" ")
        command = command.lower()
        try:
            state = self.store.rooms.get(room_id)
            has_pending_permission = bool(state and state.pending_permissions)
            if command in {"y", "n"} and not argument and has_pending_permission:
                await self.command_permission(room_id, "once" if command == "y" else "reject")
            elif command == "yolo" and not argument and has_pending_permission:
                await self.command_yolo(room_id)
            elif command == "!help":
                await self.send_text(room_id, HELP)
            elif command == "!new":
                await self.command_new(room_id, argument.strip() or None)
            elif command == "!status":
                await self.command_status(room_id)
            elif command == "!diagnose":
                await self.command_diagnose(room_id)
            elif command == "!bump":
                await self.command_bump(room_id, argument.strip().lower())
            elif command == "!pursue":
                await self.command_pursue(room_id, argument.strip())
            elif command == "!allow":
                await self.command_permission(room_id, "once")
            elif command == "!deny":
                await self.command_permission(room_id, "reject")
            elif command == "!yolo":
                await self.command_yolo_setting(room_id, argument.strip().lower())
            elif command == "!diff":
                await self.command_diff(room_id)
            elif command == "!send":
                await self.command_send(room_id, argument.strip())
            elif command == "!stop":
                await self.command_stop(room_id)
            elif command == "!reset":
                await self.command_reset(room_id)
            elif command.startswith("!"):
                await self.send_text(room_id, "Unknown command. Try !help.")
            else:
                await self.prompt(room_id, body)
        except OpenCodeError as exc:
            LOG.warning("OpenCode command failed in %s: %s", room_id, exc)
            await self.send_text(room_id, f"OpenCode error: {exc}")

    @staticmethod
    def _active_session_id(state: RoomSession) -> str:
        if state.pursuit_phase in {"specifying", "verifying"} and state.verifier_session_id:
            return state.verifier_session_id
        return state.session_id

    def _stuck_timeout_seconds(self, state: RoomSession) -> int:
        if state.pursuit_goal:
            return self.settings.pursuit_stuck_timeout_seconds
        return self.settings.stuck_timeout_seconds

    @staticmethod
    def _oldest_active_tool(state: RoomSession) -> tuple[str, int] | None:
        tools = [
            (str(value.get("name") or "tool"), _integer(value.get("started_ms")))
            for value in state.active_tools.values()
            if isinstance(value, dict) and _integer(value.get("started_ms")) > 0
        ]
        return min(tools, key=lambda item: item[1]) if tools else None

    async def _status(
        self, state: RoomSession, session_id: str | None = None
    ) -> dict[str, Any]:
        statuses = await self.opencode.session_status(state.directory)
        status = statuses.get(session_id or self._active_session_id(state), {"type": "idle"})
        return status if isinstance(status, dict) else {"type": "unknown"}

    async def command_new(self, room_id: str, requested: str | None) -> None:
        current = self.store.rooms.get(room_id)
        if current and (
            current.pending_pursuit_goal
            or current.pursuit_goal
            or current.in_flight_event_id
            or (await self._status(current)).get("type") != "idle"
        ):
            await self.send_text(room_id, "The current session is busy. Use !stop before !new.")
            return
        try:
            state = await self._create_room_session(room_id, requested)
        except ValueError as exc:
            await self.send_text(room_id, f"Cannot start session: {exc}")
            return
        await self.send_text(
            room_id,
            f"Started OpenCode session {state.session_id}\nDirectory: {state.directory}"
            f"\n\n{SESSION_REMINDER}",
        )

    async def _create_room_session(
        self, room_id: str, requested: str | None = None
    ) -> RoomSession:
        directory = self.settings.resolve_directory(requested)
        session = await self.opencode.create_session(
            str(directory), title="Matrix OpenCode session"
        )
        state = RoomSession(
            session_id=str(session["id"]),
            directory=str(directory),
            title=str(session.get("title") or "Matrix OpenCode session"),
        )
        await self.store.set(room_id, state)
        return state

    async def prompt(self, room_id: str, text: str) -> None:
        state = self.store.rooms.get(room_id)
        created = state is None
        if not state:
            try:
                state = await self._create_room_session(room_id)
            except ValueError as exc:
                await self.send_text(room_id, f"Cannot automatically start session: {exc}")
                return
        if state.pending_pursuit_goal:
            if state.pending_pursuit_yolo_confirmation:
                await self._select_pursuit_yolo(room_id, state, text)
            else:
                await self._select_pursuit_extent(room_id, state, text)
            return
        if state.pursuit_goal and state.pursuit_phase == "waiting_input":
            await self._resume_pursuit_with_input(room_id, state, text)
            return
        status = await self._status(state)
        if state.pursuit_goal or state.in_flight_event_id or status.get("type") != "idle":
            await self.send_text(room_id, "This session is busy. Wait for it to finish or use !stop.")
            return

        if created:
            await self.send_text(
                room_id,
                f"Started OpenCode session {state.session_id}\nDirectory: {state.directory}"
                f"\n\n{SESSION_REMINDER}",
            )

        state.watchdog_recovery_pending = False
        state.watchdog_recovery_attempts = 0
        await self._submit_prompt(room_id, state, text)

    async def _submit_prompt(
        self,
        room_id: str,
        state: RoomSession,
        text: str,
        *,
        session_id: str | None = None,
        system: str | None = None,
        tools: dict[str, bool] | None = None,
    ) -> bool:
        """Submit one pass after the caller has established that the session is idle."""

        if state.pursuit_goal:
            phase = (state.pursuit_phase or "working").replace("ing", "")
            label = f"Pursuing… {phase}, pass {state.pursuit_iteration}"
        else:
            label = "Working…"
        event_id = await self.send_text(room_id, label)
        if not event_id:
            LOG.error("Not submitting prompt because the Matrix progress message could not be sent")
            return False
        state.in_flight_event_id = event_id
        state.prompt_started_ms = int(time.time() * 1000)
        state.last_activity_ms = state.prompt_started_ms
        state.text_parts.clear()
        state.reasoning_parts.clear()
        state.message_roles.clear()
        state.part_message_ids.clear()
        state.activity = "starting"
        state.activity_history.clear()
        state.plan_items.clear()
        state.active_tools.clear()
        state.stop_requested = False
        self._clear_bump_confirmation(state)
        self._clear_recovery(state)
        await self.store.save()
        try:
            target = session_id or state.session_id
            if system or tools:
                await self.opencode.prompt_async(
                    target, state.directory, text, system=system, tools=tools
                )
            else:
                await self.opencode.prompt_async(target, state.directory, text)
        except OpenCodeError as exc:
            await self.send_edit(room_id, event_id, f"OpenCode error: {exc}")
            self._clear_in_flight(state)
            if state.pursuit_goal:
                state.pursuit_retry_attempts += 1
                self._schedule_pursuit_retry(room_id, state)
            await self.store.save()
            return False
        if state.pursuit_retry_attempts:
            state.pursuit_retry_attempts = 0
            await self.store.save()
        return True

    def _schedule_pursuit_retry(self, room_id: str, state: RoomSession) -> None:
        current = self.retry_tasks.get(room_id)
        if current and not current.done():
            return
        delay = min(30, 2 ** min(state.pursuit_retry_attempts - 1, 5))

        async def retry() -> None:
            await asyncio.sleep(delay)
            async with self.room_locks[room_id]:
                if state.pursuit_goal and not state.in_flight_event_id:
                    await self._resume_pursuit_phase(room_id, state)

        self.retry_tasks[room_id] = asyncio.create_task(retry())

    async def command_pursue(self, room_id: str, goal: str) -> None:
        if not goal:
            await self.send_text(room_id, "Usage: !pursue <goal>")
            return
        state = self.store.rooms.get(room_id)
        created = state is None
        if not state:
            try:
                state = await self._create_room_session(room_id)
            except ValueError as exc:
                await self.send_text(room_id, f"Cannot automatically start session: {exc}")
                return
        if state.pending_pursuit_goal:
            awaiting = (
                "its YOLO choice. Reply y or n"
                if state.pending_pursuit_yolo_confirmation
                else "its extent choice. Reply 1, 2, or 3"
            )
            await self.send_text(
                room_id,
                f"A pursuit is awaiting {awaiting}, or use !stop.",
            )
            return
        if state.pursuit_goal:
            await self.send_text(
                room_id, "A pursuit is already active. Use !stop before starting another."
            )
            return
        status = await self._status(state)
        if state.in_flight_event_id or status.get("type") != "idle":
            await self.send_text(room_id, "This session is busy. Wait for it to finish or use !stop.")
            return
        state.pending_pursuit_goal = goal
        state.pending_pursuit_reuse_session = created
        state.pending_pursuit_yolo_confirmation = True
        await self.store.save()
        if created:
            await self.send_text(
                room_id,
                f"Started OpenCode session {state.session_id}\nDirectory: {state.directory}"
                f"\n\n{SESSION_REMINDER}",
            )
        await self._ask_pursuit_yolo(room_id)

    async def _ask_pursuit_yolo(self, room_id: str, *, retry: bool = False) -> None:
        introduction = (
            "Please reply with y or n."
            if retry
            else "Use YOLO mode for this pursuit? Reply y or n."
        )
        await self.send_text(
            room_id,
            f"{introduction}\n"
            "y — automatically approve future permission requests for the entire mapped "
            "session, including pursuit worker and verifier sessions; this survives bot "
            "restarts.\n"
            "n — disable YOLO and prompt for each permission request.\n\n"
            "Use !stop to cancel.",
        )

    async def _ask_pursuit_extent(
        self, room_id: str, *, permission_mode: str | None = None
    ) -> None:
        prefix = f"Permission mode set to {permission_mode}.\n\n" if permission_mode else ""
        await self.send_text(
            room_id,
            prefix
            + (
                "How extensive should this pursuit be? Reply with a number:\n"
                "1 — Reach the goal: stop once every acceptance criterion is evidenced.\n"
                "2 — Turn most stones: search broadly, test alternatives, and check "
                "contradictions.\n"
                "3 — Exhaustive (\u201cautistic mode\u201d): systematically turn every plausible "
                "stone; this may run for hours.\n\nUse !stop to cancel."
            ),
        )

    async def _select_pursuit_yolo(
        self, room_id: str, state: RoomSession, response: str
    ) -> None:
        choice = response.strip().lower()
        if choice not in {"y", "n"}:
            await self._ask_pursuit_yolo(room_id, retry=True)
            return
        state.yolo_permissions = choice == "y"
        state.pending_pursuit_yolo_confirmation = False
        await self.store.save()
        mode = "YOLO (auto-approve)" if state.yolo_permissions else "prompt"
        await self._ask_pursuit_extent(room_id, permission_mode=mode)

    async def _select_pursuit_extent(
        self, room_id: str, state: RoomSession, response: str
    ) -> None:
        choice = response.strip()
        if choice not in {"1", "2", "3"}:
            await self.send_text(
                room_id,
                "Please reply with 1 (reach the goal), 2 (turn most stones), or "
                "3 (systematically turn every plausible stone). Use !stop to cancel.",
            )
            return
        goal = state.pending_pursuit_goal
        if not goal:
            return
        status = await self._status(state)
        if state.in_flight_event_id or status.get("type") != "idle":
            await self.send_text(room_id, "This session became busy. Use !stop and try again.")
            return
        reuse_session = state.pending_pursuit_reuse_session
        if not reuse_session:
            # A pursuit should not inherit an arbitrarily large or previously poisoned chat
            # transcript. The goal and durable pursuit state are the context it actually needs.
            worker = await self.opencode.create_session(
                state.directory, title="Matrix OpenCode pursuit worker"
            )
            state.session_id = str(worker["id"])
            state.title = str(worker.get("title") or state.title)
        verifier = await self.opencode.create_session(
            state.directory, title="Matrix pursuit verifier"
        )
        self._clear_pursuit(state)
        self._clear_bump_confirmation(state)
        state.manual_bump_pending = False
        state.watchdog_recovery_pending = False
        state.watchdog_recovery_attempts = 0
        state.pursuit_goal = goal
        state.pursuit_extent = int(choice)
        state.pursuit_phase = "specifying"
        state.verifier_session_id = str(verifier["id"])
        await self.store.save()
        await self.send_text(room_id, f"Pursuit extent set to {choice}/3.")
        await self._submit_verifier(room_id, state, self._specification_prompt(state))

    async def _submit_verifier(
        self, room_id: str, state: RoomSession, prompt: str
    ) -> bool:
        if not state.verifier_session_id:
            verifier = await self.opencode.create_session(
                state.directory, title="Matrix pursuit verifier"
            )
            state.verifier_session_id = str(verifier["id"])
            await self.store.save()
        return await self._submit_prompt(
            room_id,
            state,
            prompt,
            session_id=state.verifier_session_id,
            system=VERIFIER_SYSTEM,
            tools=VERIFIER_TOOLS,
        )

    @staticmethod
    def _specification_prompt(state: RoomSession) -> str:
        clarification = "\n".join(state.pursuit_assumptions[-5:]) or "None"
        extent = _pursuit_extent_instruction(state.pursuit_extent)
        return f"""Define a stable acceptance contract for this goal:

{state.pursuit_goal}

User clarifications already received:
{clarification}

Requested pursuit extent ({state.pursuit_extent}/3):
{extent}

Infer harmless details. Ask for input only if a missing fact would materially change the result.
Return exactly one tagged JSON object with this shape:
<pursuit-control>{{"type":"contract","criteria":["<concrete criterion derived from the goal>"],"assumptions":["<explicit harmless assumption, or use an empty array>"],"needs_input":false,"question":null}}</pursuit-control>
Replace every angle-bracketed instruction with goal-specific content; copied placeholders make the
contract invalid. Criteria must be task-aware, mandatory, and objectively checkable where possible.
The contract must encode the requested extent: levels 2 and 3 require a mandatory breadth or
exhaustion criterion that cannot pass on merely sufficient goal evidence. Normally provide 2-6
non-overlapping criteria. Do not perform the task yet."""

    @staticmethod
    def _worker_prompt(state: RoomSession, *, reset: bool = False) -> str:
        criteria = "\n".join(
            f"- [{item['id']}] {item['text']}" for item in state.acceptance_criteria
        )
        assumptions = "\n".join(f"- {item}" for item in state.pursuit_assumptions) or "- None"
        reflections = "\n".join(f"- {item}" for item in state.pursuit_reflections[-6:]) or "- None"
        evidence = "\n".join(
            f"- [{item['criterion_id']}] {item['claim']} (source: {item['source']}; "
            f"verified: {item['verification']})"
            for item in state.pursuit_evidence[-8:]
        ) or "- None"
        reset_text = (
            "This is a fresh context after stagnation or context rotation. Preserve the durable "
            "evidence above and do not repeat failed approaches."
            if reset
            else "Continue from the existing session state."
        )
        extent = _pursuit_extent_instruction(state.pursuit_extent)
        return f"""Pursue this goal and make concrete progress in this pass:

{state.pursuit_goal}

Requested pursuit extent ({state.pursuit_extent}/3):
{extent}

Frozen mandatory acceptance criteria:
{criteria}

Assumptions and user clarifications:
{assumptions}

Verified evidence so far:
{evidence}

Verifier feedback and failed approaches:
{reflections}

Current unresolved gap: {state.pursuit_gap or "Start with the highest-value unresolved criterion."}
{reset_text}

Act, observe real tool or source feedback, and verify your own work. Do not declare the overall
goal complete; the separate verifier decides that. End with a concise report containing actions,
new evidence, unresolved gaps, and failures. For research, include direct source URLs and separate
sourced facts from inference. Keep tool calls small, bounded, and independently checkable. Never
combine web research, parsing, and deliverable creation in one giant shell or Python command. Give
shell and network operations explicit timeouts, and prefer dedicated search/fetch/write tools.
Delegated task or subagent calls are disabled for pursuit workers; perform each step directly."""

    async def _submit_worker(
        self, room_id: str, state: RoomSession, *, reset: bool = False
    ) -> bool:
        return await self._submit_prompt(
            room_id,
            state,
            self._worker_prompt(state, reset=reset),
            tools=PURSUIT_WORKER_TOOLS,
        )

    @staticmethod
    def _verification_prompt(state: RoomSession) -> str:
        criteria = "\n".join(
            f"- [{item['id']}] {item['text']}" for item in state.acceptance_criteria
        )
        assumptions = "\n".join(f"- {item}" for item in state.pursuit_assumptions) or "- None"
        prior_evidence = "\n".join(
            f"- [{item['criterion_id']}] {item['claim']} (source: {item['source']}; "
            f"verified: {item['verification']})"
            for item in state.pursuit_evidence[-12:]
        ) or "- None"
        prior_feedback = "\n".join(f"- {item}" for item in state.pursuit_reflections[-6:]) or "- None"
        extent = _pursuit_extent_instruction(state.pursuit_extent)
        return f"""Independently evaluate the latest worker pass against the frozen contract.

Goal: {state.pursuit_goal}

Requested pursuit extent ({state.pursuit_extent}/3):
{extent}

Mandatory criteria:
{criteria}

Assumptions and user clarifications:
{assumptions}

Previously verified evidence:
{prior_evidence}

Prior verifier feedback:
{prior_feedback}

Worker report (claims are not evidence until independently checked):
{state.pursuit_last_worker_report or "No report was recovered."}

Use available read-only tools and external sources to check material claims. `complete` is valid only
when every mandatory criterion passes with concrete, independently checked evidence. Return each
criterion ID exactly once; never repeat or rewrite criterion text. Every `pass` needs at least one
evidence record with a specific claim, a direct source URL/file/check, and what you independently
did to verify it. A search suggestion, generic contact title, guessed address, or market benchmark
that does not prove the criterion is not passing evidence. Use `needs_input` only for a material
user fact or action; difficulty means `continue`.
Return exactly:
<pursuit-control>{{"type":"verdict","verdict":"complete|continue|needs_input","criteria":[{{"id":"c1","status":"pass|fail|unknown","evidence":[{{"claim":"specific fact","source":"direct URL, file path, or executed check","verification":"how it was independently checked"}}]}}],"feedback":"specific next strategy","gap":"most important unresolved gap or empty","question":null}}</pursuit-control>"""

    async def _resume_pursuit_with_input(
        self, room_id: str, state: RoomSession, text: str
    ) -> None:
        state.pursuit_assumptions.append(f"User clarification: {text}")
        del state.pursuit_assumptions[:-12]
        state.pursuit_pending_question = None
        if state.acceptance_criteria:
            state.pursuit_phase = "working"
            state.pursuit_iteration += 1
            await self.store.save()
            await self._submit_worker(room_id, state)
        else:
            state.pursuit_phase = "specifying"
            await self.store.save()
            await self._submit_verifier(room_id, state, self._specification_prompt(state))

    async def _handle_pursuit_idle(
        self, room_id: str, state: RoomSession, raw: str
    ) -> None:
        phase = state.pursuit_phase
        if phase == "working":
            state.pursuit_last_worker_report = raw[-16_000:]
            await self._capture_worker_input_tokens(state)
            await self.finalize(room_id, state, raw)
            if not state.acceptance_criteria:
                state.pursuit_phase = "specifying"
                await self.store.save()
                await self._submit_verifier(room_id, state, self._specification_prompt(state))
                return
            state.pursuit_phase = "verifying"
            await self.store.save()
            await self._submit_verifier(room_id, state, self._verification_prompt(state))
            return

        control = _parse_pursuit_control(raw, phase)
        if control is None:
            await self._repair_pursuit_protocol(room_id, state, raw)
            return
        state.pursuit_protocol_failures = 0

        if phase == "specifying":
            state.acceptance_criteria = [
                {"id": f"c{index}", "text": text}
                for index, text in enumerate(control["criteria"], start=1)
            ]
            state.pursuit_assumptions.extend(control["assumptions"])
            state.pursuit_assumptions = state.pursuit_assumptions[-12:]
            if control["needs_input"]:
                question = control["question"]
                state.pursuit_phase = "waiting_input"
                state.pursuit_pending_question = question
                await self.finalize(room_id, state, f"Pursuit needs input: {question}")
                return
            state.pursuit_phase = "working"
            state.pursuit_iteration = max(1, state.pursuit_iteration + 1)
            summary = "Acceptance contract:\n" + "\n".join(
                f"- [{item['id']}] {item['text']}" for item in state.acceptance_criteria
            )
            await self.finalize(room_id, state, summary)
            await self._submit_worker(room_id, state)
            return

        verdict = control["verdict"]
        expected_ids = [item["id"] for item in state.acceptance_criteria]
        returned_ids = [item["id"] for item in control["criteria"]]
        if (
            len(returned_ids) != len(set(returned_ids))
            or set(returned_ids) != set(expected_ids)
        ):
            await self._repair_pursuit_protocol(room_id, state, raw)
            return
        by_id = {item["id"]: item for item in control["criteria"]}
        ordered_criteria = [by_id[criterion_id] for criterion_id in expected_ids]
        new_evidence = [
            {"criterion_id": item["id"], **evidence}
            for item in ordered_criteria
            for evidence in item["evidence"]
        ]
        state.pursuit_criteria_status = {
            item["id"]: item["status"] for item in ordered_criteria
        }
        known_evidence = {
            (item["criterion_id"], item["claim"], item["source"], item["verification"])
            for item in state.pursuit_evidence
        }
        for item in new_evidence:
            key = (
                item["criterion_id"],
                item["claim"],
                item["source"],
                item["verification"],
            )
            if key not in known_evidence:
                state.pursuit_evidence.append(item)
                known_evidence.add(key)
        state.pursuit_evidence = state.pursuit_evidence[-16:]
        if verdict == "complete":
            passed = all(
                item["status"] == "pass" and bool(item["evidence"])
                for item in ordered_criteria
            )
            if not passed:
                verdict = "continue"
                control["feedback"] = (
                    "Completion rejected: every frozen criterion ID must have passing, "
                    "structured evidence."
                )

        if verdict == "complete":
            completion_evidence = new_evidence or state.pursuit_evidence
            evidence_text = "\n".join(
                f"- [{item['criterion_id']}] {item['claim']} — {item['source']} "
                f"({item['verification']})"
                for item in completion_evidence
            )
            final = f"✅ Pursuit complete after {state.pursuit_iteration} pass(es).\nEvidence:\n{evidence_text}"
            await self.finalize(room_id, state, final)
            await self._finish_pursuit(state)
            await self.store.save()
            return

        if verdict == "needs_input":
            question = control["question"]
            state.pursuit_phase = "waiting_input"
            state.pursuit_pending_question = question
            await self.finalize(room_id, state, f"Pursuit needs input: {question}")
            return

        feedback = control["feedback"] or "Try a materially different approach."
        state.pursuit_reflections.append(feedback)
        state.pursuit_reflections = state.pursuit_reflections[-10:]
        state.pursuit_gap = control["gap"] or "Unmet acceptance criteria remain."
        signature = "|".join(
            sorted(item["id"] for item in ordered_criteria if item["status"] != "pass")
        ) + "|" + state.pursuit_gap
        if new_evidence:
            state.pursuit_signature = signature
            state.pursuit_stagnation_count = 0
        elif signature == state.pursuit_signature:
            state.pursuit_stagnation_count += 1
        else:
            state.pursuit_signature = signature
            state.pursuit_stagnation_count = 1
        reset_for_stagnation = state.pursuit_stagnation_count >= 3
        reset_for_context = (
            state.pursuit_worker_input_tokens
            >= self.settings.pursuit_context_input_tokens
        )
        reset = reset_for_stagnation or reset_for_context
        await self.finalize(
            room_id,
            state,
            f"Verifier: continue.\nGap: {state.pursuit_gap}\nNext strategy: {feedback}",
        )
        if reset:
            worker = await self.opencode.create_session(
                state.directory,
                title=(
                    "Matrix OpenCode pursuit (strategy reset)"
                    if reset_for_stagnation
                    else "Matrix OpenCode pursuit (context rotation)"
                ),
            )
            state.session_id = str(worker["id"])
            state.title = str(worker.get("title") or state.title)
            state.pursuit_worker_input_tokens = 0
            state.pursuit_stagnation_count = 0
            state.pursuit_signature = None
            if reset_for_context:
                state.pursuit_reflections.append(
                    "Worker context was rotated after reaching the configured input-token threshold."
                )
                state.pursuit_reflections = state.pursuit_reflections[-10:]
        state.pursuit_phase = "working"
        state.pursuit_iteration += 1
        await self.store.save()
        await self._submit_worker(room_id, state, reset=reset)

    async def _capture_worker_input_tokens(self, state: RoomSession) -> None:
        try:
            session = await self.opencode.get_session(state.session_id, state.directory)
        except OpenCodeError as exc:
            LOG.warning("Could not read pursuit worker token usage for %s: %s", state.session_id, exc)
            return
        tokens = session.get("tokens")
        if isinstance(tokens, dict):
            state.pursuit_worker_input_tokens = max(
                state.pursuit_worker_input_tokens, _integer(tokens.get("input"))
            )

    async def _repair_pursuit_protocol(
        self, room_id: str, state: RoomSession, raw: str
    ) -> None:
        state.pursuit_protocol_failures += 1
        phase = state.pursuit_phase
        await self.finalize(
            room_id,
            state,
            f"Verifier returned an invalid control envelope or placeholder contract; repairing "
            f"({state.pursuit_protocol_failures}/3).",
        )
        if state.pursuit_protocol_failures >= 3:
            await self._replace_verifier(state)
            state.pursuit_protocol_failures = 0
            prompt = (
                self._specification_prompt(state)
                if phase == "specifying"
                else self._verification_prompt(state)
            )
        else:
            prompt = (
                "Your prior response was malformed or contained placeholder/example content. "
                "Return only the exact tagged JSON envelope requested previously, with concrete "
                "goal-specific values. Invalid response follows:\n" + raw[-4000:]
            )
        await self.store.save()
        await self._submit_verifier(room_id, state, prompt)

    async def _replace_verifier(self, state: RoomSession) -> None:
        old = state.verifier_session_id
        if old:
            with contextlib.suppress(OpenCodeError):
                await self.opencode.delete_session(old, state.directory)
        verifier = await self.opencode.create_session(
            state.directory, title="Matrix pursuit verifier"
        )
        state.verifier_session_id = str(verifier["id"])

    async def _finish_pursuit(self, state: RoomSession) -> None:
        verifier = state.verifier_session_id
        self._clear_pursuit(state)
        if verifier:
            with contextlib.suppress(OpenCodeError):
                await self.opencode.delete_session(verifier, state.directory)

    @staticmethod
    def _clear_pursuit(state: RoomSession) -> None:
        state.pending_pursuit_goal = None
        state.pending_pursuit_reuse_session = False
        state.pending_pursuit_yolo_confirmation = False
        state.pursuit_goal = None
        state.pursuit_extent = 1
        state.pursuit_phase = None
        state.pursuit_iteration = 0
        state.pursuit_protocol_version = PURSUIT_PROTOCOL_VERSION
        state.pursuit_worker_input_tokens = 0
        state.verifier_session_id = None
        state.acceptance_criteria.clear()
        state.pursuit_criteria_status.clear()
        state.pursuit_assumptions.clear()
        state.pursuit_reflections.clear()
        state.pursuit_evidence.clear()
        state.pursuit_gap = None
        state.pursuit_stagnation_count = 0
        state.pursuit_signature = None
        state.pursuit_pending_question = None
        state.pursuit_protocol_failures = 0
        state.pursuit_retry_attempts = 0
        state.pursuit_last_worker_report = None
        MatrixOpenCodeBot._clear_recovery(state)

    @staticmethod
    def _clear_recovery(state: RoomSession) -> None:
        state.recovery_reason = None
        state.recovery_tool = None
        state.recovery_session_id = None

    @staticmethod
    def _clear_bump_confirmation(state: RoomSession) -> None:
        state.bump_confirmation_session_id = None
        state.bump_confirmation_activity_ms = None

    async def command_status(self, room_id: str) -> None:
        state = self.store.rooms.get(room_id)
        if not state:
            await self.send_text(room_id, "No session is mapped to this room. Use !new [directory].")
            return
        status = await self._status(state)
        diffs = await self.opencode.diff(state.session_id, state.directory)
        additions = sum(_integer(item.get("additions")) for item in diffs)
        deletions = sum(_integer(item.get("deletions")) for item in diffs)
        lines = [
            f"Session: {state.title} ({state.session_id})",
            f"Directory: {state.directory}",
            f"State: {status.get('type', 'unknown')}",
        ]
        if state.activity:
            lines.append(f"Activity: {state.activity}")
        if state.in_flight_event_id:
            lines.append(f"Last activity: {_activity_age_text(state)}")
            if not state.pending_permissions and not state.watchdog_recovery_pending:
                now_ms = int(time.time() * 1000)
                active_tool = self._oldest_active_tool(state) if state.pursuit_goal else None
                if active_tool:
                    remaining = max(
                        0,
                        self.settings.pursuit_tool_timeout_seconds
                        - ((now_ms - active_tool[1]) // 1000),
                    )
                    lines.append(
                        f"Automatic recovery: tool {active_tool[0]} in "
                        f"{_duration_text(remaining)}"
                    )
                else:
                    last_ms = state.last_activity_ms or state.prompt_started_ms or now_ms
                    remaining = max(
                        0,
                        self._stuck_timeout_seconds(state)
                        - ((now_ms - last_ms) // 1000),
                    )
                    lines.append(f"Automatic recovery in {_duration_text(remaining)}")
        if state.watchdog_recovery_pending:
            lines.append(
                f"Watchdog: recovery attempt {state.watchdog_recovery_attempts} pending"
            )
        elif state.watchdog_recovery_attempts:
            lines.append(f"Watchdog recoveries: {state.watchdog_recovery_attempts}")
        if state.manual_bump_pending:
            lines.append(f"Manual bump: attempt {state.manual_bump_attempts} pending")
        elif state.bump_confirmation_session_id:
            lines.append("Manual bump: awaiting !bump confirm or !bump cancel")
        if state.pending_pursuit_goal:
            if state.pending_pursuit_yolo_confirmation:
                pending_setup = "awaiting YOLO choice (reply y or n)"
            else:
                pending_setup = "awaiting extent (reply 1, 2, or 3)"
            lines.append(f"Pursuit: {pending_setup} — {state.pending_pursuit_goal}")
        if state.pursuit_goal:
            passed = sum(
                1 for status_value in state.pursuit_criteria_status.values()
                if status_value == "pass"
            )
            lines.append(
                f"Pursuit: {state.pursuit_phase}, pass {state.pursuit_iteration} — "
                f"{state.pursuit_goal}"
            )
            lines.append(f"Extent: {state.pursuit_extent}/3")
            lines.append(
                f"Acceptance: {passed}/{len(state.acceptance_criteria)} evidenced; "
                f"stagnation {state.pursuit_stagnation_count}/3"
            )
            lines.append(
                "Worker context: "
                f"{state.pursuit_worker_input_tokens:,}/"
                f"{self.settings.pursuit_context_input_tokens:,} input tokens"
            )
            if state.pursuit_gap:
                lines.append(f"Current gap: {state.pursuit_gap}")
            if state.pursuit_evidence:
                latest = state.pursuit_evidence[-1]
                lines.append(
                    f"Latest evidence [{latest['criterion_id']}]: {latest['claim']} — "
                    f"{latest['source']}"
                )
            if state.pursuit_pending_question:
                lines.append(f"Waiting for input: {state.pursuit_pending_question}")
            if state.pursuit_retry_attempts:
                lines.append(
                    f"Submission retries: {state.pursuit_retry_attempts} "
                    "(automatic backoff pending)"
                )
        if status.get("type") == "retry":
            lines.append(
                f"Retry: attempt {status.get('attempt', '?')} — {status.get('message', 'waiting')}"
            )
        lines.extend(
            [
                "Permission mode: "
                + ("YOLO (auto-approve)" if state.yolo_permissions else "prompt"),
                f"Pending permissions: {len(state.pending_permissions)}",
                f"Changes: {len(diffs)} files, +{additions}/-{deletions}",
            ]
        )
        await self.send_text(room_id, "\n".join(lines))

    async def command_diagnose(self, room_id: str) -> None:
        """Write a bounded, credential-redacted snapshot for offline troubleshooting."""

        state = self.store.rooms.get(room_id)
        directory = Path(state.directory) if state else self.settings.default_directory
        generated = datetime.now(timezone.utc).isoformat()
        try:
            package_version = version("matrix-opencode-bot")
        except PackageNotFoundError:
            package_version = "unknown"

        report: dict[str, Any] = {
            "format": "matrix-opencode-diagnosis-v1",
            "generated_utc": generated,
            "privacy_warning": (
                "Credential-shaped fields were redacted automatically. Prompts, model output, "
                "tool output, file paths, and diffs can still contain private data; inspect this "
                "file before sharing it."
            ),
            "runtime": {
                "bot_version": package_version,
                "python": platform.python_version(),
                "platform": platform.platform(),
                "bot_uptime_seconds": max(0, (int(time.time() * 1000) - self.started_ms) // 1000),
            },
            "configuration": {
                "homeserver": self.settings.homeserver,
                "matrix_user_id": self.settings.user_id,
                "require_encryption": self.settings.require_encryption,
                "ignore_unverified_devices": self.settings.ignore_unverified_devices,
                "opencode_url": self.settings.opencode_url,
                "default_directory": str(self.settings.default_directory),
                "allowed_roots": [str(item) for item in self.settings.allowed_roots],
                "show_reasoning": self.settings.show_reasoning,
                "stuck_timeout_seconds": self.settings.stuck_timeout_seconds,
                "pursuit_stuck_timeout_seconds": self.settings.pursuit_stuck_timeout_seconds,
                "pursuit_tool_timeout_seconds": self.settings.pursuit_tool_timeout_seconds,
                "pursuit_context_input_tokens": self.settings.pursuit_context_input_tokens,
                "matrix_edit_interval_seconds": self.settings.matrix_edit_interval_seconds,
            },
            "room_id": room_id,
            "persisted_state": state.to_dict() if state else None,
            "transient_state": (
                {
                    "activity": state.activity,
                    "activity_history": state.activity_history,
                    "plan_items": state.plan_items,
                    "active_tools": state.active_tools,
                    "last_activity_ms": state.last_activity_ms,
                    "text_parts": state.text_parts,
                    "reasoning_parts": state.reasoning_parts,
                    "message_roles": state.message_roles,
                    "stop_requested": state.stop_requested,
                }
                if state
                else None
            ),
            "recent_opencode_events": list(self.diagnostic_events.get(room_id, ())),
            "opencode": {},
        }

        async def capture(label: str, operation: Any) -> None:
            try:
                report["opencode"][label] = await operation
            except Exception as exc:  # Keep partial evidence when one diagnostic endpoint fails.
                report["opencode"][label] = {
                    "diagnostic_error": f"{type(exc).__name__}: {exc}"
                }

        await capture("health", self.opencode.health())
        if state:
            await capture("all_session_statuses", self.opencode.session_status(state.directory))
            sessions = [
                ("worker", state.session_id),
                ("verifier", state.verifier_session_id),
                ("recovery", state.recovery_session_id),
            ]
            seen: set[str] = set()
            for role, session_id in sessions:
                if not session_id or session_id in seen:
                    continue
                seen.add(session_id)
                await capture(
                    f"{role}_session",
                    self.opencode.get_session(session_id, state.directory),
                )
                await capture(
                    f"{role}_messages_last_100",
                    self.opencode.messages(session_id, state.directory, limit=100),
                )
                await capture(
                    f"{role}_diff",
                    self.opencode.diff(session_id, state.directory),
                )

        sanitized = _sanitize_diagnostic(report)
        rendered = (
            "MATRIX OPENCODE DIAGNOSIS\n"
            "Copy this entire file when requesting further diagnosis.\n\n"
            + json.dumps(sanitized, indent=2, ensure_ascii=False)
            + "\n"
        )
        path = directory / "DIAGNOSIS.txt"
        temporary_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=directory,
                prefix=".DIAGNOSIS.",
                delete=False,
            ) as temporary:
                temporary_name = temporary.name
                temporary.write(rendered)
                temporary.flush()
                os.fsync(temporary.fileno())
            os.chmod(temporary_name, stat.S_IRUSR | stat.S_IWUSR)
            os.replace(temporary_name, path)
        except OSError as exc:
            if temporary_name:
                with contextlib.suppress(OSError):
                    os.unlink(temporary_name)
            await self.send_text(room_id, f"Could not write DIAGNOSIS.txt: {exc}")
            return
        await self.send_text(
            room_id,
            f"Wrote diagnostic report locally:\n{path}\n"
            "Inspect it for private prompt/tool/file content, then copy and paste it for analysis.",
        )

    async def command_bump(self, room_id: str, action: str) -> None:
        state = self.store.rooms.get(room_id)
        if not state:
            await self.send_text(room_id, "No session is mapped to this room.")
            return
        if action not in {"", "confirm", "cancel"}:
            await self.send_text(room_id, "Usage: !bump [confirm|cancel]")
            return

        if action == "cancel":
            if state.manual_bump_pending:
                await self.send_text(
                    room_id,
                    "The bump was already confirmed and cannot be cancelled; use !stop to "
                    "stop the recovery.",
                )
                return
            had_confirmation = state.bump_confirmation_session_id is not None
            self._clear_bump_confirmation(state)
            await self.store.save()
            await self.send_text(
                room_id,
                "Bump cancelled." if had_confirmation else "No bump confirmation is pending.",
            )
            return

        if state.manual_bump_pending:
            await self.send_text(
                room_id, "A confirmed bump is already waiting for OpenCode to become idle."
            )
            return

        if action == "confirm":
            expected_session = state.bump_confirmation_session_id
            if not expected_session:
                await self.send_text(room_id, "No bump is awaiting confirmation. Send !bump first.")
                return
            active_session = self._active_session_id(state)
            unchanged = (
                state.bump_confirmation_activity_ms
                == (state.last_activity_ms or state.prompt_started_ms)
            )
            if (
                expected_session != active_session
                or not state.in_flight_event_id
                or not unchanged
            ):
                self._clear_bump_confirmation(state)
                await self.store.save()
                await self.send_text(
                    room_id,
                    "The turn changed or produced activity after the bump request; confirmation "
                    "expired. Send !bump again to reassess it.",
                )
                return
            if state.pending_permissions:
                self._clear_bump_confirmation(state)
                await self.store.save()
                await self.send_text(
                    room_id,
                    "The turn is waiting for permission, not stalled. Reply with y or n.",
                )
                return
            if (await self._status(state)).get("type") == "idle":
                self._clear_bump_confirmation(state)
                await self.store.save()
                await self._complete_idle(room_id, state)
                await self.send_text(
                    room_id, "The turn had already finished; reconciled it without bumping."
                )
                return

            self._clear_bump_confirmation(state)
            state.manual_bump_pending = True
            state.manual_bump_attempts += 1
            active_tool = self._oldest_active_tool(state)
            state.recovery_reason = "manual_bump"
            state.recovery_tool = active_tool[0] if active_tool else None
            state.recovery_session_id = active_session
            state.activity = f"Manual bump requested (attempt {state.manual_bump_attempts})"
            self._touch_activity(state)
            await self.store.save()
            stopped = await self.opencode.abort(active_session, state.directory)
            if not stopped:
                state.manual_bump_pending = False
                self._clear_recovery(state)
                await self.store.save()
                await self.send_text(
                    room_id, "OpenCode did not accept the bump; the turn remains active."
                )
                return
            if state.pursuit_goal:
                await self.send_text(
                    room_id,
                    "Bump accepted. Quarantining the stalled session and resuming the same "
                    "pursuit phase now.",
                )
                await self._complete_idle(room_id, state)
                return
            await self.send_text(
                room_id,
                "Bump requested. The same task phase will resume after OpenCode confirms idle.",
            )
            return

        if not state.in_flight_event_id:
            await self.send_text(room_id, "There is no bot-submitted turn to bump.")
            return
        if state.pending_permissions:
            await self.send_text(
                room_id,
                "The turn is waiting for permission, not stalled. Reply with y or n.",
            )
            return
        if (await self._status(state)).get("type") == "idle":
            await self._complete_idle(room_id, state)
            await self.send_text(
                room_id, "The turn had already finished; reconciled it without bumping."
            )
            return

        active_session = self._active_session_id(state)
        state.bump_confirmation_session_id = active_session
        state.bump_confirmation_activity_ms = state.last_activity_ms or state.prompt_started_ms
        await self.store.save()
        age = _activity_age_text(state)
        last_ms = state.last_activity_ms or state.prompt_started_ms or int(time.time() * 1000)
        inactive_seconds = max(0, (int(time.time() * 1000) - last_ms) // 1000)
        threshold = self._stuck_timeout_seconds(state)
        assessment = (
            f"This exceeds the automatic watchdog threshold of {threshold}s."
            if inactive_seconds >= threshold
            else f"The automatic watchdog threshold is {threshold}s and has not been reached."
        )
        await self.send_text(
            room_id,
            f"Last observable activity: {age}. {assessment}\n"
            "Reply !bump confirm to abort and resume this exact turn, or !bump cancel. "
            "Any new activity invalidates this confirmation.",
        )

    async def command_permission(self, room_id: str, response: str) -> None:
        state = self.store.rooms.get(room_id)
        if not state:
            await self.send_text(room_id, "No session is mapped to this room.")
            return
        if not state.pending_permissions:
            await self.send_text(room_id, "There is no pending permission request.")
            return
        pending = min(state.pending_permissions, key=lambda value: value.created)
        await self._reply_pending_permission(state, pending, response)
        verb = "Allowed once" if response == "once" else "Denied"
        await self.send_text(room_id, f"{verb}: {pending.title}")

    async def command_yolo(self, room_id: str) -> None:
        state = self.store.rooms.get(room_id)
        if not state:
            await self.send_text(room_id, "No session is mapped to this room.")
            return
        if not state.pending_permissions:
            await self.send_text(room_id, "There is no pending permission request.")
            return

        state.yolo_permissions = True
        await self.store.save()
        approved = 0
        stale = 0
        failures: list[PendingPermission] = []
        for pending in sorted(list(state.pending_permissions), key=lambda value: value.created):
            try:
                if await self._reply_pending_permission(
                    state, pending, "once", discard_stale=True
                ):
                    approved += 1
                else:
                    stale += 1
            except OpenCodeError as exc:
                LOG.warning(
                    "YOLO could not approve permission %s in %s: %s",
                    pending.id,
                    room_id,
                    exc,
                )
                failures.append(pending)

        message = (
            "YOLO enabled for this session. Future permission requests will be "
            f"automatically approved. Approved {approved} pending request(s)."
        )
        if stale:
            message += f" Cleared {stale} stale request(s)."
        if failures:
            message += (
                f" Could not approve {len(failures)} request(s); they remain pending. "
                "Reply with y, n, or YOLO to retry."
            )
        await self.send_text(room_id, message)

    async def command_yolo_setting(self, room_id: str, argument: str) -> None:
        state = self.store.rooms.get(room_id)
        if not state:
            await self.send_text(room_id, "No session is mapped to this room.")
            return
        if argument != "off":
            await self.send_text(
                room_id,
                "Usage: !yolo off (YOLO can only be enabled from a permission prompt).",
            )
            return
        state.yolo_permissions = False
        await self.store.save()
        await self.send_text(room_id, "YOLO disabled. Future permissions will prompt again.")

    async def _reply_pending_permission(
        self,
        state: RoomSession,
        pending: PendingPermission,
        response: str,
        *,
        discard_stale: bool = False,
    ) -> bool:
        try:
            await self.opencode.reply_permission(
                pending.session_id or self._active_session_id(state),
                pending.id,
                state.directory,
                response,
            )
        except OpenCodeError as exc:
            if not discard_stale or exc.status_code != 404:
                raise
            LOG.info("Discarding stale OpenCode permission request %s", pending.id)
            replied = False
        else:
            replied = True
        state.pending_permissions = [
            item for item in state.pending_permissions if item.id != pending.id
        ]
        self._touch_activity(state)
        await self.store.save()
        return replied

    async def command_diff(self, room_id: str) -> None:
        state = self.store.rooms.get(room_id)
        if not state:
            await self.send_text(room_id, "No session is mapped to this room.")
            return
        diffs = await self.opencode.diff(state.session_id, state.directory)
        if not diffs:
            await self.send_text(room_id, "No changed files in this session.")
            return
        await self.send_chunked(room_id, render_diffs(diffs))

    async def command_send(self, room_id: str, query: str) -> None:
        if not query:
            await self.send_text(room_id, "Usage: !send <filename>")
            return

        state = self.store.rooms.get(room_id)
        root = (
            Path(state.directory) if state else self.settings.default_directory
        ).resolve()
        matches = await find_files(root, query)
        if not matches:
            await self.send_text(
                room_id,
                f'No file matching "{query}" was found beneath {root}.',
            )
            return

        exact = [path for path in matches if path.name.casefold() == query.casefold()]
        direct = _safe_direct_file(root, query)
        selected = direct or (exact[0] if len(exact) == 1 else None)
        if selected is None:
            lines = [f'Found {len(matches)} possible files. Choose one:']
            lines.extend(f"!send {path.relative_to(root)}" for path in matches)
            await self.send_text(room_id, "\n".join(lines))
            return

        try:
            selected = selected.resolve(strict=True)
            if not selected.is_file() or not selected.is_relative_to(root):
                raise OSError("file is no longer inside the session directory")
            await self.send_file(room_id, selected)
        except (OSError, RuntimeError) as exc:
            LOG.warning("Could not send %s to %s: %s", selected, room_id, exc)
            await self.send_text(room_id, f"Could not send {selected.name}: {exc}")

    async def command_stop(self, room_id: str) -> None:
        state = self.store.rooms.get(room_id)
        if not state:
            await self.send_text(room_id, "No session is mapped to this room.")
            return
        was_pursuing = state.pursuit_goal is not None or state.pending_pursuit_goal is not None
        verifier = state.verifier_session_id
        active_session_id = self._active_session_id(state)
        active_was_verifier = bool(verifier and active_session_id == verifier)
        self._clear_pursuit(state)
        self._clear_bump_confirmation(state)
        state.manual_bump_pending = False
        state.watchdog_recovery_pending = False
        state.watchdog_recovery_attempts = 0
        await self.store.save()
        status = await self._status(state, active_session_id)
        if status.get("type") == "idle":
            if state.in_flight_event_id:
                state.stop_requested = True
                await self.finalize(room_id, state)
            else:
                await self.send_text(
                    room_id,
                    "Pursuit stopped." if was_pursuing else "The session is already idle.",
                )
            if verifier:
                with contextlib.suppress(OpenCodeError):
                    await self.opencode.delete_session(verifier, state.directory)
            return
        stopped = await self.opencode.abort(active_session_id, state.directory)
        if stopped:
            state.stop_requested = True
            state.activity = "stop requested"
            if active_was_verifier and state.in_flight_event_id:
                await self.finalize(room_id, state, "Stopped.")
        await self.send_text(room_id, "Stop requested." if stopped else "OpenCode did not stop the session.")
        if verifier:
            with contextlib.suppress(OpenCodeError):
                await self.opencode.delete_session(verifier, state.directory)

    async def command_reset(self, room_id: str) -> None:
        state = self.store.rooms.get(room_id)
        if not state:
            await self.send_text(room_id, "This room has no session mapping.")
            return
        status = await self._status(state)
        if (
            state.pending_pursuit_goal
            or state.pursuit_goal
            or state.in_flight_event_id
            or status.get("type") != "idle"
        ):
            await self.send_text(room_id, "The session is busy. Use !stop before !reset.")
            return
        await self.store.remove(room_id)
        await self.send_text(
            room_id,
            "Room mapping discarded. The OpenCode session and its file changes were retained.",
        )

    async def run_event_loop(self) -> None:
        async for event in self.opencode.global_events(self.stop_events):
            try:
                await self.handle_opencode_event(event)
            except asyncio.CancelledError:
                raise
            except Exception:
                LOG.exception("Failed to process OpenCode event")

    def start_watchdog(self) -> None:
        if self.watchdog_task and not self.watchdog_task.done():
            return
        self.watchdog_task = asyncio.create_task(self.run_watchdog())

    async def run_watchdog(self) -> None:
        while not self.stop_events.is_set():
            try:
                await asyncio.wait_for(
                    self.stop_events.wait(), timeout=WATCHDOG_POLL_SECONDS
                )
                return
            except TimeoutError:
                pass
            await self.watchdog_check()

    async def watchdog_check(self) -> None:
        for room_id, state in list(self.store.rooms.items()):
            if not state.in_flight_event_id:
                continue
            async with self.room_locks[room_id]:
                if not state.in_flight_event_id:
                    continue
                try:
                    await self._watchdog_room(room_id, state)
                except asyncio.CancelledError:
                    raise
                except OpenCodeError as exc:
                    LOG.warning(
                        "Watchdog could not inspect OpenCode session %s in %s: %s",
                        self._active_session_id(state),
                        room_id,
                        exc,
                    )
                except Exception:
                    LOG.exception(
                        "Watchdog failed for OpenCode session %s",
                        self._active_session_id(state),
                    )

    async def _watchdog_room(self, room_id: str, state: RoomSession) -> None:
        status = await self._status(state)
        if status.get("type") == "idle":
            await self._complete_idle(room_id, state)
            return

        if state.pending_permissions:
            return

        # A completed assistant record is stronger evidence than the occasionally stale
        # session status map. Incomplete assistant records are created while a turn runs,
        # so completion metadata is required before taking this path.
        active_session_id = self._active_session_id(state)
        messages = await self.opencode.messages(active_session_id, state.directory, limit=20)
        latest_assistant = _latest_assistant_for_prompt(messages, state.prompt_started_ms)
        if latest_assistant and _message_completed(latest_assistant):
            cleared = await self.opencode.abort(active_session_id, state.directory)
            if not cleared:
                LOG.warning(
                    "Watchdog found a completed response for %s but could not clear stale busy status",
                    active_session_id,
                )
                return
            LOG.warning("Watchdog cleared stale busy status for %s", active_session_id)
            await self._complete_idle(room_id, state)
            return

        now_ms = int(time.time() * 1000)
        last_activity_ms = state.last_activity_ms or state.prompt_started_ms or now_ms
        silence_timeout = self._stuck_timeout_seconds(state)
        active_tool = self._oldest_active_tool(state) if state.pursuit_goal else None
        tool_timed_out = bool(
            active_tool
            and now_ms - active_tool[1]
            >= self.settings.pursuit_tool_timeout_seconds * 1000
        )
        turn_timed_out = now_ms - last_activity_ms >= silence_timeout * 1000
        recovery_retry = state.watchdog_recovery_pending
        if not recovery_retry and not tool_timed_out and not turn_timed_out:
            return

        state.watchdog_recovery_pending = True
        state.watchdog_recovery_attempts += 1
        if not recovery_retry:
            state.recovery_reason = "tool_timeout" if tool_timed_out else "turn_timeout"
            state.recovery_tool = active_tool[0] if tool_timed_out and active_tool else None
            state.recovery_session_id = active_session_id
        state.last_activity_ms = now_ms
        state.activity = (
            f"Watchdog interrupting stalled "
            f"{'tool ' + state.recovery_tool if state.recovery_tool else 'turn'} "
            f"(attempt {state.watchdog_recovery_attempts})"
        )
        await self.store.save()
        if not recovery_retry:
            if state.recovery_reason == "tool_timeout":
                alert = (
                    f"⚠️ Automatic recovery: pursuit tool "
                    f"{state.recovery_tool or 'tool'} exceeded "
                    f"{self.settings.pursuit_tool_timeout_seconds}s. Aborting the stalled "
                    "session and continuing the same phase in a fresh session."
                )
            else:
                alert = (
                    f"⚠️ Automatic recovery: no observable activity for {silence_timeout}s. "
                    "Aborting the stalled turn and continuing automatically."
                )
            await self.send_text(room_id, alert)
        if state.in_flight_event_id:
            await self.send_edit(
                room_id, state.in_flight_event_id, self._progress_text(state)
            )

        LOG.warning(
            "Watchdog interrupting session %s after stalled %s (attempt %s)",
            active_session_id,
            state.recovery_tool or f"turn ({silence_timeout}s silence)",
            state.watchdog_recovery_attempts,
        )
        stopped = await self.opencode.abort(active_session_id, state.directory)
        if not stopped:
            state.activity = "Watchdog interrupt failed; retrying after the timeout"
            if state.in_flight_event_id:
                await self.send_edit(
                    room_id, state.in_flight_event_id, self._progress_text(state)
                )
            return
        if state.pursuit_goal:
            # Do not depend on a poisoned session emitting session.idle after a successful
            # abort. It is quarantined, so late events from it will no longer be routed here.
            await self._complete_idle(room_id, state)

    async def _complete_idle(self, room_id: str, state: RoomSession) -> None:
        if not state.in_flight_event_id:
            state.activity = None
            state.stop_requested = False
            return

        manual_bump = state.manual_bump_pending
        recovering = state.watchdog_recovery_pending or manual_bump
        if recovering:
            partial = self._combined_text(state) or await self._recover_response(state)
            if state.recovery_reason == "tool_timeout":
                automatic_notice = (
                    f"⚠️ Watchdog interrupted stalled tool {state.recovery_tool or 'tool'} after "
                    f"{self.settings.pursuit_tool_timeout_seconds}s. Continuing automatically "
                    "in a fresh pursuit session."
                )
            else:
                automatic_notice = (
                    f"⚠️ Watchdog interrupted this turn after "
                    f"{self._stuck_timeout_seconds(state)}s without activity. "
                    "Continuing automatically"
                    + (" in a fresh pursuit session." if state.pursuit_goal else ".")
                )
            notice = (
                "⚠️ The user confirmed a manual bump. Continuing the same unfinished phase."
                if manual_bump
                else automatic_notice
            )
            final_text = f"{partial}\n\n{notice}" if partial else notice
            state.watchdog_recovery_pending = False
            state.manual_bump_pending = False
            await self.finalize(room_id, state, final_text)
            if state.pursuit_goal:
                await self._rotate_pursuit_session_after_recovery(state)
                await self._resume_pursuit_phase(room_id, state)
            else:
                continuation = (
                    MANUAL_BUMP_CONTINUATION if manual_bump else WATCHDOG_CONTINUATION
                )
                await self._submit_prompt(room_id, state, continuation)
            return

        state.watchdog_recovery_pending = False
        state.watchdog_recovery_attempts = 0
        raw = self._combined_text(state) or await self._recover_response(state)
        if state.pursuit_goal:
            await self._handle_pursuit_idle(room_id, state, raw)
        else:
            await self.finalize(room_id, state, raw or None)

    async def _rotate_pursuit_session_after_recovery(
        self, state: RoomSession
    ) -> None:
        tool = state.recovery_tool
        reason = state.recovery_reason or "stalled turn"
        detail = f" while running tool {tool}" if tool else ""
        state.pursuit_reflections.append(
            f"The previous {state.pursuit_phase} session was quarantined after {reason}{detail}. "
            "Do not repeat the same approach. Use bounded, non-interactive operations; prefer "
            "purpose-built task tools over ad-hoc shell pipelines, and verify each result before "
            "accepting or writing the deliverable."
        )
        state.pursuit_reflections = state.pursuit_reflections[-10:]
        if state.pursuit_phase == "working":
            worker = await self.opencode.create_session(
                state.directory, title="Matrix OpenCode pursuit (recovered)"
            )
            state.session_id = str(worker["id"])
            state.title = str(worker.get("title") or state.title)
        elif state.pursuit_phase in {"specifying", "verifying"}:
            await self._replace_verifier(state)
        self._clear_recovery(state)
        await self.store.save()

    async def handle_opencode_event(self, event: dict[str, Any]) -> None:
        directory = event.get("directory")
        payload = event.get("payload", event)
        if not isinstance(payload, dict):
            return
        event_type = payload.get("type")
        properties = payload.get("properties", {})
        if not isinstance(properties, dict):
            return
        session_id = _event_session_id(event_type, properties)
        if not session_id:
            return

        matching = [
            (room_id, state)
            for room_id, state in self.store.rooms.items()
            if session_id in {state.session_id, state.verifier_session_id}
            and (not directory or Path(state.directory) == Path(str(directory)))
        ]
        for room_id, state in matching:
            async with self.room_locks[room_id]:
                if session_id != self._active_session_id(state):
                    continue
                self._record_diagnostic_event(
                    room_id,
                    state,
                    str(event_type),
                    session_id,
                    directory,
                    properties,
                )
                await self._handle_room_event(room_id, state, str(event_type), properties)

    def _record_diagnostic_event(
        self,
        room_id: str,
        state: RoomSession,
        event_type: str,
        session_id: str,
        directory: Any,
        properties: dict[str, Any],
    ) -> None:
        """Keep token streams useful without letting them evict lifecycle events."""

        events = self.diagnostic_events[room_id]
        if event_type == "message.part.delta" and events:
            previous = events[-1]
            previous_properties = previous.get("properties", {})
            same_stream = (
                previous.get("type") == event_type
                and previous.get("session_id") == session_id
                and isinstance(previous_properties, dict)
                and previous_properties.get("partID") == properties.get("partID")
                and previous_properties.get("field") == properties.get("field")
            )
            if same_stream:
                combined = str(previous_properties.get("delta") or "") + str(
                    properties.get("delta") or ""
                )
                previous_properties["delta"] = combined[-4000:]
                previous_properties["delta_count"] = (
                    _integer(previous_properties.get("delta_count")) or 1
                ) + 1
                previous["observed_utc"] = datetime.now(timezone.utc).isoformat()
                return

        event = {
            "observed_utc": datetime.now(timezone.utc).isoformat(),
            "type": event_type,
            "session_id": session_id,
            "directory": str(directory or state.directory),
            "properties": _sanitize_diagnostic(properties, max_string=4000),
        }
        if event_type == "message.part.delta" and isinstance(event["properties"], dict):
            event["properties"]["delta_count"] = 1
        events.append(event)

    async def _handle_room_event(
        self,
        room_id: str,
        state: RoomSession,
        event_type: str,
        properties: dict[str, Any],
    ) -> None:
        if event_type != "session.idle":
            if state.bump_confirmation_session_id:
                self._clear_bump_confirmation(state)
                await self.store.save()
            self._touch_activity(state)

        if event_type in {"permission.updated", "permission.asked"}:
            permission_id = str(properties.get("id", ""))
            if not permission_id or any(p.id == permission_id for p in state.pending_permissions):
                return
            pattern_value = properties.get("patterns", properties.get("pattern", ""))
            if isinstance(pattern_value, list):
                pattern = ", ".join(map(str, pattern_value))
            else:
                pattern = str(pattern_value or "")
            permission_type = str(
                properties.get("permission") or properties.get("type") or "unknown"
            )
            pending = PendingPermission(
                id=permission_id,
                title=str(properties.get("title") or permission_type or "Permission request"),
                type=permission_type,
                pattern=pattern[:500],
                created=(
                    _integer((properties.get("time") or {}).get("created"))
                    or int(time.time() * 1000)
                ),
                session_id=str(properties.get("sessionID") or self._active_session_id(state)),
            )
            state.pending_permissions.append(pending)
            await self.store.save()
            if state.yolo_permissions:
                try:
                    approved = await self._reply_pending_permission(
                        state, pending, "once", discard_stale=True
                    )
                except OpenCodeError as exc:
                    LOG.warning(
                        "YOLO could not auto-approve permission %s in %s: %s",
                        pending.id,
                        room_id,
                        exc,
                    )
                    await self.send_text(
                        room_id,
                        f"YOLO could not auto-approve: {pending.title}\n"
                        "The request remains pending. Reply with y, n, or YOLO to retry.",
                    )
                else:
                    if approved:
                        await self.send_text(room_id, f"YOLO auto-approved: {pending.title}")
                return
            message = f"OpenCode requests permission: {pending.title}\nType: {pending.type}"
            if pending.pattern:
                message += f"\nPattern: {pending.pattern}"
            message += (
                "\nReply with y (allow once), n (deny), or YOLO "
                "(allow everything for this session)."
            )
            await self.send_text(room_id, message)
            return

        if event_type == "permission.replied":
            permission_id = str(properties.get("permissionID", ""))
            state.pending_permissions = [p for p in state.pending_permissions if p.id != permission_id]
            await self.store.save()
            return

        if event_type == "message.updated":
            info = properties.get("info", {})
            if not isinstance(info, dict):
                return
            message_id = str(info.get("id") or "")
            role = str(info.get("role") or "")
            if message_id and role:
                state.message_roles[message_id] = role
                if role != "assistant":
                    for part_id, owner_id in list(state.part_message_ids.items()):
                        if owner_id == message_id:
                            state.text_parts.pop(part_id, None)
                            state.reasoning_parts.pop(part_id, None)
            return

        if event_type == "message.part.updated" and state.in_flight_event_id:
            part = properties.get("part", {})
            if not isinstance(part, dict):
                return
            part_id = str(part.get("id") or "")
            message_id = str(part.get("messageID") or properties.get("messageID") or "")
            if part_id and message_id:
                state.part_message_ids[part_id] = message_id
            if message_id and state.message_roles.get(message_id) not in {None, "assistant"}:
                state.text_parts.pop(part_id, None)
                state.reasoning_parts.pop(part_id, None)
                return
            part_type = part.get("type")
            if part_type == "text" and not part.get("ignored"):
                state.text_parts[part_id or str(len(state.text_parts))] = str(part.get("text", ""))
                self.schedule_live_edit(room_id, state)
            elif part_type == "reasoning":
                if self.settings.show_reasoning:
                    state.reasoning_parts[part_id or str(len(state.reasoning_parts))] = (
                        str(part.get("text", ""))
                    )
                self._set_activity(state, "Reasoning")
                self.schedule_live_edit(room_id, state)
            elif part_type == "tool":
                tool_state = part.get("state", {})
                if isinstance(tool_state, dict):
                    status = str(tool_state.get("status") or "pending")
                    tool = _safe_activity_label(part.get("tool") or "tool")
                    part_id = str(part.get("id") or tool)
                    tools_changed = False
                    if status in {"pending", "running"}:
                        if part_id not in state.active_tools:
                            state.active_tools[part_id] = {
                                "name": tool,
                                "started_ms": int(time.time() * 1000),
                            }
                            tools_changed = True
                    elif part_id in state.active_tools:
                        state.active_tools.pop(part_id, None)
                        tools_changed = True
                    verb = {
                        "pending": "Preparing tool",
                        "running": "Using tool",
                        "completed": "Completed tool",
                        "error": "Tool failed",
                    }.get(status, "Tool")
                    self._set_activity(state, f"{verb}: {tool}")
                    if tools_changed:
                        await self.store.save()
                    self.schedule_live_edit(room_id, state)
            elif part_type == "patch":
                files = part.get("files", [])
                count = len(files) if isinstance(files, list) else 0
                self._set_activity(state, f"Updated {count} file{'s' if count != 1 else ''}")
                self.schedule_live_edit(room_id, state)
            elif part_type in {"agent", "subtask"}:
                agent = _safe_activity_label(part.get("name") or part.get("agent") or "agent")
                self._set_activity(state, f"Running agent: {agent}")
                self.schedule_live_edit(room_id, state)
            elif part_type == "step-start":
                self._set_activity(state, "Starting next step")
                self.schedule_live_edit(room_id, state)
            elif part_type == "step-finish":
                self._set_activity(state, "Step completed")
                self.schedule_live_edit(room_id, state)
            return

        if event_type == "message.part.delta" and state.in_flight_event_id:
            if properties.get("field") != "text":
                return
            part_id = str(properties.get("partID") or "")
            delta = str(properties.get("delta") or "")
            # OpenCode sends an initial part.updated event that identifies whether a
            # text stream is assistant output or reasoning. Only append to a known part
            # so an out-of-order reasoning delta can never leak into the response.
            if part_id in state.text_parts:
                state.text_parts[part_id] += delta
                self.schedule_live_edit(room_id, state)
            elif self.settings.show_reasoning and part_id in state.reasoning_parts:
                state.reasoning_parts[part_id] += delta
                self.schedule_live_edit(room_id, state)
            return

        if event_type == "session.status":
            status = properties.get("status", {})
            if isinstance(status, dict):
                if status.get("type") == "retry":
                    self._set_activity(
                        state,
                        f"retry {status.get('attempt', '?')}: {status.get('message', '')}",
                    )
                elif status.get("type") == "busy" and not state.activity:
                    self._set_activity(state, "working")
                if state.in_flight_event_id:
                    self.schedule_live_edit(room_id, state)
            return

        if event_type == "todo.updated" and state.in_flight_event_id:
            todos = properties.get("todos", [])
            if isinstance(todos, list):
                completed = sum(
                    1
                    for todo in todos
                    if isinstance(todo, dict) and todo.get("status") == "completed"
                )
                state.plan_items = [
                    (
                        _safe_plan_text(todo.get("content") or todo.get("title")),
                        str(todo.get("status") or "pending"),
                    )
                    for todo in todos
                    if isinstance(todo, dict)
                    and (todo.get("content") or todo.get("title"))
                ][:8]
                self._set_activity(state, f"Plan progress: {completed}/{len(todos)} tasks")
                self.schedule_live_edit(room_id, state)
            return

        if event_type == "session.error" and state.in_flight_event_id:
            error = properties.get("error") or {}
            detail = _event_error(error)
            if state.watchdog_recovery_pending or state.manual_bump_pending:
                self._set_activity(state, f"Watchdog interruption: {detail}")
                self.schedule_live_edit(room_id, state)
                return
            await self.finalize(room_id, state, f"OpenCode error: {detail}")
            if state.pursuit_goal:
                state.pursuit_retry_attempts += 1
                await self.store.save()
                self._schedule_pursuit_retry(room_id, state)
            return

        if event_type == "session.idle":
            if state.in_flight_event_id:
                # An idle event from an aborted turn can arrive after its continuation has
                # started. Confirm current server state before finalizing the current turn.
                if (await self._status(state)).get("type") != "idle":
                    LOG.info(
                        "Ignoring stale idle event for busy session %s",
                        self._active_session_id(state),
                    )
                    return
                await self._complete_idle(room_id, state)
            else:
                state.activity = None
                state.stop_requested = False

    def schedule_live_edit(self, room_id: str, state: RoomSession) -> None:
        task = self.edit_tasks.get(room_id)
        if task and not task.done():
            return

        async def update() -> None:
            elapsed = time.monotonic() - self.last_edit.get(room_id, 0.0)
            interval = self.settings.matrix_edit_interval_seconds
            if elapsed < interval:
                await asyncio.sleep(interval - elapsed)
            if state.in_flight_event_id:
                text = self._progress_text(state)
                await self.send_edit(room_id, state.in_flight_event_id, text)

        self.edit_tasks[room_id] = asyncio.create_task(update())

    async def finalize(
        self, room_id: str, state: RoomSession, forced_text: str | None = None
    ) -> None:
        event_id = state.in_flight_event_id
        if not event_id:
            return
        task = self.edit_tasks.pop(room_id, None)
        if task and task is not asyncio.current_task():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

        text = forced_text
        if text is None and state.stop_requested:
            text = "Stopped."
        if text is None:
            text = self._combined_text(state) or await self._recover_response(state)
        text = text or "OpenCode finished without a text response."
        chunks = split_text(text)
        await self.send_edit(room_id, event_id, chunks[0])
        for chunk in chunks[1:]:
            await self.send_text(room_id, chunk)
        self._clear_in_flight(state)
        await self.store.save()

    async def _recover_response(self, state: RoomSession) -> str:
        try:
            session_id = self._active_session_id(state)
            messages = await self.opencode.messages(session_id, state.directory, limit=20)
        except OpenCodeError as exc:
            LOG.warning(
                "Could not recover final response for %s: %s",
                self._active_session_id(state),
                exc,
            )
            return ""
        threshold = (state.prompt_started_ms or 0) - 1000
        for message in reversed(messages):
            info = message.get("info", {}) if isinstance(message, dict) else {}
            if not isinstance(info, dict) or info.get("role") != "assistant":
                continue
            created = _integer((info.get("time") or {}).get("created"))
            if created < threshold:
                continue
            parts = message.get("parts", [])
            text = "".join(
                str(part.get("text", ""))
                for part in parts
                if isinstance(part, dict) and part.get("type") == "text" and not part.get("ignored")
            ).strip()
            if text:
                return text
        return ""

    @staticmethod
    def _combined_text(state: RoomSession) -> str:
        return "".join(state.text_parts.values()).strip()

    def _progress_text(self, state: RoomSession) -> str:
        activity = state.activity or "Working"
        elapsed = _elapsed_text(state.prompt_started_ms)
        status_line = f"⏳ {activity}{f' · {elapsed}' if elapsed else ''}"
        details: list[str] = [f"Last activity: {_activity_age_text(state)}"]
        if state.watchdog_recovery_pending:
            details.append(
                f"Watchdog recovery attempt {state.watchdog_recovery_attempts} pending"
            )
        if state.plan_items:
            completed = sum(1 for _, status in state.plan_items if status == "completed")
            plan = [f"📋 Plan ({completed}/{len(state.plan_items)} complete):"]
            plan.extend(
                f"{_plan_marker(status)} {title}"
                for title, status in state.plan_items[:5]
            )
            if len(state.plan_items) > 5:
                plan.append(f"…and {len(state.plan_items) - 5} more")
            details.append("\n".join(plan))
        if state.activity_history:
            details.append("Recent: " + " → ".join(state.activity_history[-3:]))
        progress = "\n".join([status_line, *details])
        response = (
            ""
            if state.pursuit_phase in {"specifying", "verifying"}
            else MatrixOpenCodeBot._combined_text(state)
        )
        reasoning = "".join(state.reasoning_parts.values()).strip()
        if len(reasoning) > MAX_REASONING_CHARS:
            reasoning = "…" + reasoning[-MAX_REASONING_CHARS:]
        reasoning_block = f"🧠 Thinking:\n{reasoning}" if reasoning else ""
        supplemental = "\n\n".join(
            section for section in (reasoning_block, progress) if section
        )
        if response:
            available = max(1, MAX_MESSAGE_CHARS - len(supplemental) - 2)
            return f"{response[:available]}\n\n{supplemental}"
        return f"Working…\n{supplemental}"[:MAX_MESSAGE_CHARS]

    @staticmethod
    def _set_activity(state: RoomSession, activity: str) -> None:
        if state.activity and state.activity != activity and state.activity != "starting":
            state.activity_history.append(state.activity)
            del state.activity_history[:-6]
        state.activity = activity

    @staticmethod
    def _touch_activity(state: RoomSession) -> None:
        state.last_activity_ms = int(time.time() * 1000)

    @staticmethod
    def _clear_in_flight(state: RoomSession) -> None:
        state.in_flight_event_id = None
        state.prompt_started_ms = None
        state.text_parts.clear()
        state.reasoning_parts.clear()
        state.message_roles.clear()
        state.part_message_ids.clear()
        state.activity = None
        state.activity_history.clear()
        state.plan_items.clear()
        state.active_tools.clear()
        state.stop_requested = False
        state.last_activity_ms = None
        state.bump_confirmation_session_id = None
        state.bump_confirmation_activity_ms = None
        state.manual_bump_pending = False

    async def validate_restored_state(self) -> None:
        changed = False
        for room_id, state in list(self.store.rooms.items()):
            async with self.room_locks[room_id]:
                if self.store.rooms.get(room_id) is not state:
                    continue
                try:
                    self.settings.resolve_directory(state.directory)
                    if (
                        state.pursuit_goal
                        and state.pursuit_protocol_version < PURSUIT_PROTOCOL_VERSION
                    ):
                        await self._restart_legacy_pursuit(room_id, state)
                        changed = True
                    session = await self.opencode.get_session(
                        state.session_id, state.directory
                    )
                    title = str(session.get("title") or state.title)
                    if title != state.title:
                        state.title = title
                        changed = True
                    invalid_persisted_contract = bool(
                        state.pursuit_goal
                        and state.acceptance_criteria
                        and (
                            len(state.acceptance_criteria)
                            != len({item["id"] for item in state.acceptance_criteria})
                            or any(
                                _is_placeholder_contract_text(item["text"])
                                for item in state.acceptance_criteria
                            )
                        )
                    )
                    if invalid_persisted_contract:
                        active_session = self._active_session_id(state)
                        if state.in_flight_event_id:
                            with contextlib.suppress(OpenCodeError):
                                await self.opencode.abort(active_session, state.directory)
                            await self.finalize(
                                room_id,
                                state,
                                "Invalid placeholder acceptance contract detected after restart; "
                                "quarantining its context and generating a concrete contract.",
                            )
                        worker = await self.opencode.create_session(
                            state.directory,
                            title="Matrix OpenCode pursuit worker (contract recovery)",
                        )
                        state.session_id = str(worker["id"])
                        state.title = str(worker.get("title") or state.title)
                        await self._replace_verifier(state)
                        state.acceptance_criteria.clear()
                        state.pursuit_criteria_status.clear()
                        state.pursuit_assumptions = [
                            item
                            for item in state.pursuit_assumptions
                            if not _is_placeholder_contract_text(item)
                        ]
                        state.pursuit_phase = "specifying"
                        state.pursuit_protocol_failures = 0
                        state.pursuit_reflections.append(
                            "A persisted placeholder contract was rejected during restart recovery."
                        )
                        state.pursuit_reflections = state.pursuit_reflections[-10:]
                        changed = True
                    if state.pursuit_goal and state.verifier_session_id:
                        try:
                            await self.opencode.get_session(
                                state.verifier_session_id, state.directory
                            )
                        except OpenCodeError as verifier_error:
                            if verifier_error.status_code != 404:
                                raise
                            LOG.warning(
                                "Recreating missing pursuit verifier %s",
                                state.verifier_session_id,
                            )
                            state.verifier_session_id = None
                            if state.pursuit_phase in {"specifying", "verifying"}:
                                if state.in_flight_event_id:
                                    await self.finalize(
                                        room_id,
                                        state,
                                        "Verifier session was missing after restart; "
                                        "recreated and continuing.",
                                    )
                                await self._replace_verifier(state)
                            changed = True
                    if state.in_flight_event_id:
                        # Do not immediately interrupt a restored run based on an old prompt
                        # timestamp. Give it a complete silence window after this process starts.
                        self._touch_activity(state)
                        # Persisted tool timestamps come from the previous process. Give a
                        # restored operation one complete tool window before quarantining it.
                        now_ms = int(time.time() * 1000)
                        for tool in state.active_tools.values():
                            tool["started_ms"] = now_ms
                        changed = True
                        if (await self._status(state)).get("type") == "idle":
                            await self._complete_idle(room_id, state)
                except ValueError as exc:
                    LOG.warning("Discarding invalid restored mapping for %s: %s", room_id, exc)
                    self.store.rooms.pop(room_id, None)
                    changed = True
                except OpenCodeError as exc:
                    if exc.status_code == 404:
                        LOG.warning("Discarding missing restored session for %s: %s", room_id, exc)
                        self.store.rooms.pop(room_id, None)
                        changed = True
                    else:
                        LOG.warning(
                            "Could not validate restored mapping for %s; retaining it: %s",
                            room_id,
                            exc,
                        )
        if changed:
            await self.store.save()

    async def resume_pursuits(self) -> None:
        """Restart persisted pursuit phases after the global event listener is running."""
        for room_id, state in list(self.store.rooms.items()):
            if (
                state.pursuit_goal
                and state.pursuit_protocol_version < PURSUIT_PROTOCOL_VERSION
            ):
                async with self.room_locks[room_id]:
                    await self._restart_legacy_pursuit(room_id, state)
            if (
                not state.pursuit_goal
                or state.in_flight_event_id
                or state.pursuit_phase == "waiting_input"
            ):
                continue
            async with self.room_locks[room_id]:
                if (
                    state.pursuit_goal
                    and not state.in_flight_event_id
                    and (await self._status(state)).get("type") == "idle"
                ):
                    await self._resume_pursuit_phase(room_id, state)

    async def _restart_legacy_pursuit(self, room_id: str, state: RoomSession) -> None:
        goal = state.pursuit_goal
        if not goal:
            return
        clarifications = [
            item
            for item in state.pursuit_assumptions
            if item.startswith("User clarification:")
        ]
        if state.in_flight_event_id:
            with contextlib.suppress(OpenCodeError):
                await self.opencode.abort(self._active_session_id(state), state.directory)
            await self.finalize(
                room_id,
                state,
                "Restarting this pursuit under the upgraded evidence protocol.",
            )
        worker = await self.opencode.create_session(
            state.directory, title="Matrix OpenCode pursuit worker (protocol upgrade)"
        )
        verifier = await self.opencode.create_session(
            state.directory, title="Matrix pursuit verifier (protocol upgrade)"
        )
        state.session_id = str(worker["id"])
        state.title = str(worker.get("title") or state.title)
        state.verifier_session_id = str(verifier["id"])
        state.pursuit_goal = goal
        state.pursuit_phase = "specifying"
        state.pursuit_iteration = 0
        state.pursuit_protocol_version = PURSUIT_PROTOCOL_VERSION
        state.pursuit_worker_input_tokens = 0
        state.acceptance_criteria.clear()
        state.pursuit_criteria_status.clear()
        state.pursuit_assumptions = clarifications
        state.pursuit_reflections.clear()
        state.pursuit_evidence.clear()
        state.pursuit_gap = None
        state.pursuit_stagnation_count = 0
        state.pursuit_signature = None
        state.pursuit_pending_question = None
        state.pursuit_protocol_failures = 0
        state.pursuit_retry_attempts = 0
        state.pursuit_last_worker_report = None
        await self.store.save()

    async def _resume_pursuit_phase(self, room_id: str, state: RoomSession) -> None:
        if state.pursuit_phase == "specifying":
            await self._submit_verifier(room_id, state, self._specification_prompt(state))
        elif state.pursuit_phase == "verifying":
            await self._submit_verifier(room_id, state, self._verification_prompt(state))
        elif state.pursuit_phase == "working":
            if not state.acceptance_criteria:
                # Legacy !obsess migrations must establish a frozen contract first.
                state.pursuit_phase = "specifying"
                await self.store.save()
                await self._submit_verifier(room_id, state, self._specification_prompt(state))
            else:
                state.pursuit_iteration = max(1, state.pursuit_iteration + 1)
                await self.store.save()
                await self._submit_worker(room_id, state)

    async def send_text(self, room_id: str, body: str) -> str | None:
        try:
            response = await self.client.room_send(
                room_id=room_id,
                message_type="m.room.message",
                content={"msgtype": "m.text", "body": body},
                ignore_unverified_devices=self.settings.ignore_unverified_devices,
            )
        except OlmUnverifiedDeviceError:
            LOG.error(
                "Cannot send to %s: the room has unverified devices. Verify them or explicitly "
                "set MATRIX_IGNORE_UNVERIFIED_DEVICES=true.",
                room_id,
            )
            return None
        self.last_edit[room_id] = time.monotonic()
        event_id = getattr(response, "event_id", None)
        LOG.debug("Matrix send response: %s", response)
        return str(event_id) if event_id else None

    async def send_startup_logos(self) -> None:
        """Post the OpenBot banner to each configured room joined at startup."""

        joined_rooms = getattr(self.client, "rooms", {})
        for room_id in sorted(self.settings.allowed_rooms):
            room = joined_rooms.get(room_id)
            if room is None:
                LOG.warning("Cannot send startup logo; bot is not joined to %s", room_id)
                continue
            try:
                await self.send_image(
                    room_id,
                    STARTUP_LOGO_PATH,
                    encrypted=bool(getattr(room, "encrypted", False)),
                )
            except Exception:
                # A welcome image must never prevent the bot from serving other rooms.
                LOG.exception("Could not send startup logo to %s", room_id)

    async def send_image(self, room_id: str, path: Path, *, encrypted: bool) -> None:
        """Upload and send an image using Matrix's encrypted-media shape when needed."""

        size = path.stat().st_size
        response, decryption_info = await self.client.upload(
            lambda _got_429, _got_timeouts: path,
            content_type="image/png",
            filename=path.name,
            encrypt=encrypted,
            filesize=size,
        )
        content_uri = getattr(response, "content_uri", None)
        if not content_uri:
            raise RuntimeError(f"Matrix media upload failed: {response}")

        content: dict[str, Any] = {
            "msgtype": "m.image",
            "body": "OpenBot is online",
            "info": {
                "mimetype": "image/png",
                "size": size,
                "w": STARTUP_LOGO_WIDTH,
                "h": STARTUP_LOGO_HEIGHT,
            },
        }
        if encrypted:
            if not decryption_info:
                raise RuntimeError("Matrix encrypted media upload returned no decryption info")
            content["file"] = {**decryption_info, "url": content_uri}
        else:
            content["url"] = content_uri

        await self.client.room_send(
            room_id=room_id,
            message_type="m.room.message",
            content=content,
            ignore_unverified_devices=self.settings.ignore_unverified_devices,
        )
        self.last_edit[room_id] = time.monotonic()

    async def send_file(self, room_id: str, path: Path) -> None:
        """Upload a workspace file as Matrix media, encrypting it for encrypted rooms."""

        room = getattr(self.client, "rooms", {}).get(room_id)
        encrypted = bool(getattr(room, "encrypted", self.settings.require_encryption))
        size = path.stat().st_size
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        response, decryption_info = await self.client.upload(
            lambda _got_429, _got_timeouts: path,
            content_type=content_type,
            filename=path.name,
            encrypt=encrypted,
            filesize=size,
        )
        content_uri = getattr(response, "content_uri", None)
        if not content_uri:
            raise RuntimeError(f"Matrix media upload failed: {response}")

        content: dict[str, Any] = {
            "msgtype": "m.file",
            "body": path.name,
            "filename": path.name,
            "info": {"mimetype": content_type, "size": size},
        }
        if encrypted:
            if not decryption_info:
                raise RuntimeError("Matrix encrypted media upload returned no decryption info")
            content["file"] = {**decryption_info, "url": content_uri}
        else:
            content["url"] = content_uri

        try:
            await self.client.room_send(
                room_id=room_id,
                message_type="m.room.message",
                content=content,
                ignore_unverified_devices=self.settings.ignore_unverified_devices,
            )
        except OlmUnverifiedDeviceError as exc:
            raise RuntimeError("the room has unverified devices") from exc
        self.last_edit[room_id] = time.monotonic()

    async def send_edit(self, room_id: str, event_id: str, body: str) -> None:
        content = {
            "msgtype": "m.text",
            "body": f"* {body}",
            "m.new_content": {"msgtype": "m.text", "body": body},
            "m.relates_to": {"rel_type": "m.replace", "event_id": event_id},
        }
        try:
            await self.client.room_send(
                room_id=room_id,
                message_type="m.room.message",
                content=content,
                ignore_unverified_devices=self.settings.ignore_unverified_devices,
            )
            self.last_edit[room_id] = time.monotonic()
        except OlmUnverifiedDeviceError:
            LOG.error("Cannot edit message in %s because the room has unverified devices", room_id)

    async def send_chunked(self, room_id: str, text: str) -> None:
        for chunk in split_text(text):
            await self.send_text(room_id, chunk)

    async def close(self) -> None:
        self.stop_events.set()
        if self.watchdog_task:
            self.watchdog_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.watchdog_task
            self.watchdog_task = None
        for task in self.edit_tasks.values():
            task.cancel()
        for task in self.retry_tasks.values():
            task.cancel()
        if self.edit_tasks:
            await asyncio.gather(*self.edit_tasks.values(), return_exceptions=True)
        if self.retry_tasks:
            await asyncio.gather(*self.retry_tasks.values(), return_exceptions=True)


def _safe_direct_file(root: Path, query: str) -> Path | None:
    """Resolve an explicit path while preventing traversal and symlink escapes."""

    candidate = Path(query).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        return None
    if not resolved.is_file() or not resolved.is_relative_to(root.resolve()):
        return None
    return resolved


async def find_files(root: Path, query: str, limit: int = 10) -> list[Path]:
    """Return ranked workspace files for a case-insensitive filename/path query."""

    root = root.resolve()
    query_folded = query.casefold()
    direct = _safe_direct_file(root, query)
    ranked: list[tuple[tuple[int, float, int, str], Path]] = []

    files_seen = 0
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        # Repository internals are both noisy and never useful chat attachments.
        dirnames[:] = [name for name in dirnames if name != ".git"]
        directory_path = Path(directory)
        for filename in filenames:
            files_seen += 1
            if files_seen % 250 == 0:
                # Keep event processing responsive in unusually large workspaces.
                await asyncio.sleep(0)
            path = directory_path / filename
            try:
                resolved = path.resolve(strict=True)
            except OSError:
                continue
            if not resolved.is_file() or not resolved.is_relative_to(root):
                continue

            relative = path.relative_to(root).as_posix()
            name_folded = filename.casefold()
            relative_folded = relative.casefold()
            similarity = difflib.SequenceMatcher(None, query_folded, name_folded).ratio()
            if relative_folded == query_folded:
                tier = 0
            elif name_folded == query_folded:
                tier = 1
            elif name_folded.startswith(query_folded):
                tier = 2
            elif query_folded in name_folded:
                tier = 3
            elif query_folded in relative_folded:
                tier = 4
            elif similarity >= 0.55:
                tier = 5
            else:
                continue
            ranked.append(((tier, -similarity, len(relative), relative_folded), path))

    ranked.sort(key=lambda item: item[0])
    results = [path for _, path in ranked[:limit]]
    if direct and direct not in results:
        results.insert(0, direct)
        del results[limit:]
    return results


def split_text(text: str, limit: int = MAX_MESSAGE_CHARS) -> list[str]:
    if not text:
        return [""]
    chunks: list[str] = []
    remaining = text
    while len(remaining) > limit:
        split_at = remaining.rfind("\n", 0, limit + 1)
        if split_at < limit // 2:
            split_at = limit
        chunks.append(remaining[:split_at])
        remaining = remaining[split_at:]
        if remaining.startswith("\n"):
            remaining = remaining[1:]
    chunks.append(remaining)
    return chunks


def render_diffs(diffs: list[dict[str, Any]]) -> str:
    output: list[str] = []
    for item in diffs:
        filename = str(item.get("file") or "unknown")
        additions = _integer(item.get("additions"))
        deletions = _integer(item.get("deletions"))
        output.append(f"{filename} (+{additions}/-{deletions})")
        unified = difflib.unified_diff(
            str(item.get("before", "")).splitlines(),
            str(item.get("after", "")).splitlines(),
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            lineterm="",
        )
        output.extend(unified)
        output.append("")
    return "\n".join(output).rstrip()


def _parse_pursuit_control(text: str, phase: str | None) -> dict[str, Any] | None:
    matches = CONTROL_PATTERN.findall(text)
    if len(matches) == 1:
        encoded = matches[0]
    elif not matches:
        # Some otherwise compliant models omit the XML-style wrapper, use its name as
        # a JSON object key, or wrap that object in one Markdown JSON fence. Normalize
        # only when the variant occupies the entire response; embedded JSON and prose
        # remain invalid.
        encoded = text.strip()
        fence = re.fullmatch(r"```(?:json)?\s*\n?(.*?)\n?```", encoded, re.DOTALL)
        if fence:
            encoded = fence.group(1).strip()
        if not (encoded.startswith("{") and encoded.endswith("}")):
            return None
    else:
        return None
    try:
        value = json.loads(encoded)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict):
        return None
    if set(value) == {"pursuit-control"}:
        value = value["pursuit-control"]
        if not isinstance(value, dict):
            return None

    if phase == "specifying":
        criteria = value.get("criteria")
        assumptions = value.get("assumptions")
        needs_input = value.get("needs_input")
        question = value.get("question")
        normalized_criteria = (
            [item.strip() for item in criteria]
            if isinstance(criteria, list)
            and all(isinstance(item, str) for item in criteria)
            else []
        )
        normalized_assumptions = (
            [item.strip() for item in assumptions if item.strip()]
            if isinstance(assumptions, list)
            and all(isinstance(item, str) for item in assumptions)
            else []
        )
        if (
            value.get("type") != "contract"
            or not isinstance(criteria, list)
            or not criteria
            or not all(isinstance(item, str) and item.strip() for item in criteria)
            or len(normalized_criteria) != len(set(normalized_criteria))
            or any(_is_placeholder_contract_text(item) for item in normalized_criteria)
            or not isinstance(assumptions, list)
            or not all(isinstance(item, str) for item in assumptions)
            or any(_is_placeholder_contract_text(item) for item in normalized_assumptions)
            or not isinstance(needs_input, bool)
            or (needs_input and (not isinstance(question, str) or not question.strip()))
            or (not needs_input and not (question is None or question == ""))
        ):
            return None
        return {
            "criteria": normalized_criteria,
            "assumptions": normalized_assumptions,
            "needs_input": needs_input,
            "question": question.strip() if isinstance(question, str) else None,
        }

    criteria = value.get("criteria")
    verdict = value.get("verdict")
    question = value.get("question")
    if (
        value.get("type") != "verdict"
        or verdict not in {"complete", "continue", "needs_input"}
        or not isinstance(criteria, list)
        or not criteria
        or (verdict == "needs_input" and (not isinstance(question, str) or not question.strip()))
        or (verdict != "needs_input" and not (question is None or question == ""))
    ):
        return None
    normalized: list[dict[str, Any]] = []
    for item in criteria:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("id"), str)
            or not item["id"].strip()
            or item.get("status") not in {"pass", "fail", "unknown"}
            or not isinstance(item.get("evidence"), list)
        ):
            return None
        normalized_evidence: list[dict[str, str]] = []
        for evidence_item in item["evidence"]:
            if not isinstance(evidence_item, dict):
                return None
            fields = {
                key: evidence_item.get(key)
                for key in ("claim", "source", "verification")
            }
            if not all(isinstance(field, str) and field.strip() for field in fields.values()):
                return None
            normalized_evidence.append(
                {key: str(field).strip() for key, field in fields.items()}
            )
        if item["status"] == "pass" and not normalized_evidence:
            return None
        normalized.append(
            {
                "id": item["id"].strip(),
                "status": item["status"],
                "evidence": normalized_evidence,
            }
        )
    return {
        "verdict": verdict,
        "criteria": normalized,
        "feedback": str(value.get("feedback") or "").strip(),
        "gap": str(value.get("gap") or "").strip(),
        "question": question.strip() if isinstance(question, str) else None,
    }


def _is_placeholder_contract_text(value: str) -> bool:
    normalized = " ".join(value.lower().split()).strip(" .:-_")
    if not normalized or "<" in value or ">" in value:
        return True
    exact_placeholders = {
        "assumption",
        "criterion",
        "criteria",
        "specific mandatory criterion",
        "mandatory criterion",
        "acceptance criterion",
        "example",
        "placeholder",
        "tbd",
        "todo",
        "none",
    }
    return normalized in exact_placeholders or normalized.startswith("replace with ")


def _event_session_id(event_type: Any, properties: dict[str, Any]) -> str | None:
    if event_type in {"permission.updated", "permission.asked"}:
        value = properties.get("sessionID")
    elif event_type == "message.part.updated":
        part = properties.get("part", {})
        value = part.get("sessionID") if isinstance(part, dict) else None
    elif event_type == "session.error":
        value = properties.get("sessionID")
    else:
        value = properties.get("sessionID")
    return str(value) if value else None


def _event_error(error: Any) -> str:
    if not isinstance(error, dict):
        return str(error or "unknown error")
    data = error.get("data")
    if isinstance(data, dict) and data.get("message"):
        return str(data["message"])
    return str(error.get("message") or error.get("name") or "unknown error")


def _safe_activity_label(value: Any) -> str:
    label = "".join(
        character
        for character in str(value)
        if character.isalnum() or character in {"_", "-", ".", ":"}
    )
    return label[:80] or "unknown"


def _safe_plan_text(value: Any) -> str:
    return " ".join(str(value).split())[:160]


def _plan_marker(status: str) -> str:
    if status == "completed":
        return "✓"
    if status in {"in_progress", "in-progress", "running"}:
        return "→"
    return "·"


def _elapsed_text(started_ms: int | None) -> str:
    if not started_ms:
        return ""
    seconds = max(0, (int(time.time() * 1000) - started_ms) // 1000)
    if seconds < 60:
        return f"{seconds}s elapsed"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {seconds:02d}s elapsed"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m elapsed"


def _duration_text(seconds: int) -> str:
    seconds = max(0, int(seconds))
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {seconds:02d}s"
    if minutes:
        return f"{minutes}m {seconds:02d}s"
    return f"{seconds}s"


def _activity_age_text(state: RoomSession) -> str:
    last_activity_ms = state.last_activity_ms or state.prompt_started_ms
    if not last_activity_ms:
        return "unknown"
    seconds = max(0, (int(time.time() * 1000) - last_activity_ms) // 1000)
    if seconds < 60:
        return f"{seconds}s ago"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {seconds:02d}s ago"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m ago"


def _latest_assistant_for_prompt(
    messages: list[dict[str, Any]], prompt_started_ms: int | None
) -> dict[str, Any] | None:
    threshold = (prompt_started_ms or 0) - 1000
    for message in reversed(messages):
        if not isinstance(message, dict):
            continue
        info = message.get("info", {})
        if not isinstance(info, dict) or info.get("role") != "assistant":
            continue
        created = _integer((info.get("time") or {}).get("created"))
        if created >= threshold:
            return message
    return None


def _message_completed(message: dict[str, Any]) -> bool:
    info = message.get("info", {})
    if not isinstance(info, dict):
        return False
    time_value = info.get("time", {})
    return isinstance(time_value, dict) and _integer(time_value.get("completed")) > 0


def _integer(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _sanitize_diagnostic(value: Any, *, max_string: int = 20_000) -> Any:
    """Bound diagnostic data and redact values whose field names identify credentials."""

    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            if DIAGNOSTIC_SECRET_KEY.search(key):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = _sanitize_diagnostic(item, max_string=max_string)
        return sanitized
    if isinstance(value, (list, tuple, deque)):
        items = list(value)
        sanitized_items = [
            _sanitize_diagnostic(item, max_string=max_string) for item in items[:200]
        ]
        if len(items) > 200:
            sanitized_items.append(f"[TRUNCATED {len(items) - 200} ITEMS]")
        return sanitized_items
    if isinstance(value, str):
        redacted = DIAGNOSTIC_SECRET_VALUE.sub(r"\1\2[REDACTED]", value)
        if len(redacted) > max_string:
            return redacted[:max_string] + f"\n[TRUNCATED {len(redacted) - max_string} CHARACTERS]"
        return redacted
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:max_string]


def save_matrix_session(path: Path, response: LoginResponse, homeserver: str) -> None:
    payload = {
        "homeserver": homeserver,
        "user_id": response.user_id,
        "device_id": response.device_id,
        "access_token": response.access_token,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


async def create_matrix_client(settings: Settings) -> AsyncClient:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.data_dir.chmod(stat.S_IRWXU)
    session_path = settings.data_dir / "session.json"
    store_path = settings.data_dir / "crypto_store"
    store_path.mkdir(parents=True, exist_ok=True)
    config = AsyncClientConfig(encryption_enabled=True, store_sync_tokens=True)

    if session_path.exists():
        session = json.loads(session_path.read_text(encoding="utf-8"))
        if session["homeserver"].rstrip("/") != settings.homeserver:
            raise ValueError("Stored session homeserver differs from MATRIX_HOMESERVER")
        if session["user_id"] != settings.user_id:
            raise ValueError("Stored session user differs from MATRIX_USER_ID")
        client = AsyncClient(
            settings.homeserver,
            session["user_id"],
            device_id=session["device_id"],
            store_path=str(store_path),
            config=config,
        )
        client.restore_login(
            user_id=session["user_id"],
            device_id=session["device_id"],
            access_token=session["access_token"],
        )
        return client

    client = AsyncClient(
        settings.homeserver, settings.user_id, store_path=str(store_path), config=config
    )
    password = settings.password or getpass.getpass(f"Password for {settings.user_id}: ")
    response = await client.login(password=password, device_name="Matrix OpenCode bot")
    if not isinstance(response, LoginResponse):
        await client.close()
        raise RuntimeError(f"Matrix login failed: {response}")
    save_matrix_session(session_path, response, settings.homeserver)
    LOG.info("Created Matrix device %s; verify it in your Matrix client", response.device_id)
    return client


async def run() -> None:
    settings = Settings.from_env()
    opencode = OpenCodeClient(
        settings.opencode_url,
        settings.opencode_username,
        settings.opencode_password,
    )
    await opencode.start()
    try:
        health = await opencode.health()
        LOG.info("Connected to OpenCode %s", health.get("version", "unknown version"))
        client = await create_matrix_client(settings)
        bot: MatrixOpenCodeBot | None = None
        event_task: asyncio.Task[None] | None = None
        try:
            store = StateStore(settings.data_dir / "room_sessions.json")
            store.load()
            bot = MatrixOpenCodeBot(client, settings, opencode, store)
            client.add_event_callback(bot.on_message, RoomMessageText)
            client.add_event_callback(bot.on_invite, InviteMemberEvent)
            # Load membership and crypto state before edits used for restart recovery.
            await client.sync(timeout=30_000, full_state=True, set_presence="online")
            event_task = asyncio.create_task(bot.run_event_loop())
            await bot.send_startup_logos()
            await bot.validate_restored_state()
            await bot.resume_pursuits()
            bot.start_watchdog()
            LOG.info(
                "Matrix OpenCode bot logged in as %s on device %s",
                client.user_id,
                client.device_id,
            )
            await client.sync_forever(timeout=30_000, full_state=True, set_presence="online")
        finally:
            if bot:
                await bot.close()
            if event_task:
                event_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await event_task
            await client.close()
    finally:
        await opencode.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the encrypted Matrix bridge for a local OpenCode server."
    )
    parser.parse_args()
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
