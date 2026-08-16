"""Encrypted Matrix bot that exposes OpenCode sessions to authorized rooms."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import difflib
import getpass
import json
import logging
import os
import re
import stat
import time
from collections import defaultdict
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
from .state import PendingPermission, RoomSession, StateStore

LOG = logging.getLogger("matrix_opencode")
MAX_MESSAGE_CHARS = 20_000
MAX_REASONING_CHARS = 8_000
EDIT_INTERVAL_SECONDS = 1.0
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

HELP = """Matrix–OpenCode commands:
!new [directory] — start a session
Ordinary messages — prompt the current session, creating one if needed
!pursue <goal> — pursue a goal until independently verified or !stop
!status — show current activity
!bump [confirm|cancel] — inspect inactivity and optionally restart a stalled turn
!allow / !deny — answer the oldest permission request
!diff — show changed files
!stop — stop a pursuit and abort the current operation
!reset — discard the room-to-session mapping
!help — show this message"""

SESSION_REMINDER = (
    "Commands: !new [directory], !pursue <goal>, !status, !bump, !diff, !allow, !deny, "
    "!stop, !reset, !help"
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
            if command == "!help":
                await self.send_text(room_id, HELP)
            elif command == "!new":
                await self.command_new(room_id, argument.strip() or None)
            elif command == "!status":
                await self.command_status(room_id)
            elif command == "!bump":
                await self.command_bump(room_id, argument.strip().lower())
            elif command == "!pursue":
                await self.command_pursue(room_id, argument.strip())
            elif command == "!allow":
                await self.command_permission(room_id, "once")
            elif command == "!deny":
                await self.command_permission(room_id, "reject")
            elif command == "!diff":
                await self.command_diff(room_id)
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
            current.pursuit_goal
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
        if state.pursuit_goal:
            await self.send_text(
                room_id, "A pursuit is already active. Use !stop before starting another."
            )
            return
        status = await self._status(state)
        if state.in_flight_event_id or status.get("type") != "idle":
            await self.send_text(room_id, "This session is busy. Wait for it to finish or use !stop.")
            return
        verifier = await self.opencode.create_session(
            state.directory, title="Matrix pursuit verifier"
        )
        self._clear_pursuit(state)
        self._clear_bump_confirmation(state)
        state.manual_bump_pending = False
        state.watchdog_recovery_pending = False
        state.watchdog_recovery_attempts = 0
        state.pursuit_goal = goal
        state.pursuit_phase = "specifying"
        state.verifier_session_id = str(verifier["id"])
        await self.store.save()
        if created:
            await self.send_text(
                room_id,
                f"Started OpenCode session {state.session_id}\nDirectory: {state.directory}"
                f"\n\n{SESSION_REMINDER}",
            )
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
        return f"""Define a stable acceptance contract for this goal:

{state.pursuit_goal}

User clarifications already received:
{clarification}

Infer harmless details. Ask for input only if a missing fact would materially change the result.
Return exactly:
<pursuit-control>{{"type":"contract","criteria":["specific mandatory criterion"],"assumptions":["assumption"],"needs_input":false,"question":null}}</pursuit-control>
Criteria must be task-aware and objectively checkable where possible. Do not perform the task yet."""

    @staticmethod
    def _worker_prompt(state: RoomSession, *, reset: bool = False) -> str:
        criteria = "\n".join(f"- {item}" for item in state.acceptance_criteria)
        assumptions = "\n".join(f"- {item}" for item in state.pursuit_assumptions) or "- None"
        reflections = "\n".join(f"- {item}" for item in state.pursuit_reflections[-6:]) or "- None"
        evidence = "\n".join(f"- {item}" for item in state.pursuit_evidence[-8:]) or "- None"
        reset_text = (
            "This is a fresh strategy context after stagnation. Do not repeat failed approaches."
            if reset
            else "Continue from the existing session state."
        )
        return f"""Pursue this goal and make concrete progress in this pass:

{state.pursuit_goal}

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
sourced facts from inference."""

    @staticmethod
    def _verification_prompt(state: RoomSession) -> str:
        criteria = "\n".join(f"- {item}" for item in state.acceptance_criteria)
        assumptions = "\n".join(f"- {item}" for item in state.pursuit_assumptions) or "- None"
        prior_evidence = "\n".join(f"- {item}" for item in state.pursuit_evidence[-12:]) or "- None"
        prior_feedback = "\n".join(f"- {item}" for item in state.pursuit_reflections[-6:]) or "- None"
        return f"""Independently evaluate the latest worker pass against the frozen contract.

Goal: {state.pursuit_goal}

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
when every mandatory criterion passes with concrete evidence. Repeat each frozen criterion's text
exactly in the criteria array. Use `needs_input` only for a material
user fact or action; difficulty means `continue`.
Return exactly:
<pursuit-control>{{"type":"verdict","verdict":"complete|continue|needs_input","criteria":[{{"criterion":"...","status":"pass|fail|unknown","evidence":"..."}}],"evidence":["new verified evidence"],"feedback":"specific next strategy","gap":"most important unresolved gap or empty","question":null}}</pursuit-control>"""

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
            await self._submit_prompt(room_id, state, self._worker_prompt(state))
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
            state.acceptance_criteria = control["criteria"]
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
                f"- {item}" for item in state.acceptance_criteria
            )
            await self.finalize(room_id, state, summary)
            await self._submit_prompt(room_id, state, self._worker_prompt(state))
            return

        verdict = control["verdict"]
        new_evidence = control["evidence"] + [
            item["evidence"]
            for item in control["criteria"]
            if item["status"] == "pass" and item["evidence"]
        ]
        new_evidence = list(dict.fromkeys(new_evidence))
        state.pursuit_criteria_status = {
            item["criterion"]: item["status"] for item in control["criteria"]
        }
        state.pursuit_evidence.extend(new_evidence)
        state.pursuit_evidence = state.pursuit_evidence[-16:]
        if verdict == "complete":
            passed = all(
                item["status"] == "pass" and bool(item["evidence"])
                for item in control["criteria"]
            )
            exact_contract = {
                item["criterion"] for item in control["criteria"]
            } == set(state.acceptance_criteria)
            if not passed or not exact_contract:
                verdict = "continue"
                control["feedback"] = (
                    "Completion rejected: repeat every frozen criterion exactly and provide "
                    "passing evidence for each one."
                )

        if verdict == "complete":
            completion_evidence = new_evidence or [
                item["evidence"] for item in control["criteria"] if item["evidence"]
            ]
            evidence_text = "\n".join(f"- {item}" for item in completion_evidence)
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
            sorted(item["criterion"] for item in control["criteria"] if item["status"] != "pass")
        ) + "|" + state.pursuit_gap
        if new_evidence:
            state.pursuit_signature = signature
            state.pursuit_stagnation_count = 0
        elif signature == state.pursuit_signature:
            state.pursuit_stagnation_count += 1
        else:
            state.pursuit_signature = signature
            state.pursuit_stagnation_count = 1
        reset = state.pursuit_stagnation_count >= 3
        await self.finalize(
            room_id,
            state,
            f"Verifier: continue.\nGap: {state.pursuit_gap}\nNext strategy: {feedback}",
        )
        if reset:
            worker = await self.opencode.create_session(
                state.directory, title="Matrix OpenCode pursuit (strategy reset)"
            )
            state.session_id = str(worker["id"])
            state.title = str(worker.get("title") or state.title)
            state.pursuit_stagnation_count = 0
            state.pursuit_signature = None
        state.pursuit_phase = "working"
        state.pursuit_iteration += 1
        await self.store.save()
        await self._submit_prompt(room_id, state, self._worker_prompt(state, reset=reset))

    async def _repair_pursuit_protocol(
        self, room_id: str, state: RoomSession, raw: str
    ) -> None:
        state.pursuit_protocol_failures += 1
        phase = state.pursuit_phase
        await self.finalize(
            room_id,
            state,
            f"Verifier returned an invalid control envelope; repairing format "
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
                "Your prior response did not match the required schema. Return only the exact "
                "tagged JSON envelope requested previously. Invalid response follows:\n" + raw[-4000:]
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
        state.pursuit_goal = None
        state.pursuit_phase = None
        state.pursuit_iteration = 0
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
        if state.pursuit_goal:
            passed = sum(
                1 for status_value in state.pursuit_criteria_status.values()
                if status_value == "pass"
            )
            lines.append(
                f"Pursuit: {state.pursuit_phase}, pass {state.pursuit_iteration} — "
                f"{state.pursuit_goal}"
            )
            lines.append(
                f"Acceptance: {passed}/{len(state.acceptance_criteria)} evidenced; "
                f"stagnation {state.pursuit_stagnation_count}/3"
            )
            if state.pursuit_gap:
                lines.append(f"Current gap: {state.pursuit_gap}")
            if state.pursuit_evidence:
                lines.append(f"Latest evidence: {state.pursuit_evidence[-1]}")
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
                f"Pending permissions: {len(state.pending_permissions)}",
                f"Changes: {len(diffs)} files, +{additions}/-{deletions}",
            ]
        )
        await self.send_text(room_id, "\n".join(lines))

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
                    "The turn is waiting for permission, not stalled. Use !allow or !deny.",
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
                "The turn is waiting for permission, not stalled. Use !allow or !deny.",
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
        await self.opencode.reply_permission(
            pending.session_id or self._active_session_id(state),
            pending.id,
            state.directory,
            response,
        )
        state.pending_permissions = [item for item in state.pending_permissions if item.id != pending.id]
        self._touch_activity(state)
        await self.store.save()
        verb = "Allowed once" if response == "once" else "Denied"
        await self.send_text(room_id, f"{verb}: {pending.title}")

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

    async def command_stop(self, room_id: str) -> None:
        state = self.store.rooms.get(room_id)
        if not state:
            await self.send_text(room_id, "No session is mapped to this room.")
            return
        was_pursuing = state.pursuit_goal is not None
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
        if state.pursuit_goal or state.in_flight_event_id or status.get("type") != "idle":
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
                await self._handle_room_event(room_id, state, str(event_type), properties)

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

        if event_type == "permission.updated":
            permission_id = str(properties.get("id", ""))
            if not permission_id or any(p.id == permission_id for p in state.pending_permissions):
                return
            pattern_value = properties.get("pattern", "")
            if isinstance(pattern_value, list):
                pattern = ", ".join(map(str, pattern_value))
            else:
                pattern = str(pattern_value or "")
            pending = PendingPermission(
                id=permission_id,
                title=str(properties.get("title") or properties.get("type") or "Permission request"),
                type=str(properties.get("type") or "unknown"),
                pattern=pattern[:500],
                created=_integer((properties.get("time") or {}).get("created")),
                session_id=self._active_session_id(state),
            )
            state.pending_permissions.append(pending)
            await self.store.save()
            message = f"OpenCode requests permission: {pending.title}\nType: {pending.type}"
            if pending.pattern:
                message += f"\nPattern: {pending.pattern}"
            message += "\nReply with !allow or !deny."
            await self.send_text(room_id, message)
            return

        if event_type == "permission.replied":
            permission_id = str(properties.get("permissionID", ""))
            state.pending_permissions = [p for p in state.pending_permissions if p.id != permission_id]
            await self.store.save()
            return

        if event_type == "message.part.updated" and state.in_flight_event_id:
            part = properties.get("part", {})
            if not isinstance(part, dict):
                return
            part_type = part.get("type")
            if part_type == "text" and not part.get("ignored"):
                state.text_parts[str(part.get("id", len(state.text_parts)))] = str(part.get("text", ""))
                self.schedule_live_edit(room_id, state)
            elif part_type == "reasoning":
                if self.settings.show_reasoning:
                    state.reasoning_parts[str(part.get("id", len(state.reasoning_parts)))] = (
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
            if elapsed < EDIT_INTERVAL_SECONDS:
                await asyncio.sleep(EDIT_INTERVAL_SECONDS - elapsed)
            if state.in_flight_event_id:
                text = self._progress_text(state)
                await self.send_edit(room_id, state.in_flight_event_id, text)
                self.last_edit[room_id] = time.monotonic()

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
                    session = await self.opencode.get_session(
                        state.session_id, state.directory
                    )
                    title = str(session.get("title") or state.title)
                    if title != state.title:
                        state.title = title
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
                await self._submit_prompt(room_id, state, self._worker_prompt(state))

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
        event_id = getattr(response, "event_id", None)
        LOG.debug("Matrix send response: %s", response)
        return str(event_id) if event_id else None

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
    if len(matches) != 1:
        return None
    try:
        value = json.loads(matches[0])
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict):
        return None

    if phase == "specifying":
        criteria = value.get("criteria")
        assumptions = value.get("assumptions")
        needs_input = value.get("needs_input")
        question = value.get("question")
        if (
            value.get("type") != "contract"
            or not isinstance(criteria, list)
            or not criteria
            or not all(isinstance(item, str) and item.strip() for item in criteria)
            or not isinstance(assumptions, list)
            or not all(isinstance(item, str) for item in assumptions)
            or not isinstance(needs_input, bool)
            or (needs_input and (not isinstance(question, str) or not question.strip()))
        ):
            return None
        return {
            "criteria": [item.strip() for item in criteria],
            "assumptions": [item.strip() for item in assumptions if item.strip()],
            "needs_input": needs_input,
            "question": question.strip() if isinstance(question, str) else None,
        }

    criteria = value.get("criteria")
    evidence = value.get("evidence")
    verdict = value.get("verdict")
    question = value.get("question")
    if (
        value.get("type") != "verdict"
        or verdict not in {"complete", "continue", "needs_input"}
        or not isinstance(criteria, list)
        or not criteria
        or not isinstance(evidence, list)
        or not all(isinstance(item, str) for item in evidence)
        or (verdict == "needs_input" and (not isinstance(question, str) or not question.strip()))
    ):
        return None
    normalized: list[dict[str, str]] = []
    for item in criteria:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("criterion"), str)
            or item.get("status") not in {"pass", "fail", "unknown"}
            or not isinstance(item.get("evidence"), str)
        ):
            return None
        normalized.append(
            {
                "criterion": item["criterion"].strip(),
                "status": item["status"],
                "evidence": item["evidence"].strip(),
            }
        )
    return {
        "verdict": verdict,
        "criteria": normalized,
        "evidence": [item.strip() for item in evidence if item.strip()],
        "feedback": str(value.get("feedback") or "").strip(),
        "gap": str(value.get("gap") or "").strip(),
        "question": question.strip() if isinstance(question, str) else None,
    }


def _event_session_id(event_type: Any, properties: dict[str, Any]) -> str | None:
    if event_type == "permission.updated":
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
