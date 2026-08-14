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
EDIT_INTERVAL_SECONDS = 1.0

HELP = """Matrix–OpenCode commands:
!new [directory] — start a session
Ordinary messages — prompt the current session
!status — show current activity
!allow / !deny — answer the oldest permission request
!diff — show changed files
!stop — abort the current operation
!reset — discard the room-to-session mapping
!help — show this message"""


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
        self.last_edit: dict[str, float] = {}

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

    async def _status(self, state: RoomSession) -> dict[str, Any]:
        statuses = await self.opencode.session_status(state.directory)
        status = statuses.get(state.session_id, {"type": "idle"})
        return status if isinstance(status, dict) else {"type": "unknown"}

    async def command_new(self, room_id: str, requested: str | None) -> None:
        current = self.store.rooms.get(room_id)
        if current and (current.in_flight_event_id or (await self._status(current)).get("type") != "idle"):
            await self.send_text(room_id, "The current session is busy. Use !stop before !new.")
            return
        try:
            directory = self.settings.resolve_directory(requested)
        except ValueError as exc:
            await self.send_text(room_id, f"Cannot start session: {exc}")
            return
        session = await self.opencode.create_session(str(directory), title="Matrix OpenCode session")
        state = RoomSession(
            session_id=str(session["id"]),
            directory=str(directory),
            title=str(session.get("title") or "Matrix OpenCode session"),
        )
        await self.store.set(room_id, state)
        await self.send_text(
            room_id,
            f"Started OpenCode session {state.session_id}\nDirectory: {state.directory}",
        )

    async def prompt(self, room_id: str, text: str) -> None:
        state = self.store.rooms.get(room_id)
        if not state:
            await self.send_text(room_id, "No session is mapped to this room. Use !new [directory].")
            return
        status = await self._status(state)
        if state.in_flight_event_id or status.get("type") != "idle":
            await self.send_text(room_id, "This session is busy. Wait for it to finish or use !stop.")
            return

        event_id = await self.send_text(room_id, "Working…")
        if not event_id:
            LOG.error("Not submitting prompt because the Matrix progress message could not be sent")
            return
        state.in_flight_event_id = event_id
        state.prompt_started_ms = int(time.time() * 1000)
        state.text_parts.clear()
        state.activity = "starting"
        state.stop_requested = False
        await self.store.save()
        try:
            await self.opencode.prompt_async(state.session_id, state.directory, text)
        except OpenCodeError as exc:
            await self.send_edit(room_id, event_id, f"OpenCode error: {exc}")
            self._clear_in_flight(state)
            await self.store.save()

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
            state.session_id, pending.id, state.directory, response
        )
        state.pending_permissions = [item for item in state.pending_permissions if item.id != pending.id]
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
        status = await self._status(state)
        if status.get("type") == "idle":
            if state.in_flight_event_id:
                await self.finalize(room_id, state)
            else:
                await self.send_text(room_id, "The session is already idle.")
            return
        stopped = await self.opencode.abort(state.session_id, state.directory)
        if stopped:
            state.stop_requested = True
            state.activity = "stop requested"
        await self.send_text(room_id, "Stop requested." if stopped else "OpenCode did not stop the session.")

    async def command_reset(self, room_id: str) -> None:
        state = self.store.rooms.get(room_id)
        if not state:
            await self.send_text(room_id, "This room has no session mapping.")
            return
        status = await self._status(state)
        if state.in_flight_event_id or status.get("type") != "idle":
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
            if state.session_id == session_id
            and (not directory or Path(state.directory) == Path(str(directory)))
        ]
        for room_id, state in matching:
            async with self.room_locks[room_id]:
                await self._handle_room_event(room_id, state, str(event_type), properties)

    async def _handle_room_event(
        self,
        room_id: str,
        state: RoomSession,
        event_type: str,
        properties: dict[str, Any],
    ) -> None:
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
            if part.get("type") == "text" and not part.get("ignored"):
                state.text_parts[str(part.get("id", len(state.text_parts)))] = str(part.get("text", ""))
                self.schedule_live_edit(room_id, state)
            elif part.get("type") == "tool":
                tool_state = part.get("state", {})
                if isinstance(tool_state, dict):
                    status = tool_state.get("status")
                    if status in {"pending", "running"}:
                        state.activity = str(tool_state.get("title") or part.get("tool") or "tool")
                    elif status == "error":
                        state.activity = f"{part.get('tool', 'tool')} failed"
            return

        if event_type == "session.status":
            status = properties.get("status", {})
            if isinstance(status, dict):
                if status.get("type") == "retry":
                    state.activity = f"retry {status.get('attempt', '?')}: {status.get('message', '')}"
                elif status.get("type") == "busy" and not state.activity:
                    state.activity = "working"
            return

        if event_type == "session.error" and state.in_flight_event_id:
            error = properties.get("error") or {}
            detail = _event_error(error)
            await self.finalize(room_id, state, f"OpenCode error: {detail}")
            return

        if event_type == "session.idle":
            if state.in_flight_event_id:
                await self.finalize(room_id, state)
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
                text = self._combined_text(state)
                if text:
                    await self.send_edit(room_id, state.in_flight_event_id, text[:MAX_MESSAGE_CHARS])
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
            messages = await self.opencode.messages(state.session_id, state.directory, limit=20)
        except OpenCodeError as exc:
            LOG.warning("Could not recover final response for %s: %s", state.session_id, exc)
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

    @staticmethod
    def _clear_in_flight(state: RoomSession) -> None:
        state.in_flight_event_id = None
        state.prompt_started_ms = None
        state.text_parts.clear()
        state.activity = None
        state.stop_requested = False

    async def validate_restored_state(self) -> None:
        changed = False
        for room_id, state in list(self.store.rooms.items()):
            try:
                self.settings.resolve_directory(state.directory)
                session = await self.opencode.get_session(state.session_id, state.directory)
                title = str(session.get("title") or state.title)
                if title != state.title:
                    state.title = title
                    changed = True
                if state.in_flight_event_id and (await self._status(state)).get("type") == "idle":
                    await self.finalize(room_id, state)
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
                    LOG.warning("Could not validate restored mapping for %s; retaining it: %s", room_id, exc)
        if changed:
            await self.store.save()

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
        for task in self.edit_tasks.values():
            task.cancel()
        if self.edit_tasks:
            await asyncio.gather(*self.edit_tasks.values(), return_exceptions=True)


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
            await bot.validate_restored_state()
            event_task = asyncio.create_task(bot.run_event_loop())
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
