from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from matrix_opencode_bot.bot import MatrixOpenCodeBot, render_diffs, split_text
from matrix_opencode_bot.config import Settings
from matrix_opencode_bot.state import PendingPermission, RoomSession, StateStore


def settings(tmp_path: Path, *, show_reasoning: bool = False) -> Settings:
    work = tmp_path.resolve()
    return Settings(
        homeserver="https://matrix.example",
        user_id="@bot:example",
        password=None,
        data_dir=tmp_path / "data",
        allowed_rooms=frozenset({"!one:example", "!two:example"}),
        allowed_senders=frozenset({"@alice:example"}),
        auto_join=False,
        require_encryption=True,
        ignore_unverified_devices=False,
        opencode_url="http://localhost:4096",
        opencode_username="opencode",
        opencode_password=None,
        default_directory=work,
        allowed_roots=(work,),
        show_reasoning=show_reasoning,
    )


def make_bot(tmp_path: Path, *, show_reasoning: bool = False):
    counter = 0

    async def room_send(**_: object):
        nonlocal counter
        counter += 1
        return SimpleNamespace(event_id=f"$event{counter}")

    matrix = SimpleNamespace(user_id="@bot:example", room_send=AsyncMock(side_effect=room_send))
    opencode = SimpleNamespace(
        session_status=AsyncMock(return_value={}),
        create_session=AsyncMock(return_value={"id": "ses_1", "title": "Matrix"}),
        prompt_async=AsyncMock(),
        diff=AsyncMock(return_value=[]),
        reply_permission=AsyncMock(return_value=True),
        abort=AsyncMock(return_value=True),
        messages=AsyncMock(return_value=[]),
        get_session=AsyncMock(return_value={"id": "ses_1", "title": "Matrix"}),
    )
    store = StateStore(tmp_path / "state.json")
    bot = MatrixOpenCodeBot(
        matrix, settings(tmp_path, show_reasoning=show_reasoning), opencode, store
    )
    return bot, matrix, opencode, store


def message(bot: MatrixOpenCodeBot, body: str, sender: str = "@alice:example"):
    return SimpleNamespace(
        sender=sender, server_timestamp=bot.started_ms + 1, body=body, decrypted=True
    )


def room(room_id: str = "!one:example"):
    return SimpleNamespace(room_id=room_id, encrypted=True)


async def test_unauthorized_sender_is_ignored(tmp_path: Path) -> None:
    bot, matrix, _, _ = make_bot(tmp_path)
    await bot.on_message(room(), message(bot, "!help", "@mallory:example"))
    matrix.room_send.assert_not_awaited()


async def test_unencrypted_room_is_ignored(tmp_path: Path) -> None:
    bot, matrix, _, _ = make_bot(tmp_path)
    event = message(bot, "!help")
    event.decrypted = False
    await bot.on_message(SimpleNamespace(room_id="!one:example", encrypted=False), event)
    matrix.room_send.assert_not_awaited()


async def test_new_creates_and_persists_session(tmp_path: Path) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    await bot.on_message(room(), message(bot, "!new"))
    opencode.create_session.assert_awaited_once_with(
        str(tmp_path.resolve()), title="Matrix OpenCode session"
    )
    assert store.rooms["!one:example"].session_id == "ses_1"
    assert store.path.exists()
    assert "Started OpenCode session" in matrix.room_send.await_args.kwargs["content"]["body"]


async def test_prompt_creates_placeholder_and_calls_async_api(tmp_path: Path) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession("ses_1", str(tmp_path))
    await bot.on_message(room(), message(bot, "Fix the tests"))
    assert matrix.room_send.await_args_list[0].kwargs["content"]["body"] == "Working…"
    opencode.prompt_async.assert_awaited_once_with("ses_1", str(tmp_path), "Fix the tests")
    assert store.rooms["!one:example"].in_flight_event_id == "$event1"


async def test_prompt_automatically_creates_missing_session(tmp_path: Path) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)

    await bot.on_message(room(), message(bot, "Hello OpenCode"))

    opencode.create_session.assert_awaited_once_with(
        str(tmp_path.resolve()), title="Matrix OpenCode session"
    )
    opencode.prompt_async.assert_awaited_once_with(
        "ses_1", str(tmp_path.resolve()), "Hello OpenCode"
    )
    assert store.rooms["!one:example"].session_id == "ses_1"
    assert matrix.room_send.await_args_list[0].kwargs["content"]["body"] == "Working…"


async def test_busy_prompt_is_rejected(tmp_path: Path) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession(
        "ses_1", str(tmp_path), in_flight_event_id="$old"
    )
    await bot.on_message(room(), message(bot, "Another prompt"))
    opencode.prompt_async.assert_not_awaited()
    assert "busy" in matrix.room_send.await_args.kwargs["content"]["body"]


async def test_text_event_and_idle_finalize_with_matrix_edit(tmp_path: Path) -> None:
    bot, matrix, _, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession(
        "ses_1", str(tmp_path), in_flight_event_id="$progress", prompt_started_ms=1
    )
    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {
            "type": "message.part.updated",
            "properties": {
                "part": {
                    "id": "part", "sessionID": "ses_1", "type": "text", "text": "Done"
                }
            },
        },
    })
    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {"type": "session.idle", "properties": {"sessionID": "ses_1"}},
    })
    edit = matrix.room_send.await_args.kwargs["content"]
    assert edit["m.relates_to"] == {"rel_type": "m.replace", "event_id": "$progress"}
    assert edit["m.new_content"]["body"] == "Done"
    assert store.rooms["!one:example"].in_flight_event_id is None


async def test_tool_progress_is_reported_without_tool_arguments(tmp_path: Path) -> None:
    bot, matrix, _, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession(
        "ses_1", str(tmp_path), in_flight_event_id="$progress", prompt_started_ms=1
    )
    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {
            "type": "message.part.updated",
            "properties": {
                "part": {
                    "id": "tool-part", "sessionID": "ses_1", "type": "tool",
                    "tool": "bash", "state": {
                        "status": "running", "input": {"command": "secret-command"},
                        "title": "secret-command",
                    },
                }
            },
        },
    })
    await bot.edit_tasks["!one:example"]
    progress = matrix.room_send.await_args.kwargs["content"]["m.new_content"]["body"]
    assert "Using tool: bash" in progress
    assert "secret-command" not in progress


async def test_reasoning_phase_is_reported_without_reasoning_text(tmp_path: Path) -> None:
    bot, matrix, _, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession(
        "ses_1", str(tmp_path), in_flight_event_id="$progress", prompt_started_ms=1
    )
    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {
            "type": "message.part.updated",
            "properties": {
                "part": {
                    "id": "reasoning", "sessionID": "ses_1", "type": "reasoning",
                    "text": "private internal reasoning",
                }
            },
        },
    })
    await bot.edit_tasks["!one:example"]
    progress = matrix.room_send.await_args.kwargs["content"]["m.new_content"]["body"]
    assert "Reasoning" in progress
    assert "private internal reasoning" not in progress


async def test_provider_reasoning_can_be_streamed_to_chat(tmp_path: Path) -> None:
    bot, matrix, _, store = make_bot(tmp_path, show_reasoning=True)
    store.rooms["!one:example"] = RoomSession(
        "ses_1", str(tmp_path), in_flight_event_id="$progress", prompt_started_ms=1
    )
    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {
            "type": "message.part.updated",
            "properties": {
                "part": {
                    "id": "reasoning", "sessionID": "ses_1", "type": "reasoning",
                    "text": "Inspecting the event handler before changing it.",
                }
            },
        },
    })
    await bot.edit_tasks["!one:example"]
    progress = matrix.room_send.await_args.kwargs["content"]["m.new_content"]["body"]
    assert "Thinking:" in progress
    assert "Inspecting the event handler before changing it." in progress


async def test_reasoning_progress_shows_plan_and_recent_activity(
    tmp_path: Path, monkeypatch
) -> None:
    bot, matrix, _, store = make_bot(tmp_path)
    monkeypatch.setattr("matrix_opencode_bot.bot.time.time", lambda: 1_000.0)
    state = RoomSession(
        "ses_1", str(tmp_path), in_flight_event_id="$progress",
        prompt_started_ms=935_000,
    )
    state.activity = "Using tool: rg"
    state.activity_history = ["Starting next step"]
    state.plan_items = [
        ("Inspect progress events", "completed"),
        ("Improve the chat indicator", "in_progress"),
    ]
    store.rooms["!one:example"] = state

    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {
            "type": "message.part.updated",
            "properties": {
                "part": {
                    "id": "reasoning", "sessionID": "ses_1", "type": "reasoning",
                    "text": "private internal reasoning",
                }
            },
        },
    })
    await bot.edit_tasks["!one:example"]

    progress = matrix.room_send.await_args.kwargs["content"]["m.new_content"]["body"]
    assert "Reasoning · 1m 05s elapsed" in progress
    assert "Plan (1/2 complete)" in progress
    assert "✓ Inspect progress events" in progress
    assert "→ Improve the chat indicator" in progress
    assert "Starting next step → Using tool: rg" in progress
    assert "private internal reasoning" not in progress


async def test_permission_is_scoped_to_matching_room_and_can_be_answered(tmp_path: Path) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession("ses_1", str(tmp_path))
    store.rooms["!two:example"] = RoomSession("ses_2", str(tmp_path))
    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {
            "type": "permission.updated",
            "properties": {
                "id": "perm_1", "sessionID": "ses_1", "title": "Run command",
                "type": "bash", "pattern": "git status", "time": {"created": 2},
            },
        },
    })
    assert len(store.rooms["!one:example"].pending_permissions) == 1
    assert store.rooms["!two:example"].pending_permissions == []
    await bot.command_permission("!one:example", "once")
    opencode.reply_permission.assert_awaited_once_with(
        "ses_1", "perm_1", str(tmp_path), "once"
    )
    assert "Allowed once" in matrix.room_send.await_args.kwargs["content"]["body"]


async def test_permission_answers_oldest_request(tmp_path: Path) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession(
        "ses_1", str(tmp_path),
        pending_permissions=[
            PendingPermission("new", "New", "bash", created=20),
            PendingPermission("old", "Old", "edit", created=10),
        ],
    )
    await bot.command_permission("!one:example", "reject")
    assert opencode.reply_permission.await_args.args[1] == "old"


async def test_reset_refuses_busy_session(tmp_path: Path) -> None:
    bot, matrix, _, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession(
        "ses_1", str(tmp_path), in_flight_event_id="$event"
    )
    await bot.command_reset("!one:example")
    assert "!one:example" in store.rooms
    assert "Use !stop" in matrix.room_send.await_args.kwargs["content"]["body"]


async def test_stop_marks_response_and_calls_abort(tmp_path: Path) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    state = RoomSession("ses_1", str(tmp_path), in_flight_event_id="$event")
    store.rooms["!one:example"] = state
    opencode.session_status.return_value = {"ses_1": {"type": "busy"}}
    await bot.command_stop("!one:example")
    opencode.abort.assert_awaited_once_with("ses_1", str(tmp_path))
    assert state.stop_requested is True


def test_render_diffs_and_chunking() -> None:
    rendered = render_diffs([
        {"file": "a.txt", "before": "old\n", "after": "new\n", "additions": 1, "deletions": 1}
    ])
    assert "a.txt (+1/-1)" in rendered
    assert "--- a/a.txt" in rendered
    assert "+new" in rendered
    assert split_text("123456789", 4) == ["1234", "5678", "9"]
