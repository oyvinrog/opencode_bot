import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from matrix_opencode_bot.bot import MatrixOpenCodeBot, render_diffs, split_text
from matrix_opencode_bot.config import Settings
from matrix_opencode_bot.opencode import OpenCodeError
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
        health=AsyncMock(return_value={"healthy": True, "version": "test"}),
        session_status=AsyncMock(return_value={}),
        create_session=AsyncMock(return_value={"id": "ses_1", "title": "Matrix"}),
        prompt_async=AsyncMock(),
        diff=AsyncMock(return_value=[]),
        reply_permission=AsyncMock(return_value=True),
        abort=AsyncMock(return_value=True),
        delete_session=AsyncMock(return_value=True),
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


async def pursuit_text_and_idle(
    bot: MatrixOpenCodeBot, tmp_path: Path, session_id: str, text: str
) -> None:
    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {
            "type": "message.part.updated",
            "properties": {
                "part": {
                    "id": "answer", "sessionID": session_id,
                    "type": "text", "text": text,
                }
            },
        },
    })
    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {"type": "session.idle", "properties": {"sessionID": session_id}},
    })


async def pursuit_response(
    bot: MatrixOpenCodeBot, tmp_path: Path, session_id: str, payload: dict[str, object]
) -> None:
    await pursuit_text_and_idle(
        bot,
        tmp_path,
        session_id,
        f"<pursuit-control>{json.dumps(payload)}</pursuit-control>",
    )


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
    assert "Commands:" in matrix.room_send.await_args_list[0].kwargs["content"]["body"]
    assert matrix.room_send.await_args_list[1].kwargs["content"]["body"] == "Working…"


async def test_new_session_includes_command_reminder(tmp_path: Path) -> None:
    bot, matrix, _, _ = make_bot(tmp_path)

    await bot.command_new("!one:example", None)

    body = matrix.room_send.await_args.kwargs["content"]["body"]
    assert "Commands:" in body
    assert "!new [directory]" in body
    assert "!pursue <goal>" in body
    assert "!bump" in body
    assert "!diagnose" in body
    assert "!obsess" not in body


async def test_diagnose_writes_redacted_local_report(tmp_path: Path) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    state = RoomSession("ses_1", str(tmp_path), pursuit_goal="Investigate failure")
    state.activity = "Using tool: bash"
    store.rooms["!one:example"] = state
    opencode.messages.return_value = [
        {
            "info": {"role": "assistant", "access_token": "never-share-this"},
            "parts": [
                {
                    "type": "text",
                    "text": "password=hunter2 command failed with exit 1",
                }
            ],
        }
    ]

    await bot.on_message(room(), message(bot, "!diagnose"))

    report_path = tmp_path / "DIAGNOSIS.txt"
    assert report_path.exists()
    report = report_path.read_text(encoding="utf-8")
    assert "MATRIX OPENCODE DIAGNOSIS" in report
    assert "Investigate failure" in report
    assert "Using tool: bash" in report
    assert "never-share-this" not in report
    assert "hunter2" not in report
    assert "[REDACTED]" in report
    assert report_path.stat().st_mode & 0o777 == 0o600
    opencode.messages.assert_awaited_once_with("ses_1", str(tmp_path), limit=100)
    assert str(report_path) in matrix.room_send.await_args.kwargs["content"]["body"]


async def test_removed_obsess_command_is_rejected(tmp_path: Path) -> None:
    bot, matrix, opencode, _ = make_bot(tmp_path)
    await bot.on_message(room(), message(bot, "!obsess old behavior"))
    assert "Unknown command" in matrix.room_send.await_args.kwargs["content"]["body"]
    opencode.create_session.assert_not_awaited()


async def test_pursue_specifies_works_verifies_and_completes(tmp_path: Path) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession("ses_1", str(tmp_path))
    opencode.create_session.side_effect = [
        {"id": "ses_pursue", "title": "Pursuit worker"},
        {"id": "ses_verify", "title": "Verifier"},
    ]

    await bot.command_pursue("!one:example", "Find the root cause")

    state = store.rooms["!one:example"]
    assert state.pursuit_goal == "Find the root cause"
    assert state.pursuit_phase == "specifying"
    assert opencode.prompt_async.await_args.args[0] == "ses_verify"
    assert "authoritative or primary sources" in opencode.prompt_async.await_args.kwargs["system"]
    assert opencode.prompt_async.await_args.kwargs["tools"]["write"] is False

    await pursuit_response(bot, tmp_path, "ses_verify", {
        "type": "contract",
        "criteria": ["The root cause is demonstrated with evidence"],
        "assumptions": ["Use the current workspace"],
        "needs_input": False,
        "question": None,
    })
    assert state.pursuit_phase == "working"
    assert state.pursuit_iteration == 1
    assert opencode.prompt_async.await_args.args[0] == "ses_pursue"

    await pursuit_text_and_idle(bot, tmp_path, "ses_pursue", "The bug is in parser X.")
    assert state.pursuit_phase == "verifying"
    assert opencode.prompt_async.await_args.args[0] == "ses_verify"

    await pursuit_response(bot, tmp_path, "ses_verify", {
        "type": "verdict",
        "verdict": "complete",
        "criteria": [{
            "criterion": "The root cause is demonstrated with evidence",
            "status": "pass",
            "evidence": "Independent inspection confirms parser X",
        }],
        "evidence": ["Independent inspection confirms parser X"],
        "feedback": "",
        "gap": "",
        "question": None,
    })
    assert state.pursuit_goal is None
    opencode.delete_session.assert_awaited_once_with("ses_verify", str(tmp_path))
    final = matrix.room_send.await_args.kwargs["content"]["m.new_content"]["body"]
    assert "Pursuit complete" in final


async def test_stop_clears_pursuit_before_aborting(tmp_path: Path) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    state = RoomSession(
        "ses_1",
        str(tmp_path),
        in_flight_event_id="$event",
        pursuit_goal="Keep looking",
        pursuit_phase="working",
        pursuit_iteration=4,
        verifier_session_id="ses_verify",
    )
    store.rooms["!one:example"] = state
    opencode.session_status.return_value = {"ses_1": {"type": "busy"}}

    await bot.command_stop("!one:example")

    assert state.pursuit_goal is None
    assert state.pursuit_iteration == 0
    opencode.abort.assert_awaited_once_with("ses_1", str(tmp_path))
    opencode.delete_session.assert_awaited_once_with("ses_verify", str(tmp_path))


async def test_persisted_idle_pursuit_resumes(tmp_path: Path) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    state = RoomSession(
        "ses_1",
        str(tmp_path),
        pursuit_goal="Keep investigating",
        pursuit_phase="working",
        pursuit_iteration=2,
        acceptance_criteria=["Find reliable evidence"],
    )
    store.rooms["!one:example"] = state

    await bot.resume_pursuits()

    assert state.pursuit_iteration == 3
    assert state.in_flight_event_id is not None
    assert "Keep investigating" in opencode.prompt_async.await_args.args[2]


async def test_pursuit_pauses_for_material_input_and_normal_reply_resumes(
    tmp_path: Path,
) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession("ses_1", str(tmp_path))
    opencode.create_session.side_effect = [
        {"id": "ses_pursue"},
        {"id": "ses_verify"},
    ]
    await bot.command_pursue("!one:example", "Find a suitable product")

    await pursuit_response(bot, tmp_path, "ses_verify", {
        "type": "contract",
        "criteria": ["The product matches the user's required region"],
        "assumptions": [],
        "needs_input": True,
        "question": "Which country should availability be checked in?",
    })
    state = store.rooms["!one:example"]
    assert state.pursuit_phase == "waiting_input"

    await bot.prompt("!one:example", "Norway")
    assert state.pursuit_phase == "working"
    assert "User clarification: Norway" in state.pursuit_assumptions
    assert opencode.prompt_async.await_args.args[0] == "ses_pursue"


async def test_verifier_continue_records_feedback_and_replans(tmp_path: Path) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    state = RoomSession(
        "ses_1",
        str(tmp_path),
        pursuit_goal="Research the claim",
        pursuit_phase="verifying",
        pursuit_iteration=1,
        verifier_session_id="ses_verify",
        acceptance_criteria=["The claim is supported by a current primary source"],
        pursuit_last_worker_report="A blog repeats the claim.",
        in_flight_event_id="$verify",
    )
    store.rooms["!one:example"] = state

    await pursuit_response(bot, tmp_path, "ses_verify", {
        "type": "verdict",
        "verdict": "continue",
        "criteria": [{
            "criterion": "The claim is supported by a current primary source",
            "status": "unknown",
            "evidence": "Only a secondary blog was found",
        }],
        "evidence": [],
        "feedback": "Search the issuing authority's records and check contrary sources.",
        "gap": "No primary source",
        "question": None,
    })
    assert state.pursuit_phase == "working"
    assert state.pursuit_iteration == 2
    assert state.pursuit_gap == "No primary source"
    assert "issuing authority" in state.pursuit_reflections[-1]
    assert "issuing authority" in opencode.prompt_async.await_args.args[2]
    verifier_edit = matrix.room_send.await_args_list[-2].kwargs["content"]["m.new_content"]["body"]
    assert "Verifier: continue" in verifier_edit


async def test_invalid_verifier_envelope_is_hidden_and_repaired(tmp_path: Path) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession("ses_1", str(tmp_path))
    opencode.create_session.side_effect = [
        {"id": "ses_pursue"},
        {"id": "ses_verify"},
    ]
    await bot.command_pursue("!one:example", "Research carefully")

    await pursuit_text_and_idle(bot, tmp_path, "ses_verify", "not valid control JSON")
    state = store.rooms["!one:example"]
    assert state.pursuit_protocol_failures == 1
    assert state.pursuit_phase == "specifying"
    assert "malformed or contained placeholder" in opencode.prompt_async.await_args.args[2]
    visible = matrix.room_send.await_args_list[-2].kwargs["content"]["m.new_content"]["body"]
    assert "not valid control JSON" not in visible


async def test_placeholder_acceptance_contract_is_rejected(tmp_path: Path) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession("ses_old", str(tmp_path))
    opencode.create_session.side_effect = [
        {"id": "ses_pursue"},
        {"id": "ses_verify"},
    ]
    await bot.command_pursue("!one:example", "Research current jobs")

    await pursuit_response(bot, tmp_path, "ses_verify", {
        "type": "contract",
        "criteria": ["specific mandatory criterion"],
        "assumptions": ["assumption"],
        "needs_input": False,
        "question": None,
    })

    state = store.rooms["!one:example"]
    assert state.session_id == "ses_pursue"
    assert state.pursuit_phase == "specifying"
    assert state.acceptance_criteria == []
    assert state.pursuit_protocol_failures == 1
    assert all(call.args[0] == "ses_verify" for call in opencode.prompt_async.await_args_list)


async def test_three_identical_evidence_free_gaps_reset_worker_context(
    tmp_path: Path,
) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    state = RoomSession(
        "ses_1",
        str(tmp_path),
        pursuit_goal="Find the record",
        pursuit_phase="verifying",
        pursuit_iteration=1,
        verifier_session_id="ses_verify",
        acceptance_criteria=["Locate the authoritative record"],
        pursuit_last_worker_report="No result",
        in_flight_event_id="$verify",
    )
    store.rooms["!one:example"] = state
    opencode.create_session.return_value = {"id": "ses_reset", "title": "Reset"}
    verdict = {
        "type": "verdict",
        "verdict": "continue",
        "criteria": [{
            "criterion": "Locate the authoritative record",
            "status": "unknown",
            "evidence": "No authoritative record located",
        }],
        "evidence": [],
        "feedback": "Change search vocabulary and database.",
        "gap": "Authoritative record not located",
        "question": None,
    }

    for index in range(3):
        await pursuit_response(bot, tmp_path, "ses_verify", verdict)
        if index < 2:
            await pursuit_text_and_idle(bot, tmp_path, "ses_1", "Still no result")

    assert state.session_id == "ses_reset"
    assert state.pursuit_stagnation_count == 0
    assert "fresh strategy context" in opencode.prompt_async.await_args.args[2]


async def test_status_reports_pursuit_progress_and_pending_question(tmp_path: Path) -> None:
    bot, matrix, _, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession(
        "ses_1",
        str(tmp_path),
        pursuit_goal="Answer a question",
        pursuit_phase="waiting_input",
        pursuit_iteration=2,
        acceptance_criteria=["A", "B"],
        pursuit_criteria_status={"A": "pass", "B": "unknown"},
        pursuit_evidence=["Primary source confirms A"],
        pursuit_gap="B remains unknown",
        pursuit_pending_question="Which date range?",
        bump_confirmation_session_id="ses_1",
        bump_confirmation_activity_ms=1,
    )
    await bot.command_status("!one:example")
    body = matrix.room_send.await_args.kwargs["content"]["body"]
    assert "Pursuit: waiting_input, pass 2" in body
    assert "Acceptance: 1/2" in body
    assert "Which date range?" in body
    assert "awaiting !bump confirm" in body


async def test_status_shows_pursuit_tool_recovery_countdown(
    tmp_path: Path, monkeypatch
) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    monkeypatch.setattr("matrix_opencode_bot.bot.time.time", lambda: 1_000.0)
    store.rooms["!one:example"] = RoomSession(
        "ses_1",
        str(tmp_path),
        in_flight_event_id="$work",
        prompt_started_ms=900_000,
        last_activity_ms=999_000,
        pursuit_goal="Finish",
        pursuit_phase="working",
        active_tools={"part": {"name": "bash", "started_ms": 940_000}},
    )
    opencode.session_status.return_value = {"ses_1": {"type": "busy"}}

    await bot.command_status("!one:example")

    body = matrix.room_send.await_args.kwargs["content"]["body"]
    assert "Automatic recovery: tool bash in 1m 00s" in body


async def test_pursuit_submission_error_retries_with_backoff(
    tmp_path: Path, monkeypatch
) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession("ses_1", str(tmp_path))
    opencode.create_session.side_effect = [
        {"id": "ses_pursue"},
        {"id": "ses_verify"},
    ]
    opencode.prompt_async.side_effect = [OpenCodeError("offline"), None]
    sleep = AsyncMock()
    monkeypatch.setattr("matrix_opencode_bot.bot.asyncio.sleep", sleep)

    await bot.command_pursue("!one:example", "Keep trying")
    await bot.retry_tasks["!one:example"]

    assert opencode.prompt_async.await_count == 2
    sleep.assert_awaited_once_with(1)
    assert store.rooms["!one:example"].pursuit_retry_attempts == 0


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
    state = RoomSession(
        "ses_1", str(tmp_path), in_flight_event_id="$progress", prompt_started_ms=1
    )
    store.rooms["!one:example"] = state
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
    assert state.active_tools["tool-part"]["name"] == "bash"
    assert "input" not in state.active_tools["tool-part"]

    bot.last_edit.clear()
    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {
            "type": "message.part.updated",
            "properties": {
                "part": {
                    "id": "tool-part", "sessionID": "ses_1", "type": "tool",
                    "tool": "bash", "state": {"status": "completed"},
                }
            },
        },
    })
    await bot.edit_tasks["!one:example"]
    assert state.active_tools == {}


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


async def test_live_edits_respect_matrix_rate_limit_interval(
    tmp_path: Path, monkeypatch
) -> None:
    bot, _, _, _ = make_bot(tmp_path)
    state = RoomSession(
        "ses_1", str(tmp_path), in_flight_event_id="$progress", prompt_started_ms=1
    )
    bot.last_edit["!one:example"] = 98.0
    monkeypatch.setattr("matrix_opencode_bot.bot.time.monotonic", lambda: 100.0)
    sleep = AsyncMock()
    monkeypatch.setattr("matrix_opencode_bot.bot.asyncio.sleep", sleep)

    bot.schedule_live_edit("!one:example", state)
    await bot.edit_tasks["!one:example"]

    sleep.assert_awaited_once_with(3.0)


async def test_initial_matrix_message_also_delays_first_live_edit(
    tmp_path: Path, monkeypatch
) -> None:
    bot, _, _, _ = make_bot(tmp_path)
    state = RoomSession(
        "ses_1", str(tmp_path), in_flight_event_id="$progress", prompt_started_ms=1
    )
    monkeypatch.setattr("matrix_opencode_bot.bot.time.monotonic", lambda: 100.0)
    sleep = AsyncMock()
    monkeypatch.setattr("matrix_opencode_bot.bot.asyncio.sleep", sleep)

    await bot.send_text("!one:example", "Working…")
    bot.schedule_live_edit("!one:example", state)
    await bot.edit_tasks["!one:example"]

    sleep.assert_awaited_once_with(5.0)


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


async def test_current_permission_asked_schema_is_forwarded_to_matrix(
    tmp_path: Path,
) -> None:
    bot, matrix, _, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession("ses_1", str(tmp_path))

    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {
            "type": "permission.asked",
            "properties": {
                "id": "per_external",
                "sessionID": "ses_1",
                "permission": "external_directory",
                "patterns": ["/home/user/Documents/jobbsoek/*"],
                "always": ["/home/user/Documents/jobbsoek/*"],
            },
        },
    })

    pending = store.rooms["!one:example"].pending_permissions
    assert len(pending) == 1
    assert pending[0].type == "external_directory"
    assert pending[0].pattern == "/home/user/Documents/jobbsoek/*"
    body = matrix.room_send.await_args.kwargs["content"]["body"]
    assert "external_directory" in body
    assert "!allow or !deny" in body


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
    state.watchdog_recovery_pending = True
    state.watchdog_recovery_attempts = 4
    await bot.command_stop("!one:example")
    opencode.abort.assert_awaited_once_with("ses_1", str(tmp_path))
    assert state.stop_requested is True
    assert state.watchdog_recovery_pending is False
    assert state.watchdog_recovery_attempts == 0


async def test_bump_reports_inactivity_then_confirm_resumes_same_pursuit_phase(
    tmp_path: Path, monkeypatch
) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    monkeypatch.setattr("matrix_opencode_bot.bot.time.time", lambda: 1_000.0)
    state = RoomSession(
        "ses_1",
        str(tmp_path),
        in_flight_event_id="$work",
        prompt_started_ms=1,
        pursuit_goal="Finish the research",
        pursuit_phase="working",
        pursuit_iteration=1,
        acceptance_criteria=["Answer every material question with evidence"],
    )
    state.last_activity_ms = 100_000
    store.rooms["!one:example"] = state
    opencode.session_status.side_effect = [
        {"ses_1": {"type": "busy"}},
        {"ses_1": {"type": "busy"}},
    ]
    opencode.create_session.return_value = {
        "id": "ses_recovered",
        "title": "Recovered pursuit",
    }

    await bot.command_bump("!one:example", "")
    prompt = matrix.room_send.await_args.kwargs["content"]["body"]
    assert "15m 00s ago" in prompt
    assert "!bump confirm" in prompt
    assert state.bump_confirmation_session_id == "ses_1"

    await bot.command_bump("!one:example", "confirm")
    opencode.abort.assert_awaited_once_with("ses_1", str(tmp_path))
    assert state.manual_bump_pending is False
    assert state.session_id == "ses_recovered"
    assert state.pursuit_phase == "working"
    assert state.pursuit_iteration == 2
    assert "Finish the research" in opencode.prompt_async.await_args.args[2]


async def test_bump_confirmation_expires_when_activity_resumes(tmp_path: Path) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    state = RoomSession(
        "ses_1", str(tmp_path), in_flight_event_id="$work", prompt_started_ms=1
    )
    state.last_activity_ms = 1
    store.rooms["!one:example"] = state
    opencode.session_status.return_value = {"ses_1": {"type": "busy"}}

    await bot.command_bump("!one:example", "")
    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {
            "type": "message.part.updated",
            "properties": {
                "part": {
                    "id": "answer", "sessionID": "ses_1",
                    "type": "text", "text": "I am making progress",
                }
            },
        },
    })
    await bot.edit_tasks["!one:example"]
    assert state.bump_confirmation_session_id is None

    await bot.command_bump("!one:example", "confirm")
    opencode.abort.assert_not_awaited()
    assert "No bump is awaiting confirmation" in matrix.room_send.await_args.kwargs["content"]["body"]


async def test_bump_never_interrupts_pending_permission(tmp_path: Path) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession(
        "ses_1",
        str(tmp_path),
        in_flight_event_id="$work",
        pending_permissions=[PendingPermission("perm", "Approve search", "web")],
    )
    await bot.command_bump("!one:example", "")
    assert "waiting for permission" in matrix.room_send.await_args.kwargs["content"]["body"]
    opencode.abort.assert_not_awaited()


def assistant_message(*, created: int, completed: int | None = None, text: str = ""):
    time_value = {"created": created}
    if completed is not None:
        time_value["completed"] = completed
    return {
        "info": {"role": "assistant", "time": time_value},
        "parts": [{"type": "text", "text": text}] if text else [],
    }


async def test_watchdog_waits_for_full_silence_window(
    tmp_path: Path, monkeypatch
) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    monkeypatch.setattr("matrix_opencode_bot.bot.time.time", lambda: 1_000.0)
    state = RoomSession(
        "ses_1", str(tmp_path), in_flight_event_id="$event", prompt_started_ms=1
    )
    state.last_activity_ms = 101_000
    store.rooms["!one:example"] = state
    opencode.session_status.return_value = {"ses_1": {"type": "busy"}}
    opencode.messages.return_value = [assistant_message(created=2)]

    await bot.watchdog_check()
    opencode.abort.assert_not_awaited()

    state.last_activity_ms = 100_000
    await bot.watchdog_check()
    opencode.abort.assert_awaited_once_with("ses_1", str(tmp_path))
    assert state.watchdog_recovery_pending is True
    assert state.watchdog_recovery_attempts == 1
    assert state.last_activity_ms == 1_000_000


async def test_pursuit_stalled_tool_is_quarantined_and_resumed_in_fresh_worker(
    tmp_path: Path, monkeypatch
) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    monkeypatch.setattr("matrix_opencode_bot.bot.time.time", lambda: 1_000.0)
    state = RoomSession(
        "ses_poisoned",
        str(tmp_path),
        in_flight_event_id="$event",
        prompt_started_ms=900_000,
        last_activity_ms=999_000,
        pursuit_goal="Finish reliable research",
        pursuit_phase="working",
        pursuit_iteration=1,
        acceptance_criteria=["Every claim has verified evidence"],
        active_tools={"part": {"name": "bash", "started_ms": 879_000}},
    )
    store.rooms["!one:example"] = state
    opencode.session_status.return_value = {"ses_poisoned": {"type": "busy"}}
    opencode.messages.return_value = [assistant_message(created=900_001)]
    opencode.create_session.return_value = {
        "id": "ses_recovered",
        "title": "Recovered pursuit",
    }

    await bot.watchdog_check()

    opencode.abort.assert_awaited_once_with("ses_poisoned", str(tmp_path))
    alerts = [
        call.kwargs["content"]["body"]
        for call in bot.client.room_send.await_args_list
        if "m.relates_to" not in call.kwargs["content"]
    ]
    assert any("Automatic recovery" in body and "tool bash" in body for body in alerts)
    assert state.session_id == "ses_recovered"
    assert state.pursuit_phase == "working"
    assert state.pursuit_iteration == 2
    assert state.watchdog_recovery_pending is False
    assert state.recovery_reason is None
    assert any("tool bash" in item for item in state.pursuit_reflections)
    opencode.prompt_async.assert_awaited_once()
    assert opencode.prompt_async.await_args.args[0] == "ses_recovered"
    worker_prompt = opencode.prompt_async.await_args.args[2]
    assert "bounded, non-interactive operations" in worker_prompt


async def test_pursuit_stalled_verifier_is_recreated_immediately(
    tmp_path: Path, monkeypatch
) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    monkeypatch.setattr("matrix_opencode_bot.bot.time.time", lambda: 1_000.0)
    state = RoomSession(
        "ses_worker",
        str(tmp_path),
        in_flight_event_id="$event",
        prompt_started_ms=900_000,
        last_activity_ms=999_000,
        pursuit_goal="Verify the answer",
        pursuit_phase="verifying",
        pursuit_iteration=2,
        verifier_session_id="ses_verifier_poisoned",
        acceptance_criteria=["The answer is evidenced"],
        active_tools={"part": {"name": "webfetch", "started_ms": 879_000}},
    )
    store.rooms["!one:example"] = state
    opencode.session_status.return_value = {
        "ses_verifier_poisoned": {"type": "busy"}
    }
    opencode.messages.return_value = [assistant_message(created=900_001)]
    opencode.create_session.return_value = {"id": "ses_verifier_recovered"}

    await bot.watchdog_check()

    opencode.abort.assert_awaited_once_with("ses_verifier_poisoned", str(tmp_path))
    opencode.delete_session.assert_awaited_once_with(
        "ses_verifier_poisoned", str(tmp_path)
    )
    assert state.session_id == "ses_worker"
    assert state.verifier_session_id == "ses_verifier_recovered"
    assert state.pursuit_phase == "verifying"
    opencode.prompt_async.assert_awaited_once()
    assert opencode.prompt_async.await_args.args[0] == "ses_verifier_recovered"


async def test_watchdog_activity_and_permission_pause_recovery(
    tmp_path: Path, monkeypatch
) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    current_time = 1_000.0
    monkeypatch.setattr(
        "matrix_opencode_bot.bot.time.time", lambda: current_time
    )
    state = RoomSession(
        "ses_1",
        str(tmp_path),
        in_flight_event_id="$event",
        prompt_started_ms=1,
        pending_permissions=[PendingPermission("perm", "Approve", "bash")],
    )
    state.last_activity_ms = 1
    store.rooms["!one:example"] = state
    opencode.session_status.return_value = {"ses_1": {"type": "busy"}}
    opencode.messages.return_value = [assistant_message(created=2)]

    await bot.watchdog_check()
    opencode.abort.assert_not_awaited()

    current_time = 1_001.0
    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {
            "type": "session.status",
            "properties": {"sessionID": "ses_1", "status": {"type": "busy"}},
        },
    })
    assert state.last_activity_ms == 1_001_000
    await bot.edit_tasks["!one:example"]


async def test_watchdog_reconciles_missed_idle_event(tmp_path: Path) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    state = RoomSession(
        "ses_1", str(tmp_path), in_flight_event_id="$event", prompt_started_ms=1
    )
    state.text_parts["answer"] = "Recovered answer"
    store.rooms["!one:example"] = state

    await bot.watchdog_check()

    assert state.in_flight_event_id is None
    body = matrix.room_send.await_args.kwargs["content"]["m.new_content"]["body"]
    assert body == "Recovered answer"
    opencode.abort.assert_not_awaited()


async def test_watchdog_clears_stale_busy_only_for_completed_message(
    tmp_path: Path,
) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    state = RoomSession(
        "ses_1", str(tmp_path), in_flight_event_id="$event", prompt_started_ms=1
    )
    store.rooms["!one:example"] = state
    opencode.session_status.return_value = {"ses_1": {"type": "busy"}}
    opencode.messages.return_value = [
        assistant_message(created=2, completed=3, text="Already finished")
    ]

    await bot.watchdog_check()

    opencode.abort.assert_awaited_once_with("ses_1", str(tmp_path))
    opencode.prompt_async.assert_not_awaited()
    assert state.in_flight_event_id is None
    body = matrix.room_send.await_args.kwargs["content"]["m.new_content"]["body"]
    assert body == "Already finished"


async def test_watchdog_aborts_then_continues_after_confirmed_idle(
    tmp_path: Path, monkeypatch
) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    monkeypatch.setattr("matrix_opencode_bot.bot.time.time", lambda: 1_000.0)
    state = RoomSession(
        "ses_1", str(tmp_path), in_flight_event_id="$event", prompt_started_ms=1
    )
    state.last_activity_ms = 1
    store.rooms["!one:example"] = state
    opencode.session_status.side_effect = [
        {"ses_1": {"type": "busy"}},
        {},
        {"ses_1": {"type": "busy"}},
    ]
    opencode.messages.return_value = [assistant_message(created=2)]

    await bot.watchdog_check()
    assert state.watchdog_recovery_pending is True
    assert state.in_flight_event_id == "$event"
    opencode.prompt_async.assert_not_awaited()

    await bot.watchdog_check()
    assert state.watchdog_recovery_pending is False
    assert state.watchdog_recovery_attempts == 1
    assert state.in_flight_event_id is not None
    continuation = opencode.prompt_async.await_args.args[2]
    assert "automatically interrupted" in continuation
    assert "avoid repeating" in continuation

    state.last_activity_ms = 1
    await bot.watchdog_check()
    assert state.watchdog_recovery_pending is True
    assert state.watchdog_recovery_attempts == 2
    assert opencode.abort.await_count == 2


async def test_watchdog_retries_rejected_abort_on_next_check(
    tmp_path: Path, monkeypatch
) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    monkeypatch.setattr("matrix_opencode_bot.bot.time.time", lambda: 1_000.0)
    state = RoomSession(
        "ses_1", str(tmp_path), in_flight_event_id="$event", prompt_started_ms=1
    )
    state.last_activity_ms = 1
    store.rooms["!one:example"] = state
    opencode.session_status.return_value = {"ses_1": {"type": "busy"}}
    opencode.messages.return_value = [assistant_message(created=2)]
    opencode.abort.return_value = False

    await bot.watchdog_check()
    await bot.watchdog_check()

    assert opencode.abort.await_count == 2
    assert state.watchdog_recovery_pending is True
    assert state.watchdog_recovery_attempts == 2


async def test_abort_error_waits_for_idle_before_watchdog_continuation(
    tmp_path: Path,
) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    state = RoomSession(
        "ses_1",
        str(tmp_path),
        in_flight_event_id="$event",
        prompt_started_ms=1,
        watchdog_recovery_pending=True,
        watchdog_recovery_attempts=1,
    )
    store.rooms["!one:example"] = state

    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {
            "type": "session.error",
            "properties": {
                "sessionID": "ses_1",
                "error": {"message": "aborted"},
            },
        },
    })

    assert state.in_flight_event_id == "$event"
    assert state.watchdog_recovery_pending is True
    opencode.prompt_async.assert_not_awaited()
    await bot.edit_tasks["!one:example"]

    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {"type": "session.idle", "properties": {"sessionID": "ses_1"}},
    })
    opencode.prompt_async.assert_awaited_once()


async def test_restored_pending_recovery_continues_when_idle(tmp_path: Path) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    state = RoomSession(
        "ses_1",
        str(tmp_path),
        in_flight_event_id="$event",
        prompt_started_ms=1,
        watchdog_recovery_pending=True,
        watchdog_recovery_attempts=2,
    )
    store.rooms["!one:example"] = state

    await bot.validate_restored_state()

    opencode.prompt_async.assert_awaited_once()
    assert state.watchdog_recovery_pending is False
    assert state.watchdog_recovery_attempts == 2
    assert state.last_activity_ms is not None


async def test_restart_quarantines_persisted_placeholder_contract(
    tmp_path: Path,
) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    state = RoomSession(
        "ses_poisoned",
        str(tmp_path),
        in_flight_event_id="$event",
        prompt_started_ms=1,
        pursuit_goal="Research jobs",
        pursuit_phase="working",
        pursuit_iteration=2,
        verifier_session_id="ses_bad_verifier",
        acceptance_criteria=["specific mandatory criterion"],
        pursuit_assumptions=["assumption"],
    )
    store.rooms["!one:example"] = state
    opencode.get_session.return_value = {"id": "ses_poisoned", "title": "Old"}
    opencode.create_session.side_effect = [
        {"id": "ses_recovered_worker", "title": "Recovered"},
        {"id": "ses_recovered_verifier"},
    ]

    await bot.validate_restored_state()

    opencode.abort.assert_awaited_once_with("ses_poisoned", str(tmp_path))
    opencode.delete_session.assert_awaited_once_with(
        "ses_bad_verifier", str(tmp_path)
    )
    assert state.session_id == "ses_recovered_worker"
    assert state.verifier_session_id == "ses_recovered_verifier"
    assert state.pursuit_phase == "specifying"
    assert state.acceptance_criteria == []
    assert state.pursuit_assumptions == []
    assert state.in_flight_event_id is None


async def test_watchdog_task_is_cancelled_on_close(tmp_path: Path) -> None:
    bot, _, _, _ = make_bot(tmp_path)
    bot.start_watchdog()
    task = bot.watchdog_task
    assert task is not None
    await bot.close()
    assert task.cancelled()
    assert bot.watchdog_task is None


def test_render_diffs_and_chunking() -> None:
    rendered = render_diffs([
        {"file": "a.txt", "before": "old\n", "after": "new\n", "additions": 1, "deletions": 1}
    ])
    assert "a.txt (+1/-1)" in rendered
    assert "--- a/a.txt" in rendered
    assert "+new" in rendered
    assert split_text("123456789", 4) == ["1234", "5678", "9"]
