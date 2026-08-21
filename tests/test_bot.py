import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from matrix_opencode_bot.bot import (
    MatrixOpenCodeBot,
    _parse_pursuit_control,
    render_diffs,
    split_text,
)
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
        pursuit_tool_timeout_seconds=120,
    )


def make_bot(tmp_path: Path, *, show_reasoning: bool = False):
    counter = 0

    async def room_send(**_: object):
        nonlocal counter
        counter += 1
        return SimpleNamespace(event_id=f"$event{counter}")

    matrix = SimpleNamespace(
        user_id="@bot:example",
        rooms={},
        room_send=AsyncMock(side_effect=room_send),
        upload=AsyncMock(),
    )
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


def criteria(*texts: str) -> list[dict[str, str]]:
    return [
        {"id": f"c{index}", "text": text}
        for index, text in enumerate(texts, start=1)
    ]


def evidence(
    claim: str = "Independent inspection confirms the claim",
    source: str = "/work/result.txt",
    verification: str = "Opened the source and checked the relevant record",
) -> list[dict[str, str]]:
    return [{"claim": claim, "source": source, "verification": verification}]


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
    assert store.rooms["!one:example"].yolo_permissions is False
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
    assert "!send" in body
    assert "!obsess" not in body


async def test_startup_logo_is_encrypted_and_sized_for_element(tmp_path: Path) -> None:
    bot, matrix, _, _ = make_bot(tmp_path)
    matrix.rooms = {
        "!one:example": SimpleNamespace(encrypted=True),
        "!two:example": SimpleNamespace(encrypted=True),
    }
    matrix.upload.return_value = (
        SimpleNamespace(content_uri="mxc://example/logo"),
        {
            "key": {"kty": "oct", "k": "secret"},
            "iv": "iv",
            "hashes": {"sha256": "hash"},
            "v": "v2",
        },
    )

    await bot.send_startup_logos()

    assert matrix.upload.await_count == 2
    assert all(call.kwargs["encrypt"] is True for call in matrix.upload.await_args_list)
    content = matrix.room_send.await_args.kwargs["content"]
    assert content["msgtype"] == "m.image"
    assert content["body"] == "OpenBot is online"
    assert content["info"]["w"] == 1280
    assert content["info"]["h"] == 720
    assert content["file"]["url"] == "mxc://example/logo"
    assert "url" not in content


async def test_startup_logo_uses_plain_media_for_unencrypted_room(tmp_path: Path) -> None:
    bot, matrix, _, _ = make_bot(tmp_path)
    matrix.rooms = {"!one:example": SimpleNamespace(encrypted=False)}
    matrix.upload.return_value = (SimpleNamespace(content_uri="mxc://example/logo"), None)

    await bot.send_startup_logos()

    assert matrix.upload.await_args.kwargs["encrypt"] is False
    content = matrix.room_send.await_args.kwargs["content"]
    assert content["url"] == "mxc://example/logo"
    assert "file" not in content


async def test_send_finds_and_uploads_unique_file_encrypted(tmp_path: Path) -> None:
    bot, matrix, _, store = make_bot(tmp_path)
    document = tmp_path / "reports" / "myfile.pdf"
    document.parent.mkdir()
    document.write_bytes(b"a small pdf")
    store.rooms["!one:example"] = RoomSession("ses_1", str(tmp_path))
    matrix.rooms = {"!one:example": SimpleNamespace(encrypted=True)}
    matrix.upload.return_value = (
        SimpleNamespace(content_uri="mxc://example/document"),
        {"key": {"kty": "oct", "k": "secret"}, "iv": "iv", "hashes": {}},
    )

    await bot.on_message(room(), message(bot, "!send myfile.pdf"))

    assert matrix.upload.await_args.kwargs == {
        "content_type": "application/pdf",
        "filename": "myfile.pdf",
        "encrypt": True,
        "filesize": len(b"a small pdf"),
    }
    content = matrix.room_send.await_args.kwargs["content"]
    assert content["msgtype"] == "m.file"
    assert content["body"] == "myfile.pdf"
    assert content["file"]["url"] == "mxc://example/document"
    assert "url" not in content


async def test_send_suggests_relative_paths_when_filename_is_ambiguous(
    tmp_path: Path,
) -> None:
    bot, matrix, _, store = make_bot(tmp_path)
    for folder in ("drafts", "final"):
        path = tmp_path / folder / "report.pdf"
        path.parent.mkdir()
        path.write_bytes(folder.encode())
    store.rooms["!one:example"] = RoomSession("ses_1", str(tmp_path))

    await bot.on_message(room(), message(bot, "!send report.pdf"))

    matrix.upload.assert_not_awaited()
    body = matrix.room_send.await_args.kwargs["content"]["body"]
    assert "!send drafts/report.pdf" in body
    assert "!send final/report.pdf" in body

    matrix.rooms = {"!one:example": SimpleNamespace(encrypted=False)}
    matrix.upload.return_value = (SimpleNamespace(content_uri="mxc://example/report"), None)
    await bot.on_message(room(), message(bot, "!send final/report.pdf"))
    assert matrix.upload.await_args.kwargs["encrypt"] is False
    assert matrix.room_send.await_args.kwargs["content"]["url"] == "mxc://example/report"


async def test_send_rejects_paths_outside_workspace(tmp_path: Path) -> None:
    bot, matrix, _, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession("ses_1", str(tmp_path))

    await bot.on_message(room(), message(bot, "!send ../secret.pdf"))

    matrix.upload.assert_not_awaited()
    assert "No file matching" in matrix.room_send.await_args.kwargs["content"]["body"]


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
    assert '"pursuit_context_input_tokens": 250000' in report
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
    await bot.prompt("!one:example", "n")
    await bot.prompt("!one:example", "1")

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
            "id": "c1",
            "status": "pass",
            "evidence": evidence("Independent inspection confirms parser X"),
        }],
        "feedback": "",
        "gap": "",
        "question": None,
    })
    assert state.pursuit_goal is None
    opencode.delete_session.assert_awaited_once_with("ses_verify", str(tmp_path))
    final = matrix.room_send.await_args.kwargs["content"]["m.new_content"]["body"]
    assert "Pursuit complete" in final


async def test_pursue_in_new_room_starts_session_then_asks_for_yolo(
    tmp_path: Path,
) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)

    await bot.command_pursue("!one:example", "Investigate")

    state = store.rooms["!one:example"]
    assert state.pending_pursuit_yolo_confirmation is True
    assert state.pending_pursuit_reuse_session is True
    assert "Started OpenCode session" in (
        matrix.room_send.await_args_list[0].kwargs["content"]["body"]
    )
    assert "Use YOLO mode" in matrix.room_send.await_args_list[1].kwargs["content"]["body"]
    opencode.prompt_async.assert_not_awaited()


async def test_pursue_waits_for_yolo_then_extent_and_applies_exhaustive_mode(
    tmp_path: Path,
) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession("ses_1", str(tmp_path))
    opencode.create_session.side_effect = [
        {"id": "ses_pursue", "title": "Pursuit worker"},
        {"id": "ses_verify", "title": "Verifier"},
    ]

    await bot.command_pursue("!one:example", "Map the whole problem")

    state = store.rooms["!one:example"]
    assert state.pending_pursuit_goal == "Map the whole problem"
    assert state.pending_pursuit_yolo_confirmation is True
    assert state.pursuit_goal is None
    opencode.create_session.assert_not_awaited()
    question = matrix.room_send.await_args.kwargs["content"]["body"]
    assert "Use YOLO mode" in question
    assert "entire mapped session" in question
    assert "worker and verifier" in question

    await bot.prompt("!one:example", "Y")

    assert state.yolo_permissions is True
    assert state.pending_pursuit_yolo_confirmation is False
    opencode.create_session.assert_not_awaited()
    question = matrix.room_send.await_args.kwargs["content"]["body"]
    assert "Reply with a number" in question
    assert "may run for hours" in question

    await bot.prompt("!one:example", "3")

    assert state.pending_pursuit_goal is None
    assert state.pursuit_goal == "Map the whole problem"
    assert state.pursuit_extent == 3
    assert "every plausible search space" in opencode.prompt_async.await_args.args[2]
    assert "may run for hours" in opencode.prompt_async.await_args.args[2]


async def test_invalid_pursuit_extent_keeps_waiting(tmp_path: Path) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession("ses_1", str(tmp_path))

    await bot.command_pursue("!one:example", "Investigate")
    await bot.prompt("!one:example", "n")
    await bot.prompt("!one:example", "very")

    state = store.rooms["!one:example"]
    assert state.pending_pursuit_goal == "Investigate"
    assert "Please reply with 1" in matrix.room_send.await_args.kwargs["content"]["body"]
    opencode.create_session.assert_not_awaited()


async def test_invalid_pursuit_yolo_choice_keeps_waiting(tmp_path: Path) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession("ses_1", str(tmp_path))

    await bot.command_pursue("!one:example", "Investigate")
    await bot.prompt("!one:example", "maybe")

    state = store.rooms["!one:example"]
    assert state.pending_pursuit_yolo_confirmation is True
    assert state.pending_pursuit_goal == "Investigate"
    assert "Please reply with y or n" in matrix.room_send.await_args.kwargs["content"]["body"]
    opencode.create_session.assert_not_awaited()


async def test_pursuit_no_disables_existing_yolo_mode(tmp_path: Path) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession(
        "ses_1", str(tmp_path), yolo_permissions=True
    )

    await bot.command_pursue("!one:example", "Investigate")
    await bot.prompt("!one:example", "N")

    state = store.rooms["!one:example"]
    assert state.yolo_permissions is False
    assert state.pending_pursuit_yolo_confirmation is False
    body = matrix.room_send.await_args.kwargs["content"]["body"]
    assert "Permission mode set to prompt" in body
    assert "Reply with a number" in body
    opencode.create_session.assert_not_awaited()


async def test_pending_pursuit_setup_status_duplicate_and_stop(tmp_path: Path) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    state = RoomSession("ses_1", str(tmp_path))
    store.rooms["!one:example"] = state

    await bot.command_pursue("!one:example", "Investigate")
    await bot.command_status("!one:example")
    assert "awaiting YOLO choice" in matrix.room_send.await_args.kwargs["content"]["body"]

    await bot.command_pursue("!one:example", "Another goal")
    assert "awaiting its YOLO choice" in matrix.room_send.await_args.kwargs["content"]["body"]

    await bot.prompt("!one:example", "n")
    await bot.command_status("!one:example")
    assert "awaiting extent" in matrix.room_send.await_args.kwargs["content"]["body"]

    await bot.command_stop("!one:example")
    assert state.pending_pursuit_goal is None
    assert state.pending_pursuit_yolo_confirmation is False
    assert "Pursuit stopped" in matrix.room_send.await_args.kwargs["content"]["body"]
    opencode.prompt_async.assert_not_awaited()


async def test_criterion_text_punctuation_is_not_part_of_verdict_protocol(
    tmp_path: Path,
) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    state = RoomSession(
        "ses_worker",
        str(tmp_path),
        pursuit_goal="Find good jobs",
        pursuit_phase="verifying",
        pursuit_iteration=1,
        verifier_session_id="ses_verify",
        acceptance_criteria=criteria('Jobs qualify as "good" using the frozen rubric'),
        in_flight_event_id="$verify",
    )
    store.rooms["!one:example"] = state

    await pursuit_response(bot, tmp_path, "ses_verify", {
        "type": "verdict",
        "verdict": "complete",
        "criteria": [{"id": "c1", "status": "pass", "evidence": evidence()}],
        "feedback": "",
        "gap": "",
        "question": None,
    })

    assert state.pursuit_goal is None
    opencode.delete_session.assert_awaited_once_with("ses_verify", str(tmp_path))


async def test_mismatched_verdict_ids_are_repaired_without_persisting_evidence(
    tmp_path: Path,
) -> None:
    bot, _, _, store = make_bot(tmp_path)
    state = RoomSession(
        "ses_worker",
        str(tmp_path),
        pursuit_goal="Verify two facts",
        pursuit_phase="verifying",
        verifier_session_id="ses_verify",
        acceptance_criteria=criteria("First fact", "Second fact"),
        in_flight_event_id="$verify",
    )
    store.rooms["!one:example"] = state

    await pursuit_response(bot, tmp_path, "ses_verify", {
        "type": "verdict",
        "verdict": "complete",
        "criteria": [
            {"id": "c1", "status": "pass", "evidence": evidence("one")},
            {"id": "c1", "status": "pass", "evidence": evidence("duplicate")},
        ],
        "feedback": "",
        "gap": "",
        "question": None,
    })

    assert state.pursuit_protocol_failures == 1
    assert state.pursuit_evidence == []
    assert state.pursuit_criteria_status == {}


def test_verdict_requires_structured_evidence_for_a_pass() -> None:
    base = {
        "type": "verdict",
        "verdict": "complete",
        "feedback": "",
        "gap": "",
        "question": None,
    }
    without_evidence = {
        **base,
        "criteria": [{"id": "c1", "status": "pass", "evidence": []}],
    }
    assert _parse_pursuit_control(json.dumps(without_evidence), "verifying") is None

    for source in ("https://example.test/record", "/work/result.json", "pytest -q"):
        payload = {
            **base,
            "criteria": [{
                "id": "c1",
                "status": "pass",
                "evidence": evidence(source=source),
            }],
        }
        assert _parse_pursuit_control(json.dumps(payload), "verifying") is not None


async def test_continue_persists_valid_partial_evidence_by_criterion(
    tmp_path: Path,
) -> None:
    bot, _, _, store = make_bot(tmp_path)
    state = RoomSession(
        "ses_worker",
        str(tmp_path),
        pursuit_goal="Verify two facts",
        pursuit_phase="verifying",
        verifier_session_id="ses_verify",
        acceptance_criteria=criteria("First fact", "Second fact"),
        in_flight_event_id="$verify",
    )
    store.rooms["!one:example"] = state

    await pursuit_response(bot, tmp_path, "ses_verify", {
        "type": "verdict",
        "verdict": "continue",
        "criteria": [
            {"id": "c1", "status": "pass", "evidence": evidence("First confirmed")},
            {"id": "c2", "status": "unknown", "evidence": []},
        ],
        "feedback": "Find the second primary source.",
        "gap": "Second fact remains unknown",
        "question": None,
    })

    assert state.pursuit_phase == "working"
    assert state.pursuit_criteria_status == {"c1": "pass", "c2": "unknown"}
    assert state.pursuit_evidence[0]["criterion_id"] == "c1"
    assert "First confirmed" in MatrixOpenCodeBot._worker_prompt(state)


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
        acceptance_criteria=criteria("Find reliable evidence"),
    )
    store.rooms["!one:example"] = state

    await bot.resume_pursuits()

    assert state.pursuit_iteration == 3
    assert state.in_flight_event_id is not None
    assert "Keep investigating" in opencode.prompt_async.await_args.args[2]
    assert opencode.prompt_async.await_args.kwargs["tools"]["task"] is False


async def test_legacy_active_pursuit_restarts_with_only_user_clarifications(
    tmp_path: Path,
) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    state = RoomSession(
        "ses_old_worker",
        str(tmp_path),
        pursuit_goal="Research carefully",
        pursuit_phase="verifying",
        pursuit_protocol_version=1,
        verifier_session_id="ses_old_verifier",
        acceptance_criteria=criteria("Old criterion"),
        pursuit_assumptions=[
            "Assume the market is global",
            "User clarification: Only Norway",
        ],
        pursuit_evidence=[{
            "criterion_id": "c1",
            "claim": "Old claim",
            "source": "https://example.test/old",
            "verification": "Old verifier said so",
        }],
        in_flight_event_id="$legacy",
    )
    store.rooms["!one:example"] = state
    opencode.create_session.side_effect = [
        {"id": "ses_new_worker", "title": "New worker"},
        {"id": "ses_new_verifier", "title": "New verifier"},
    ]

    await bot.validate_restored_state()

    opencode.abort.assert_awaited_once_with("ses_old_verifier", str(tmp_path))
    opencode.delete_session.assert_not_awaited()
    assert state.session_id == "ses_new_worker"
    assert state.verifier_session_id == "ses_new_verifier"
    assert state.pursuit_protocol_version == 2
    assert state.pursuit_phase == "specifying"
    assert state.pursuit_iteration == 0
    assert state.pursuit_assumptions == ["User clarification: Only Norway"]
    assert state.acceptance_criteria == []
    assert state.pursuit_evidence == []


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
    await bot.prompt("!one:example", "n")
    await bot.prompt("!one:example", "1")

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
        acceptance_criteria=criteria("The claim is supported by a current primary source"),
        pursuit_last_worker_report="A blog repeats the claim.",
        in_flight_event_id="$verify",
    )
    store.rooms["!one:example"] = state

    await pursuit_response(bot, tmp_path, "ses_verify", {
        "type": "verdict",
        "verdict": "continue",
        "criteria": [{
            "id": "c1",
            "status": "unknown",
            "evidence": [],
        }],
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
    await bot.prompt("!one:example", "n")
    await bot.prompt("!one:example", "1")

    await pursuit_text_and_idle(bot, tmp_path, "ses_verify", "not valid control JSON")
    state = store.rooms["!one:example"]
    assert state.pursuit_protocol_failures == 1
    assert state.pursuit_phase == "specifying"
    assert "malformed or contained placeholder" in opencode.prompt_async.await_args.args[2]
    visible = matrix.room_send.await_args_list[-2].kwargs["content"]["m.new_content"]["body"]
    assert "not valid control JSON" not in visible


async def test_bare_verifier_json_is_accepted_when_it_is_the_entire_response(
    tmp_path: Path,
) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession("ses_old", str(tmp_path))
    opencode.create_session.side_effect = [
        {"id": "ses_pursue"},
        {"id": "ses_verify"},
    ]
    await bot.command_pursue("!one:example", "Research current jobs")
    await bot.prompt("!one:example", "n")
    await bot.prompt("!one:example", "1")

    await pursuit_text_and_idle(
        bot,
        tmp_path,
        "ses_verify",
        json.dumps(
            {
                "type": "contract",
                "criteria": ["Every listed role is currently open and located in Oslo"],
                "assumptions": ["Roles advertised as hybrid in Oslo qualify"],
                "needs_input": False,
                "question": None,
            }
        ),
    )

    state = store.rooms["!one:example"]
    assert state.pursuit_phase == "working"
    assert state.pursuit_protocol_failures == 0
    assert state.acceptance_criteria == criteria(
        "Every listed role is currently open and located in Oslo"
    )
    assert opencode.prompt_async.await_args.args[0] == "ses_pursue"


def test_alternate_whole_response_control_wrappers_are_accepted() -> None:
    contract = {
        "type": "contract",
        "criteria": ["At least ten current Oslo jobs are supported by listing URLs"],
        "assumptions": [],
        "needs_input": False,
        "question": None,
    }
    nested = json.dumps({"pursuit-control": contract})

    assert _parse_pursuit_control(nested, "specifying") is not None
    assert _parse_pursuit_control(f"```json\n{nested}\n```", "specifying") is not None
    assert _parse_pursuit_control(f"Here is the result:\n{nested}", "specifying") is None


async def test_verifier_prompt_text_is_not_combined_with_assistant_contract(
    tmp_path: Path,
) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession("ses_old", str(tmp_path))
    opencode.create_session.side_effect = [
        {"id": "ses_pursue"},
        {"id": "ses_verify"},
    ]
    await bot.command_pursue("!one:example", "Research current jobs")
    await bot.prompt("!one:example", "n")
    await bot.prompt("!one:example", "1")

    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {
            "type": "message.updated",
            "properties": {
                "sessionID": "ses_verify",
                "info": {"id": "msg_user", "role": "user"},
            },
        },
    })
    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {
            "type": "message.part.updated",
            "properties": {
                "sessionID": "ses_verify",
                "part": {
                    "id": "prompt",
                    "messageID": "msg_user",
                    "sessionID": "ses_verify",
                    "type": "text",
                    "text": (
                        'Return <pursuit-control>{"criteria":["<criterion>"]}'
                        "</pursuit-control>"
                    ),
                },
            },
        },
    })
    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {
            "type": "message.updated",
            "properties": {
                "sessionID": "ses_verify",
                "info": {"id": "msg_assistant", "role": "assistant"},
            },
        },
    })
    contract = {
        "type": "contract",
        "criteria": ["Every listed role is currently open and located in Oslo"],
        "assumptions": [],
        "needs_input": False,
        "question": None,
    }
    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {
            "type": "message.part.updated",
            "properties": {
                "sessionID": "ses_verify",
                "part": {
                    "id": "answer",
                    "messageID": "msg_assistant",
                    "sessionID": "ses_verify",
                    "type": "text",
                    "text": f"<pursuit-control>{json.dumps(contract)}</pursuit-control>",
                },
            },
        },
    })
    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {
            "type": "session.idle",
            "properties": {"sessionID": "ses_verify"},
        },
    })

    state = store.rooms["!one:example"]
    assert state.pursuit_phase == "working"
    assert state.pursuit_protocol_failures == 0
    assert state.acceptance_criteria == criteria(*contract["criteria"])


async def test_placeholder_acceptance_contract_is_rejected(tmp_path: Path) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession("ses_old", str(tmp_path))
    opencode.create_session.side_effect = [
        {"id": "ses_pursue"},
        {"id": "ses_verify"},
    ]
    await bot.command_pursue("!one:example", "Research current jobs")
    await bot.prompt("!one:example", "n")
    await bot.prompt("!one:example", "1")

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
        acceptance_criteria=criteria("Locate the authoritative record"),
        pursuit_last_worker_report="No result",
        in_flight_event_id="$verify",
    )
    store.rooms["!one:example"] = state
    opencode.create_session.return_value = {"id": "ses_reset", "title": "Reset"}
    verdict = {
        "type": "verdict",
        "verdict": "continue",
        "criteria": [{
            "id": "c1",
            "status": "unknown",
            "evidence": [],
        }],
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
    assert "fresh context after stagnation or context rotation" in (
        opencode.prompt_async.await_args.args[2]
    )


async def test_worker_context_rotates_after_configured_input_threshold(
    tmp_path: Path,
) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    state = RoomSession(
        "ses_large",
        str(tmp_path),
        pursuit_goal="Find the record",
        pursuit_phase="working",
        pursuit_iteration=1,
        verifier_session_id="ses_verify",
        acceptance_criteria=criteria("Locate the record"),
        in_flight_event_id="$work",
    )
    store.rooms["!one:example"] = state
    opencode.get_session.return_value = {
        "id": "ses_large",
        "tokens": {"input": bot.settings.pursuit_context_input_tokens},
    }
    opencode.create_session.return_value = {
        "id": "ses_rotated",
        "title": "Rotated",
    }

    await pursuit_text_and_idle(bot, tmp_path, "ses_large", "Worker report")
    assert state.pursuit_worker_input_tokens == bot.settings.pursuit_context_input_tokens
    await pursuit_response(bot, tmp_path, "ses_verify", {
        "type": "verdict",
        "verdict": "continue",
        "criteria": [{"id": "c1", "status": "unknown", "evidence": []}],
        "feedback": "Try another source.",
        "gap": "Record not found",
        "question": None,
    })

    assert state.session_id == "ses_rotated"
    assert state.pursuit_worker_input_tokens == 0
    assert "input-token threshold" in state.pursuit_reflections[-1]
    assert opencode.create_session.await_count == 1


async def test_context_and_stagnation_thresholds_cause_one_rotation(
    tmp_path: Path,
) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    state = RoomSession(
        "ses_large",
        str(tmp_path),
        pursuit_goal="Find the record",
        pursuit_phase="verifying",
        pursuit_iteration=3,
        verifier_session_id="ses_verify",
        acceptance_criteria=criteria("Locate the record"),
        pursuit_worker_input_tokens=bot.settings.pursuit_context_input_tokens,
        pursuit_stagnation_count=2,
        pursuit_signature="c1|Record not found",
        in_flight_event_id="$verify",
    )
    store.rooms["!one:example"] = state
    opencode.create_session.return_value = {"id": "ses_rotated", "title": "Rotated"}

    await pursuit_response(bot, tmp_path, "ses_verify", {
        "type": "verdict",
        "verdict": "continue",
        "criteria": [{"id": "c1", "status": "unknown", "evidence": []}],
        "feedback": "Try another source.",
        "gap": "Record not found",
        "question": None,
    })

    assert state.session_id == "ses_rotated"
    assert opencode.create_session.await_count == 1


async def test_worker_token_metadata_failure_keeps_current_context(
    tmp_path: Path,
) -> None:
    bot, _, opencode, _ = make_bot(tmp_path)
    state = RoomSession("ses_worker", str(tmp_path), pursuit_worker_input_tokens=123)
    opencode.get_session.side_effect = OpenCodeError("metadata unavailable")

    await bot._capture_worker_input_tokens(state)

    assert state.pursuit_worker_input_tokens == 123


async def test_status_reports_pursuit_progress_and_pending_question(tmp_path: Path) -> None:
    bot, matrix, _, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession(
        "ses_1",
        str(tmp_path),
        pursuit_goal="Answer a question",
        pursuit_phase="waiting_input",
        pursuit_iteration=2,
        acceptance_criteria=criteria("A", "B"),
        pursuit_criteria_status={"c1": "pass", "c2": "unknown"},
        pursuit_evidence=[{
            "criterion_id": "c1",
            "claim": "Primary source confirms A",
            "source": "https://example.test/a",
            "verification": "Fetched and checked the primary source",
        }],
        pursuit_gap="B remains unknown",
        pursuit_pending_question="Which date range?",
        bump_confirmation_session_id="ses_1",
        bump_confirmation_activity_ms=1,
    )
    await bot.command_status("!one:example")
    body = matrix.room_send.await_args.kwargs["content"]["body"]
    assert "Pursuit: waiting_input, pass 2" in body
    assert "Acceptance: 1/2" in body
    assert "0/250,000 input tokens" in body
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
    await bot.prompt("!one:example", "n")
    await bot.prompt("!one:example", "1")
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


async def test_ordinary_prompt_does_not_override_tool_availability(tmp_path: Path) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession("ses_1", str(tmp_path))

    await bot.prompt("!one:example", "Inspect the project")

    opencode.prompt_async.assert_awaited_once_with(
        "ses_1", str(tmp_path), "Inspect the project"
    )


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


async def test_text_deltas_stream_and_are_compacted_in_diagnostics(tmp_path: Path) -> None:
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
                    "id": "answer", "sessionID": "ses_1", "type": "text", "text": ""
                }
            },
        },
    })
    for delta in ("Hello", " world"):
        await bot.handle_opencode_event({
            "directory": str(tmp_path),
            "payload": {
                "type": "message.part.delta",
                "properties": {
                    "sessionID": "ses_1",
                    "messageID": "msg_1",
                    "partID": "answer",
                    "field": "text",
                    "delta": delta,
                },
            },
        })

    await bot.edit_tasks["!one:example"]
    progress = matrix.room_send.await_args.kwargs["content"]["m.new_content"]["body"]
    assert progress.startswith("Hello world")
    delta_events = [
        event
        for event in bot.diagnostic_events["!one:example"]
        if event["type"] == "message.part.delta"
    ]
    assert len(delta_events) == 1
    assert delta_events[0]["properties"]["delta"] == "Hello world"
    assert delta_events[0]["properties"]["delta_count"] == 2


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
    assert "y (allow once)" in body
    assert "YOLO (allow everything for this session)" in body


async def test_y_and_n_answer_pending_permissions(tmp_path: Path) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    state = RoomSession(
        "ses_1",
        str(tmp_path),
        pending_permissions=[PendingPermission("allow", "Allow", "bash", created=1)],
    )
    store.rooms["!one:example"] = state

    await bot.on_message(room(), message(bot, "y"))

    opencode.reply_permission.assert_awaited_once_with(
        "ses_1", "allow", str(tmp_path), "once"
    )

    state.pending_permissions = [PendingPermission("deny", "Deny", "bash", created=2)]
    opencode.reply_permission.reset_mock()

    await bot.on_message(room(), message(bot, "N"))

    opencode.reply_permission.assert_awaited_once_with(
        "ses_1", "deny", str(tmp_path), "reject"
    )


async def test_y_without_pending_permission_remains_an_ordinary_prompt(tmp_path: Path) -> None:
    bot, _, opencode, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession("ses_1", str(tmp_path))

    await bot.on_message(room(), message(bot, "y"))

    opencode.prompt_async.assert_awaited_once_with("ses_1", str(tmp_path), "y")
    opencode.reply_permission.assert_not_awaited()


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


async def test_yolo_approves_all_pending_permissions_and_persists(tmp_path: Path) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    state = RoomSession(
        "ses_1",
        str(tmp_path),
        pending_permissions=[
            PendingPermission("new", "New", "bash", created=20),
            PendingPermission("old", "Old", "edit", created=10),
        ],
    )
    store.rooms["!one:example"] = state

    await bot.on_message(room(), message(bot, "YOLO"))

    assert state.yolo_permissions is True
    assert state.pending_permissions == []
    assert [call.args[1] for call in opencode.reply_permission.await_args_list] == [
        "old",
        "new",
    ]
    assert all(call.args[3] == "once" for call in opencode.reply_permission.await_args_list)
    assert json.loads(store.path.read_text())["rooms"]["!one:example"][
        "yolo_permissions"
    ] is True
    body = matrix.room_send.await_args.kwargs["content"]["body"]
    assert "YOLO enabled for this session" in body
    assert "Approved 2 pending request(s)" in body


async def test_yolo_auto_approves_future_permission_without_prompt(tmp_path: Path) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    state = RoomSession(
        "ses_worker",
        str(tmp_path),
        yolo_permissions=True,
        pursuit_goal="Verify it",
        pursuit_phase="verifying",
        verifier_session_id="ses_verify",
    )
    store.rooms["!one:example"] = state

    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {
            "type": "permission.asked",
            "properties": {
                "id": "perm_auto",
                "sessionID": "ses_verify",
                "permission": "bash",
                "patterns": ["git status"],
            },
        },
    })

    opencode.reply_permission.assert_awaited_once_with(
        "ses_verify", "perm_auto", str(tmp_path), "once"
    )
    assert state.pending_permissions == []
    body = matrix.room_send.await_args.kwargs["content"]["body"]
    assert body == "YOLO auto-approved: bash"
    assert "Reply with" not in body


async def test_yolo_auto_approval_failure_keeps_request_pending(tmp_path: Path) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    state = RoomSession("ses_1", str(tmp_path), yolo_permissions=True)
    store.rooms["!one:example"] = state
    opencode.reply_permission.side_effect = OpenCodeError("offline")

    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {
            "type": "permission.asked",
            "properties": {
                "id": "perm_failed",
                "sessionID": "ses_1",
                "permission": "bash",
            },
        },
    })

    assert [pending.id for pending in state.pending_permissions] == ["perm_failed"]
    body = matrix.room_send.await_args.kwargs["content"]["body"]
    assert "remains pending" in body
    assert "y, n, or YOLO" in body


async def test_yolo_discards_stale_permission(tmp_path: Path) -> None:
    bot, matrix, opencode, store = make_bot(tmp_path)
    state = RoomSession("ses_1", str(tmp_path), yolo_permissions=True)
    store.rooms["!one:example"] = state
    opencode.reply_permission.side_effect = OpenCodeError("not found", status_code=404)

    await bot.handle_opencode_event({
        "directory": str(tmp_path),
        "payload": {
            "type": "permission.asked",
            "properties": {
                "id": "perm_stale",
                "sessionID": "ses_1",
                "permission": "bash",
            },
        },
    })

    assert state.pending_permissions == []
    matrix.room_send.assert_not_awaited()


async def test_yolo_off_disables_auto_approval_and_status_reports_mode(
    tmp_path: Path,
) -> None:
    bot, matrix, _, store = make_bot(tmp_path)
    state = RoomSession("ses_1", str(tmp_path), yolo_permissions=True)
    store.rooms["!one:example"] = state

    await bot.on_message(room(), message(bot, "!yolo off"))

    assert state.yolo_permissions is False
    assert "YOLO disabled" in matrix.room_send.await_args.kwargs["content"]["body"]

    await bot.command_status("!one:example")
    body = matrix.room_send.await_args.kwargs["content"]["body"]
    assert "Permission mode: prompt" in body


async def test_new_and_reset_do_not_carry_yolo_to_another_mapping(tmp_path: Path) -> None:
    bot, _, _, store = make_bot(tmp_path)
    store.rooms["!one:example"] = RoomSession(
        "ses_old", str(tmp_path), yolo_permissions=True
    )

    await bot.command_new("!one:example", None)

    assert store.rooms["!one:example"].session_id == "ses_1"
    assert store.rooms["!one:example"].yolo_permissions is False

    store.rooms["!one:example"].yolo_permissions = True
    await bot.command_reset("!one:example")

    assert "!one:example" not in store.rooms


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
        acceptance_criteria=criteria("Answer every material question with evidence"),
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
        acceptance_criteria=criteria("Every claim has verified evidence"),
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
        acceptance_criteria=criteria("The answer is evidenced"),
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
        acceptance_criteria=criteria("specific mandatory criterion"),
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
