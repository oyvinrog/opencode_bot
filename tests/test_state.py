import json
import stat
from pathlib import Path

from matrix_opencode_bot.state import PendingPermission, RoomSession, StateStore


async def test_state_round_trip_and_owner_only_mode(tmp_path: Path) -> None:
    path = tmp_path / "data" / "room_sessions.json"
    store = StateStore(path)
    await store.set(
        "!room:example",
        RoomSession(
            session_id="ses_1",
            directory="/work",
            title="Test",
            in_flight_event_id="$event",
            prompt_started_ms=123,
            pending_permissions=[PendingPermission("perm_1", "Run", "bash", "git status", 5)],
            pursuit_goal="Investigate thoroughly",
            pursuit_phase="verifying",
            pursuit_iteration=7,
            verifier_session_id="ses_verify",
            acceptance_criteria=["Answer is source-grounded"],
            pursuit_criteria_status={"Answer is source-grounded": "unknown"},
            pursuit_evidence=["Primary record found"],
            watchdog_recovery_pending=True,
            watchdog_recovery_attempts=3,
        ),
    )
    restored = StateStore(path)
    restored.load()
    assert restored.rooms["!room:example"].session_id == "ses_1"
    assert restored.rooms["!room:example"].pending_permissions[0].pattern == "git status"
    assert restored.rooms["!room:example"].pursuit_goal == "Investigate thoroughly"
    assert restored.rooms["!room:example"].pursuit_iteration == 7
    assert restored.rooms["!room:example"].verifier_session_id == "ses_verify"
    assert restored.rooms["!room:example"].pursuit_evidence == ["Primary record found"]
    assert restored.rooms["!room:example"].watchdog_recovery_pending is True
    assert restored.rooms["!room:example"].watchdog_recovery_attempts == 3
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not path.with_suffix(".json.tmp").exists()


def test_legacy_obsession_migrates_to_pursuit(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text(json.dumps({
        "version": 1,
        "rooms": {
            "!room": {
                "session_id": "ses",
                "directory": str(tmp_path),
                "obsess_goal": "Keep investigating",
                "obsess_iteration": 4,
            }
        },
    }))
    store = StateStore(path)
    store.load()
    state = store.rooms["!room"]
    assert state.pursuit_goal == "Keep investigating"
    assert state.pursuit_phase == "specifying"
    assert state.pursuit_iteration == 4


async def test_remove_persists_empty_mapping(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    store = StateStore(path)
    await store.set("!room", RoomSession("ses", str(tmp_path)))
    assert await store.remove("!room") is not None
    assert json.loads(path.read_text())["rooms"] == {}
