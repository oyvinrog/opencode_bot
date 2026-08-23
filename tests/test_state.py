import json
import hashlib
import stat
from pathlib import Path

import pytest

from matrix_opencode_bot.state import (
    AttemptRecord,
    BudgetLedger,
    CheckResult,
    CriterionStatus,
    ObservationProvenance,
    PendingPermission,
    PursuitBudget,
    PursuitContract,
    PursuitCriterion,
    PursuitOutcome,
    RoomSession,
    StateStore,
    VerificationKind,
)


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
            yolo_permissions=True,
            pending_pursuit_goal="Await a depth choice",
            pending_pursuit_reuse_session=True,
            pending_pursuit_yolo_confirmation=True,
            pursuit_goal="Investigate thoroughly",
            pursuit_extent=3,
            pursuit_phase="verifying",
            pursuit_iteration=7,
            pursuit_worker_input_tokens=42_000,
            verifier_session_id="ses_verify",
            acceptance_criteria=[{"id": "c1", "text": "Answer is source-grounded"}],
            pursuit_criteria_status={"c1": "unknown"},
            pursuit_evidence=[{
                "criterion_id": "c1",
                "claim": "Primary record found",
                "source": "https://example.test/record",
                "verification": "Fetched and inspected the record",
            }],
            bump_confirmation_session_id="ses_1",
            bump_confirmation_activity_ms=122,
            manual_bump_pending=True,
            manual_bump_attempts=2,
            active_tools={"part_1": {"name": "bash", "started_ms": 121}},
            recovery_reason="tool_timeout",
            recovery_tool="bash",
            recovery_session_id="ses_1",
            watchdog_recovery_pending=True,
            watchdog_recovery_attempts=3,
        ),
    )
    restored = StateStore(path)
    restored.load()
    assert restored.rooms["!room:example"].session_id == "ses_1"
    assert restored.rooms["!room:example"].pending_permissions[0].pattern == "git status"
    assert restored.rooms["!room:example"].yolo_permissions is True
    assert restored.rooms["!room:example"].pursuit_goal == "Investigate thoroughly"
    assert restored.rooms["!room:example"].pending_pursuit_goal == "Await a depth choice"
    assert restored.rooms["!room:example"].pending_pursuit_reuse_session is True
    assert restored.rooms["!room:example"].pending_pursuit_yolo_confirmation is True
    assert restored.rooms["!room:example"].pursuit_extent == 3
    assert restored.rooms["!room:example"].pursuit_iteration == 7
    assert restored.rooms["!room:example"].verifier_session_id == "ses_verify"
    assert restored.rooms["!room:example"].pursuit_evidence[0]["claim"] == "Primary record found"
    assert restored.rooms["!room:example"].pursuit_worker_input_tokens == 42_000
    assert json.loads(path.read_text())["version"] == 3
    assert restored.rooms["!room:example"].bump_confirmation_session_id == "ses_1"
    assert restored.rooms["!room:example"].manual_bump_pending is True
    assert restored.rooms["!room:example"].manual_bump_attempts == 2
    assert restored.rooms["!room:example"].active_tools["part_1"]["name"] == "bash"
    assert restored.rooms["!room:example"].recovery_reason == "tool_timeout"
    assert restored.rooms["!room:example"].recovery_tool == "bash"
    assert restored.rooms["!room:example"].recovery_session_id == "ses_1"
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
    assert state.pursuit_phase == "awaiting_approval"
    assert state.pursuit_iteration == 4
    assert state.pursuit_protocol_version == 3
    assert state.pursuit_contract is not None
    assert state.pursuit_contract.goal == "Keep investigating"
    assert state.pursuit_contract.approved is False
    assert state.yolo_permissions is False


def test_existing_pending_pursuit_defaults_to_extent_stage(tmp_path: Path) -> None:
    state = RoomSession.from_dict({
        "session_id": "ses",
        "directory": str(tmp_path),
        "pending_pursuit_goal": "Already chose the old extent flow",
    })

    assert state.pending_pursuit_goal == "Already chose the old extent flow"
    assert state.pending_pursuit_yolo_confirmation is False


async def test_remove_persists_empty_mapping(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    store = StateStore(path)
    await store.set("!room", RoomSession("ses", str(tmp_path)))
    assert await store.remove("!room") is not None
    assert json.loads(path.read_text())["rooms"] == {}


def test_extent_budgets_and_boundaries() -> None:
    assert PursuitBudget.for_extent(1) == PursuitBudget(4, 40, 250_000, 3_600)
    assert PursuitBudget.for_extent(2) == PursuitBudget(12, 120, 750_000, 10_800)
    assert PursuitBudget.for_extent(3) == PursuitBudget(32, 320, 2_000_000, 28_800)

    ledger = BudgetLedger(limits=PursuitBudget.for_extent(1), started_ms=1_000)
    ledger.record_cycle(3)
    ledger.record_tool_call(39)
    ledger.record_input_tokens(249_999)
    assert ledger.exhausted_limits(now_ms=3_600_999) == []

    ledger.record_cycle()
    ledger.record_tool_call()
    ledger.record_input_tokens(1)
    assert ledger.exhausted_limits(now_ms=3_601_000) == [
        "cycles",
        "tool_calls",
        "input_tokens",
        "elapsed_seconds",
    ]

    ledger.start_next_tranche(now_ms=3_601_000)
    assert ledger.tranche == 2
    assert ledger.usage.cycles == 0
    assert ledger.usage.elapsed_seconds == 0
    assert ledger.total_usage.cycles == 4
    assert ledger.total_usage.elapsed_seconds == 3_600
    assert ledger.exhausted_limits(now_ms=3_601_000) == []


def test_contract_approval_is_versioned_and_content_bound() -> None:
    contract = PursuitContract.draft(
        "Fix the parser",
        [
            PursuitCriterion(
                "tests",
                "Parser tests pass",
                VerificationKind.COMMAND,
                {"argv": ["pytest", "tests/test_parser.py"]},
            )
        ],
        constraints=["Do not change the public API"],
        assumptions=["The regression is reproducible"],
        extent=2,
    )
    assert contract.approval_is_current() is False
    contract.approve("$approval", 123)
    assert contract.approval_is_current() is True

    contract.assumptions.append("A model-authored change after approval")
    assert contract.approval_is_current() is False

    revised = contract.revise(assumptions=["The user supplied a new assumption"])
    assert revised.version == 2
    assert revised.approved is False
    assert revised.approval_digest is None


def _check_result(
    state: RoomSession,
    *,
    criterion_id: str = "c1",
    status: CriterionStatus = CriterionStatus.PASS,
    digest_seed: str = "observation",
    observation_id: str | None = None,
    contract_version: int | None = None,
) -> CheckResult:
    assert state.pursuit_contract is not None
    issued = observation_id or state.issue_observation_id()
    return CheckResult(
        id=f"check-{digest_seed}",
        criterion_id=criterion_id,
        verification_kind=VerificationKind.COMMAND,
        status=status,
        provenance=ObservationProvenance(
            observation_id=issued,
            attempt_id="attempt-1",
            workspace_revision=state.pursuit_workspace_revision,
            captured_at_ms=100,
            source_ref="isolated-snapshot",
            digest=hashlib.sha256(digest_seed.encode()).hexdigest(),
        ),
        contract_version=contract_version or state.pursuit_contract.version,
        summary="exit 0",
        raw_output="12 passed",
        source="command:pytest",
    )


def _room_with_contract(tmp_path: Path) -> RoomSession:
    contract = PursuitContract.draft(
        "Pass the checks",
        [
            PursuitCriterion(
                "c1",
                "Tests pass",
                VerificationKind.COMMAND,
                {"argv": ["pytest"]},
            )
        ],
    )
    contract.approve("$approval", 10)
    return RoomSession(
        "ses",
        str(tmp_path),
        pursuit_goal=contract.goal,
        pursuit_phase="checking",
        pursuit_contract=contract,
        pursuit_budget_ledger=BudgetLedger(limits=contract.budget),
    )


def test_controller_observations_reject_forgery_duplicates_and_stale_results(
    tmp_path: Path,
) -> None:
    state = _room_with_contract(tmp_path)

    forged = _check_result(state, observation_id="model-supplied-id")
    with pytest.raises(ValueError, match="not issued"):
        state.record_check_result(forged)

    first = _check_result(state)
    assert state.record_check_result(first) is True
    assert state.current_check_results() == {"c1": first}

    duplicate_observation = _check_result(state, digest_seed="observation")
    assert state.record_check_result(duplicate_observation) is False
    assert len(state.pursuit_check_results) == 1

    state.mark_workspace_mutated("tool-part-2")
    assert state.current_check_results() == {}
    assert state.pursuit_action_trace[-1]["ref"] == "tool-part-2"

    stale = _check_result(state)
    stale.contract_version = state.pursuit_contract.version + 1  # type: ignore[union-attr]
    with pytest.raises(ValueError, match="stale contract"):
        state.record_check_result(stale)


async def test_protocol_v3_records_round_trip(tmp_path: Path) -> None:
    state = _room_with_contract(tmp_path)
    state.pursuit_attempts.append(
        AttemptRecord("attempt-1", 1, 0, 0, 10, 20, 3, 1_000, ["part-1"], "checked")
    )
    state.pursuit_workspace_fingerprint = "sha256:workspace"
    result = _check_result(state)
    assert state.record_check_result(result)
    state.pursuit_remaining_uncertainty = ["Network state was not observable"]
    state.pursuit_artifact_refs = ["artifact://report"]

    path = tmp_path / "state.json"
    store = StateStore(path)
    await store.set("!room", state)
    restored_store = StateStore(path)
    restored_store.load()
    restored = restored_store.rooms["!room"]

    assert restored.pursuit_contract is not None
    assert restored.pursuit_contract.approval_is_current()
    assert restored.pursuit_contract.criteria[0].verification_kind is VerificationKind.COMMAND
    assert restored.pursuit_check_results[0].raw_output == "12 passed"
    assert restored.current_check_results()["c1"].status is CriterionStatus.PASS
    assert restored.pursuit_attempts[0].action_trace_refs == ["part-1"]
    assert restored.pursuit_workspace_fingerprint == "sha256:workspace"
    assert restored.pursuit_remaining_uncertainty == ["Network state was not observable"]


def test_protocol_v2_migration_requires_approval_and_distrusts_prose(
    tmp_path: Path,
) -> None:
    state = RoomSession.from_dict(
        {
            "session_id": "ses-v2",
            "directory": str(tmp_path),
            "pursuit_protocol_version": 2,
            "pursuit_goal": "Verify the release",
            "pursuit_phase": "verifying",
            "pursuit_extent": 3,
            "acceptance_criteria": [{"id": "c1", "text": "Release is valid"}],
            "pursuit_criteria_status": {"c1": "pass"},
            "pursuit_evidence": [
                {
                    "criterion_id": "c1",
                    "claim": "The verifier said so",
                    "source": "model prose",
                    "verification": "same-model review",
                }
            ],
        }
    )

    assert state.pursuit_protocol_version == 3
    assert state.pursuit_phase == "awaiting_approval"
    assert state.pursuit_contract is not None
    assert state.pursuit_contract.approved is False
    assert state.pursuit_contract.criteria[0].verification_kind is VerificationKind.HUMAN
    assert state.pursuit_criteria_status == {"c1": "unknown"}
    assert state.pursuit_check_results == []
    assert state.pursuit_evidence[0]["trust"] == "legacy_untrusted"
    assert state.pursuit_budget_ledger is not None
    assert state.pursuit_budget_ledger.limits == PursuitBudget.for_extent(3)

    archive = state.archive_pursuit(PursuitOutcome.STOPPED, "Migrated and stopped")
    assert archive.legacy_untrusted_evidence == state.pursuit_evidence
    restored_archive = type(archive).from_dict(archive.to_dict())
    assert restored_archive is not None
    assert restored_archive.legacy_untrusted_evidence[0]["trust"] == "legacy_untrusted"


def test_pursuit_history_is_bounded_and_keeps_audit_records(tmp_path: Path) -> None:
    state = _room_with_contract(tmp_path)
    for index in range(12):
        state.archive_pursuit(
            PursuitOutcome.STOPPED,
            f"Stopped report {index}",
            artifact_refs=[f"artifact://{index}"],
            archived_at_ms=index + 1,
        )

    assert len(state.pursuit_history) == 10
    assert state.pursuit_history[0].final_report == "Stopped report 2"
    assert state.pursuit_history[-1].artifact_refs == ["artifact://11"]
    assert state.pursuit_outcome is PursuitOutcome.STOPPED
