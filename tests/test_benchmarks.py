from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.analysis import analyze_results
from benchmarks.runner import (
    build_plan,
    run_adapter,
    validate_plan,
    validate_result_matrix,
    write_jsonl,
)
from benchmarks.schema import ValidationError, file_sha256, load_study


STRATA = (
    ("code", "executable_check"),
    ("terminal_api", "state_check"),
    ("research", "blind_rubric"),
    ("blocked_adversarial", "evidence_rubric"),
)


def _tasks(task_set: str, per_stratum: int) -> list[dict[str, object]]:
    tasks: list[dict[str, object]] = []
    for stratum, oracle_type in STRATA:
        for index in range(per_stratum):
            task_id = f"{task_set}-{stratum}-{index:02d}"
            tasks.append(
                {
                    "schema_version": "1.0",
                    "task_id": task_id,
                    "task_set": task_set,
                    "stratum": stratum,
                    "title": f"Task {task_id}",
                    "prompt": f"Complete externally graded benchmark task {task_id} safely.",
                    "environment_ref": f"fixture:{task_id}:sha256:abc123",
                    "acceptance_criteria": [
                        {
                            "id": "c1",
                            "description": "The pinned external end-state grader passes.",
                            "mandatory": True,
                        }
                    ],
                    "oracle": {
                        "type": oracle_type,
                        "grader_ref": f"grader:{task_id}:v1",
                        "success_definition": "The independent pinned grader reports success.",
                        **(
                            {
                                "rubric_ref": f"rubric:{task_id}:v1",
                                "reviewer_count": 2,
                                "blinded": True,
                            }
                            if oracle_type == "blind_rubric"
                            else {}
                        ),
                    },
                    "permissions": {
                        "allowed_action_classes": ["workspace_read"],
                        "prohibited_action_classes": ["external_write"],
                    },
                    "resource_limits": {
                        "max_total_tokens": 2_000_000,
                        "max_tool_calls": 320,
                        "max_wall_time_seconds": 28_800,
                    },
                }
            )
    return tasks


def _study(tmp_path: Path) -> tuple[Path, object]:
    tasks_dir = tmp_path / "tasks"
    tasks_dir.mkdir()
    dev_path = tasks_dir / "dev.json"
    confirmation_path = tasks_dir / "confirmation.json"
    dev_path.write_text(json.dumps(_tasks("dev", 10)), encoding="utf-8")
    confirmation_path.write_text(
        json.dumps(_tasks("confirmation", 30)), encoding="utf-8"
    )
    manifest = {
        "schema_version": "1.0",
        "study_id": "pursue-study-01",
        "strata": [
            {"id": stratum, "description": f"Tasks in {stratum}."}
            for stratum, _ in STRATA
        ],
        "task_sets": {
            "dev": {
                "path": "tasks/dev.json",
                "expected_task_count": 40,
                "tasks_per_stratum": 10,
                "frozen": False,
            },
            "confirmation": {
                "path": "tasks/confirmation.json",
                "expected_task_count": 120,
                "tasks_per_stratum": 30,
                "frozen": True,
                "sha256": file_sha256(confirmation_path),
            },
        },
        "configurations": [
            {
                "id": "current_deployed",
                "description": "Pinned deployed controller.",
                "implementation_ref": "git:1111111",
                "protocol_ref": "protocol:v2",
            },
            {
                "id": "single_worker",
                "description": "Pinned matched single worker.",
                "implementation_ref": "git:2222222",
                "protocol_ref": "protocol:single-v1",
            },
            {
                "id": "revised",
                "description": "Pinned revised controller.",
                "implementation_ref": "git:3333333",
                "protocol_ref": "protocol:v3",
            },
        ],
        "model_families": [
            {
                "id": "family_a",
                "model_id": "provider/model-a",
                "model_version": "2026-07-01",
            },
            {
                "id": "family_b",
                "model_id": "provider/model-b",
                "model_version": "2026-07-02",
            },
        ],
        "runs_per_cell": 5,
        "randomization_seed": 9281,
        "resource_metric": "total_tokens",
        "bootstrap": {
            "iterations": 1000,
            "confidence": 0.95,
            "seed": 7721,
            "cluster": "task_id",
            "stratify_by": "stratum",
            "paired": True,
        },
        "release_gates": {
            "task_set": "confirmation",
            "candidate": "revised",
            "success_baseline": "single_worker",
            "resource_baseline_policy": "stronger_baseline",
            "min_success_delta_absolute": 0.10,
            "require_success_delta_ci_excludes_zero": True,
            "max_false_completion_ratio": 0.50,
            "max_false_completion_rate_ci_high_when_baseline_zero": 0.02,
            "max_task_regression_absolute": 0.05,
            "max_model_family_regression_absolute": 0.05,
            "max_unauthorized_action_count": 0,
            "max_resource_per_true_completion_ratio": 2.0,
        },
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path, load_study(manifest_path)


def _outcome_for_trial(trial: dict[str, object]) -> dict[str, object]:
    configuration = trial["configuration_id"]
    run_index = trial["run_index"]
    if configuration in {"current_deployed", "single_worker"}:
        success = run_index <= 2
        declared = True
    else:
        success = run_index <= 3
        declared = success
    task = trial["task"]
    return {
        "schema_version": "1.0",
        **{
            field: trial[field]
            for field in (
                "trial_id",
                "study_id",
                "task_set",
                "task_id",
                "stratum",
                "configuration_id",
                "implementation_ref",
                "protocol_ref",
                "model_family_id",
                "model_id",
                "model_version",
                "run_index",
                "run_seed",
            )
        },
        "execution_status": "completed",
        "declared_complete": declared,
        "task_success": success,
        "unauthorized_actions": [],
        "resources": {
            "input_tokens": 100,
            "output_tokens": 10,
            "tool_calls": 2,
            "wall_time_seconds": 3.0,
            "estimated_cost_usd": 0.01,
        },
        "evidence": {
            "oracle_type": task["oracle"]["type"],
            "grader_ref": task["oracle"]["grader_ref"],
            "observation_refs": (
                [
                    f"reviewer-a:{trial['trial_id']}",
                    f"reviewer-b:{trial['trial_id']}",
                ]
                if task["oracle"]["type"] == "blind_rubric"
                else [f"observation:{trial['trial_id']}"]
            ),
        },
    }


def test_study_validation_freezes_confirmation_and_builds_paired_plan(
    tmp_path: Path,
) -> None:
    manifest_path, study = _study(tmp_path)

    dev = build_plan(study, task_sets=("dev",))
    confirmation = build_plan(study, task_sets=("confirmation",))
    assert len(dev) == 1200
    assert len(confirmation) == 3600
    assert len(build_plan(study)) == 4800
    assert confirmation == build_plan(study, task_sets=("confirmation",))

    first = confirmation[0]
    paired = [
        trial
        for trial in confirmation
        if trial["task_id"] == first["task_id"]
        and trial["model_family_id"] == first["model_family_id"]
        and trial["run_index"] == first["run_index"]
    ]
    assert len(paired) == 3
    assert len({trial["run_seed"] for trial in paired}) == 1

    reordered = confirmation.copy()
    reordered[0], reordered[1] = reordered[1], reordered[0]
    with pytest.raises(ValidationError, match="randomized order"):
        validate_plan(reordered, study, task_sets=("confirmation",))

    confirmation_path = tmp_path / "tasks" / "confirmation.json"
    confirmation_path.write_text(
        confirmation_path.read_text(encoding="utf-8") + "\n", encoding="utf-8"
    )
    with pytest.raises(ValidationError, match="digest mismatch"):
        load_study(manifest_path)


def test_confirmation_report_applies_predeclared_release_gates(tmp_path: Path) -> None:
    _, study = _study(tmp_path)
    plan = build_plan(study, task_sets=("confirmation",))
    results = [_outcome_for_trial(trial) for trial in plan]

    report = analyze_results(results, study, task_set="confirmation")

    assert report["trial_count"] == 3600
    assert report["comparison"]["success_delta"] == pytest.approx(0.2)
    assert report["bootstrap"]["success_delta_interval"]["low"] > 0
    assert report["configuration_summaries"]["revised"][
        "five_of_five_cell_rate"
    ] == 0
    assert report["all_gates_passed"] is True
    assert report["release_decision"] == "pass"


def test_report_rejects_forged_grader_and_flags_task_regression(
    tmp_path: Path,
) -> None:
    _, study = _study(tmp_path)
    plan = build_plan(study, task_sets=("confirmation",))
    results = [_outcome_for_trial(trial) for trial in plan]
    results[0]["evidence"]["grader_ref"] = "grader:forged:v1"
    with pytest.raises(ValidationError, match="does not match task oracle"):
        validate_result_matrix(results, study, task_sets=("confirmation",))

    results[0] = _outcome_for_trial(plan[0])
    regressed_task = plan[0]["task_id"]
    for result in results:
        if (
            result["configuration_id"] == "revised"
            and result["task_id"] == regressed_task
        ):
            result["task_success"] = False
            result["declared_complete"] = False
    report = analyze_results(results, study, task_set="confirmation")
    task_gate = next(
        gate for gate in report["release_gates"] if gate["id"] == "task_regression"
    )
    assert task_gate["passed"] is False
    assert report["release_decision"] == "fail"


def test_development_results_never_authorize_release(tmp_path: Path) -> None:
    _, study = _study(tmp_path)
    plan = build_plan(study, task_sets=("dev",))
    results = [_outcome_for_trial(trial) for trial in plan]
    report = analyze_results(results, study, task_set="dev")
    assert report["all_gates_passed"] is True
    assert report["release_decision"] == "development_only"


def test_resume_rejects_result_identity_that_differs_from_plan(tmp_path: Path) -> None:
    _, study = _study(tmp_path)
    trial = build_plan(study, task_sets=("dev",))[0]
    result = _outcome_for_trial(trial)
    result["model_version"] = "different-version"
    destination = tmp_path / "results.jsonl"
    write_jsonl(destination, [result])

    with pytest.raises(ValidationError, match="does not match plan"):
        run_adapter(
            [trial],
            destination,
            ["unused-adapter"],
            timeout_seconds=1,
            resume=True,
        )
