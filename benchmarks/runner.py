"""Validate a study, create its trial matrix, and run an external adapter.

The adapter is deliberately outside this package. It receives one trial record as
JSON on stdin and returns an outcome JSON object on stdout. This keeps provider
credentials and agent implementations out of the frozen analysis code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Iterable

from .schema import (
    SCHEMA_VERSION,
    Study,
    ValidationError,
    file_sha256,
    load_study,
    validate_result,
)


IDENTITY_FIELDS = (
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


def _stable_digest(*parts: object) -> str:
    encoded = "\x1f".join(str(part) for part in parts).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_plan(
    study: Study, *, task_sets: Iterable[str] = ("dev", "confirmation")
) -> list[dict[str, Any]]:
    """Expand selected task sets into a deterministic, paired trial plan."""

    manifest = study.manifest
    selected = tuple(task_sets)
    unknown = set(selected) - set(study.tasks)
    if unknown:
        raise ValidationError(
            f"plan: unknown task sets: {', '.join(sorted(unknown))}"
        )
    if not selected:
        raise ValidationError("plan: at least one task set is required")
    if len(selected) != len(set(selected)):
        raise ValidationError("plan: task sets must not be repeated")
    records: list[dict[str, Any]] = []
    for task_set in selected:
        for task in sorted(study.tasks[task_set], key=lambda item: item["task_id"]):
            for family in manifest["model_families"]:
                for run_index in range(1, manifest["runs_per_cell"] + 1):
                    # The seed excludes configuration so configurations receive paired
                    # stochastic conditions. Trial identity includes configuration.
                    run_seed = int(
                        _stable_digest(
                            manifest["randomization_seed"],
                            manifest["study_id"],
                            task_set,
                            task["task_id"],
                            family["id"],
                            run_index,
                        )[:15],
                        16,
                    )
                    for configuration in manifest["configurations"]:
                        trial_hash = _stable_digest(
                            manifest["study_id"],
                            task_set,
                            task["task_id"],
                            configuration["id"],
                            family["id"],
                            run_index,
                        )
                        records.append(
                            {
                                "schema_version": SCHEMA_VERSION,
                                "trial_id": f"trial-{trial_hash[:24]}",
                                "study_id": manifest["study_id"],
                                "task_set": task_set,
                                "task_id": task["task_id"],
                                "stratum": task["stratum"],
                                "configuration_id": configuration["id"],
                                "implementation_ref": configuration["implementation_ref"],
                                "protocol_ref": configuration["protocol_ref"],
                                "model_family_id": family["id"],
                                "model_id": family["model_id"],
                                "model_version": family["model_version"],
                                "run_index": run_index,
                                "run_seed": run_seed,
                                "task": task,
                            }
                        )
    ordering_seed = manifest["randomization_seed"]
    records.sort(
        key=lambda record: _stable_digest(ordering_seed, record["trial_id"])
    )
    return records


def write_jsonl(path: str | Path, records: Iterable[dict[str, Any]]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")))
            handle.write("\n")


def load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    source = Path(path)
    records: list[dict[str, Any]] = []
    try:
        with source.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValidationError(
                        f"{source}:{line_number}: invalid JSON: {exc}"
                    ) from exc
                if not isinstance(value, dict):
                    raise ValidationError(
                        f"{source}:{line_number}: record must be an object"
                    )
                records.append(value)
    except OSError as exc:
        raise ValidationError(f"{source}: cannot read JSONL: {exc}") from exc
    return records


def validate_plan(
    plan: list[dict[str, Any]],
    study: Study,
    *,
    require_complete: bool = True,
    task_sets: Iterable[str] = ("dev", "confirmation"),
) -> dict[str, dict[str, Any]]:
    expected_records = build_plan(study, task_sets=task_sets)
    expected = {record["trial_id"]: record for record in expected_records}
    seen: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(plan):
        trial_id = record.get("trial_id")
        if not isinstance(trial_id, str):
            raise ValidationError(f"plan[{index}].trial_id: must be a string")
        if trial_id in seen:
            raise ValidationError(f"plan[{index}].trial_id: duplicate {trial_id}")
        if trial_id not in expected:
            raise ValidationError(f"plan[{index}].trial_id: unexpected {trial_id}")
        if record != expected[trial_id]:
            raise ValidationError(
                f"plan[{index}]: content differs from manifest-generated trial {trial_id}"
            )
        seen[trial_id] = record
    if require_complete and set(seen) != set(expected):
        missing = len(set(expected) - set(seen))
        raise ValidationError(f"plan: missing {missing} expected trials")
    if require_complete and [record["trial_id"] for record in plan] != [
        record["trial_id"] for record in expected_records
    ]:
        raise ValidationError("plan: trials are not in the predeclared randomized order")
    return seen


def validate_result_matrix(
    results: list[dict[str, Any]],
    study: Study,
    *,
    require_complete: bool = True,
    task_sets: Iterable[str] = ("dev", "confirmation"),
) -> dict[str, dict[str, Any]]:
    expected = {
        record["trial_id"]: record
        for record in build_plan(study, task_sets=task_sets)
    }
    seen: dict[str, dict[str, Any]] = {}
    seen_observations: set[str] = set()
    for index, raw in enumerate(results):
        try:
            result = validate_result(raw)
        except ValidationError as exc:
            raise ValidationError(f"results[{index}]: {exc}") from exc
        trial_id = result["trial_id"]
        if trial_id in seen:
            raise ValidationError(f"results[{index}].trial_id: duplicate {trial_id}")
        trial = expected.get(trial_id)
        if trial is None:
            raise ValidationError(f"results[{index}].trial_id: unexpected {trial_id}")
        for field in IDENTITY_FIELDS:
            if result[field] != trial[field]:
                raise ValidationError(
                    f"results[{index}].{field}: expected {trial[field]!r}, "
                    f"got {result[field]!r}"
                )
        if result["execution_status"] == "completed":
            oracle = trial["task"]["oracle"]
            evidence = result["evidence"]
            if evidence["oracle_type"] != oracle["type"]:
                raise ValidationError(
                    f"results[{index}].evidence.oracle_type: does not match task oracle"
                )
            if evidence["grader_ref"] != oracle["grader_ref"]:
                raise ValidationError(
                    f"results[{index}].evidence.grader_ref: does not match task oracle"
                )
            for observation_ref in evidence["observation_refs"]:
                if observation_ref in seen_observations:
                    raise ValidationError(
                        f"results[{index}].evidence.observation_refs: duplicate "
                        f"study-wide observation {observation_ref!r}"
                    )
                seen_observations.add(observation_ref)
        seen[trial_id] = result
    if require_complete and set(seen) != set(expected):
        missing = len(set(expected) - set(seen))
        raise ValidationError(f"results: missing {missing} expected trials")
    return seen


def _zero_resources(wall_time_seconds: float) -> dict[str, int | float]:
    return {
        "input_tokens": 0,
        "output_tokens": 0,
        "tool_calls": 0,
        "wall_time_seconds": max(0.0, wall_time_seconds),
        "estimated_cost_usd": 0.0,
    }


def _error_result(
    trial: dict[str, Any], status: str, message: str, wall_time_seconds: float
) -> dict[str, Any]:
    result = {
        "schema_version": SCHEMA_VERSION,
        **{field: trial[field] for field in IDENTITY_FIELDS},
        "execution_status": status,
        "declared_complete": False,
        "task_success": False,
        "unauthorized_actions": [],
        "resources": _zero_resources(wall_time_seconds),
        "error": message[:2000],
    }
    return validate_result(result)


def _result_from_outcome(
    trial: dict[str, Any], outcome: Any, observed_wall_time: float
) -> dict[str, Any]:
    if not isinstance(outcome, dict):
        raise ValidationError("adapter outcome must be a JSON object")
    required = {
        "declared_complete",
        "task_success",
        "unauthorized_actions",
        "resources",
        "evidence",
    }
    missing = sorted(required - outcome.keys())
    if missing:
        raise ValidationError(f"adapter outcome missing: {', '.join(missing)}")
    result = {
        "schema_version": SCHEMA_VERSION,
        **{field: trial[field] for field in IDENTITY_FIELDS},
        "execution_status": outcome.get("execution_status", "completed"),
        "declared_complete": outcome["declared_complete"],
        "task_success": outcome["task_success"],
        "unauthorized_actions": outcome["unauthorized_actions"],
        "resources": outcome["resources"],
    }
    result["evidence"] = outcome["evidence"]
    if "terminal_status" in outcome:
        result["terminal_status"] = outcome["terminal_status"]
    # This records harness-observed time without replacing the adapter's resource
    # accounting, which may include remote work not visible to this process.
    result["runner_wall_time_seconds"] = observed_wall_time
    return validate_result(result)


def run_adapter(
    plan: list[dict[str, Any]],
    results_path: str | Path,
    adapter: list[str],
    *,
    timeout_seconds: float,
    resume: bool,
) -> None:
    if not adapter or not all(isinstance(value, str) and value for value in adapter):
        raise ValidationError("adapter: command must contain non-empty strings")
    if timeout_seconds <= 0 or not math.isfinite(timeout_seconds):
        raise ValidationError("timeout_seconds: must be a positive finite number")
    destination = Path(results_path)
    planned = {trial["trial_id"]: trial for trial in plan}
    if len(planned) != len(plan):
        raise ValidationError("plan: duplicate trial ids")
    completed: set[str] = set()
    completed_observations: set[str] = set()
    if destination.exists():
        if not resume:
            raise ValidationError(
                f"{destination}: already exists; pass --resume to append missing trials"
            )
        existing = load_jsonl(destination)
        for index, record in enumerate(existing):
            validated = validate_result(record)
            trial_id = validated["trial_id"]
            if trial_id in completed:
                raise ValidationError(f"{destination}: duplicate trial {trial_id}")
            trial = planned.get(trial_id)
            if trial is None:
                raise ValidationError(
                    f"{destination}: result {trial_id} is not in the supplied plan"
                )
            for field in IDENTITY_FIELDS:
                if validated[field] != trial[field]:
                    raise ValidationError(
                        f"{destination}: result {index} field {field} does not match plan"
                    )
            if validated["execution_status"] == "completed":
                evidence = validated["evidence"]
                oracle = trial["task"]["oracle"]
                if (
                    evidence["oracle_type"] != oracle["type"]
                    or evidence["grader_ref"] != oracle["grader_ref"]
                ):
                    raise ValidationError(
                        f"{destination}: result {index} evidence does not match plan oracle"
                    )
                for observation_ref in evidence["observation_refs"]:
                    if observation_ref in completed_observations:
                        raise ValidationError(
                            f"{destination}: duplicate study-wide observation "
                            f"{observation_ref!r}"
                        )
                    completed_observations.add(observation_ref)
            completed.add(trial_id)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("a", encoding="utf-8", newline="\n") as handle:
        for trial in plan:
            if trial["trial_id"] in completed:
                continue
            started = time.monotonic()
            try:
                process = subprocess.run(
                    adapter,
                    input=json.dumps(trial),
                    text=True,
                    capture_output=True,
                    timeout=timeout_seconds,
                    check=False,
                )
                elapsed = time.monotonic() - started
                if process.returncode != 0:
                    result = _error_result(
                        trial,
                        "adapter_error",
                        f"adapter exited {process.returncode}: {process.stderr.strip()}",
                        elapsed,
                    )
                else:
                    try:
                        outcome = json.loads(process.stdout)
                        result = _result_from_outcome(trial, outcome, elapsed)
                        if result["execution_status"] == "completed":
                            oracle = trial["task"]["oracle"]
                            evidence = result["evidence"]
                            if (
                                evidence["oracle_type"] != oracle["type"]
                                or evidence["grader_ref"] != oracle["grader_ref"]
                            ):
                                raise ValidationError(
                                    "adapter grader evidence does not match the task oracle"
                                )
                            duplicate = next(
                                (
                                    observation
                                    for observation in evidence["observation_refs"]
                                    if observation in completed_observations
                                ),
                                None,
                            )
                            if duplicate is not None:
                                raise ValidationError(
                                    f"adapter reused study-wide observation {duplicate!r}"
                                )
                    except (json.JSONDecodeError, ValidationError) as exc:
                        result = _error_result(
                            trial,
                            "adapter_error",
                            f"invalid adapter output: {exc}; stderr={process.stderr.strip()}",
                            elapsed,
                        )
            except subprocess.TimeoutExpired as exc:
                elapsed = time.monotonic() - started
                result = _error_result(
                    trial,
                    "timeout",
                    f"adapter timed out after {timeout_seconds:g}s: {exc}",
                    elapsed,
                )
            handle.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
            handle.write("\n")
            handle.flush()
            completed.add(trial["trial_id"])
            if result["execution_status"] == "completed":
                completed_observations.update(result["evidence"]["observation_refs"])


def _adapter_from_remainder(values: list[str]) -> list[str]:
    adapter = list(values)
    if adapter and adapter[0] == "--":
        adapter.pop(0)
    if not adapter:
        raise ValidationError("run requires an adapter command after --")
    return adapter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate manifest and task sets")
    validate.add_argument("--manifest", required=True)

    digest = subparsers.add_parser("hash-tasks", help="print a task file SHA-256")
    digest.add_argument("--tasks", required=True)

    plan = subparsers.add_parser("plan", help="write the complete randomized trial plan")
    plan.add_argument("--manifest", required=True)
    plan.add_argument("--output", required=True)
    plan.add_argument(
        "--task-set",
        choices=("all", "dev", "confirmation"),
        default="all",
    )

    check = subparsers.add_parser("validate-results", help="validate result JSONL")
    check.add_argument("--manifest", required=True)
    check.add_argument("--results", required=True)
    check.add_argument("--allow-partial", action="store_true")
    check.add_argument(
        "--task-set",
        choices=("all", "dev", "confirmation"),
        default="all",
    )

    run = subparsers.add_parser("run", help="execute plan trials through an adapter")
    run.add_argument("--manifest", required=True)
    run.add_argument("--plan", required=True)
    run.add_argument("--results", required=True)
    run.add_argument("--timeout-seconds", type=float, default=1800.0)
    run.add_argument("--resume", action="store_true")
    run.add_argument("adapter", nargs=argparse.REMAINDER)

    report = subparsers.add_parser(
        "report", help="calculate predeclared metrics and release gates"
    )
    report.add_argument("--manifest", required=True)
    report.add_argument("--results", required=True)
    report.add_argument("--task-set", choices=("dev", "confirmation"), required=True)
    report.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "hash-tasks":
            print(file_sha256(args.tasks))
            return 0
        study = load_study(args.manifest)
        if args.command == "validate":
            trial_count = len(build_plan(study))
            print(
                f"valid: {sum(len(tasks) for tasks in study.tasks.values())} tasks, "
                f"{trial_count} trials"
            )
            return 0
        if args.command == "plan":
            task_sets = (
                ("dev", "confirmation")
                if args.task_set == "all"
                else (args.task_set,)
            )
            records = build_plan(study, task_sets=task_sets)
            write_jsonl(args.output, records)
            print(f"wrote {len(records)} trials to {args.output}")
            return 0
        if args.command == "validate-results":
            records = load_jsonl(args.results)
            task_sets = (
                ("dev", "confirmation")
                if args.task_set == "all"
                else (args.task_set,)
            )
            validate_result_matrix(
                records,
                study,
                require_complete=not args.allow_partial,
                task_sets=task_sets,
            )
            print(f"valid: {len(records)} result records")
            return 0
        if args.command == "run":
            plan = load_jsonl(args.plan)
            raw_sets = {record.get("task_set") for record in plan}
            if any(not isinstance(value, str) for value in raw_sets):
                raise ValidationError("plan: every trial must identify a task set")
            selected_sets = tuple(sorted(raw_sets))
            validate_plan(plan, study, task_sets=selected_sets)
            adapter = _adapter_from_remainder(args.adapter)
            run_adapter(
                plan,
                args.results,
                adapter,
                timeout_seconds=args.timeout_seconds,
                resume=args.resume,
            )
            return 0
        if args.command == "report":
            from .analysis import analyze_results

            records = load_jsonl(args.results)
            report = analyze_results(records, study, task_set=args.task_set)
            report["results_sha256"] = file_sha256(args.results)
            encoded = json.dumps(report, sort_keys=True, indent=2, allow_nan=False)
            if args.output:
                destination = Path(args.output)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(encoded + "\n", encoding="utf-8")
                print(f"wrote report to {destination}")
            else:
                print(encoded)
            return 0
    except ValidationError as exc:
        print(f"benchmark validation failed: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
