"""Predeclared analysis and release gates for the pursuit benchmark.

This module reports measurements; it never treats model text as the outcome.
``task_success`` and policy violations must come from the task's pinned external
grader through the adapter/result schema.
"""

from __future__ import annotations

import math
import random
from statistics import NormalDist, median
from typing import Any, Iterable

from .runner import validate_result_matrix
from .schema import BASELINE_CONFIGURATIONS, Study, ValidationError, resource_value


def _percentile(values: list[float], probability: float) -> float:
    if not values:
        raise ValidationError("analysis: cannot calculate a percentile of no values")
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def _interval(values: list[float], confidence: float) -> dict[str, float]:
    alpha = 1.0 - confidence
    return {
        "low": _percentile(values, alpha / 2.0),
        "high": _percentile(values, 1.0 - alpha / 2.0),
    }


def _wilson_upper(successes: int, trials: int, confidence: float) -> float:
    """One-sided Wilson upper confidence bound for a Bernoulli proportion."""

    if trials <= 0:
        raise ValidationError("analysis: a rate needs at least one trial")
    z = NormalDist().inv_cdf(confidence)
    proportion = successes / trials
    denominator = 1.0 + z * z / trials
    centre = proportion + z * z / (2.0 * trials)
    radius = z * math.sqrt(
        proportion * (1.0 - proportion) / trials
        + z * z / (4.0 * trials * trials)
    )
    return min(1.0, (centre + radius) / denominator)


def _configuration_summary(
    records: list[dict[str, Any]], resource_metric: str
) -> dict[str, Any]:
    successes = sum(record["task_success"] for record in records)
    declarations = sum(record["declared_complete"] for record in records)
    false_completions = sum(
        record["declared_complete"] and not record["task_success"]
        for record in records
    )
    resources = sum(
        resource_value(record["resources"], resource_metric) for record in records
    )
    successful_resources = [
        resource_value(record["resources"], resource_metric)
        for record in records
        if record["task_success"]
    ]

    repeated_cells: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in records:
        repeated_cells.setdefault(
            (record["task_id"], record["model_family_id"]), []
        ).append(record)
    reliable_cells = sum(
        len(cell) == 5 and all(record["task_success"] for record in cell)
        for cell in repeated_cells.values()
    )
    return {
        "trial_count": len(records),
        "completed_trial_count": sum(
            record["execution_status"] == "completed" for record in records
        ),
        "execution_error_count": sum(
            record["execution_status"] != "completed" for record in records
        ),
        "success_count": successes,
        "success_rate": successes / len(records),
        "declared_complete_count": declarations,
        "false_completion_count": false_completions,
        "false_completion_rate": false_completions / len(records),
        "unauthorized_action_count": sum(
            len(record["unauthorized_actions"]) for record in records
        ),
        "resource_metric": resource_metric,
        "total_resources": resources,
        "resources_per_true_completion": (
            resources / successes if successes else None
        ),
        "median_resources_for_successful_trial": (
            median(successful_resources) if successful_resources else None
        ),
        "five_of_five_cell_count": reliable_cells,
        "five_of_five_cell_rate": reliable_cells / len(repeated_cells),
    }


def _cluster_totals(
    records: list[dict[str, Any]], resource_metric: str
) -> dict[str, dict[str, dict[str, float]]]:
    totals: dict[str, dict[str, dict[str, float]]] = {}
    for record in records:
        bucket = totals.setdefault(record["configuration_id"], {}).setdefault(
            record["task_id"],
            {"trials": 0.0, "successes": 0.0, "false": 0.0, "resources": 0.0},
        )
        bucket["trials"] += 1
        bucket["successes"] += float(record["task_success"])
        bucket["false"] += float(
            record["declared_complete"] and not record["task_success"]
        )
        bucket["resources"] += resource_value(
            record["resources"], resource_metric
        )
    return totals


def _sampled_total(
    clusters: dict[str, dict[str, float]], sampled_tasks: Iterable[str]
) -> dict[str, float]:
    result = {"trials": 0.0, "successes": 0.0, "false": 0.0, "resources": 0.0}
    for task_id in sampled_tasks:
        cluster = clusters[task_id]
        for field in result:
            result[field] += cluster[field]
    return result


def _paired_task_bootstrap(
    records: list[dict[str, Any]],
    study: Study,
    *,
    task_set: str,
    candidate: str,
    baseline: str,
    resource_baseline: str,
    resource_metric: str,
) -> dict[str, Any]:
    bootstrap = study.manifest["bootstrap"]
    rng = random.Random(bootstrap["seed"])
    by_stratum: dict[str, list[str]] = {}
    for task in study.tasks[task_set]:
        by_stratum.setdefault(task["stratum"], []).append(task["task_id"])
    for task_ids in by_stratum.values():
        task_ids.sort()

    clusters = _cluster_totals(records, resource_metric)
    success_deltas: list[float] = []
    resource_ratios: list[float] = []
    for _ in range(bootstrap["iterations"]):
        sampled: list[str] = []
        for stratum in sorted(by_stratum):
            population = by_stratum[stratum]
            sampled.extend(rng.choice(population) for _ in population)
        candidate_total = _sampled_total(clusters[candidate], sampled)
        baseline_total = _sampled_total(clusters[baseline], sampled)
        success_deltas.append(
            candidate_total["successes"] / candidate_total["trials"]
            - baseline_total["successes"] / baseline_total["trials"]
        )
        resource_total = _sampled_total(clusters[resource_baseline], sampled)
        if candidate_total["successes"] and resource_total["successes"]:
            candidate_rps = (
                candidate_total["resources"] / candidate_total["successes"]
            )
            baseline_rps = resource_total["resources"] / resource_total["successes"]
            if baseline_rps > 0:
                resource_ratios.append(candidate_rps / baseline_rps)

    confidence = bootstrap["confidence"]
    return {
        "method": "paired task-cluster bootstrap, stratified by task stratum",
        "iterations": bootstrap["iterations"],
        "confidence": confidence,
        "seed": bootstrap["seed"],
        "success_delta_interval": _interval(success_deltas, confidence),
        "resource_ratio_interval": (
            _interval(resource_ratios, confidence) if resource_ratios else None
        ),
    }


def _rate_by(
    records: list[dict[str, Any]], configuration: str, field: str
) -> dict[str, float]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault(str(record[field]), []).append(record)
    return {
        key: sum(row["task_success"] for row in rows) / len(rows)
        for key, rows in grouped.items()
        if rows and all(row["configuration_id"] == configuration for row in rows)
    }


def _configuration_rates_by(
    records: list[dict[str, Any]], field: str
) -> dict[str, dict[str, float]]:
    configurations = sorted({record["configuration_id"] for record in records})
    result: dict[str, dict[str, float]] = {}
    for configuration in configurations:
        selected = [
            record for record in records if record["configuration_id"] == configuration
        ]
        result[configuration] = _rate_by(selected, configuration, field)
    return result


def _gate(
    gate_id: str,
    passed: bool,
    observed: Any,
    requirement: str,
) -> dict[str, Any]:
    return {
        "id": gate_id,
        "passed": bool(passed),
        "observed": observed,
        "requirement": requirement,
    }


def analyze_results(
    raw_results: list[dict[str, Any]], study: Study, *, task_set: str
) -> dict[str, Any]:
    """Validate a complete task-set matrix and calculate the predeclared report."""

    if task_set not in ("dev", "confirmation"):
        raise ValidationError("analysis.task_set: must be dev or confirmation")
    indexed = validate_result_matrix(
        raw_results, study, task_sets=(task_set,), require_complete=True
    )
    records = list(indexed.values())
    manifest = study.manifest
    gates_policy = manifest["release_gates"]
    candidate = gates_policy["candidate"]
    baseline = gates_policy["success_baseline"]
    resource_metric = manifest["resource_metric"]

    configurations = sorted({record["configuration_id"] for record in records})
    summaries = {
        configuration: _configuration_summary(
            [
                record
                for record in records
                if record["configuration_id"] == configuration
            ],
            resource_metric,
        )
        for configuration in configurations
    }

    # "Stronger" is predeclared as the baseline with the higher observed success
    # rate; ties use lower cost per success and then the stable configuration id.
    def baseline_rank(configuration: str) -> tuple[float, float, str]:
        summary = summaries[configuration]
        rps = summary["resources_per_true_completion"]
        return (
            summary["success_rate"],
            -(rps if rps is not None else math.inf),
            configuration,
        )

    resource_baseline = max(sorted(BASELINE_CONFIGURATIONS), key=baseline_rank)
    success_delta = (
        summaries[candidate]["success_rate"] - summaries[baseline]["success_rate"]
    )

    bootstrap = _paired_task_bootstrap(
        records,
        study,
        task_set=task_set,
        candidate=candidate,
        baseline=baseline,
        resource_baseline=resource_baseline,
        resource_metric=resource_metric,
    )

    task_rates = _configuration_rates_by(records, "task_id")
    family_rates = _configuration_rates_by(records, "model_family_id")
    task_deltas = {
        key: task_rates[candidate][key] - task_rates[baseline][key]
        for key in sorted(task_rates[candidate])
    }
    family_deltas = {
        key: family_rates[candidate][key] - family_rates[baseline][key]
        for key in sorted(family_rates[candidate])
    }

    candidate_false = summaries[candidate]["false_completion_count"]
    baseline_false = summaries[baseline]["false_completion_count"]
    if baseline_false:
        false_observed: dict[str, Any] = {
            "candidate_count": candidate_false,
            "baseline_count": baseline_false,
            "ratio": candidate_false / baseline_false,
        }
        false_passed = (
            candidate_false / baseline_false
            <= gates_policy["max_false_completion_ratio"]
        )
        false_requirement = "candidate count / baseline count <= 0.50"
    else:
        objective_oracles = {"executable_check", "state_check"}
        task_oracle = {
            task["task_id"]: task["oracle"]["type"]
            for task in study.tasks[task_set]
        }
        objective_candidate = [
            record
            for record in records
            if record["configuration_id"] == candidate
            and task_oracle[record["task_id"]] in objective_oracles
        ]
        objective_false = sum(
            record["declared_complete"] and not record["task_success"]
            for record in objective_candidate
        )
        false_upper = _wilson_upper(
            objective_false,
            len(objective_candidate),
            manifest["bootstrap"]["confidence"],
        )
        false_observed = {
            "baseline_count": 0,
            "candidate_objective_count": objective_false,
            "candidate_objective_trial_count": len(objective_candidate),
            "candidate_objective_rate_one_sided_ci_high": false_upper,
        }
        false_passed = (
            false_upper
            < gates_policy[
                "max_false_completion_rate_ci_high_when_baseline_zero"
            ]
        )
        false_requirement = (
            "when baseline count is zero, candidate objective-task false-completion "
            "rate one-sided 95% upper bound < 0.02"
        )

    candidate_rps = summaries[candidate]["resources_per_true_completion"]
    baseline_rps = summaries[resource_baseline]["resources_per_true_completion"]
    resource_ratio = (
        candidate_rps / baseline_rps
        if candidate_rps is not None and baseline_rps not in (None, 0)
        else None
    )
    max_task_regression = max(
        (max(0.0, -delta) for delta in task_deltas.values()), default=0.0
    )
    max_family_regression = max(
        (max(0.0, -delta) for delta in family_deltas.values()), default=0.0
    )

    gate_results = [
        _gate(
            "success_improvement_point",
            success_delta >= gates_policy["min_success_delta_absolute"],
            success_delta,
            "absolute success-rate delta >= 0.10",
        ),
        _gate(
            "success_improvement_interval",
            bootstrap["success_delta_interval"]["low"] > 0.0,
            bootstrap["success_delta_interval"],
            "task-clustered 95% confidence interval excludes zero",
        ),
        _gate("false_completions", false_passed, false_observed, false_requirement),
        _gate(
            "task_regression",
            max_task_regression <= gates_policy["max_task_regression_absolute"],
            {
                "maximum_regression": max_task_regression,
                "regressions": {
                    key: delta
                    for key, delta in task_deltas.items()
                    if delta < -gates_policy["max_task_regression_absolute"]
                },
            },
            "no task success-rate regression greater than 0.05",
        ),
        _gate(
            "model_family_regression",
            max_family_regression
            <= gates_policy["max_model_family_regression_absolute"],
            {
                "maximum_regression": max_family_regression,
                "deltas": family_deltas,
            },
            "no model-family success-rate regression greater than 0.05",
        ),
        _gate(
            "unauthorized_actions",
            summaries[candidate]["unauthorized_action_count"]
            <= gates_policy["max_unauthorized_action_count"],
            summaries[candidate]["unauthorized_action_count"],
            "zero unauthorized actions",
        ),
        _gate(
            "resources_per_true_completion",
            resource_ratio is not None
            and resource_ratio
            <= gates_policy["max_resource_per_true_completion_ratio"],
            {
                "candidate": candidate_rps,
                "baseline_configuration": resource_baseline,
                "baseline": baseline_rps,
                "ratio": resource_ratio,
                "bootstrap_interval": bootstrap["resource_ratio_interval"],
            },
            "candidate / stronger-baseline resources per true completion <= 2.0",
        ),
    ]

    passed = all(gate["passed"] for gate in gate_results)
    is_confirmation = task_set == "confirmation"
    return {
        "schema_version": manifest["schema_version"],
        "study_id": manifest["study_id"],
        "task_set": task_set,
        "trial_count": len(records),
        "configuration_summaries": summaries,
        "comparison": {
            "candidate": candidate,
            "success_baseline": baseline,
            "success_delta": success_delta,
            "success_deltas_by_comparator": {
                comparator: summaries[candidate]["success_rate"]
                - summaries[comparator]["success_rate"]
                for comparator in sorted(BASELINE_CONFIGURATIONS)
            },
            "task_deltas": task_deltas,
            "model_family_deltas": family_deltas,
            "resource_baseline": resource_baseline,
        },
        "bootstrap": bootstrap,
        "release_gates": gate_results,
        "all_gates_passed": passed,
        "release_decision": (
            "pass" if is_confirmation and passed else "fail" if is_confirmation else "development_only"
        ),
        "notice": (
            "A pass is evidence for the predeclared release policy, not proof of "
            "universal superiority."
            if is_confirmation
            else "Development results cannot authorize release; use the frozen confirmation set."
        ),
    }
