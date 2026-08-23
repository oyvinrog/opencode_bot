"""Strict model-to-controller protocol parsing for ``!pursue``.

The model is allowed to *propose* a contract.  It is never allowed to submit check
results, observation identifiers, criterion statuses, or a completion outcome.  This
module therefore accepts only the small drafting schema below and discards nothing
silently: unknown fields make the envelope invalid.
"""

from __future__ import annotations

import json
import re
from typing import Any


_CONTROL = re.compile(
    r"<pursuit-control>\s*(\{.*?\})\s*</pursuit-control>", re.DOTALL
)
_PLACEHOLDER = re.compile(
    r"(?:<[^>]+>|\b(?:todo|tbd|placeholder|criterion text|insert here)\b)",
    re.IGNORECASE,
)
_TOP_LEVEL_FIELDS = {
    "type",
    "constraints",
    "assumptions",
    "criteria",
    "needs_input",
    "question",
}
_CRITERION_FIELDS = {"text", "verification"}
_COMMAND_FIELDS = {
    "kind",
    "argv",
    "cwd",
    "timeout_seconds",
    "expected_exit",
    "stdout_contains",
}
_STATE_FIELDS = {"kind", "path", "url", "predicate", "expected", "timeout_seconds"}
_HUMAN_FIELDS = {"kind"}
_PATH_STATE_PREDICATES = {
    "exists",
    "not_exists",
    "file",
    "directory",
    "nonempty",
    "contains",
    "equals",
    "json_equals",
}
_URL_STATE_PREDICATES = {"status", "contains", "json_equals"}


def parse_contract_control(text: str) -> dict[str, Any] | None:
    """Return a normalized contract proposal or ``None`` for any schema violation.

    Criterion IDs are deliberately absent from the accepted schema.  The controller
    assigns them after parsing, so a model cannot collide with or impersonate durable
    controller records.  The same rule excludes evidence, status, observation, attempt,
    approval, version, budget, and outcome fields.
    """

    encoded = _extract_single_object(text)
    if encoded is None:
        return None
    try:
        value = json.loads(encoded)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict):
        return None
    if set(value) == {"pursuit-control"}:
        value = value["pursuit-control"]
        if not isinstance(value, dict):
            return None
    if set(value) - _TOP_LEVEL_FIELDS or value.get("type") != "contract":
        return None

    constraints = _string_list(value.get("constraints"), maximum=20)
    assumptions = _string_list(value.get("assumptions"), maximum=20)
    if constraints is None or assumptions is None:
        return None
    needs_input = value.get("needs_input")
    question = value.get("question")
    if not isinstance(needs_input, bool):
        return None
    if needs_input:
        if not isinstance(question, str) or not _valid_text(question, maximum=2_000):
            return None
        normalized_question: str | None = question.strip()
    else:
        if question not in {None, ""}:
            return None
        normalized_question = None

    raw_criteria = value.get("criteria")
    if not isinstance(raw_criteria, list) or not (1 <= len(raw_criteria) <= 12):
        return None
    criteria: list[dict[str, Any]] = []
    seen_text: set[str] = set()
    for raw in raw_criteria:
        criterion = _normalize_criterion(raw)
        if criterion is None or criterion["text"] in seen_text:
            return None
        seen_text.add(criterion["text"])
        criteria.append(criterion)

    return {
        "constraints": constraints,
        "assumptions": assumptions,
        "criteria": criteria,
        "needs_input": needs_input,
        "question": normalized_question,
    }


def _extract_single_object(text: str) -> str | None:
    matches = _CONTROL.findall(text)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        return None
    encoded = text.strip()
    fence = re.fullmatch(r"```(?:json)?\s*\n?(.*?)\n?```", encoded, re.DOTALL)
    if fence:
        encoded = fence.group(1).strip()
    if encoded.startswith("{") and encoded.endswith("}"):
        return encoded
    return None


def _normalize_criterion(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or set(value) != _CRITERION_FIELDS:
        return None
    text = value.get("text")
    if not isinstance(text, str) or not _valid_text(text, maximum=4_000):
        return None
    verification = value.get("verification")
    if not isinstance(verification, dict):
        return None
    kind = verification.get("kind")
    if kind == "human":
        if set(verification) != _HUMAN_FIELDS:
            return None
        normalized = {"kind": "human"}
    elif kind == "command":
        normalized = _normalize_command(verification)
    elif kind == "state":
        normalized = _normalize_state(verification)
    else:
        return None
    if normalized is None:
        return None
    return {"text": text.strip(), "verification": normalized}


def _normalize_command(value: dict[str, Any]) -> dict[str, Any] | None:
    if set(value) - _COMMAND_FIELDS:
        return None
    argv = value.get("argv")
    if (
        not isinstance(argv, list)
        or not (1 <= len(argv) <= 64)
        or not all(isinstance(item, str) and 0 < len(item) <= 4_000 for item in argv)
    ):
        return None
    cwd = value.get("cwd", ".")
    timeout = value.get("timeout_seconds", 300)
    expected_exit = value.get("expected_exit", 0)
    contains = value.get("stdout_contains")
    if not isinstance(cwd, str) or not cwd or len(cwd) > 1_000:
        return None
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 1_800:
        return None
    if not isinstance(expected_exit, int) or isinstance(expected_exit, bool):
        return None
    if contains is not None and (not isinstance(contains, str) or len(contains) > 4_000):
        return None
    return {
        "kind": "command",
        "argv": list(argv),
        "cwd": cwd,
        "timeout_seconds": timeout,
        "expected_exit": expected_exit,
        "stdout_contains": contains,
    }


def _normalize_state(value: dict[str, Any]) -> dict[str, Any] | None:
    if set(value) - _STATE_FIELDS:
        return None
    path = value.get("path")
    url = value.get("url")
    if (isinstance(path, str)) == (isinstance(url, str)):
        return None
    target = path if isinstance(path, str) else url
    if not target or len(target) > 4_000:
        return None
    predicate = value.get(
        "predicate", "exists" if isinstance(path, str) else "status"
    )
    timeout = value.get("timeout_seconds", 30)
    allowed = (
        _PATH_STATE_PREDICATES if isinstance(path, str) else _URL_STATE_PREDICATES
    )
    if predicate not in allowed:
        return None
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 60:
        return None
    if predicate in {"contains", "equals", "json_equals"} and "expected" not in value:
        return None
    result: dict[str, Any] = {
        "kind": "state",
        "predicate": predicate,
        "timeout_seconds": timeout,
    }
    result["path" if isinstance(path, str) else "url"] = target
    if "expected" in value:
        try:
            json.dumps(value["expected"], allow_nan=False)
        except (TypeError, ValueError):
            return None
        result["expected"] = value["expected"]
    return result


def _string_list(value: Any, *, maximum: int) -> list[str] | None:
    if not isinstance(value, list) or len(value) > maximum:
        return None
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not _valid_text(item, maximum=4_000):
            return None
        result.append(item.strip())
    if len(result) != len(set(result)):
        return None
    return result


def _valid_text(value: str, *, maximum: int) -> bool:
    stripped = value.strip()
    return bool(stripped) and len(stripped) <= maximum and not _PLACEHOLDER.search(stripped)
