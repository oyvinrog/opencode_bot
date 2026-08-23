import json

from matrix_opencode_bot.pursuit_protocol import parse_contract_control


def envelope(value: dict[str, object]) -> str:
    return f"<pursuit-control>{json.dumps(value)}</pursuit-control>"


def valid_contract() -> dict[str, object]:
    return {
        "type": "contract",
        "constraints": ["Do not change files outside the workspace"],
        "assumptions": [],
        "criteria": [
            {
                "text": "The test suite passes",
                "verification": {
                    "kind": "command",
                    "argv": ["pytest", "-q"],
                    "expected_exit": 0,
                },
            },
            {
                "text": "The operator accepts the qualitative result",
                "verification": {"kind": "human"},
            },
        ],
        "needs_input": False,
        "question": None,
    }


def test_parses_only_contract_proposals_and_normalizes_defaults() -> None:
    parsed = parse_contract_control(envelope(valid_contract()))

    assert parsed is not None
    assert [item["text"] for item in parsed["criteria"]] == [
        "The test suite passes",
        "The operator accepts the qualitative result",
    ]
    command = parsed["criteria"][0]["verification"]
    assert command["cwd"] == "."
    assert command["timeout_seconds"] == 300
    assert command["stdout_contains"] is None


def test_rejects_model_authored_evidence_status_and_observation_ids() -> None:
    for forged in (
        {"status": "pass"},
        {"evidence": [{"source": "worker prose"}]},
        {"observation_id": "controller-looking-id"},
        {"attempt_id": "attempt-1"},
        {"id": "c1"},
    ):
        value = valid_contract()
        criterion = dict(value["criteria"][0])  # type: ignore[index]
        criterion.update(forged)
        value["criteria"] = [criterion]
        assert parse_contract_control(envelope(value)) is None


def test_rejects_unknown_top_level_completion_and_budget_fields() -> None:
    for key, forged in (
        ("outcome", "verified_complete"),
        ("version", 99),
        ("approved", True),
        ("budget", {"max_cycles": 1}),
    ):
        value = valid_contract()
        value[key] = forged
        assert parse_contract_control(envelope(value)) is None


def test_rejects_multiple_envelopes_embedded_prose_and_placeholders() -> None:
    encoded = envelope(valid_contract())
    assert parse_contract_control(encoded + encoded) is None
    assert parse_contract_control("Here is the draft:\n" + json.dumps(valid_contract())) is None
    value = valid_contract()
    value["criteria"] = [
        {"text": "<criterion text>", "verification": {"kind": "human"}}
    ]
    assert parse_contract_control(envelope(value)) is None


def test_requires_exactly_one_state_target_and_supported_predicate() -> None:
    value = valid_contract()
    value["criteria"] = [
        {
            "text": "The result exists",
            "verification": {
                "kind": "state",
                "path": "result.json",
                "url": "https://example.invalid/result",
                "predicate": "exists",
            },
        }
    ]
    assert parse_contract_control(envelope(value)) is None

    verification = value["criteria"][0]["verification"]  # type: ignore[index]
    del verification["url"]  # type: ignore[index]
    verification["predicate"] = "execute"  # type: ignore[index]
    assert parse_contract_control(envelope(value)) is None


def test_material_question_and_human_checker_are_supported() -> None:
    value = valid_contract()
    value["needs_input"] = True
    value["question"] = "Which production account is in scope?"
    value["criteria"] = [
        {
            "text": "The user signs off on the result",
            "verification": {"kind": "human"},
        }
    ]

    parsed = parse_contract_control(f"```json\n{json.dumps(value)}\n```")
    assert parsed is not None
    assert parsed["question"] == "Which production account is in scope?"

