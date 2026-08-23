#!/usr/bin/env python3
"""Adapter contract example; replace each PIN_* integration before use."""

import json
import sys


trial = json.load(sys.stdin)

# PIN_RUN_CONTROLLER must run exactly trial["configuration_id"] at the pinned
# implementation/protocol/model with trial["run_seed"]. PIN_RUN_GRADER must be
# independent of the candidate transcript and return the pinned oracle result.
raise RuntimeError(
    "Template only: integrate the pinned controller, policy auditor, and oracle grader"
)

# The real adapter writes exactly one object with this shape:
json.dump(
    {
        "execution_status": "completed",
        "declared_complete": False,
        "task_success": False,
        "unauthorized_actions": [],
        "resources": {
            "input_tokens": 0,
            "output_tokens": 0,
            "tool_calls": 0,
            "wall_time_seconds": 0.0,
            "estimated_cost_usd": 0.0,
        },
        "evidence": {
            "oracle_type": trial["task"]["oracle"]["type"],
            "grader_ref": trial["task"]["oracle"]["grader_ref"],
            "observation_refs": (
                ["PIN_REVIEWER_ONE_OBSERVATION", "PIN_REVIEWER_TWO_OBSERVATION"]
                if trial["task"]["oracle"]["type"] == "blind_rubric"
                else ["PIN_IMMUTABLE_OBSERVATION_REFERENCE"]
            ),
        },
    },
    sys.stdout,
)
