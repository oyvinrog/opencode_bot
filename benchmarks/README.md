# `!pursue` benchmark harness

This package implements the evaluation protocol; it does **not** contain or
claim benchmark results. The development and confirmation tasks must be curated,
their graders audited, and every implementation and model version pinned before
the first scored run. In particular, generated filler tasks are not a 120-task
confirmation suite.

The study has four strata (code, terminal/API state, research, and
blocked/adversarial), three configurations, two model families, and five runs per
task/configuration/model cell. The required 40-task development set expands to
1,200 trials. The frozen 120-task confirmation set expands to 3,600 trials. A
combined plan contains 4,800 trials.

## Preparing a study

1. Copy `templates/manifest.template.json` to a study directory. Replace every
   `PIN_*` value with an immutable commit, protocol, model version, grader, or
   digest. Do this before inspecting confirmation outcomes.
2. Author `tasks/dev.json` with exactly 10 tasks per stratum and
   `tasks/confirmation.json` with exactly 30 per stratum. `task.template.json`
   documents one record. Keep hidden tests and rubric answers outside prompts.
3. Pilot task setup and graders on the development set. A grader must judge the
   external end state; it must not accept the controller's completion prose as
   evidence. Independently audit permission logs.
4. Freeze the confirmation file and put its digest in the manifest:

       python -m benchmarks.runner hash-tasks --tasks STUDY/tasks/confirmation.json

5. Commit the manifest, task digest, graders, adapter, and analysis code. Do not
   edit them after any confirmation run. If a defect forces a change, invalidate
   the run, increment the study ID, and rerun every configuration.

Validation fails unless the exact task counts, balanced strata, fixed release
policy, pinned model/configuration fields, and confirmation digest are present:

    python -m benchmarks.runner validate --manifest STUDY/manifest.json

## Planning and running

Generate a randomized plan. Configurations in the same task/model/run cell share
a seed, giving a paired comparison:

    python -m benchmarks.runner plan \
      --manifest STUDY/manifest.json --task-set dev --output dev-plan.jsonl

The runner calls an external adapter once per trial. It sends the full trial as
JSON on standard input; the adapter returns one outcome object on standard
output. Provider credentials, controller startup, workspace reset, external
oracle execution, and policy-log inspection belong in that adapter. Start from
`templates/adapter.template.py`; the template intentionally refuses to run.

    python -m benchmarks.runner run \
      --manifest STUDY/manifest.json --plan dev-plan.jsonl \
      --results dev-results.jsonl --timeout-seconds 1800 -- \
      STUDY/adapter.py

`--resume` only appends missing trials and rejects an existing result whose full
pinned identity differs from the plan. Non-zero exits, timeouts, malformed
output, and absent grader evidence become failed trials rather than disappearing
from the denominator.

## Analysis and promotion

Validate a complete result matrix and write a machine-readable report:

    python -m benchmarks.runner report \
      --manifest STUDY/manifest.json --task-set confirmation \
      --results confirmation-results.jsonl --output confirmation-report.json

The primary success difference uses a paired, stratum-preserving bootstrap whose
resampling unit is the task. The report also shows five-of-five repeated-run
reliability, false completions, per-task and per-model-family differences,
unauthorized actions, and resources per true completion. Error trials count as
failures.

The fixed confirmation gates are:

- at least 10 percentage points more success than the matched single-worker
  baseline, with the task-clustered 95% interval above zero;
- at least 50% fewer false completions when the baseline has any; otherwise, a
  one-sided 95% upper bound below 2% on objectively graded candidate trials;
- no individual task or model-family regression greater than 5 points;
- zero unauthorized candidate actions; and
- no more than twice the stronger baseline's predeclared resource metric per true
  completion.

Only a complete, digest-matched confirmation report can say `pass`. Development
reports always say `development_only`, even when every numerical gate passes.
These gates are product policy, not evidence that the thresholds are laws of
agent performance.

## Interpretation limits

The harness cannot make a poor oracle good. Hidden checks can omit important
behavior, API state can race, and blinded reviewers can disagree. The study
owner should publish task-level outcomes, grader audit findings, exclusions (the
default protocol permits none after freezing), and the exact result/manifest
digests. Generalization is limited to the sampled tasks, tools, environments,
permissions, controllers, and pinned model versions.
