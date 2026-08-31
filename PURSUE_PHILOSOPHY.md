# The Philosophy Behind `!pursue`

`!pursue` exists to make a tool-using agent more likely to finish a real task,
not merely to produce a longer answer. It is a bounded controller around one
worker: make an attempt, check the resulting world, give failures back to the
worker, and stop or ask the operator when continued work is no longer authorized.
In unattended YOLO mode, one contract approval authorizes that loop until early
verified completion, a genuine external blocker, an explicit stop, or a fixed
deadline; internal accounting limits do not become interruptions.

The design rests on three principles. They are deliberately narrower than the
claims made by the earlier design.

1. **Reality decides.** Model prose cannot establish that model work is correct.
2. **Complexity must earn its keep.** Additional inference, retries, memory, or
   agents are features to test, not assumed improvements.
3. **Reliability is a distribution.** A controller is useful only if it improves
   repeated, end-to-end outcomes on representative tasks.

These principles are supported by direct research on language models and agents.
They do not imply that `!pursue` is universally reliable, that any particular
checker is sound, or that the current budget values are optimal.

## 1. Reality Decides

The worker may propose a plan, use tools, change files, and explain what it did.
It may not turn those statements into proof of success. Completion is determined
by a controller-recorded observation of the latest result.

This boundary follows the most consistent result in the self-correction
literature. Kamoi et al.'s critical survey found no general demonstration of
successful correction from feedback produced by prompted LLMs themselves,
except on tasks unusually suited to self-correction; reliable external feedback
and large-scale fine-tuning were materially different settings
([TACL 2024](https://aclanthology.org/2024.tacl-1.78/)). Huang et al. found that
intrinsic self-correction on reasoning tasks often failed to improve answers and
could make them worse
([ICLR 2024](https://proceedings.iclr.cc/paper_files/paper/2024/hash/8b4add8b0aa8749d80a34ca5d941c355-Abstract-Conference.html)).
On three formal reasoning and planning domains, Stechly et al. observed
performance collapse with self-critique and gains from sound external verifiers
([ICLR 2025](https://proceedings.iclr.cc/paper_files/paper/2025/hash/f3c5e56274140e0420baa3916c529210-Abstract-Conference.html)).

Positive results have the same important qualifier. CRITIC improved results on
the particular question-answering, mathematical/program-synthesis, and toxicity
tasks it studied by placing tool feedback in the correction loop
([ICLR 2024](https://proceedings.iclr.cc/paper_files/paper/2024/hash/fef126561bbf9d4467dbb8d27334b8fe-Abstract-Conference.html)).
RefineBench evaluated 1,000 problems in 11 domains: unguided self-refinement was
small or inconsistent for frontier models, whereas targeted checklist feedback
made refinement much more effective for sufficiently capable models
([ICLR 2026](https://proceedings.iclr.cc/paper_files/paper/2026/hash/835b6c04ca2daaa1a682c2eaad4a70ea-Abstract-Conference.html)).
These studies support correction from relevant external feedback. They do not
show that every test, search result, model judge, or checklist is trustworthy.

### What Counts as Verification

`!pursue` recognizes three verification methods:

- **Command verification** runs a contract-approved check against an isolated
  snapshot of the result and records its raw output and exit status. Examples
  include tests, builds, linters, and artifact validators.
- **State verification** performs a read-only query for a specified environment
  or API postcondition. The expected value is fixed in the approved contract.
- **Human verification** is required when correctness depends on judgment or no
  adequate objective checker is available. It never passes autonomously.

Only the controller creates a check result. Every result is tied to the contract
version, worker attempt, and workspace or state revision that it observed. A
later mutation invalidates affected results and requires new checks. Failed,
unknown, duplicated, stale, or model-authored "evidence" cannot become a pass.

The distinction matters most where fluent language resembles evidence. For
research, retrieving a source can demonstrate that the source was accessed. It
does not demonstrate that the source is true, that a paraphrase is faithful, or
that the investigation is complete. Those claims need a suitable deterministic
checker or human sign-off. The same caution applies to tests: passing an
incomplete test suite proves only what that suite measures. External feedback is
valuable only to the extent that the checker is relevant and sound, so checker
scope and remaining uncertainty stay visible in the result.

### The Contract Preserves Intent

Before work starts, `!pursue` drafts a versioned contract containing the user's
goal, authorization constraints, assumptions, acceptance criteria, verification
method for each criterion, chosen extent, and finite budget. The user must
approve it. A material revision creates a new version and requires approval
again.

Approval is a product control, not an empirical claim that LLM-generated
contracts are optimal. It prevents the controller from silently changing the
goal, accepting unsafe authority, or choosing a weak proxy without showing the
operator. The user's original request remains authoritative over the draft. If
the draft selects unattended YOLO, approval also creates a pursuit-scoped lease
bound to that contract's digest. A session-wide permission setting cannot
authorize a new or revised contract.

The interactive lifecycle is:

> draft contract → await approval → work → check → repair, finish, or pause

With unattended YOLO, the approved lease starts an absolute deadline when the
worker launches:

> draft contract → await approval → work ↔ check/repair/rotate → verified result, true blocker, stop, or deadline

An objectively checked pursuit can reach `verified_complete` as soon as the
latest checks pass. An interactive pursuit with unresolved human criteria reaches
`awaiting_signoff`, with its result explicitly marked provisional; an unattended
pursuit instead finishes provisionally without claiming human approval. Missing
facts or authority produce `needs_input`, and an operator may always choose
`stopped`. `budget_checkpoint` remains an interactive state, not a routine pause
inside a valid unattended lease.

## 2. Complexity Must Earn Its Keep

The default architecture is one capable worker receiving concrete failures from
external checks. A new attempt is justified by a failed check or an unresolved
criterion, not by a general instruction to think again. Work ends as soon as the
latest applicable checks pass.

The reason is empirical rather than aesthetic. A controlled study of 260
configurations across six agent benchmarks, five coordination architectures, and
three model families found that multi-agent coordination ranged from substantial
improvement to severe degradation depending on the task and architecture. The
authors present their fitted threshold as a within-domain selection rule, not a
universal scaling law
([Nature Machine Intelligence 2026](https://www.nature.com/articles/s42256-026-01268-y)).
Adaptive-Consistency reduced sampling by as much as 7.9 times across 17 reasoning
and code-generation datasets and three models, with less than 0.1% average
accuracy loss, by stopping sampling based on observed agreement
([EMNLP 2023](https://aclanthology.org/2023.emnlp-main.761/)). That study concerns
sample aggregation rather than long-running tool agents, but it is direct
evidence that allocating the same inference budget to every problem is not
automatically efficient.

Consequently, verbal reflection memory, tree search, multiple candidates,
parallel workers, model critics, recursive decomposition, and transcript
summarization are disabled by default. Some have produced gains on particular
benchmarks; none is accepted here as a universal law. Each may be promoted only
after a matched OpenBot experiment shows a reproducible benefit for the task
class where it will run.

### Finite, Visible Budgets and Leases

Persistence is bounded. The initial budget is shown before approval:

| Input / extent | Worker/check cycles | Tool calls | Input tokens | Wall time |
| --- | ---: | ---: | ---: | ---: |
| `1` — Focused | 4 | 40 | 250,000 | 60 minutes |
| `2` — Thorough | 12 | 120 | 750,000 | 180 minutes |
| `3` — Extended | 32 | 320 | 2,000,000 | 480 minutes |

The operator may instead enter a positive whole-minute or whole-hour duration,
such as `90m` or `4h`, up to eight hours. Its cycle, tool-call, and input-token
allowances scale at the hourly rates above. These numbers are OpenBot policy
defaults. No cited experiment establishes them as optimal. They provide
predictable operator control and measurable starting points for later tuning.

In interactive mode, reaching any limit creates a `budget_checkpoint`; it does
not turn incomplete work into success. The operator may grant another visible
tranche, revise and reapprove the contract, or stop.

In unattended YOLO mode, wall time is the maximum lease duration and the absolute
deadline never moves. Reaching a cycle, tool-call, or input-token allowance
rotates to a fresh worker and renews that internal tranche automatically without
a reply, while cumulative usage and the original deadline remain visible. Bot
downtime counts against the lease. The controller resumes after restart only if
time remains.

At the deadline, worker actions stop and one bounded, read-only final check
records either the verified outcome or a terminal `deadline_reached` report. If
only human checks remain, the terminal result is clearly provisional; the
controller never fabricates sign-off. Before the deadline, only a true external
blocker—missing credentials or authority, a material user-only fact, an
unavailable required verifier, or an explicit non-retryable permission
refusal—may pause unattended work. Transient permission failures are retried.
`!yolo off` revokes the lease, and `!stop` remains immediate. A material contract
revision always requires new approval and starts a new deadline.

YOLO enabled later for the current worker is still bound to that exact session
and contract. It does not create an unattended deadline or renew quotas, but it
does allow a completed run whose only remaining checks require judgment to return
an explicitly provisional result instead of pausing for sign-off.

Automatic rotations and progress messages may be reported to the room, but they
are notices rather than prompts. A message that actually requires approval,
input, or a permission decision says so explicitly. There is no promise to try
every plausible avenue, and consuming more compute is never evidence by itself.

## 3. Reliability Is a Distribution

An agent that succeeds once can still be operationally unreliable. `!pursue`
therefore treats repeated full-task success—not a persuasive trace or selected
demo—as the unit of progress.

This distinction is substantial in agent systems. In the original `tau`-bench
experiments, a leading function-calling agent completed fewer than half of tasks
in the two tested domains, while the probability of succeeding on every one of
eight repeated retail trials was below 25%
([ICLR 2025](https://proceedings.iclr.cc/paper_files/paper/2025/hash/1b126cc38b8638e07bef37e7b2bb72bf-Abstract-Conference.html)).
The benchmark's end-state comparison and repeated-run metric are useful design
ideas, but its domains and simulated users do not establish OpenBot performance.

Evaluators can also be wrong. An audit of prominent agent benchmarks identified
task-setup and reward defects capable of changing reported performance by up to
100% in relative terms
([NeurIPS 2025](https://proceedings.neurips.cc/paper_files/paper/2025/hash/f316275b44ee2de533102913828a8107-Abstract-Datasets_and_Benchmarks_Track.html)).
This is why OpenBot must test the evaluator as carefully as the agent and inspect
false completions, not only aggregate reward.

### The Promotion Standard

Controller changes are evaluated against the deployed controller and a strong
single-worker baseline with matched tasks, tools, permissions, information, and
resource ceilings. A 40-task development suite is used for iteration. Promotion
uses a separate frozen 120-task confirmation suite: 30 software tasks with hidden
tests, 30 terminal/API tasks with target-state and policy graders, 30
source-grounded research tasks with two blinded human reviewers, and 30
impossible, underspecified, adversarial, or permission-bound tasks. Each
task/controller combination receives five independent runs with the production
model and with one different model family.

The primary measurements are:

- full task success at the true end state;
- false completion, especially on objectively graded tasks;
- repeated-run reliability;
- unauthorized or unintended actions; and
- resources per verified completion.

A new mechanism ships by default only after the planned confirmation experiment
shows at least a 10 percentage-point absolute success improvement with a
task-clustered 95% confidence interval excluding zero, at least 50% fewer false
completions when the baseline has any, and otherwise no increase with a 95%
upper bound below 2% on objectively graded tasks. No task or model-family stratum
may regress by more than five points; there must be zero unauthorized actions;
and median resources per true completion may be no more than twice the stronger
baseline. These thresholds are release policy, not natural constants; their
purpose is to make "better" falsifiable.

## What `!pursue` Does Not Claim

`!pursue` cannot guarantee completion. The contract may encode the wrong proxy,
tests may omit a defect, external state may change after observation, sources may
be inaccessible, and a capable worker may still fail. Human sign-off can also be
mistaken. A `verified_complete` result means that every objective criterion in
the approved contract passed its latest applicable checker—not that all possible
interpretations of the goal are true.

The philosophy is therefore intentionally simple: let the model generate and
repair; let observed outcomes determine what passed; add machinery only after it
wins a fair experiment; and judge the controller across repeated complete tasks.
