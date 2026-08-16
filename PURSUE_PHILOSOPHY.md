# The Philosophy Behind `!pursue`

## Persistence Is Not Repetition

The purpose of `!pursue` is simple to state: give an agent a goal and let it keep
working until there is good reason to believe the goal has been achieved. The
important phrase is *good reason*. An agent that merely repeats the same request
forever is persistent in a mechanical sense, but it is not persistent in the
sense we care about. It can spend unlimited tokens reproducing the same mistaken
assumption, searching the same places, or polishing an answer whose foundation
is wrong.

Real persistence is adaptive. A serious attempt at a goal must be able to notice
failure, learn from evidence, change strategy, and distinguish movement from
progress. This is the central philosophy of `!pursue`: perseverance should be a
closed feedback loop, not an infinite prompt loop.

The original `!obsess` command embodied useful stubbornness. It prevented the
agent from treating the end of one model response as the end of the task. That
was valuable, because language models are naturally organized around turns while
many real goals require sustained work. But `!obsess` had no internal definition
of success. It continued because it had been told to continue, not because it
understood what remained unfinished. `!pursue` preserves the stubbornness while
giving it direction.

## Goals Need Observable Meaning

A natural-language goal is rarely a complete specification. “Find a data
engineering job near Oslo,” “explain this historical dispute,” and “fix the
application” each leave different questions unanswered. What counts as a job
being relevant? How current must the listing be? Which sources are authoritative?
Which behavior demonstrates that the application is fixed?

`!pursue` therefore begins by translating the request into a stable acceptance
contract. The contract is not meant to replace the user's words. It makes their
practical meaning explicit by identifying criteria that can be checked against
the world. Harmless gaps can be covered by stated assumptions. A missing fact
that would materially change the result should instead cause the pursuit to ask
the user.

Freezing the criteria matters. Without a stable contract, an agent can quietly
move the goalposts until its current output appears successful. A frozen contract
forces later evaluation to answer the harder question: did the work satisfy the
original standard?

The standard must also fit the task. Software work can often be evaluated with
tests, builds, reproduction steps, and inspection of the resulting files. Web
research calls for different evidence: correct identification, current
information, authoritative or primary sources, coverage of material claims, and
attention to contradictory evidence. Analytical and subjective work needs an
explicit rubric and honest separation between sourced facts, interpretations,
and uncertainty. There is no universal test command for truth.

## Action Must Meet the World

The intellectual model behind `!pursue` is the cycle

> specify → act → observe → verify → reflect → replan

The worker does not succeed by producing plausible language. It acts through the
tools available to it and collects observations: command output, test results,
documents, source pages, database records, or other evidence supplied by the
environment. This follows the broad insight of ReAct: reasoning becomes more
reliable when it is interleaved with action and observation rather than conducted
entirely inside a model's generated text.

This distinction is especially important for internet research. A fluent answer
about a current topic is not evidence that the answer is current. A cited URL is
not evidence that the page supports the associated claim. Search results are
leads, not conclusions. The agent must open sources, compare what they actually
say, consider dates and provenance, and investigate meaningful disagreements.
One decisive primary source may be stronger than ten derivative pages repeating
one another, so verification should reward evidential quality rather than an
arbitrary citation count.

More tokens create more opportunities to perform this work, but they do not make
unsupported reasoning true. Compute is useful when it purchases additional
experiments, searches, checks, and alternative strategies. Compute spent on
repeating an ungrounded belief merely makes the belief more expensive.

## The Worker Should Not Grade Its Own Exam

`!pursue` separates doing the work from deciding whether the work is finished.
The worker operates in the main session. A separate verifier session receives the
goal, the frozen criteria, the worker's report, and the accumulated evidence. It
then checks the important claims independently before returning one of three
judgments:

- `complete`: every mandatory criterion passes with concrete evidence;
- `continue`: useful work remains, accompanied by a specific critique and next
  direction;
- `needs_input`: progress depends on a material fact or action that only the user
  can provide.

Separation does not make the verifier infallible. It may use the same underlying
model, and it remains capable of error. Its value is procedural: a fresh role and
separate context reduce the temptation to defend the worker's narrative, while
independent tool use forces important claims back into contact with observable
evidence. This reflects the lesson of research on language-agent reflection:
feedback can improve later attempts, but intrinsic self-correction without
external feedback can also preserve or worsen errors.

The verifier is deliberately read-only in spirit. Its job is to inspect, test,
search, and judge—not to quietly repair the work it is evaluating. If evaluation
and intervention are mixed together, it becomes difficult to know whether the
worker succeeded or the judge changed the answer until it passed.

## Memory Turns Failure Into Information

An unsuccessful pass is not wasted if it changes the next pass. `!pursue`
maintains bounded, durable records of accepted evidence, failed approaches,
verifier feedback, assumptions, and the most important unresolved gap. This is a
practical form of episodic memory inspired by Reflexion: the model's parameters do
not change, but the controller carries forward a compact account of what
experience has taught it.

Memory must be selective. An indefinitely growing transcript eventually becomes
noisy, expensive, and difficult to reason over. It can anchor the model to early
mistakes simply because those mistakes occupy so much context. `!pursue` retains
the information needed for the decision—what has been established, what failed,
and what remains—rather than treating every generated token as equally valuable.

When the same unmet criteria recur for three cycles without new evidence, the
controller treats that as stagnation. It does not give up. It creates a fresh
worker context supplied with the distilled memory and explicitly asks for a new
strategy. Forgetting the conversational path while preserving the learned facts
is a form of controlled escape from fixation.

## Completion Is a Claim That Requires Evidence

The worker is not allowed to terminate the pursuit merely by saying “done.” The
verifier must account for every frozen criterion, echo it exactly, assign it a
status, and attach concrete evidence to a passing judgment. A malformed or
incomplete verdict is rejected. Protocol errors are repaired, and repeated
protocol failure causes the verifier itself to be recreated from persisted state.

Automatic completion is therefore not the opposite of persistence. It is what
makes persistence meaningful. An endless system cannot distinguish success from
failure; it can only consume time. `!pursue` continues without an arbitrary pass
or token ceiling, but it stops when the evidence warrants stopping.

Some conditions should pause rather than complete or fail. The user may need to
choose a region, authorize an action, provide credentials, resolve an ambiguity,
or decide among genuinely different interpretations of the goal. Safety and
permissions remain authoritative. “Do not give up” cannot mean “invent consent”
or “silently choose a materially different objective.” When human input is
essential, waiting is progress-preserving behavior.

## Reliability Without the Pretence of Certainty

No controller can guarantee that an arbitrary goal will be reached. The world may
not contain the requested information. Sources may be inaccessible. A software
defect may depend on unavailable infrastructure. The model, worker, verifier, and
tools can all fail. `!pursue` is designed to increase the probability of success,
not to manufacture certainty.

Its philosophy is therefore both ambitious and modest. It is ambitious about
effort: difficulty alone is not a stopping condition, transient failures are
retried, repeated strategies are replaced, and available local compute may be
used fully. It is modest about knowledge: claims require evidence, assumptions
must remain visible, contradictions deserve investigation, and unverifiable
conclusions must not be presented as verified facts.

The command's name captures this balance. To pursue is to remain oriented toward
a destination while adapting one's route. It is neither the passivity of a
single answer nor the blindness of obsession. It is disciplined persistence:
keep acting, keep learning, keep checking, and stop only when the goal has been
earned by the evidence—or pause when continuing responsibly requires the human.

## Intellectual Background

The design is informed principally by:

- Shunyu Yao et al., [“ReAct: Synergizing Reasoning and Acting in Language
  Models”](https://arxiv.org/abs/2210.03629), which interleaves reasoning, action,
  and environmental observation.
- Noah Shinn et al., [“Reflexion: Language Agents with Verbal Reinforcement
  Learning”](https://arxiv.org/abs/2303.11366), which carries feedback and
  reflection into later attempts through episodic memory.
- Jie Huang et al., [“Large Language Models Cannot Self-Correct Reasoning
  Yet”](https://arxiv.org/abs/2310.01798), which documents the limits of
  correction performed without external feedback.
- Shunyu Yao et al., [“Tree of Thoughts: Deliberate Problem Solving with Large
  Language Models”](https://arxiv.org/abs/2305.10601), whose broader lesson is
  that difficult problems benefit from evaluating alternatives and escaping
  unproductive reasoning paths.

`!pursue` is not a literal implementation of any one paper. It is an engineering
synthesis of their shared practical lesson: an agent becomes more capable not by
thinking forever, but by organizing continued effort around feedback, memory,
verification, and explicit criteria for success.
