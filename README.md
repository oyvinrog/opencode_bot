<p align="center">
  <img src="matrix_opencode_bot/assets/openbot-logo.png" alt="OpenBot" width="760">
</p>

# Matrix–OpenCode bot

An end-to-end encrypted Matrix bot that controls an OpenCode coding session. Each
authorized Matrix room maps to one OpenCode session, ordinary messages become
prompts, and responses are streamed back by editing a Matrix message.

The bot connects to an `opencode serve` process through its HTTP API. The included
`run.sh` launcher starts and supervises both processes for local use.

## Example chats

![Fictitious OpenBot conversations in Element-style desktop and mobile clients](docs/images/element-chat-examples.png)

*Fictitious examples showing how OpenBot conversations can look in Element on
desktop and mobile.*

## Requirements and setup

- Python 3.11+
- OpenCode with a working provider/model configuration
- A dedicated Matrix account and an encrypted Matrix room
- On some Linux systems, `matrix-nio[e2e]` also needs `libolm-dev`, Python headers,
  and a C compiler

Create the environment and install the project:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
cp .env.example .env
```

After configuring `.env`, start both OpenCode and the bot with:

```bash
./run.sh
```

The launcher loads `.env`, starts OpenCode when needed, waits for it to become
healthy, then starts the bot. If a healthy server is already listening at
`OPENCODE_URL`, the launcher reuses it and leaves it running when the bot stops.
Otherwise, Ctrl-C stops both processes. By default OpenCode serves on
`127.0.0.1:4096`; optional `OPENCODE_SERVER_HOSTNAME` and
`OPENCODE_SERVER_PORT` values in `.env` can change that, and `OPENCODE_URL` must
point to the same address.

To run the processes separately instead, start OpenCode on loopback with Basic
Auth (using the same password as `.env`):

```bash
OPENCODE_SERVER_PASSWORD='a-strong-separate-password' \
  opencode serve --hostname 127.0.0.1 --port 4096
```

Then load the configuration and run the bot in another terminal:

```bash
set -a
. ./.env
set +a
matrix-opencode
```

The first run logs in with `MATRIX_PASSWORD`, creates a Matrix device, and stores
the access token and encryption keys under `MATRIX_DATA_DIR`. Remove the Matrix
password from `.env` after the first successful login. Keep the entire data
directory private and persistent. Existing `data/session.json` and
`data/crypto_store` files from the ELIZA example are reused unchanged.

After the initial sync, the bot posts an OpenBot welcome banner to every allowed
room it has joined. The banner is sent as native Matrix image media, including
encrypted-media metadata for encrypted rooms and dimensions that Element uses to
scale it cleanly on mobile and desktop.

Verify the new **Matrix OpenCode bot** device in Element or another full Matrix
client. The bot refuses to send to unverified recipient devices by default.
`MATRIX_IGNORE_UNVERIFIED_DEVICES=true` permits unattended use but weakens device
identity assurance; message contents remain encrypted.

## Background service

On a Linux system using systemd, install the bot as a system service after
configuring `.env`:

```bash
./install.sh
```

The installer creates or updates `.venv`, installs the project, validates the
configuration, and prompts for `sudo` to install the service. The bot starts
immediately, restarts after a failure, and starts during machine boot without
requiring a user login. The service refers to this repository by its absolute
path, so rerun the installer after moving the repository.

Use systemd to inspect or manage it:

```bash
sudo systemctl status matrix-opencode-bot.service
sudo journalctl -u matrix-opencode-bot.service -f
sudo systemctl restart matrix-opencode-bot.service
```

Stop the bot temporarily, for example before updating the repository, with:

```bash
./stop.sh
```

The service remains enabled and will start again at boot. Running `./install.sh`
after an update also starts it again.

Remove the background service with:

```bash
./uninstall.sh
```

Uninstalling preserves `.env`, `.venv`, the Matrix session and encryption
store, room mappings, and all bot data.

## Access policy

`MATRIX_ALLOWED_ROOMS` and `MATRIX_ALLOWED_SENDERS` are mandatory comma-separated
allowlists. An accepted command must satisfy both. Everyone on the sender list in
a room shares control of that room's OpenCode session, including permission
decisions and aborts.

`OPENCODE_DEFAULT_DIRECTORY` must be an existing directory beneath one of the
existing directories in `OPENCODE_ALLOWED_ROOTS`. Separate roots using the
platform path separator (`:` on Linux/macOS). `!new relative/path` resolves from
the default directory; absolute paths are also accepted when their fully resolved
target remains beneath an allowed root. This rejects `..` traversal and symlink
escapes.

Protect the OpenCode server with `OPENCODE_SERVER_PASSWORD`, bind it to loopback,
and do not expose port 4096 publicly. The username defaults to `opencode`.

## Commands

- `!help` — show the command list
- `!new [directory]` — create a new session, using the default directory when omitted
- Ordinary messages — prompt the current session, creating one in the default directory if needed
- `!pursue <goal>` — approve a bounded, checkable contract, then work until it is verified, blocked, or out of time
- `!status` — show the session, directory, activity, permissions, pursuit lease, resource usage, and change totals
- `!diagnose` — write `DIAGNOSIS.txt` in the mapped session directory
- `!bump` — report inactivity and ask before restarting the same stalled turn
- `!bump confirm` / `!bump cancel` — approve or cancel the proposed restart
- `!send <filename>` — find and send a file from the mapped session directory
- `!test_file` — immediately send a small attachment through the report delivery path
- `!yolo off` — disable automatic permission approval and revoke the active pursuit's unattended lease
- `!diff` — show unified diffs for the session
- `!stop` — abort the current operation
- `!reset` — discard only the room mapping

The first ordinary message in an unmapped room automatically creates a session in
`OPENCODE_DEFAULT_DIRECTORY`. Use `!new [directory]` when you want to choose a
different workspace. One prompt at a time is accepted per room. `!reset` neither
deletes the OpenCode session nor reverts files, and it is refused while the
session is busy. New sessions also leave earlier OpenCode sessions and their
changes intact.

`!send` searches recursively and case-insensitively within the room's mapped
session directory. A unique exact filename is uploaded immediately as native
Matrix file media; ambiguous or partial matches produce up to ten relative-path
commands that can be copied back into chat to select the intended file. In an
unmapped room, the search uses `OPENCODE_DEFAULT_DIRECTORY`. Path traversal and
symlinks escaping the workspace are rejected, and uploads to encrypted rooms use
Matrix encrypted-media metadata.

When a pursuit ends, the bot also attaches its final report as a Markdown file.
Use `!test_file` to verify Matrix attachment delivery without starting a pursuit.

`!diagnose` snapshots the mapped room state, transient progress, the last 200
OpenCode event records observed since the bot started (with adjacent token deltas
compacted), server health/status, and up to
100 recent messages plus diffs for the pursuit worker and quarantined recovery
sessions. The report is written atomically with owner-only permissions and the bot
replies with its absolute path. Credential-shaped fields and assignments are
redacted, but arbitrary prompts, model/tool output, paths, and source diffs can
still contain private data. Inspect `DIAGNOSIS.txt` before copying or sharing it.

Starting a session posts a compact reminder of the available commands. `!pursue`
first asks whether this pursuit should use unattended YOLO mode, accepting `y` or
`n`, and then asks for an extent or exact duration with a visible budget. Choosing
`y` is only part of the draft: unattended authority begins when the user approves
that exact contract. An older session-wide YOLO setting never authorizes a new or
revised pursuit contract.

| Input / extent | Worker/check cycles | Tool calls | Input tokens | Wall time |
| --- | ---: | ---: | ---: | ---: |
| `1` — Focused | 4 | 40 | 250,000 | 60 minutes |
| `2` — Thorough | 12 | 120 | 750,000 | 180 minutes |
| `3` — Extended | 32 | 320 | 2,000,000 | 480 minutes |

The duration may instead be a positive whole number of minutes or hours, such as
`90m` or `4h`, up to the same eight-hour maximum. Custom-duration cycle,
tool-call, and input-token quotas scale at the rates shown in the table. These are
finite product defaults, not claims that those values are optimal.
After the budget choice, the bot drafts a versioned contract containing the goal,
constraints, assumptions, acceptance criteria, a verification method for every
criterion, and the selected budget. Review the draft and reply `approve` to start
or `revise <changes>` to request a new version. Material changes always require a
fresh approval. For unattended YOLO, approval binds the lease to the approved
contract digest and starts one absolute deadline when its worker launches. A
material revision invalidates that lease; approving the new contract starts a new
one. `stop` or `!stop` ends the pursuit immediately.

An approved pursuit starts one fresh worker, preventing a large or poisoned
ordinary-chat transcript from contaminating the work. Worker output is relayed as
**unverified** until the controller runs the contract's checks. Command checks run
against an isolated snapshot. State checks use read-only postcondition queries.
Criteria that cannot be checked objectively are human criteria and never pass
autonomously. Each controller-created result is tied to the contract version,
attempt, and observed workspace or state revision; later mutations make affected
results stale and force a fresh check. Failed, unknown, duplicate, stale, or
model-authored evidence cannot complete a criterion.

Failed checks are returned to the worker for a bounded repair cycle. There is no
separate LLM verifier and no free-form reflection loop. The pursuit reaches
`verified_complete` only when every objective criterion passes against the latest
result, and it may finish before its maximum duration.

Without unattended YOLO, pursuits remain interactive. Unresolved human criteria
pause at `awaiting_signoff`, missing facts or authorization pause at
`needs_input`, and an exhausted cycle, tool-call, input-token, or wall-time tranche
pauses at `budget_checkpoint`. The user can reply `continue`, revise and approve a
new contract, sign off on the exact provisional result, or stop as appropriate.

With an unattended YOLO lease, cycle, tool-call, and input-token quotas are
internal rotation boundaries. The controller starts a fresh worker and renews the
tranche automatically, preserving the fixed absolute deadline and cumulative
usage; no Matrix reply is needed. It retries transient permission failures and
pauses only for a genuine external blocker: missing credentials or authority, a
material fact only the user can supply, an unavailable required verifier, or an
explicit non-retryable permission refusal. If a blocker leads to a material
contract revision, continuation requires approval of the new contract and a new
lease.

At the absolute deadline, worker actions stop and the controller performs one
bounded, read-only final check. It then archives a terminal `verified_complete`
or `deadline_reached` report instead of waiting at `budget_checkpoint`. If only
human-judgment criteria remain, an unattended pursuit finishes with a clearly
marked provisional result; it never invents human sign-off. Every final report
contains the usable result, assumptions, per-criterion checks, remaining
uncertainty, cumulative resource usage, and artifact references.

Pursuits, approved unattended leases, absolute deadlines, and cumulative budget
ledgers survive bot restarts. Downtime counts against the deadline: an authorized
pursuit resumes while time remains, while an expired pursuit proceeds directly to
its bounded final check and terminal report. Approval and input states remain
waiting after restart, and unattended human-signoff states become provisional
completion rather than false approval. `!status` shows whether unattended mode is
active, the fixed deadline and remaining time, automatic renewal count, and
cumulative resource usage.

Pursuit workers use direct, observable tools; delegated `task` calls are disabled.
`!stop` aborts an active worker or check and records a stopped outcome. When
upgrading a persisted protocol-v2 pursuit, the bot retains its goal and draft
criteria, returns to contract approval, marks earlier prose evidence
`legacy_untrusted`, and requires fresh controller checks. Old OpenCode sessions
remain available for audit.

Verification adapts conservatively to the task. Tests and builds can objectively
check specified software behavior, and read-only API queries can check specified
state. Retrieving a source proves access to that source, not the truth or quality
of a synthesis; research and qualitative criteria therefore remain provisional
unless a genuine objective checker exists or the user signs off. Checker limits
and unresolved uncertainty remain visible. OpenCode's normal permissions govern
worker actions, while controller checkers are isolated and non-mutating.

Assistant text and safe progress are relayed through Matrix `m.replace` edits at
most once per `MATRIX_EDIT_INTERVAL_SECONDS` (five seconds by default, to stay
below typical homeserver rate limits). The interval is measured from every successful
outgoing room message, so a live edit does not immediately follow a command reply,
permission prompt, or initial progress message. While busy, the progress message shows elapsed time, the
current plan item, plan completion, recent phases, tool names and status, retries,
subagents, and file-update counts. Raw hidden reasoning, tool arguments, and
commands are not posted; user-visible plan descriptions may mention files.
Progress and automatic-renewal notices are informational and never require a
reply. Actual approval, input, or permission prompts are sent as distinct messages
with an explicit reply instruction. Permission errors are sent immediately.
Replies longer than 20,000 characters are split at completion.

Both the current OpenCode `permission.asked` event schema and the legacy
`permission.updated` schema are normalized. This is especially important for
`external_directory`: an operation targeting a path outside the session worktree
is paused and surfaced in Matrix for `y`, `n`, or `YOLO`, rather than appearing as
an indefinitely running tool. These replies are interpreted as permission answers
only while the room has a pending request. During `!pursue` setup, `y` and `n`
instead answer the explicit YOLO question; outside those two states they remain
ordinary messages.
`YOLO` on a pending permission request approves all currently pending requests and
automatically answers future requests for the mapped session, including its
pursuit worker. That session setting survives bot restarts, but it does not create
or extend an unattended pursuit lease; only approval of a draft that explicitly
selected unattended YOLO can do that. `!new` and `!reset` clear the session
setting. `!yolo off` disables it and revokes an active pursuit lease, after which
continuation follows the interactive rules. Automatic approvals never override a
permission OpenCode explicitly denies.

An in-process watchdog checks active bot-submitted prompts every 30 seconds.
Ordinary turns use `OPENCODE_STUCK_TIMEOUT_SECONDS` (900 seconds by default).
Pursuits use the shorter `OPENCODE_PURSUE_STUCK_TIMEOUT_SECONDS` (600 seconds),
and a pursuit tool continuously reported as running has its own hard ceiling,
`OPENCODE_PURSUE_TOOL_TIMEOUT_SECONDS` (300 seconds). A timeout aborts the turn,
quarantines the poisoned pursuit worker, and resumes the same bounded attempt in
a fresh worker session with the interrupted action recorded in the action trace.
Each repeated recovery requires another full timeout, and `!stop` cancels automatic
continuation. If OpenCode initially rejects the abort, the watchdog retries on its
next 30-second check rather than waiting through another timeout. Pending permission
requests are never interrupted. The watchdog also
reconciles missed idle events and OpenCode's occasional stale `busy` status by
requiring a completed timestamp on the latest assistant message before treating a
busy response as finished.

When a watchdog recovery deadline is reached, the bot sends a new Matrix room message—not
only a replacement edit—so clients can generate a notification for the recovery.
External-directory and other permission requests likewise arrive as new messages
with explicit `y` / `n` / `YOLO` instructions.

`!bump` exposes the same recovery mechanism under explicit user control. It
reports time since the last observable activity and compares it with the watchdog
threshold, but never interrupts immediately. `!bump confirm` aborts and resumes
only if the same turn has remained unchanged; any intervening activity expires the
confirmation. During a pursuit, a confirmed bump also quarantines the active
session before resuming. Turns waiting for `y` or `n` are not considered
stalled.

Set `MATRIX_SHOW_REASONING=true` to also stream the provider-exposed reasoning
text that OpenCode displays in its thinking view. This text is shown only while
the response is in progress and is removed when the final answer replaces the
live message. It can contain sensitive workspace or prompt context, so enable it
only for rooms whose members are allowed to see that material.

## Persistence and recovery

Room mappings and in-flight Matrix event IDs are stored atomically in
`data/room_sessions.json` with owner-only permissions. On restart, the bot checks
that directories are still allowed and that sessions still exist. If a response
completed while disconnected, it reads recent OpenCode messages and finishes the
pending Matrix edit. Pending watchdog recovery state is also restored; active
restored prompts receive a fresh full silence window before intervention.

## Testing and smoke check

The test suite does not contact Matrix or OpenCode:

```bash
pip install -e '.[test]'
pytest
```

Before starting the bot, check the configured server manually:

```bash
curl -u "${OPENCODE_SERVER_USERNAME:-opencode}:${OPENCODE_SERVER_PASSWORD}" \
  "${OPENCODE_URL:-http://127.0.0.1:4096}/global/health"
```

Then invite the bot to an allowed encrypted room, verify its device, send a small
read-only prompt, and confirm `!status`, `!diff`, and permission handling.

## Security notes

- Use dedicated Matrix and OpenCode credentials and keep `.env` and `data/` out
  of version control.
- An allowed sender can ask OpenCode to read, edit, or execute within its own
  configured permissions. Keep OpenCode's permission policy restrictive.
- Matrix E2EE protects room events. HTTPS or loopback transport separately
  protects the connection to OpenCode.
- Interactive emoji verification, cross-signing, and key backup are not
  implemented by this bot.
