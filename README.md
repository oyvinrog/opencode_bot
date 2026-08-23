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
- `!pursue <goal>` — approve a bounded, checkable contract, then work until it is verified or pauses
- `!status` — show the session, directory, activity, permissions, and change totals
- `!diagnose` — write `DIAGNOSIS.txt` in the mapped session directory
- `!bump` — report inactivity and ask before restarting the same stalled turn
- `!bump confirm` / `!bump cancel` — approve or cancel the proposed restart
- `!send <filename>` — find and send a file from the mapped session directory
- `!yolo off` — disable session-scoped automatic permission approval
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

`!diagnose` snapshots the mapped room state, transient progress, the last 200
OpenCode event records observed since the bot started (with adjacent token deltas
compacted), server health/status, and up to
100 recent messages plus diffs for the pursuit worker and quarantined recovery
sessions. The report is written atomically with owner-only permissions and the bot
replies with its absolute path. Credential-shaped fields and assignments are
redacted, but arbitrary prompts, model/tool output, paths, and source diffs can
still contain private data. Inspect `DIAGNOSIS.txt` before copying or sharing it.

Starting a session posts a compact reminder of the available commands. `!pursue`
first asks whether to enable session-scoped YOLO mode, accepting `y` or `n`. A `y`
automatically approves future permission requests for the mapped session and its
pursuit worker; `n` disables YOLO even if it was previously enabled. It then asks
for an extent with a visible initial budget:

| Extent | Worker/check cycles | Tool calls | Input tokens | Wall time |
| --- | ---: | ---: | ---: | ---: |
| `1` — Focused | 4 | 40 | 250,000 | 60 minutes |
| `2` — Thorough | 12 | 120 | 750,000 | 180 minutes |
| `3` — Extended | 32 | 320 | 2,000,000 | 480 minutes |

These are finite product defaults, not claims that those values are optimal.
After the extent choice, the bot drafts a versioned contract containing the goal,
constraints, assumptions, acceptance criteria, a verification method for every
criterion, and the selected budget. Review the draft and reply `approve` to start
or `revise <changes>` to request a new version. Material changes always require a
fresh approval. `stop` or `!stop` ends the pursuit.

An approved pursuit starts one fresh worker, preventing a large or poisoned
ordinary-chat transcript from contaminating the work. Worker output is relayed as
**unverified** until the controller runs the contract's checks. Command checks run
against an isolated snapshot. State checks use read-only postcondition queries.
Criteria that cannot be checked objectively are human criteria and never pass
autonomously. Each controller-created result is tied to the contract version,
attempt, and observed workspace or state revision; later mutations make affected
results stale and force a fresh check. Failed, unknown, duplicate, stale, or
model-authored evidence cannot complete a criterion.

Failed checks are returned to the same worker for a bounded repair cycle. There
is no separate LLM verifier and no free-form reflection loop. The pursuit reaches
`verified_complete` only when every objective criterion passes against the latest
result. If human criteria remain, it pauses at `awaiting_signoff` and labels the
result provisional; `approve` signs off on that exact contract and result. A
missing fact or authorization pauses at `needs_input` for an ordinary reply.

Reaching any cycle, tool-call, input-token, or wall-time limit pauses at
`budget_checkpoint`; it never converts incomplete work into success. Reply
`continue` to grant another visible tranche, `revise <changes>` to create and
review a new contract version, or `stop` to finish without verification. A
revised contract still requires `approve`. The final report contains the usable
result, assumptions, per-criterion checks, remaining uncertainty, resource usage,
and artifact references.

Pursuits and their budget ledgers survive bot restarts. Pursuit workers use
direct, observable tools; delegated `task` calls are disabled. `!stop` aborts an
active worker or check and records a stopped outcome. When upgrading a persisted
protocol-v2 pursuit, the bot retains its goal and draft criteria, returns to
contract approval, marks earlier prose evidence `legacy_untrusted`, and requires
fresh controller checks. Old OpenCode sessions remain available for audit.

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
Permission requests and errors are sent immediately. Replies longer than 20,000
characters are split at completion.

Both the current OpenCode `permission.asked` event schema and the legacy
`permission.updated` schema are normalized. This is especially important for
`external_directory`: an operation targeting a path outside the session worktree
is paused and surfaced in Matrix for `y`, `n`, or `YOLO`, rather than appearing as
an indefinitely running tool. These replies are interpreted as permission answers
only while the room has a pending request. During `!pursue` setup, `y` and `n`
instead answer the explicit YOLO question; outside those two states they remain
ordinary messages.
`YOLO` approves all currently pending requests and automatically answers future
requests for the mapped session, including its pursuit worker.
It survives bot restarts, but `!new` and `!reset` clear it; `!yolo off` disables it.
Automatic approvals do not override permissions OpenCode explicitly denies.

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
requests are never interrupted. `!status` shows
the active deadline as a countdown. The watchdog also
reconciles missed idle events and OpenCode's occasional stale `busy` status by
requiring a completed timestamp on the latest assistant message before treating a
busy response as finished.

When a watchdog deadline is reached, the bot sends a new Matrix room message—not
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
