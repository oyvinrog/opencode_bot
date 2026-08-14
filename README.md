# Matrix–OpenCode bot

An end-to-end encrypted Matrix bot that controls an OpenCode coding session. Each
authorized Matrix room maps to one OpenCode session, ordinary messages become
prompts, and responses are streamed back by editing a Matrix message.

The bot connects to an existing `opencode serve` process through its HTTP API. It
does not start or supervise OpenCode.

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
pip install -e '.[test]'
cp .env.example .env
```

Start OpenCode on loopback with Basic Auth. Use the same password in `.env`:

```bash
OPENCODE_SERVER_PASSWORD='a-strong-separate-password' \
  opencode serve --hostname 127.0.0.1 --port 4096
```

Configure `.env`, then run the bot:

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

Verify the new **Matrix OpenCode bot** device in Element or another full Matrix
client. The bot refuses to send to unverified recipient devices by default.
`MATRIX_IGNORE_UNVERIFIED_DEVICES=true` permits unattended use but weakens device
identity assurance; message contents remain encrypted.

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
- `!status` — show the session, directory, activity, permissions, and change totals
- `!allow` — allow the oldest pending permission once
- `!deny` — reject the oldest pending permission
- `!diff` — show unified diffs for the session
- `!stop` — abort the current operation
- `!reset` — discard only the room mapping

The first ordinary message in an unmapped room automatically creates a session in
`OPENCODE_DEFAULT_DIRECTORY`. Use `!new [directory]` when you want to choose a
different workspace. One prompt at a time is accepted per room. `!reset` neither
deletes the OpenCode session nor reverts files, and it is refused while the
session is busy. New sessions also leave earlier OpenCode sessions and their
changes intact.

Assistant text is relayed through Matrix `m.replace` edits at most once per
second. Reasoning and tool internals are not posted. Permission requests and
errors are sent immediately. Replies longer than 20,000 characters are split at
completion.

## Persistence and recovery

Room mappings and in-flight Matrix event IDs are stored atomically in
`data/room_sessions.json` with owner-only permissions. On restart, the bot checks
that directories are still allowed and that sessions still exist. If a response
completed while disconnected, it reads recent OpenCode messages and finishes the
pending Matrix edit.

## Testing and smoke check

The test suite does not contact Matrix or OpenCode:

```bash
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
