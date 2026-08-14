# Matrix ELIZA bot

A Python ELIZA-style chat bot using `matrix-nio`. It reads and replies in
end-to-end encrypted Matrix rooms and sends an end-to-end encrypted image when
someone types `!send_pic`.

## Set up

Requirements: Python 3.11+, a Matrix account for the bot, and a Matrix room with
encryption enabled. On some Linux distributions the `matrix-nio[e2e]` install
also needs the system packages `libolm-dev`, `python3-dev`, and a C compiler.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
cp .env.example .env
```

Edit `.env`, then export it and start the bot:

```bash
set -a
. ./.env
set +a
matrix-eliza
```

On the first run it logs in with `MATRIX_PASSWORD`, creates a Matrix device, and
saves its access token plus encryption keys under `ELIZA_DATA_DIR`. Remove the
password from `.env` after that first successful login. Keep the entire data
directory private and persistent; losing it changes the device identity and
loses old room keys.

In Element (or another full Matrix client), verify the newly created **ELIZA
bot** device. Invite the bot to an already encrypted room, or list that room in
`MATRIX_ALLOWED_ROOMS` and enable `MATRIX_AUTO_JOIN=true`. Matrix room encryption
cannot be disabled once enabled, but this bot still checks it before responding.

The default `MATRIX_IGNORE_UNVERIFIED_DEVICES=false` is the safer policy: the bot
will refuse to send when another room member has an unverified device. Verify
those devices from the bot account. For a fully unattended bot you can set the
option to `true`; messages remain encrypted, but the bot no longer authenticates
recipient device identities, so an unexpected device could receive them.

Set `ELIZA_PICTURE` to a PNG, JPEG, GIF, or other Pillow-supported image. If it
is omitted, the bot generates a small ELIZA illustration. The uploaded image
bytes are encrypted before upload and the room event contains the decryption
key, so the homeserver does not receive the plaintext image.

## Commands

- `!send_pic` — upload and send the configured picture with encrypted attachment metadata
- `!help` — show a short help message
- Anything else — receive an ELIZA-style response

Run the local tests with `pytest`. They do not contact a Matrix server.

## Security notes

- Prefer a dedicated Matrix account and an explicit `MATRIX_ALLOWED_ROOMS` list.
- Do not commit `.env`, `data/session.json`, or `data/crypto_store`.
- Use HTTPS for `MATRIX_HOMESERVER`; transport TLS and Matrix E2EE protect
  different parts of the connection.
- This implements encrypted messaging and encrypted attachments. It does not
  implement interactive emoji verification or cross-signing/key backup.
