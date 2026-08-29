#!/usr/bin/env bash

set -Eeuo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$project_dir"

if [[ ! -f .env ]]; then
    echo "Missing $project_dir/.env (copy .env.example and configure it first)." >&2
    exit 1
fi

set -a
# shellcheck disable=SC1091
source ./.env
set +a

opencode_url="${OPENCODE_URL:-http://127.0.0.1:4096}"
server_hostname="${OPENCODE_SERVER_HOSTNAME:-127.0.0.1}"
server_port="${OPENCODE_SERVER_PORT:-4096}"
server_username="${OPENCODE_SERVER_USERNAME:-opencode}"
server_password="${OPENCODE_SERVER_PASSWORD:-}"

if [[ -z "$server_password" ]]; then
    echo "Warning: OPENCODE_SERVER_PASSWORD is not set in .env; OpenCode is unsecured." >&2
fi

if [[ -n "${OPENCODE_BIN:-}" && -x "$OPENCODE_BIN" ]]; then
    opencode_command="$OPENCODE_BIN"
elif command -v opencode >/dev/null 2>&1; then
    opencode_command="$(command -v opencode)"
elif [[ -n "${HOME:-}" && -x "$HOME/.opencode/bin/opencode" ]]; then
    opencode_command="$HOME/.opencode/bin/opencode"
else
    echo "Cannot find opencode. Add it to PATH or set OPENCODE_BIN in .env." >&2
    exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required to wait for the OpenCode server." >&2
    exit 1
fi

if [[ ! -x .venv/bin/matrix-opencode ]]; then
    echo "matrix-opencode is not installed. Run: ./install.sh" >&2
    exit 1
fi

server_pid=""
bot_pid=""

cleanup() {
    trap - EXIT INT TERM
    [[ -n "$bot_pid" ]] && kill "$bot_pid" 2>/dev/null || true
    [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null || true
    [[ -n "$bot_pid" ]] && wait "$bot_pid" 2>/dev/null || true
    [[ -n "$server_pid" ]] && wait "$server_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

health_url="${opencode_url%/}/global/health"
curl_args=(-sS --max-time 1)
if [[ -n "$server_password" ]]; then
    curl_args+=(--user "$server_username:$server_password")
fi

health_status="$(curl "${curl_args[@]}" -o /dev/null -w '%{http_code}' "$health_url" 2>/dev/null || true)"
if [[ "$health_status" == 2* ]]; then
    echo "Using the OpenCode server already running at $opencode_url."
elif [[ "$health_status" == "401" || "$health_status" == "403" ]]; then
    echo "An OpenCode server is already running at $opencode_url, but its credentials do not match .env." >&2
    exit 1
else
    echo "Starting OpenCode at $opencode_url ..."
    "$opencode_command" serve --hostname "$server_hostname" --port "$server_port" &
    server_pid=$!

    for ((attempt = 1; attempt <= 60; attempt++)); do
        if ! kill -0 "$server_pid" 2>/dev/null; then
            wait "$server_pid" || true
            echo "OpenCode exited before becoming ready." >&2
            exit 1
        fi

        if curl "${curl_args[@]}" -f "$health_url" >/dev/null 2>&1; then
            break
        fi
        if ((attempt == 60)); then
            echo "Timed out waiting for OpenCode at $health_url." >&2
            exit 1
        fi
        sleep 0.25
    done
fi

echo "OpenCode is ready; starting the Matrix bot."
.venv/bin/matrix-opencode &
bot_pid=$!

set +e
if [[ -n "$server_pid" ]]; then
    wait -n "$server_pid" "$bot_pid"
else
    wait "$bot_pid"
fi
status=$?
set -e

if [[ -z "$server_pid" ]]; then
    echo "Matrix bot stopped; the pre-existing OpenCode server was left running." >&2
elif kill -0 "$server_pid" 2>/dev/null && ! kill -0 "$bot_pid" 2>/dev/null; then
    echo "Matrix bot stopped." >&2
elif kill -0 "$bot_pid" 2>/dev/null && ! kill -0 "$server_pid" 2>/dev/null; then
    echo "OpenCode server stopped." >&2
fi

exit "$status"
