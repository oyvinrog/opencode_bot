#!/usr/bin/env bash

set -Eeuo pipefail

service_name="matrix-opencode-bot.service"
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

die() {
    echo "Error: $*" >&2
    exit 1
}

if [[ -n "${INVOCATION_ID:-}" && "${SYSTEMD_EXEC_PID:-}" == "$$" ]]; then
    exec "$project_dir/service.sh"
fi

[[ "$(uname -s)" == "Linux" ]] || die "this launcher only supports Linux systemd services."
command -v systemctl >/dev/null 2>&1 || die "systemctl is required."
[[ -d /run/systemd/system ]] || die "systemd is not running as the system service manager."
systemctl cat "$service_name" >/dev/null 2>&1 \
    || die "$service_name is not installed. Run: ./install.sh"

if systemctl is-active --quiet "$service_name"; then
    echo "$service_name is already running."
    exit 0
fi

if (( EUID == 0 )); then
    as_root=()
else
    command -v sudo >/dev/null 2>&1 || die "sudo is required to start the system service."
    as_root=(sudo)
fi

echo "Starting $service_name..."
if ! "${as_root[@]}" systemctl start "$service_name"; then
    "${as_root[@]}" systemctl --no-pager --full status "$service_name" >&2 || true
    die "could not start $service_name. Run ./install.sh to repair its unit."
fi
if ! systemctl is-active --quiet "$service_name"; then
    "${as_root[@]}" systemctl --no-pager --full status "$service_name" >&2 || true
    die "$service_name did not start."
fi

echo "Matrix OpenCode bot started."
echo "Status: sudo systemctl status $service_name"
echo "Logs:   sudo journalctl -u $service_name -f"
