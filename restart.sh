#!/usr/bin/env bash

set -Eeuo pipefail

service_name="matrix-opencode-bot.service"

die() {
    echo "Error: $*" >&2
    exit 1
}

[[ "$(uname -s)" == "Linux" ]] || die "this restart script only supports Linux."
command -v systemctl >/dev/null 2>&1 || die "systemctl is required."
[[ -d /run/systemd/system ]] || die "systemd is not running as the system service manager."
systemctl cat "$service_name" >/dev/null 2>&1 \
    || die "$service_name is not installed. Run: ./install.sh"

if (( EUID == 0 )); then
    as_root=()
else
    command -v sudo >/dev/null 2>&1 || die "sudo is required to restart the system service."
    as_root=(sudo)
fi

echo "Restarting $service_name..."
"${as_root[@]}" systemctl restart "$service_name"
if ! systemctl is-active --quiet "$service_name"; then
    "${as_root[@]}" systemctl --no-pager --full status "$service_name" >&2 || true
    die "$service_name did not restart."
fi

echo "Matrix OpenCode bot restarted."
echo "Status: sudo systemctl status $service_name"
echo "Logs:   sudo journalctl -u $service_name -f"
