#!/usr/bin/env bash

set -Eeuo pipefail

service_name="matrix-opencode-bot.service"

die() {
    echo "Error: $*" >&2
    exit 1
}

[[ "$(uname -s)" == "Linux" ]] || die "this stop script only supports Linux."
command -v systemctl >/dev/null 2>&1 || die "systemctl is required."
[[ -d /run/systemd/system ]] || die "systemd is not running as the system service manager."

if (( EUID == 0 )); then
    as_root=()
else
    command -v sudo >/dev/null 2>&1 || die "sudo is required to stop the system service."
    as_root=(sudo)
fi

if ! systemctl cat "$service_name" >/dev/null 2>&1; then
    die "$service_name is not installed."
fi

if ! systemctl is-active --quiet "$service_name"; then
    echo "$service_name is already stopped."
    exit 0
fi

echo "Stopping $service_name..."
"${as_root[@]}" systemctl stop "$service_name"

if systemctl is-active --quiet "$service_name"; then
    die "$service_name did not stop. Check its status with: sudo systemctl status $service_name"
fi

echo "Matrix OpenCode bot stopped. It remains enabled and will start again at boot."
echo "Start it again with: sudo systemctl start $service_name"
