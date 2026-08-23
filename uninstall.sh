#!/usr/bin/env bash

set -Eeuo pipefail

service_name="matrix-opencode-bot.service"
unit_path="/etc/systemd/system/$service_name"

die() {
    echo "Error: $*" >&2
    exit 1
}

[[ "$(uname -s)" == "Linux" ]] || die "this uninstaller only supports Linux."
command -v systemctl >/dev/null 2>&1 || die "systemctl is required."

if (( EUID == 0 )); then
    as_root=()
else
    command -v sudo >/dev/null 2>&1 || die "sudo is required to remove a system service."
    as_root=(sudo)
fi

if [[ -e "$unit_path" ]] || systemctl cat "$service_name" >/dev/null 2>&1; then
    echo "Stopping and disabling $service_name..."
    "${as_root[@]}" systemctl disable --now "$service_name" || true
    "${as_root[@]}" rm -f "$unit_path"
    "${as_root[@]}" systemctl daemon-reload
    "${as_root[@]}" systemctl reset-failed "$service_name" 2>/dev/null || true
    echo "Removed $service_name."
else
    echo "$service_name is not installed; nothing to remove."
fi

echo "Configuration, virtual environment, Matrix session, room mappings, and bot data were preserved."
