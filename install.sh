#!/usr/bin/env bash

set -Eeuo pipefail

service_name="matrix-opencode-bot.service"
unit_path="/etc/systemd/system/$service_name"
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
install_user="${SUDO_USER:-$(id -un)}"
install_group="$(id -gn "$install_user")"

die() {
    echo "Error: $*" >&2
    exit 1
}

if (( EUID == 0 )); then
    as_root=()
else
    command -v sudo >/dev/null 2>&1 || die "sudo is required to install a system service."
    as_root=(sudo)
fi

run_as_install_user() {
    if (( EUID == 0 )) && [[ "$install_user" != "root" ]]; then
        sudo -u "$install_user" -- "$@"
    else
        "$@"
    fi
}

systemd_quote() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//%/%%}"
    printf '"%s"' "$value"
}

[[ "$(uname -s)" == "Linux" ]] || die "this installer only supports Linux."
command -v systemctl >/dev/null 2>&1 || die "systemctl is required."
[[ -d /run/systemd/system ]] || die "systemd is not running as the system service manager."
command -v python3 >/dev/null 2>&1 || die "Python 3.11 or newer is required."
python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' \
    || die "Python 3.11 or newer is required (found $(python3 --version 2>&1))."
[[ -f "$project_dir/.env" ]] \
    || die "missing $project_dir/.env; copy .env.example and configure it first."
[[ -x "$project_dir/service.sh" ]] || die "$project_dir/service.sh is not executable."

if [[ ! -x "$project_dir/.venv/bin/python" ]]; then
    echo "Creating Python virtual environment..."
    run_as_install_user python3 -m venv "$project_dir/.venv" \
        || die "could not create $project_dir/.venv. Install the Python venv package and retry."
fi

run_as_install_user "$project_dir/.venv/bin/python" \
    -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' \
    || die "$project_dir/.venv must use Python 3.11 or newer."

echo "Installing Matrix OpenCode bot dependencies..."
run_as_install_user "$project_dir/.venv/bin/python" -m pip install -e "$project_dir" \
    || die "dependency installation failed."

echo "Validating bot configuration..."
run_as_install_user bash -c '
    set -Eeuo pipefail
    set -a
    # The bot intentionally treats .env as a shell environment file.
    source "$1"
    set +a
    "$2" -c "from matrix_opencode_bot.config import Settings; Settings.from_env()"
' bash "$project_dir/.env" "$project_dir/.venv/bin/python" \
    || die "$project_dir/.env is not a valid bot configuration."

chmod 600 "$project_dir/.env" || die "could not restrict permissions on $project_dir/.env."

unit_file="$(mktemp)"
trap 'rm -f "$unit_file"' EXIT
quoted_project_dir="$(systemd_quote "$project_dir")"
quoted_service_script="$(systemd_quote "$project_dir/service.sh")"

{
    echo "# Managed by $project_dir/install.sh"
    echo "[Unit]"
    echo "Description=Matrix OpenCode bot"
    echo "Wants=network-online.target"
    echo "After=network-online.target"
    echo
    echo "[Service]"
    echo "Type=simple"
    echo "User=$install_user"
    echo "Group=$install_group"
    echo "WorkingDirectory=$quoted_project_dir"
    echo "ExecStart=$quoted_service_script"
    echo "Restart=on-failure"
    echo "RestartSec=10s"
    echo "UMask=0077"
    echo "PrivateTmp=true"
    echo "NoNewPrivileges=true"
    echo
    echo "[Install]"
    echo "WantedBy=multi-user.target"
} >"$unit_file"

echo "Installing systemd service..."
"${as_root[@]}" install -m 0644 "$unit_file" "$unit_path"
"${as_root[@]}" systemctl daemon-reload
"${as_root[@]}" systemctl enable "$service_name"
"${as_root[@]}" systemctl restart "$service_name"

sleep 2
if ! "${as_root[@]}" systemctl is-active --quiet "$service_name"; then
    echo "The service did not become active. Current status:" >&2
    "${as_root[@]}" systemctl --no-pager --full status "$service_name" >&2 || true
    echo >&2
    echo "Recent logs:" >&2
    "${as_root[@]}" journalctl --no-pager -u "$service_name" -n 30 >&2 || true
    die "service startup failed."
fi

echo "Matrix OpenCode bot is installed, running, and enabled at boot."
echo "Status: sudo systemctl status $service_name"
echo "Logs:   sudo journalctl -u $service_name -f"
