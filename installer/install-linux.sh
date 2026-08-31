#!/usr/bin/env bash
set -euo pipefail

PREFIX="/usr/local/bin"
STATE="/var/lib/neonet"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
DEFAULT_BINARY="$PROJECT_ROOT/target/release/neonet"
BINARY="${1:-$DEFAULT_BINARY}"
BOOTSTRAP="${2:-}"
ALLOW_FILE="${3:-}"

# Resolve relative paths before privilege escalation so sudo does not change their meaning.
if [[ "$BINARY" != /* ]]; then BINARY="$(cd -- "$(dirname -- "$BINARY")" && pwd)/$(basename -- "$BINARY")"; fi
if [[ -n "$BOOTSTRAP" && "$BOOTSTRAP" != /* ]]; then BOOTSTRAP="$(cd -- "$(dirname -- "$BOOTSTRAP")" && pwd)/$(basename -- "$BOOTSTRAP")"; fi
if [[ -n "$ALLOW_FILE" && "$ALLOW_FILE" != /* ]]; then ALLOW_FILE="$(cd -- "$(dirname -- "$ALLOW_FILE")" && pwd)/$(basename -- "$ALLOW_FILE")"; fi

# Developer-friendly path: run this script as the normal user. If the release
# binary is missing, build it without sudo, then re-enter here as root.
if [[ -n "$BINARY" && ! -f "$BINARY" ]]; then
    if [[ -f "$PROJECT_ROOT/Cargo.toml" && -x "$(command -v cargo || true)" ]]; then
        if [[ $EUID -eq 0 ]]; then
            echo "NeoNet binary not found at: $BINARY" >&2
            echo "Run this installer once without sudo; it will build the release binary as your user and then request sudo." >&2
            exit 1
        fi
        echo "NeoNet release binary not found. Building it with Cargo..."
        (cd "$PROJECT_ROOT" && cargo build --release)
    else
        echo "NeoNet binary not found: $BINARY" >&2
        echo "Build it first with: cargo build --release" >&2
        echo "Then run: sudo $0 $DEFAULT_BINARY [bootstrap.json [allow.json]]" >&2
        exit 1
    fi
fi

if [[ $EUID -ne 0 ]]; then
    if [[ -n "$ALLOW_FILE" ]]; then
        exec sudo "$0" "$BINARY" "$BOOTSTRAP" "$ALLOW_FILE"
    elif [[ -n "$BOOTSTRAP" ]]; then
        exec sudo "$0" "$BINARY" "$BOOTSTRAP"
    else
        exec sudo "$0" "$BINARY"
    fi
fi

if [[ ! -x "$BINARY" ]]; then
    echo "NeoNet binary is not executable: $BINARY" >&2
    exit 1
fi
if [[ -n "$BOOTSTRAP" && ! -f "$BOOTSTRAP" ]]; then
    echo "Bootstrap file not found: $BOOTSTRAP" >&2
    exit 1
fi
if [[ -n "$ALLOW_FILE" && ! -f "$ALLOW_FILE" ]]; then
    echo "Allow-list file not found: $ALLOW_FILE" >&2
    exit 1
fi

install -m 0755 "$BINARY" "$PREFIX/neonet"
install -d -m 0700 "$STATE"
if [[ -n "$BOOTSTRAP" ]]; then install -m 0600 "$BOOTSTRAP" "$STATE/bootstrap.json"; fi
if [[ -n "$ALLOW_FILE" ]]; then install -m 0600 "$ALLOW_FILE" "$STATE/allow.json"; fi

EXEC="$PREFIX/neonet core --listen 0.0.0.0:4242"
if [[ -n "$ALLOW_FILE" ]]; then EXEC="$EXEC --allow-file $STATE/allow.json"; fi

cat >/etc/systemd/system/neonet.service <<UNIT
[Unit]
Description=NeoNet core node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Environment=NEONET_HOME=$STATE
ExecStart=$EXEC
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now neonet.service

echo "NeoNet installed successfully."
echo "Binary: $PREFIX/neonet"
echo "Service: neonet.service"
echo "State: $STATE"
if [[ -n "$BOOTSTRAP" ]]; then echo "Bootstrap trust: $STATE/bootstrap.json"; fi
if [[ -n "$ALLOW_FILE" ]]; then echo "Allow-list: $STATE/allow.json"; else echo "WARNING: no allow-list was installed — the core accepts any authenticated peer. Run the installer with an allow.json (JSON array of 64-hex public keys) or see docs/CLI.md#access-control."; fi
