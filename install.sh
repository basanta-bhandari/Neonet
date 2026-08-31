#!/usr/bin/env bash
# install.sh — set up NeoNet on this machine and put `neonet` on your PATH.
#
# Installing is the whole setup story: it checks for the Rust toolchain
# (cargo/rustc), creates the state home, builds the binary, and installs a
# `neonet` command. That's the only entry you need — running `neonet` with no
# arguments opens the shell, and every tool (whoami, devices, connect, nsh,
# send, browse, fork, store, channel, host/join, pairing, rendezvous,
# core/edge daemons, update) is a command at that prompt. Running
# `neonet <command>` skips the shell and does that one thing, for scripting.
#
# Nothing here touches your git checkout or your code. Updates are manual:
# run `neonet update` at the prompt (fast-forward only, never a force-reset).

set -uo pipefail

# --- helpers (same voice as the rest of the toolchain) ----------------------
c_green=$'\033[1;32m'; c_cyan=$'\033[1;36m'; c_yellow=$'\033[1;33m'; c_red=$'\033[1;31m'; c_bold=$'\033[1m'; c_norm=$'\033[0m'

info() { printf '%s[* ]%s %s\n' "$c_cyan" "$c_norm" "$*"; }
ok()   { printf '%s[ok]%s %s\n'   "$c_green" "$c_norm" "$*"; }
warn() { printf '%s[! ]%s %s\n'   "$c_yellow" "$c_norm" "$*"; }
fail() { printf '%s[x ]%s %s\n'   "$c_red" "$c_norm" "$*" >&2; exit 1; }

ask() {
    local question="$1" default="${2:-}"
    if [ -n "$default" ]; then
        printf '%s[? ]%s %s %s[%s]%s: ' "$c_yellow" "$c_norm" "$question" "$c_bold" "$default" "$c_norm" >&2
    else
        printf '%s[? ]%s %s: ' "$c_yellow" "$c_norm" "$question" >&2
    fi
    local answer
    IFS= read -r answer || answer="$default"
    printf '%s' "${answer:-$default}"
}

# --- locate the repo ---------------------------------------------------------
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- 1. Rust toolchain -------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
    fail "the Rust toolchain (cargo/rustc) is required but wasn't found.

Install it with rustup (recommended):
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
and restart your shell, then re-run ./install.sh.
Or, on Debian/Ubuntu:  sudo apt install cargo
Re-run ./install.sh once cargo is on your PATH."
fi
info "Rust toolchain found: $(command -v cargo) $(cargo --version | awk '{print $2}')"

# --- 2. state home -----------------------------------------------------------
# Default state home follows NEONET_HOME, else ~/.neonet (the binary default).
if [ -n "${NEONET_HOME:-}" ]; then
    state_home="$NEONET_HOME"
    state_source="\$NEONET_HOME"
else
    state_home="$HOME/.neonet"
    state_source="\$HOME/.neonet"
fi
mkdir -p "$state_home" || fail "could not create state home $state_home"
info "state home: $state_home"

# --- 3. cargo home (writable registry) ---------------------------------------
CARGO_CANDIDATE="${CARGO_HOME:-}"
if [ -z "$CARGO_CANDIDATE" ] && [ -w "$HOME/.cargo/registry" ] 2>/dev/null; then
    CARGO_CANDIDATE="$HOME/.cargo"
fi
if [ -z "${CARGO_CANDIDATE:-}" ]; then
    CARGO_CANDIDATE="$(ask "a writable cargo home (registry under ~/.cargo is not writable)" /tmp/opencode/cargo-home)"
fi
export CARGO_HOME="$CARGO_CANDIDATE"
info "cargo home:  $CARGO_HOME"

# --- 4. build -----------------------------------------------------------------
profile="$(ask "build profile (release is ~3x faster to launch)" release)"
[ "$profile" = debug ] || profile=release

info "building neonet ($profile)... this is the slow bit, only once"
cargo_flags=()
[ "$profile" = release ] && cargo_flags=(--release)
(cd "$repo" && cargo build "${cargo_flags[@]}") >/dev/null 2>&1 || {
    warn "quiet build failed; retrying with output as-is"
    (cd "$repo" && cargo build "${cargo_flags[@]}") || fail "build failed — see the error above"
}
BIN="$repo/target/$profile/neonet"
[ -x "$BIN" ] || fail "compiled binary not found at $BIN"

# --- 5. install directory ------------------------------------------------------
candidates=("$HOME/.local/bin" "$HOME/bin" "/usr/local/bin")
dest=""
for d in "${candidates[@]}"; do
    if [ -d "$d" ] && [ -w "$d" ]; then dest="$d"; break; fi
done
if [ -z "$dest" ]; then
    dest="$(ask "install directory" "$HOME/.local/bin")"
    mkdir -p "$dest" || fail "could not create $dest"
fi

# Atomic install: copy to a temp name, then rename into place. `rename` (mv)
# atomically swaps the name even while another `neonet` is still running, so
# re-installing doesn't trip over a live shell session ("Text file busy" from a
# plain `cp` onto an executing binary).
tmp_dest="$dest/.neonet.tmp.$$"
cp "$BIN" "$tmp_dest" || fail "could not copy the binary into $dest"
chmod +x "$tmp_dest"
mv -f "$tmp_dest" "$dest/neonet" || { rm -f "$tmp_dest"; fail "could not install into $dest"; }

# --- 6. done ------------------------------------------------------------------
ok "installed:   $dest/neonet"
if [ -n "${PATH##*"$dest":*}" ] && [ -n "${PATH##*:"$dest"*}" ] && [ "$dest" != "/usr/local/bin" ]; then
    warn "$dest is not on your PATH — add it, then run \`neonet\`:"
    warn "    export PATH=\"$dest:\$PATH\"   # add to your ~/.bashrc (or ~/.zshrc)"
else
    ok "run \`neonet\` (no args) to open the shell."
fi
