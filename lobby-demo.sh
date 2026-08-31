#!/usr/bin/env bash
# lobby-demo.sh — pack up the whole NeoNet lobby demo into one run.
#
# Spins up its own throwaway relay core, host, and member (each with a fresh
# identity in its own temp state dir — cores route per-identity, so the three
# roles must not share a home), then drops you into an interactive member
# prompt. Everything that is a real variable gets an "input taker": a default
# is shown in [brackets] and Enter accepts it.
#
# Terabytes of config? No. Three flags on `neonet host`. That's the point.

set -uo pipefail

# --- you can change these ---------------------------------------------------
# REPO_URL is the git remote `neonet update` pulls from (and /update in the
# member menu runs). Leave empty and it falls back to this checkout's origin.
# Updates are manual on purpose: nothing force-resets, nothing auto-runs.
REPO_URL=""
REPO_BRANCH="main"

# --- helpers ---------------------------------------------------------------
c_green=$'\033[1;32m'; c_cyan=$'\033[1;36m'; c_yellow=$'\033[1;33m'; c_red=$'\033[1;31m'; c_bold=$'\033[1m'; c_norm=$'\033[0m'

info() { printf '%s[* ]%s %s\n' "$c_cyan" "$c_norm" "$*"; }
warn() { printf '%s[! ]%s %s\n' "$c_yellow" "$c_norm" "$*"; }
fail() { printf '%s[x ]%s %s\n' "$c_red" "$c_norm" "$*" >&2; exit 1; }

# ask "question" "default"  ->  echoes the chosen value on stdout; Enter => default
# The prompt itself goes to stderr so `x="$(ask ...)"` captures the answer only.
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

# --- locate the repo & the binary to run ----------------------------------
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CARGO_CANDIDATE="${CARGO_HOME:-}"
[ -z "$CARGO_CANDIDATE" ] && [ -w "$HOME/.cargo/registry" ] 2>/dev/null && CARGO_CANDIDATE="$HOME/.cargo"
if [ -z "${CARGO_CANDIDATE:-}" ]; then
    CARGO_CANDIDATE="$(ask "a writable cargo home (registry under ~/.cargo is not writable)" /tmp/opencode/cargo-home)"
fi
export CARGO_HOME="$CARGO_CANDIDATE"

profile="$(ask "build profile" debug)"
[ "$profile" = release ] || profile=debug

info "building neonet ($profile)... this is the slow bit, only once"
cargo_flags=()
[ "$profile" = release ] && cargo_flags=(--release)
(cd "$repo" && cargo build "${cargo_flags[@]}") >/dev/null 2>&1 || {
    warn "quiet build failed; retrying with output as-is"
    (cd "$repo" && cargo build "${cargo_flags[@]}") || exit 1
}
BIN="$repo/target/$profile/neonet"
[ -x "$BIN" ] || fail "compiled binary not found at $BIN"

# --- the variables, each an input taker (Enter = the [default]) -----------
listen="$(ask "core listen address" 127.0.0.1)"
port="$(ask "core listen port" 4242)"
lobby_name="$(ask "lobby name" retreat)"
title="$(ask "display title (Enter = lobby name)" "$lobby_name")"
welcome="$(ask "welcome message (Enter = none)")"
max_members="$(ask "max members" 16)"

if [ "$listen" = "127.0.0.1" ] || [ "$listen" = "localhost" ]; then
    info "demo is local-only; to reach it from other machines re-run with listen = 0.0.0.0"
fi

# --- fresh playground ------------------------------------------------------
DEMO="$(mktemp -d /tmp/neonet-lobby.XXXXXX)"
CORE_HOME="$DEMO/core"; HOST_HOME="$DEMO/host"; MEMBER_HOME="$DEMO/member"
mkdir -p "$CORE_HOME" "$HOST_HOME" "$MEMBER_HOME"

CORE_PID=""; HOST_PID=""
cleanup() {
    trap - INT TERM EXIT
    [ -n "${HOST_PID:-}" ] && kill "$HOST_PID" 2>/dev/null
    [ -n "${CORE_PID:-}" ] && kill "$CORE_PID" 2>/dev/null
    wait 2>/dev/null
    printf '\n%s[ok]%s demo stopped. state (identities, logs, roster) left in %s%s\n' "$c_green" "$c_norm" "$DEMO" "$c_norm"
    exit 0
}
trap cleanup INT TERM EXIT

ne() { # run a neonet subcommand with a given state home
    local home="$1"; shift
    NEONET_HOME="$home" "$BIN" "$@"
}

# --- 1. relay core ---------------------------------------------------------
CORE_PUBKEY="$(ne "$CORE_HOME" whoami | awk '/public key/ {print $3}')"
[ -n "$CORE_PUBKEY" ] || fail "could not read the core's public key"
BSTRAP='[{"address":"'$listen':'$port'","pinned_public_key":"'$CORE_PUBKEY'"}]'
printf '%s\n' "$BSTRAP" > "$HOST_HOME/bootstrap.json"
printf '%s\n' "$BSTRAP" > "$MEMBER_HOME/bootstrap.json"

# The member's join resolves the host through devices.json, so provision one
# record for it (identity fingerprint match; the SSH fields are dummies — mesh
# messaging never uses them). Pure bash hex -> int array, no python needed.
HOST_PUBKEY="$(ne "$HOST_HOME" whoami | awk '/public key/ {print $3}')"
host_pubkey_json="[$(
    hex="$HOST_PUBKEY"
    s=""
    for ((i = 0; i < 32; i++)); do s+="$((16#${hex:$((i * 2)):2})),"; done
    printf '%s' "${s%,}"
)]"
printf '{"devices":[{"identity":{"public_key":%s},"alias":"host","user":"host","resolution":{"host":"%s","port":22,"known_hosts":""}}]}\n' \
    "$host_pubkey_json" "$listen" > "$MEMBER_HOME/devices.json"

ne "$CORE_HOME" core --listen "$listen:$port" >"$DEMO/core.log" 2>&1 </dev/null &
CORE_PID=$!
info "relay core up on $listen:$port (pid $CORE_PID)"

for _ in $(seq 1 60); do
    (exec 3<>"/dev/tcp/$listen/$port") 2>/dev/null && { exec 3>&- 3<&-; break; }
    sleep 0.2
done
(exec 3<>"/dev/tcp/$listen/$port") 2>/dev/null || fail "core never started listening"

# --- 2. the host and its lobby --------------------------------------------
HOST_FP="$(ne "$HOST_HOME" whoami | awk '/identity fingerprint/ {print $3}')"
host_args=("$lobby_name" --title "$title" --max-members "$max_members")
[ -n "$welcome" ] && host_args+=(--welcome "$welcome")
ne "$HOST_HOME" host "${host_args[@]}" >"$DEMO/host.log" 2>&1 </dev/null &
HOST_PID=$!

KEY=""
for _ in $(seq 1 100); do
    KEY="$(awk '/^[[:space:]]*[0-9a-f]{64}[[:space:]]*$/ {print $1; exit}' "$DEMO/host.log" 2>/dev/null)"
    [ -n "$KEY" ] && break
    sleep 0.2
done
[ -n "$KEY" ] || { warn "host did not print a lobby key; its log:"; cat "$DEMO/host.log"; fail "host failed to start"; }

info "hosting '${lobby_name}' as '$title' — members run:"
info "${c_bold}  neonet join \"$lobby_name\" $HOST_FP $KEY${c_norm}"
warn "the join command is the only secret you must share out-of-band"

# --- 3. interactive member prompt -----------------------------------------
joined=0
join_lobby() {
    [ "$joined" -eq 1 ] && return
    NEONET_HOME="$MEMBER_HOME" "$BIN" join "$lobby_name" "$HOST_FP" "$KEY"
    joined=1
}

info "you're the member. type a message to post it; /help lists commands; /quit or Ctrl-D leaves."
while true; do
    printf '%s%s%s> ' "${c_green}${c_bold}" "$lobby_name" "$c_norm"
    IFS= read -r line || break
    case "$line" in
        "" ) continue ;;
        /quit|/exit ) break ;;
        /help )
            printf 'post text          send it to the lobby\n'
            printf '/join              (re)join the host\n'
            printf '/log               show your decrypted post log\n'
            printf '/members           ask the host who is in right now\n'
            printf '/channel <id> <m>  private 1:1 text to a device\n'
            printf '/update            pull + rebuild from REPO_URL (top of this script)\n'
            printf '/quit              leave (stops core + host too)\n'
            ;;
        /log )       ne "$MEMBER_HOME" lobby log "$lobby_name" ;;
        /members )   ne "$MEMBER_HOME" lobby members "$lobby_name" ;;
        /join )      join_lobby ;;
        /update )
            upd_flags=()
            [ "$profile" = release ] && upd_flags=(--release)
            NEONET_UPDATE_REPO="$REPO_URL" NEONET_UPDATE_BRANCH="$REPO_BRANCH" \
                "$BIN" update "${upd_flags[@]}"
            ;;
        /channel\ * )
            dev="${line#/channel }"; dev="${dev%% *}"
            text="${line#/channel $dev }"
            [ -n "$text" ] && ne "$MEMBER_HOME" channel "$dev" "$text"
            ;;
        * )
            join_lobby
            NEONET_HOME="$MEMBER_HOME" "$BIN" lobby post "$lobby_name" "$line"
            ;;
    esac
done