#!/usr/bin/env bash
# flasher-install.sh — build a portable NeoNet "flasher" drive.
#
# Usage:  ./flasher-install.sh [DEST_DIR]
#
# Creates (in DEST_DIR, default ./flasher-drive) the layout a NeoNet flasher
# drive carries:
#
#   DEST_DIR/
#     bin/neonet      # a prebuilt Linux binary, so `neonet flasher ensure`
#                     # can install it onto a machine that has no toolchain
#     README.txt      # what the drive is and how to use it
#     neonet          # a small bootstrap wrapper (best-effort convenience)
#
# The drive is authored (its flashed.json identity+token bundle is written)
# later, on the machine it will be "flashed from":
#
#   neonet flasher author --dir DEST_DIR
#
# Then, on any other machine, plug the drive in and run:
#
#   neonet flasher ensure --dir DEST_DIR   # install neonet if missing
#   neonet flasher adopt  --dir DEST_DIR   # confirm + pair & trust the source
#
# Re-running this script re-bundles the binary (it reloads the config) but
# never overwrites an existing flashed.json authored from a real machine, so
# you don't clobber a pairing in progress by mistake.

set -uo pipefail

c_green=$'\033[1;32m'; c_cyan=$'\033[1;36m'; c_yellow=$'\033[1;33m'; c_red=$'\033[1;31m'; c_bold=$'\033[1m'; c_norm=$'\033[0m'
info() { printf '%s[* ]%s %s\n' "$c_cyan" "$c_norm" "$*"; }
ok()   { printf '%s[ok]%s %s\n'   "$c_green" "$c_norm" "$*"; }
fail() { printf '%s[x ]%s %s\n'   "$c_red" "$c_norm" "$*" >&2; exit 1; }

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dest="${1:-$repo/flasher-drive}"

# --- 1. a prebuilt binary -----------------------------------------------------
BIN=""
for cand in "$repo/target/release/neonet" "$repo/target/debug/neonet"; do
    [ -x "$cand" ] && { BIN="$cand"; break; }
done
if [ -z "$BIN" ]; then
    fail "no compiled neonet found — run './install.sh' first (a bundled binary is what \
makes 'flasher ensure' work on a machine without a toolchain)."
fi

# --- 2. build the layout ------------------------------------------------------
bin_dir="$dest/bin"
mkdir -p "$bin_dir" || fail "could not create $bin_dir"

# Atomic copy into place so re-running never leaves a half-written binary.
tmp_bin="$bin_dir/.neonet.tmp.$$"
cp "$BIN" "$tmp_bin" || fail "could not copy the binary"
chmod +x "$tmp_bin"
mv -f "$tmp_bin" "$bin_dir/neonet" || { rm -f "$tmp_bin"; fail "could not install binary"; }
ok "bundled binary: $bin_dir/neonet ($(stat -c%s "$bin_dir/neonet" 2>/dev/null) bytes)"

# --- 3. a bootstrap wrapper ----------------------------------------------------
if [ ! -f "$dest/neonet" ]; then
    cat > "$dest/neonet" <<'EOF'
#!/usr/bin/env bash
# Convenience launcher on the flasher drive: if `neonet` isn't installed,
# install the bundled binary first (ensuring), then forward the rest of the
# command line to it. This is a thin best-effort bridge; the direct path is
# `neonet flasher ensure` / `neonet flasher adopt`.
set -e
root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v neonet >/dev/null 2>&1; then
    "$root/bin/neonet" flasher ensure --dir "$root" >&2
fi
exec "$root/bin/neonet" "$@"
EOF
    chmod +x "$dest/neonet"
    ok "bootstrap wrapper: $dest/neonet"
fi

# --- 4. README ------------------------------------------------------------------
if [ ! -f "$dest/README.txt" ]; then
    cat > "$dest/README.txt" <<'EOF'
This is a NeoNet flasher drive.

It carries a self-contained copy of the neoNet binary so that:
  * `neonet flasher ensure` can install neoNet onto a machine that does not
    have it (no toolchain required), and
  * the machine can pair-and-trust another neoNet device without typing
    keys, codes, or pins.

Use it on two machines:

  ON THE MACHINE YOU ARE FLASHING FROM:
    neonet flasher author --dir /path/to/this/drive

  ON THE TARGET MACHINE (any other computer):
    neonet flasher ensure --dir /path/to/this/drive   # install if missing
    neonet flasher adopt  --dir /path/to/this/drive   # confirm, pair, trust

`flasher ensure` copies `bin/neonet` onto the target's PATH when neoNet is
missing. `flasher adopt` always asks for explicit confirmation before it
trusts this drive's origin — a dropped drive can never silently pair and trust
on its own.
EOF
    ok "readme: $dest/README.txt"
fi

# --- 5. done --------------------------------------------------------------------
if [ -f "$dest/flashed.json" ]; then
    warn=1
    info "existing flashed.json present — this drive is already authored (skipped)"
fi
ok "flasher drive ready at $dest"
echo
if [ -n "${warn:-}" ]; then
    info "re-author if you want a fresh pairing:  neonet flasher author --dir $dest"
else
    info "next:  neonet flasher author --dir $dest   (on the machine to flash from)"
fi
