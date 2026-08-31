#!/bin/bash
set -euo pipefail

PREFIX="/usr/local/bin"
STATE="/Library/Application Support/NeoNet"
BINARY="${1:-./neonet}"
BOOTSTRAP="${2:-}"
PLIST="/Library/LaunchDaemons/org.neonet.core.plist"

install -m 0755 "$BINARY" "$PREFIX/neonet"
mkdir -p "$STATE"
chmod 700 "$STATE"
if [[ -n "$BOOTSTRAP" ]]; then install -m 600 "$BOOTSTRAP" "$STATE/bootstrap.json"; fi

cat >"$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>org.neonet.core</string>
<key>ProgramArguments</key><array><string>$PREFIX/neonet</string><string>core</string><string>--listen</string><string>0.0.0.0:4242</string></array>
<key>EnvironmentVariables</key><dict><key>NEONET_HOME</key><string>$STATE</string></dict>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>
PLIST

launchctl bootstrap system "$PLIST"
echo "NeoNet installed as a launchd service."
