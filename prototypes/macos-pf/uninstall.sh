#!/bin/sh
# Remove the Anthropic kill switch. Run with: sudo ./uninstall.sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo: sudo $0" >&2; exit 1; }
PLIST=/Library/LaunchDaemons/com.isaacpaezz.anthropic-killswitch.plist
launchctl bootout system "$PLIST" 2>/dev/null || true
rm -f "$PLIST" /etc/pf.anchors/anthropic-killswitch
pfctl -a com.apple/250.AnthropicKillSwitch -F all 2>/dev/null || true
echo "Kill switch removed."
