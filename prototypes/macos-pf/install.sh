#!/bin/sh
# Install the Anthropic kill switch. Run with: sudo ./install.sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo: sudo $0" >&2; exit 1; }
DIR=$(cd "$(dirname "$0")" && pwd)
LABEL=com.isaacpaezz.anthropic-killswitch
PLIST=/Library/LaunchDaemons/$LABEL.plist

install -m 644 -o root -g wheel "$DIR/anthropic-killswitch.pf" /etc/pf.anchors/anthropic-killswitch
install -m 644 -o root -g wheel "$DIR/$LABEL.plist" "$PLIST"
launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
sleep 1

echo "== Rules loaded:"
pfctl -a com.apple/250.AnthropicKillSwitch -s rules 2>/dev/null
echo "== Test: Anthropic via the real connection (en1) must FAIL:"
if curl -s -m 8 --interface en1 -o /dev/null https://api.anthropic.com; then
  echo "   LEAK: reached Anthropic outside the VPN" >&2; exit 1
else
  echo "   OK: blocked"
fi
echo "== Test: Anthropic via the VPN must work:"
curl -s -m 8 -o /dev/null -w "   HTTP %{http_code}\n" https://api.anthropic.com || echo "   VPN down or unreachable"
