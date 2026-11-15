# Anthropic kill switch

Traffic to Anthropic (Claude Code, Claude Desktop, claude.ai) may only leave
through the corporate VPN (`ipsec0`, Chile). If the VPN drops, pf rejects every
packet to Anthropic instead of sending it through the real connection, so the
apps fail as if offline and Anthropic never sees the real IP.
The rest of the Mac keeps working normally.

- `anthropic-killswitch.pf` — pf anchor rules (Anthropic IPv4 AS399358 + `2607:6bc0::/48`).
- `com.isaacpaezz.anthropic-killswitch.plist` — LaunchDaemon: loads the anchor
  `com.apple/250.AnthropicKillSwitch` at boot and re-applies it every 5 minutes.
  It needs no change to `/etc/pf.conf`.

```sh
sudo ./install.sh     # install, then test that en1 is blocked and the VPN works
sudo ./uninstall.sh   # remove
sudo pfctl -a com.apple/250.AnthropicKillSwitch -s rules   # inspect
```

If the VPN interface name changes from `ipsec0`, update the `pass` rule.
