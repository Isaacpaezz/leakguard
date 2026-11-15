# Handoff: where this project comes from and how to continue

Read this first when resuming work in a new session.

## Origin

The project was born in `~/dotfiles/vpn-killswitch/` (2026-11-14). The owner
works from Venezuela behind a corporate IPsec VPN (`ipsec0`) that exits in
Chile. VPN Bypass runs in `vpnOnly` mode, so only some traffic (AI services)
goes through the VPN. Problem: if the VPN drops, that traffic silently falls
back to the real connection and exposes the real IP.

## What already works (`prototypes/macos-pf/`)

- pf anchor `com.apple/250.AnthropicKillSwitch`, loaded by a LaunchDaemon
  (`RunAtLoad`, re-applied every 300 s). It needs no change to `/etc/pf.conf`.
- Verified on 2026-11-15:
  - curl through `en1` and `utun4` is refused; through `ipsec0` it works.
  - With the VPN down, curl fails in about 8 ms.
  - `sudo pfctl -s rules` and `-T show` show both rules and all 6 CIDRs.

## Known gaps and lessons

1. **Shared CDN IPs.** Services behind Cloudflare or Google Cloud (OpenAI,
   Datadog, Sentry) share their IPs with other sites. Blocking them by IP hits
   unrelated sites. Options:
   - resolve domains periodically into a dynamic table;
   - a local DNS-aware approach;
   - accept the collateral blocking.
2. **Telemetry outside the main provider.** For example, Claude Code also talks
   to Datadog, Sentry and statsig. A destination list must cover a whole app,
   not just its main API.
3. **The VPN interface name varies** (`ipsec0`, `utun*`, `tun0`, `wg0`,
   Windows adapters). The tool needs detection plus explicit configuration.
4. **IPv6.** Always include the v6 ranges. Without them, the kill switch has a
   hole on networks that have IPv6.
5. **Persistence.** OS updates and VPN clients may flush firewall rules.
   Re-apply them on boot and periodically, and verify after applying.

## Proposed architecture (to decide)

- One binary in **Go**: a single static executable per OS, easy to
  cross-compile and package with Homebrew, apt and winget.
- Config file (YAML/TOML):
  - the VPN interface;
  - named profiles (`anthropic`, `openai`, custom) with CIDRs and domains.
- Commands: `leakguard enable | disable | status | test | profiles`.
  - `test` reproduces the proof from the prototype: connect to each protected
    destination through the non-VPN interface and expect a refusal.
- Backends: macOS `pf`; Linux `nftables`; Windows Firewall rules. Windows
  rules block on interface types Wired and Wireless and allow RemoteAccess,
  because a block rule always beats an allow rule in Windows Firewall.
- Later: a menu-bar or tray UI.

## First milestones

1. Port the macOS prototype into the Go CLI with configurable profiles, plus
   `leakguard test`.
2. Linux `nftables` backend.
3. Windows backend.
4. Release pipeline (GoReleaser, Homebrew tap) and CONTRIBUTING.md.

## Resume prompt

Open a session in this folder and paste:

> Read README.md and docs/HANDOFF.md. Continue with the next milestone.
