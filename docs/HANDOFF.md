# Handoff: where this project comes from and how to continue

Read this first when resuming work in a new session.

## Origin

The project was born in `~/dotfiles/vpn-killswitch/` (2026-11-14). The owner
works from Venezuela behind a corporate IPsec VPN (`ipsec0`) that exits in
Chile. VPN Bypass runs in `vpnOnly` mode, so only some traffic (AI services)
goes through the VPN. Problem: if the VPN drops, that traffic silently falls
back to the real connection and exposes the real IP.

## Product vision (owner, 2026-11-15)

- Purpose: block chosen services (Claude, OpenAI, others) when the VPN drops,
  so they never try the real connection. Audience: Venezuela and other
  countries where these services are restricted.
- Must be as simple as VPN Bypass: a menu-bar or tray icon on macOS, Windows
  and Linux that shows whether you are protected, and checkboxes to pick one
  or several services.
- The project keeps the IP ranges up to date for users (service catalog).
- Open source with outside contributors; the owner decides what is merged.

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

## Decisions (2026-11-15)

| Topic | Decision |
|---|---|
| Tray app | Pure Go: a privileged service applies the firewall; a light Go systray app picks services and shows status. |
| Landing page | README styled like gentle-shell; `tools/readmegen` generates the services table and "What's new"; CI blocks any PR whose README is stale (no bot pushes, compatible with branch protection). |
| Contribution flow | Light: issue/PR templates, Conventional Commits, ~400-line PRs. Control via CODEOWNERS + branch protection on `main`. |
| Catalog format | `catalog/services/<id>.json`, validated by `internal/catalog` (stdlib only, no dependencies). |

Owner to-do on GitHub once the repo exists: enable branch protection on `main`
(require PR, Code Owner review and the `CI` check), enable private
vulnerability reporting, create labels `status:needs-triage`,
`status:approved`, `catalog`.

## Proposed architecture

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

## Milestones

0. ✅ Open source foundation: CONTRIBUTING, templates, CODEOWNERS, SECURITY,
   AGENTS.md + skills, service catalog, self-updating README.
1. 🚧 In review. Port the macOS prototype into the Go CLI. Profiles come from
   `internal/catalog`. Commands: `enable`, `disable`, `status`, `test`.
   Done in `cmd/leakguard` (plus `services`, `interfaces`, `apply`): JSON
   config at `/Library/Application Support/leakguard/config.json`, pf anchor
   `com.apple/250.leakguard`, LaunchDaemon `dev.leakguard` running a
   root-owned copy at `/usr/local/libexec/leakguard/leakguard` every 60 s.
   Pending: a live run by the owner (`sudo leakguard enable`, `test`,
   `disable`), since tests never touch the real firewall.
2. Menu-bar app on macOS (Go systray) talking to the privileged service.
3. Linux `nftables` backend and tray app.
4. Windows backend and tray app.
5. Self-updating catalog: a scheduled workflow refreshes ranges from their
   sources (ASN prefixes) and opens a PR; the app downloads a signed catalog.
   Domain-aware blocking for CDN-hosted services (OpenAI).
6. Release pipeline (GoReleaser, Homebrew tap, winget, installers).

## Resume prompt

Open a session in this folder and paste:

> Read README.md and docs/HANDOFF.md. Continue with the next milestone.
