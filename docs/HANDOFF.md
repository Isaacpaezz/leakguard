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
   root-owned copy at `/usr/local/libexec/leakguard/leakguard` (since
   milestone 2 it runs `serve`, which verifies every 30 s and reloads only
   when the check fails or the saved choice changed).
   Pending: a live run by the owner (`sudo leakguard enable`, `test`,
   `disable`), since tests never touch the real firewall.
2. 🚧 Menu-bar app on macOS (Go systray) talking to the privileged service.
   Done (PR A, `feat/daemon-socket`): the LaunchDaemon runs `leakguard serve`
   (RunAtLoad, KeepAlive) instead of a periodic `apply`. It applies the saved
   config at start and every 30 s unless paused (since session stats it
   verifies every 30 s and reloads only on failure or a changed choice), and
   serves
   `/var/run/leakguard.sock` (`internal/ipc`): one newline-terminated JSON
   request and response per connection, at most 64 KiB, 5 s deadline;
   commands `status`, `set`, `pause` (flush and save `"paused": true`; `set`,
   `sudo leakguard enable` and `sudo leakguard apply` end it;
   `sudo leakguard disable` still uninstalls). The command was called
   `disable` before the first release; it was renamed so it never reads like
   the uninstalling CLI command. Requests are decoded strictly (unknown
   fields refused); responses ignore unknown fields so an older app keeps
   working with a newer daemon. A refused peer gets `not authorized`, which
   the client returns as `ipc.ErrNotAuthorized`.
   Authorization is twofold: the socket is `root:admin` (gid 80) mode 0660,
   and the server reads `LOCAL_PEERCRED` and refuses peers that are not uid 0
   or in group 80. Other platforms refuse every peer. One mutex serializes
   the apply loop and requests. `leakguard status` without root asks the
   socket and falls back to reading the files.
   Done (PR B, `feat/menu-bar-app`): `cmd/leakguard-menubar`, a separate
   binary on `fyne.io/systray` v1.12.2 (cgo; the CLI stays cgo-free and never
   imports it; other systems get a stub that exits 1). The logic lives in
   `internal/menubar` and is tested without a GUI: status to menu (template
   icons: filled shield protected, outline not protected or paused, slashed
   not set up), clicks to `set`/`pause` (unticking the last service pauses),
   plain-language errors. When the daemon answers but has no services yet,
   choosing a VPN is held by the app and sent with the first ticked service;
   ticking a service first uses the only connected VPN, or asks for the VPN.
   The error line of a failed click is cleared by a later successful poll.
   The app polls every 3 s and after each click.
   First run works from the menu: while the daemon is unavailable, ticking
   services and choosing the VPN only edit a local draft (default: no
   services; the VPN when exactly one candidate is connected). "Set up
   leakguard…" is enabled once the draft is complete and runs
   `<leakguard> enable --vpn IFACE SERVICE...` once through
   `osascript ... with administrator privileges`. The draft must pass
   `config.Validate` against the embedded catalog, and every argument is
   quoted for the shell, then the command for AppleScript (paths must be
   absolute, valid UTF-8, without control characters). The binary run as
   root is the installed copy only when `/Library/LaunchDaemons/dev.leakguard.plist`
   runs `serve` (`menubar.InstalledState`) and `menubar.CheckInstalledCLI`
   confirms, with `lstat` (no symlinks), that it and every parent directory
   are owned by root and not group/other-writable; a failed check refuses
   instead of falling back. Upgrades from an older install (plist runs a
   periodic `apply`) work from the menu: the status says "Update needed" and
   "Set up" uses the `leakguard` next to the app (possibly user-writable),
   which is otherwise used only for the first install. Before running setup
   the app polls the daemon once more and drops the draft if it now answers.
   Pending: a live check by the owner.
   Setup wizard (`feat/setup-wizard`, `odd/tasks/setup-wizard.md`): the menu
   draft and the VPN interface submenu are replaced by a 3-step wizard in
   `internal/menubar/wizard.go`, driven by a `Dialogs` interface (osascript
   `display dialog` / `choose from list` in the app, a fake in tests). Step 2
   snapshots the connected VPN candidates with the VPN disconnected and then
   connected; exactly one new interface is the VPN, named only by its kind
   ("VPN IPsec") with a "Choose another" button to the list; otherwise the
   user retries or chooses from a list with friendly labels ("VPN IPsec
   (ipsec0)"). It never guesses and never sends a partial choice; cancelling
   returns `ErrCancelled` before anything is sent. Any other failure is shown
   in a dialog and on the menu's error line through `menubar.WizardMessage`;
   SetupScript, choice and dialog-driver errors wrap sentinels
   (`ErrUnsafeCLIPath`, `ErrInvalidChoice`, `ErrUnexpectedAnswer`) that
   `Explain` translates. The setup opens by itself only on the app's first
   poll when the daemon is unavailable and no current install exists
   (`menubar.ShouldAutoOpen`), so a daemon restart never reopens it. Step 3 warns about the password
   and the administrator prompt uses `with prompt`. Every user-facing string
   is in `internal/menubar/i18n.go` in Spanish and English, chosen from
   `defaults read -g AppleLanguages`. Every AppleScript string escapes
   backslashes, quotes and line breaks; tests round-trip them through
   `osascript -e 'return ...'` and compile the scripts with `osacompile`,
   never running a dialog or administrator rights.
   Session stats (`feat/session-stats`, `odd/tasks/session-stats.md`): the
   menu shows "VPN connected for 2 h 15 min" (or "disconnected for") and
   "Today: 14 blocks · VPN dropped 2 times" under the status, and today's
   VPN time in the tooltip; `leakguard status` prints the same. The daemon
   owns the numbers (`internal/stats`, pure, fed with timestamped samples):
   it samples the saved VPN every 5 s, reads the packet counter of the
   `block return` rule (`pf.Firewall.BlockCount`, `pfctl -a ANCHOR -s rules
   -v`) on each 30 s tick and right before every reload, `set` load and
   pause flush (after the config is saved, so blocks meanwhile count), and
   saves `/Library/Application Support/leakguard/stats.json` at most once a
   minute and at shutdown, from its own goroutine so a slow disk never
   delays a verify (shutdown waits for a save in flight). At start the
   daemon loads the rules first and reads the stats file after, replaying
   the start reading on it; `stats.Load` opens without blocking and refuses
   anything but a regular file of at most 64 KiB, so a FIFO or a hung file
   at that path never keeps the rules from loading. pf resets rule counters on every anchor
   load, so the loop no longer reloads every 30 s: it loads at start, then
   verifies (pf enabled and `State.Verify`) and reloads only when the check
   fails or the saved choice differs from the one it loaded. Counting rule
   (never double counts, may undercount): a lower reading than the last
   means a reset, so the reading itself is new; the daemon's own loads and
   flushes set the baseline to zero; a tracker without a saved file takes
   its first reading as a baseline; after a restart the saved reading is
   the baseline. A reload that fails after pf loaded the anchor resets the
   counter unseen: blocks may be lost then, never counted twice. VPN gaps over 2 min (sleep, daemon down) add no time and
   no drop. "Today" resets at local midnight, also across DST. Stats
   errors are logged once and never change protection.
3. Linux `nftables` backend and tray app.
4. Windows backend and tray app.
5. Self-updating catalog: a scheduled workflow refreshes ranges from their
   sources (ASN prefixes) and opens a PR; the app downloads a signed catalog.
   Domain-aware blocking for CDN-hosted services (OpenAI).
6. 🚧 In review (macOS part, `feat/macos-installer`,
   `odd/tasks/macos-installer.md`): `leakguard.app` in a DMG on GitHub
   Releases. `scripts/build-macos.sh VERSION` builds both binaries for arm64
   and amd64 with `-X internal/version.Version`, merges them with `lipo`,
   writes `Contents/Info.plist` (`tools/infoplist`: bundle id
   `dev.leakguard.menubar`, `LSUIElement`, minimum macOS 13; a pre-release
   keeps only its numbers in the bundle versions), draws `AppIcon.icns`
   (`tools/genappicon` + `iconutil`), signs ad-hoc (`codesign --deep -s -`;
   no Developer ID yet, owner choice, so users click "Open Anyway" once) and
   makes a UDZO DMG with an Applications link and `docs/install-macos.md` as
   "Cómo abrir leakguard.txt", plus a `.sha256`. The release workflow runs on
   `v*` tags (pushed only by the maintainer) with `contents: write` at job
   level, refuses a tag whose version is not the newest CHANGELOG section
   (`tools/releasenotes`), and marks versions below 1.0 as pre-releases. CI
   builds the DMG on every pull request. The CLI ships inside the bundle next
   to the menu-bar binary, where `FindCLI` already looks on first run.
   Login item: a per-user LaunchAgent (works without a Developer ID, unlike
   SMAppService) written by the app on launch only when it runs from a
   `.app` bundle, rewritten when the app moved, never loaded with launchctl
   (RunAtLoad at the next login; no second copy now). The user's choice
   lives in `~/Library/Application Support/leakguard/menubar.json`.
   Uninstall: `menubar.Uninstaller` (confirm with Cancel as default, then
   `<cli> disable` through the same administrator script builder with its
   own prompt, then remove the LaunchAgent and `menubar.json`, then quit);
   cancelling or a failed disable changes nothing else and says so.
   Quarantine: before running the CLI as administrator, the app clears
   `com.apple.quarantine` with `xattr -d` on exactly its own bundled CLI when
   it carries the mark (`menubar.PrepareCLI`); a failure is
   `ErrQuarantined`, explained in plain words with a link to the guide.
   Pending (T4): verify the release workflow, a live install from the DMG by
   the owner, whether a quarantined CLI runs from the administrator prompt
   at all, and the root uninstall.
   Later: Homebrew tap, winget, Linux packages, Developer ID signing and
   notarization (the bundle layout stays the same).

## Resume prompt

Open a session in this folder and paste:

> Read README.md and docs/HANDOFF.md. Continue with the next milestone.
