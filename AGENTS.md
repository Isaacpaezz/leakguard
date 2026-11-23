# Rules for AI agents

Read this before changing anything in this repository. Humans can read it too.

## Project in one paragraph

leakguard is a destination-scoped VPN kill switch. The user picks services
(Claude, OpenAI, ...). Traffic to them may leave **only** through the VPN
interface; if the VPN drops, those services fail as if offline while the rest
of the machine keeps working. The audience is people in countries where these
services are restricted, such as Venezuela. The product must stay as simple as
VPN Bypass: a tray or menu-bar icon plus service checkboxes.

## Layout

| Path | What it is |
|---|---|
| `catalog/services/*.json` | Service catalog: IP ranges, domains, sources. One file per service; the file name must equal `<id>.json`. |
| `cmd/leakguard` | The CLI: `services`, `interfaces`, `enable`, `disable`, `status`, `test`, `apply`, `serve` (the daemon), `version`. `main` is a thin wrapper over a testable `run` with an injected `Env`. |
| `internal/ipc` | Socket protocol between the root daemon and the apps: one JSON request and response per connection, strict decoding, peer check (root or the administrators group only: `admin` on macOS; on Linux the first of `sudo`, `wheel`, `admin`, read with `SO_PEERCRED`, socket `/run/leakguard.sock`). Other systems refuse every peer. |
| `internal/catalog` | Loads and validates the catalog, embedded in the binary. The CLI and the future tray app reuse it. |
| `internal/config` | The user's VPN interface and services; load, save, validate, VPN interface candidates, per-OS paths. On Linux a VPN is judged by sysfs facts (physical device, wireless, bridge, veth, loopback, link type), a missing one by name; Ethernet, Wi-Fi, Docker, bridges and loopback are refused (`ErrVPNRefused`). Windows refuses every VPN for now. |
| `internal/firewall` | The `Firewall` interface every backend implements (`Apply`, `Flush`, `Enabled`, `Verify`, `BlockCount`; `ErrNotLoaded`, `ErrUnsupported`). Only `main` picks the backend. |
| `internal/nft` | Linux `nftables` backend through `nft`: table `inet leakguard` with interval sets of protected IPv4 and IPv6 destinations and an output chain that rejects them outside the VPN, with a counter; verifies with `nft -j`. An empty VPN loads block-all rules. Real-rules integration test behind `LEAKGUARD_NFT_INTEGRATION=1` (root). |
| `internal/pf` | macOS `pf` backend: renders, applies, flushes and verifies the `com.apple/250.leakguard` anchor, and reads its block counter. |
| `cmd/leakguard-menubar` | The menu-bar and tray app (`fyne.io/systray`): shared `app.go` behind a per-OS `platform`; draws `internal/menubar` (status, session and today lines), polls the daemon every 3 s, runs the setup wizard, embeds the icons made by `gen_icons.go`. macOS (needs cgo): osascript dialogs, template icons. Linux (no cgo, D-Bus StatusNotifierItem; shipped as `leakguard-tray`): zenity or kdialog dialogs, colored icons, pkexec. Other systems get a stub that exits 1. The CLI must never import systray. |
| `internal/menubar` | The menu-bar app's logic without a GUI: status to menu description, clicks to `set`/`pause` requests, the 3-step setup wizard and the uninstall flow over an injected `Dialogs` driver, the login item (macOS LaunchAgent `dev.leakguard.menubar`; Linux XDG autostart `~/.config/autostart/leakguard.desktop`; both with `menubar.json`), the quarantine decision for the bundled CLI, the Spanish/English message catalog (`i18n.go`; Linux language from `LANGUAGE`/`LC_ALL`/`LC_MESSAGES`/`LANG`), plain-language errors, the quoted AppleScript for dialogs and for the administrator setup, the zenity/kdialog driver and pkexec argv on Linux, which CLI is safe to run as root (current install, root-owned without symlinks, else the one next to the app). |
| `internal/version` | The version string, set at link time with `-ldflags -X` (`dev` otherwise). |
| `internal/daemon` | The background service that runs the root-owned copy `/usr/local/libexec/leakguard/leakguard serve`, behind the `Manager` interface: macOS LaunchDaemon `dev.leakguard` (plist, `launchctl`, KeepAlive); Linux systemd unit `/etc/systemd/system/leakguard.service` (`Restart=always`, before `network-pre.target`, log `/var/log/leakguard.log`). |
| `internal/stats` | Session stats without I/O beyond its JSON file: VPN session start or end, today's VPN time, drops and blocks (pf block-rule packet deltas, never double counted), reset at local midnight. The daemon feeds it; `status` and the menu show it. |
| `internal/probe` | `leakguard test`: connects to protected addresses outside the VPN (macOS `IP_BOUND_IF`, Linux `SO_BINDTODEVICE`) and expects a refusal. |
| `internal/readme`, `tools/readmegen` | Generate the README landing sections. |
| `scripts/build-macos.sh` | Builds `dist/leakguard.app` (universal, ad-hoc signed) and `dist/leakguard-VERSION-macos.dmg` with its `.sha256`. Uses `tools/infoplist`, `tools/genappicon`; the release workflow also uses `tools/releasenotes`. |
| `docs/install-macos.md` | The install guide (Spanish, then English), also copied into the DMG. |
| `scripts/build-linux.sh` | Builds static `leakguard` and `leakguard-tray` for linux/amd64 and arm64 into `dist/`: `leakguard-VERSION-linux-ARCH.tar.gz` and `leakguard_VERSION_ARCH.deb` (Debian version from `tools/debversion`), each with its `.sha256`. Needs Linux with `dpkg-deb`. |
| `packaging/linux` | The `.deb`'s files: `control` template (depends on `nftables`), `leakguard.desktop`, the polkit policy `dev.leakguard.policy` and `prerm` (runs `leakguard disable` on removal when the systemd unit exists, never failing the removal). |
| `docs/install-linux.md` | The Linux install guide (Spanish, then English), also inside both packages. |
| `prototypes/macos-pf` | Working macOS `pf` prototype. Reference only; do not extend it. |
| `CHANGELOG.md` | User-visible changes; its newest section feeds "What's new" in the README. |
| `.github/` | CI, issue and pull request templates, CODEOWNERS. |
| `docs/HANDOFF.md` | Origin, lessons learned, architecture decisions, milestones. Read it before design work. |
| `skills/` | Task guides for agents (see below). |

## Commands

```sh
go test ./... && go vet ./... && gofmt -l .
go run ./tools/readmegen         # after any catalog or CHANGELOG change
go run ./tools/readmegen -check  # CI gate
scripts/build-macos.sh 0.0.0-local  # macOS app and DMG into dist/ (macOS only)
scripts/build-linux.sh 0.0.0-local  # .deb and .tar.gz into dist/ (Linux with dpkg-deb; on macOS:
# docker run --rm -v "$PWD":/src -w /src -e GOFLAGS=-buildvcs=false golang:1.25 scripts/build-linux.sh 0.0.0-local)
```

## Hard rules

1. **Never invent IP ranges or domains.** Every range needs a verifiable source in `sources`. If you cannot verify it, do not add it; say so.
2. **IPv4 and IPv6 always together** for supported services. A missing IPv6 range is a leak.
3. **No shared CDN ranges** (Cloudflare, Google Cloud, Akamai, Fastly) in the catalog. Mark the service `planned` and explain why in `notes`.
4. **Fail closed.** When the VPN interface is unknown or the rules cannot be verified, protected traffic must be blocked, never allowed.
5. **Never edit inside `<!-- BEGIN/END GENERATED -->` markers** in README.md. Change the source and run `readmegen`.
6. **Test first** for behavior changes: write the failing test, then the code.
7. **Repository artifacts in English** (code, comments, commits, docs). Issues and discussions may be in Spanish.
8. **Small pull requests** (about 400 changed lines or fewer) with Conventional Commits, and tests and docs alongside the code.
9. **No private data or credentials** in commits, issues or logs: no users' real IPs, VPN server names, tokens or keys.
10. The maintainer decides what gets merged. Do not merge, push to `main`, push `v*` tags, publish releases or change repository settings.

## Skills

| Skill | Use it when |
|---|---|
| [`skills/add-service`](skills/add-service/SKILL.md) | Adding a service or updating its ranges or domains. |
