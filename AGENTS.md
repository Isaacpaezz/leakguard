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
| `cmd/leakguard` | The CLI: `services`, `interfaces`, `enable`, `disable`, `status`, `test`, `apply`, `serve` (the daemon), `version`, plus the internal `reinstall-service` (not in the help; the `.deb`'s postinst runs it on upgrade to copy the new binary to the root-owned place and restart the service, keeping the choice and the loaded rules). `main` is a thin wrapper over a testable `run` with an injected `Env`. On Windows: the Windows help (an administrator terminal instead of sudo, adapter aliases in quotes), an elevated token counts as root, `serve` runs under the Service Control Manager, the default route comes from `GetIpForwardTable2` (route plus interface metric), the Windows installer runs `reinstall-service` on upgrade too, and `enable`/`disable` take the internal `--report-file PATH` (not in the help): the elevated run started by the tray writes its final error message there, never creating the file or following a link. |
| `internal/ipc` | Socket protocol between the root daemon and the apps: one JSON request and response per connection, strict decoding, peer check (root or the administrators group only: `admin` on macOS; on Linux the first of `sudo`, `wheel`, `admin`, resolved once when the socket is created and used for both its group and the `SO_PEERCRED` check, socket `/run/leakguard.sock`; without such a group, root only). On Windows: the named pipe `\\.\pipe\leakguard` (`go-winio`, SDDL for SYSTEM, Administrators and interactive users), the server reads the request before impersonating the client and runs it only when the token holds SYSTEM or `BUILTIN\Administrators` (enabled or deny-only, so an administrator without elevation is allowed). Other systems refuse every peer. |
| `internal/catalog` | Loads and validates the catalog, embedded in the binary. The CLI and the future tray app reuse it. |
| `internal/config` | The user's VPN interface and services; load, save, validate, VPN interface candidates, per-OS paths. On Linux a VPN is judged by sysfs facts (physical device, wireless, bridge, veth, loopback, link type), a missing one by name; Ethernet, Wi-Fi, Docker, bridges and loopback are refused (`ErrVPNRefused`). On Windows the config stores the adapter alias (may hold spaces and any letter) and an adapter is judged from `GetAdaptersAddresses`: tunnel, PPP and virtual types and known VPN descriptions (TAP-Windows, Wintun, WireGuard, OpenVPN, AnyConnect, Fortinet) are accepted; Ethernet, Wi-Fi, loopback, IPv6 transition tunnels, Bluetooth and virtual machine adapters are refused; a missing one by name. Config and stats live in `%ProgramData%\leakguard`, which only SYSTEM and Administrators may write (a planted folder, junction or file is refused or replaced). |
| `internal/firewall` | The `Firewall` interface every backend implements (`Apply`, `Flush`, `Enabled`, `Verify`, `BlockCount`; `ErrNotLoaded`, `ErrUnsupported`). Only `main` picks the backend. |
| `internal/nft` | Linux `nftables` backend through `nft`: table `inet leakguard` with interval sets of protected IPv4 and IPv6 destinations and two chains with the same counted reject rules outside the VPN: `output` (this computer's traffic) and `forward` (traffic it routes for containers and VMs, which pf filters on the way out on macOS); verifies both with `nft -j`. An empty VPN loads block-all rules. Real-rules integration tests (local and forwarded through network namespaces) behind `LEAKGUARD_NFT_INTEGRATION=1`, which fail without root, `nft` or `ip`. |
| `internal/wfp` | Windows Filtering Platform backend on `github.com/tailscale/wf` (pinned): one persistent provider and sublayer with fixed GUIDs, never tied to the service, so the filters stay while it is stopped or upgraded; at `ALE_AUTH_CONNECT_V4/V6` a block per protected range (weight 1) and a permit per range when the connection leaves on the VPN adapter's LUID (weight 2), and the same pair at `IPFORWARD_V4/V6` (destination and forward interface) for traffic this computer's IP stack routes, such as ICS (unproven); the alias is resolved to a LUID on every apply and verify, and an absent or empty VPN loads only the blocks. Apply adds the new generation of filters before deleting the old one (no gap) and rolls back a failed add; Verify compares the provider's filters as a multiset; `BlockCount` is `ErrUnsupported`. It lists only its own filters through its own provider-template enumeration (`filter0.go`, its own FWPM_FILTER0 and condition layouts), never tailscale/wf's `Rules()`, so other programs' filters never break Apply, Verify or Flush. Gotcha: tailscale/wf declares FWPM_FILTER0's 16-byte union after `action` as two fields, so every later field (filterId, effectiveWeight) reads 8 bytes off and weights come back 0. CI proved: process-isolated Windows containers are blocked at this computer's `ALE_AUTH_CONNECT` (also with the VPN up: over-blocking, fail closed); KNOWN GAP: Hyper-V guests (WSL2 in NAT mode, Hyper-V VMs and isolated containers) are NAT-translated inside the Hyper-V switch, reach neither layer and are not filtered (closing it needs the WFP vSwitch layers and an owner decision). Real-filters integration test behind `LEAKGUARD_WFP_INTEGRATION=1`, which fails when the shell is not elevated; the container test behind `LEAKGUARD_WFP_FORWARD_INTEGRATION=1` logs the gap as `KNOWN GAP`, which CI shows as a warning. |
| `internal/pf` | macOS `pf` backend: renders, applies, flushes and verifies the `com.apple/250.leakguard` anchor, and reads its block counter. |
| `cmd/leakguard-menubar` | The menu-bar and tray app (`fyne.io/systray`): shared `app.go` behind a per-OS `platform`; draws `internal/menubar` (status, session and today lines), polls the daemon every 3 s, runs the setup wizard, embeds the icons made by `gen_icons.go`. macOS (needs cgo): osascript dialogs, template icons. Linux (no cgo, D-Bus StatusNotifierItem; shipped as `leakguard-tray`): zenity or kdialog dialogs, colored icons, pkexec. Windows (no cgo; shipped as `leakguard-tray.exe`): TaskDialogIndirect dialogs (comctl32 v6 from the manifest the installer build embeds; MessageBoxW without it), colored `.ico` icons in the notification area, UAC through `ShellExecuteExW` `runas` with a report file for the CLI's error, the `HKCU` Run key, language from `GetUserDefaultUILanguage`. Other systems get a stub that exits 1. The CLI must never import systray. |
| `internal/menubar` | The menu-bar app's logic without a GUI: status to menu description, clicks to `set`/`pause` requests, the 3-step setup wizard and the uninstall flow over an injected `Dialogs` driver, the login item (macOS LaunchAgent `dev.leakguard.menubar`; Linux XDG autostart `~/.config/autostart/leakguard.desktop`; both with `menubar.json`), the quarantine decision for the bundled CLI, the Spanish/English message catalog (`i18n.go`; Linux language from `LANGUAGE`/`LC_ALL`/`LC_MESSAGES`/`LANG`), plain-language errors, the quoted AppleScript for dialogs and for the administrator setup, the zenity/kdialog driver and pkexec argv on Linux, which CLI is safe to run as root (current install, root-owned without symlinks, else the one next to the app). On Windows: the Windows wording, the TaskDialog/MessageBox driver (one Yes/No question per service), the elevated argv and its quoting (`CommandLineToArgvW` rules), the report file the elevated CLI writes its error to (read capped at 4 KiB, shown instead of the exit status), the installed CLI `%ProgramFiles%\leakguard\service\leakguard.exe` (only while the service runs it and it is admin-only; else `leakguard.exe` next to the tray), the Run-key login item. |
| `internal/version` | The version string, set at link time with `-ldflags -X` (`dev` otherwise). |
| `internal/daemon` | The background service that runs the root-owned copy `/usr/local/libexec/leakguard/leakguard serve`, behind the `Manager` interface: macOS LaunchDaemon `dev.leakguard` (plist, `launchctl`, KeepAlive); Linux systemd unit `/etc/systemd/system/leakguard.service` (`Restart=always`, before `network-pre.target`, log `/var/log/leakguard.log`; files are secured before they replace the running copy; uninstall fails, removing nothing, when `stop` fails and the service may still run). Windows: the service `leakguard` (LocalSystem, automatic start, restart on failure after 5 s) runs its own admin-only copy `%ProgramFiles%\leakguard\service\leakguard.exe serve`, through a portable `ServiceManager` and an `x/sys/windows/svc/mgr` adapter; log `%ProgramData%\leakguard\leakguard.log`. |
| `internal/stats` | Session stats without I/O beyond its JSON file: VPN session start or end, today's VPN time, drops and blocks (pf block-rule packet deltas, never double counted), reset at local midnight. The daemon feeds it; `status` and the menu show it. |
| `internal/probe` | `leakguard test`: connects to protected addresses outside the VPN (macOS `IP_BOUND_IF`, Linux `SO_BINDTODEVICE`, Windows `IP_UNICAST_IF`/`IPV6_UNICAST_IF`) and expects a refusal (on Windows WFP refuses with `WSAEACCES`, which counts as blocked). |
| `internal/readme`, `tools/readmegen` | Generate the README landing sections. |
| `scripts/build-macos.sh` | Builds `dist/leakguard.app` (universal, ad-hoc signed) and `dist/leakguard-VERSION-macos.dmg` with its `.sha256`. Uses `tools/infoplist`, `tools/genappicon`; the release workflow also uses `tools/releasenotes`. |
| `docs/install-macos.md` | The install guide (Spanish, then English), also copied into the DMG. |
| `scripts/build-linux.sh` | Builds static `leakguard` and `leakguard-tray` for linux/amd64 and arm64 into `dist/`: `leakguard-VERSION-linux-ARCH.tar.gz` and `leakguard_VERSION_ARCH.deb` (Debian version from `tools/debversion`), each with its `.sha256`. Needs Linux with `dpkg-deb`. |
| `packaging/linux` | The `.deb`'s files: `control` template (depends on `nftables`), `leakguard.desktop`, the polkit policy `dev.leakguard.policy` (`auth_admin`: one prompt per change, never cached), `prerm` (runs `leakguard disable` on removal when the systemd unit exists), `postinst` (runs `leakguard reinstall-service` on upgrade when the unit exists), `postrm` (purge deletes `/etc/leakguard`, `/var/lib/leakguard` and the logs), `logrotate` (`/etc/logrotate.d/leakguard`, weekly, 4 kept, a conffile listed in `conffiles`). The scripts never fail the package operation. |
| `docs/install-linux.md` | The Linux install guide (Spanish, then English), also inside both packages. |
| `scripts/build-windows.sh` | Builds `leakguard.exe` and `leakguard-tray.exe` for windows/amd64 and arm64 (the tray's comctl32 v6 manifest and icon resource generated with go-winres through `go run`, never committed) and the NSIS installers `leakguard-VERSION-windows-ARCH-setup.exe` with `makensis`, each with its `.sha256`. Runs on Linux or macOS with Go and `makensis` (NSIS 3.04 or newer). |
| `packaging/windows` | The NSIS installer: per-machine install to `%ProgramFiles%\leakguard` (CLI and tray), Start menu shortcut, Settings > Apps uninstall entry; on upgrade it runs `leakguard.exe reinstall-service` when the service exists; uninstall runs `leakguard.exe disable` (service and filters removed), then removes the files, the Start menu entry, the current user's Run value and the uninstall key. |
| `docs/install-windows.md` | The Windows install guide (Spanish, then English): SmartScreen, UAC, the tray, the CLI in an administrator terminal, what is not verified live yet. |
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
