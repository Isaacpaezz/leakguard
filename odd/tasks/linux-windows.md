# Feature: leakguard on Linux and Windows

Bring the working macOS product (CLI, root daemon, tray icon, setup wizard, session stats, installer) to Linux first, then Windows.
Branches `feat/linux-support` (shared base + Linux), then `feat/windows-support`; reviewable slices of about 400 lines.

## Specs

- S1 (L1): "ahora necesitamos que funcione en linux y en windows". On Linux and Windows leakguard offers the same product as on macOS: a tray icon that shows whether you are protected, service checkboxes, the 3-step setup, pause, session stats ("VPN conectada hace …", "Hoy: N bloqueos · la VPN se cayó N veces"), uninstall, and the CLI commands `services`, `interfaces`, `enable`, `disable`, `status`, `test`, `apply`, `serve`, `version`.
- S2 (L1): "ya en mac va perfecto". macOS behavior, output, paths and tests stay unchanged.
- S3 (L2): "Linux primero, luego Windows (recomendado)". The shared base goes first, then Linux, then Windows.
- S4 (L3): "Ninguna: solo CI y Docker". There is no real Linux or Windows machine for a live check. The firewall is proven with privileged integration tests that load real rules and probe them: in Docker locally and on GitHub runners (`ubuntu-latest`, `windows-latest`). The tray app and a real VPN drop stay unverified live; install guides and release notes say so plainly, and these releases are pre-releases.
- S5 (L4): ".deb + .tar.gz (recomendado)". Linux ships a `.deb` (depends on `nftables`; covers Ubuntu, Debian, Mint) and a `.tar.gz`. The guide says the tray icon works out of the box on Ubuntu and needs the AppIndicator extension on other GNOME desktops.
- S6 (L5): "Instalador .exe (recomendado)". Windows ships an `.exe` installer: Start menu shortcut, uninstall from Settings, service installed with UAC. Unsigned, so the guide explains SmartScreen's "Más información → Ejecutar de todas formas".
- S7 (AGENTS.md rule 4, fail closed): on every OS, when the VPN interface is unknown, is a physical or other non-VPN interface, or the rules cannot be verified, protected traffic is blocked, never allowed. Linux must never accept `eth0`, `enp*`, `wlan0`, `wlp*`, `docker0`, bridges, veth pairs or loopback as the VPN (today's macOS-only list would accept them).
- S8 (parity with macOS authorization): only administrators can change protection through the daemon: root, or members of the administrators group (Linux: `sudo`, `wheel` or `admin`; Windows: Administrators, also when the app runs without elevation). Anyone else gets `not authorized`.
- S9 (AGENTS.md rules 6-8): test first; repository artifacts in English; install guides in Spanish then English like `docs/install-macos.md`; tests and docs in the same slice as the behavior.

## Design (parent decision)

- Shared: a firewall interface (`Apply`, `Flush`, `Enabled`, `Verify(vpn, services)`, `BlockCount`, `ErrNotLoaded`) and a service-manager interface (install, uninstall, installed, legacy, last log line). Only `main` picks the per-OS implementation; tests pick backends explicitly so the whole suite runs on every OS.
- Linux firewall: nftables through `nft` (exec runner, like `pfctl`): table `inet leakguard`, interval sets of protected IPv4 and IPv6 destinations, an output-hook chain that rejects protected destinations whose output interface is not the VPN, with a counter (block count). Verification reads `nft -j`. The probe must see `ECONNREFUSED`.
- Linux service: systemd unit `/etc/systemd/system/leakguard.service` running the root-owned copy `/usr/local/libexec/leakguard/leakguard serve`, `Restart=always`, started before the network (`network-pre.target`). Config `/etc/leakguard/config.json`, stats `/var/lib/leakguard/stats.json`, log `/var/log/leakguard.log`.
- Linux IPC: `/run/leakguard.sock`, `root:<admin group>` mode 0660; peer check with `SO_PEERCRED` plus the peer's groups.
- Linux probe: `SO_BINDTODEVICE`.
- Linux VPN detection: by kernel facts (sysfs: physical `device`, wireless, bridge, veth, loopback, link type), not only by name. A VPN interface that does not exist yet (VPN down) is judged by name, so the Linux daemon must re-check the saved VPN on every apply and verify: when it exists and is refused (not a tunnel), it loads rules that allow no interface, so protected traffic stays blocked (T3/T4).
- Linux tray: `fyne.io/systray` (DBus StatusNotifierItem), dialogs through `zenity` (fallback `kdialog`), elevation with `pkexec`, language from `LANGUAGE`/`LC_ALL`/`LC_MESSAGES`/`LANG`, login item in `~/.config/autostart`.
- Windows: persistent WFP filters (block protected destinations unless the local interface is the VPN), Windows service, named pipe with an ACL plus an administrators check, `IP_UNICAST_IF` probe, tray dialogs and UAC elevation, `HKCU\...\Run` login item, `%ProgramData%\leakguard`. The WFP library (own bindings or an existing one) is chosen at T9 after research.

## Tasks

| ID | Task | Specs | Route | Commit |
|---|---|---|---|---|
| T1 | Per-OS VPN interface rules (Linux by sysfs facts; Windows refuses until T10) and per-OS config/stats paths | S2, S7 | worker | done, pending commit |
| T2 | Firewall and service-manager interfaces; CLI and daemon depend on them; cross-OS build/vet in CI | S1, S2 | worker | done, pending commit |
| T3 | Linux nftables backend + privileged integration test (Docker, CI ubuntu) | S1, S4, S7 | | |
| T4 | Linux systemd service and paths; `enable`/`disable`/`status`/`apply`/`serve` on Linux | S1, S7 | | |
| T5 | Linux IPC peer check and `leakguard test` probe | S1, S8 | | |
| T6 | Linux tray app: systray, zenity/kdialog dialogs, pkexec, language, autostart | S1 | | |
| T7 | Linux packages (.deb + .tar.gz), release job, `docs/install-linux.md`, README/CHANGELOG | S4, S5 | | |
| T8 | Linux verification (independent, high-risk) and end-to-end run in Docker | all | parent | |
| T9 | Windows WFP backend + CI integration test | S1, S4, S7 | | |
| T10 | Windows service, paths and VPN interface rules | S1, S7 | | |
| T11 | Windows IPC (named pipe) and probe | S1, S8 | | |
| T12 | Windows tray app | S1 | | |
| T13 | Windows `.exe` installer, release job, `docs/install-windows.md` | S4, S6 | | |
| T14 | Windows verification | all | parent | |

## Log

- L1 (owner, 2026-11-22): "ahora necesitamos que funcione en linux y en windows, ya en mac va perfecto"
- L2 (owner, order): "Linux primero, luego Windows (recomendado)"
- L3 (owner, real machines): "Ninguna: solo CI y Docker"
- L4 (owner, Linux packages): ".deb + .tar.gz (recomendado)"
- L5 (owner, Windows packages): "Instalador .exe (recomendado)"
- L6 (evidence, 2026-11-22): `GOOS=linux` and `GOOS=windows` `go build ./...` and `go vet ./...` pass today only because every macOS seam has a stub that fails closed: `ipc/peer_other.go` refuses every peer, `cmd/leakguard-menubar/main_other.go` exits 1, `probe/dial_other.go` returns `ErrNotSupported`, `daemon/owner_other.go` fails. CI runs `go test` on `ubuntu-latest` and `macos-latest`, no Windows runner. `pf.Firewall` and `daemon.Daemon` are concrete structs used directly by `cmd/leakguard`. `config.VPNCandidates` only knows macOS interface names (`config.go:40-43`), so on Linux it would accept `eth0`/`wlan0`. Docker (linux/arm64) is available locally; the Parallels VM "Windows 11" is `invalid`.
- L7 (T1/T2 workers, 2026-11-22): T1 adds `internal/config/vpn.go` (`classifyLinux` over sysfs facts, injectable root; unreadable `type`/`flags` refuse; a missing interface is judged by name, refusing `lo, eth, en, wl, ww, docker, br, virbr, veth, dummy, bond`), per-OS `config.DefaultPath`/`stats.DefaultPath` (now `var`), Windows refuses every VPN. T2 adds `internal/firewall` (`Firewall` with `Name`, `Apply`, `Flush`, `Enabled`, `Verify`, `BlockCount`; `ErrNotLoaded`, `ErrUnsupported`), `daemon.Manager`, `Env.Firewall`/`Env.Services` factories picked in `main` (darwin: pf + launchd; else unsupported, fail closed: `leakguard: cannot protect services on this computer: this operating system is not supported yet (<GOOS>)`, exit 1, no config written), and cross-OS `go vet` in CI. Known: PPPoE `ppp0` is accepted as a tunnel (link type 512); the CLI usage text still names pf and macOS paths on every OS (T4). Parent fixed `TestServeLoadsTheRulesWithCorruptStats` (stats dir differs from config dir on Linux) and skipped `TestServePauseWithAFailedSaveNeverDoubleCounts` as root (root ignores directory permissions).
