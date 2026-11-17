# Feature: macOS menu-bar app (milestone 2)

A menu-bar icon that shows whether you are protected and lets you tick services, without a password prompt for every change.
Delivered as two stacked PRs: A (`feat/daemon-socket`): the root daemon listens on a socket. B (`feat/menu-bar-app`): the menu-bar app that talks to it.

## Specs

- S1 (L1, owner 2026-11-15): "debe ser un sistema muy sencillo muy fácil de usar que aparezca como en la barra de estado de la computadora ... como que está conectado que la configuración sea muy fácil que el usuario pueda elegir lo que quiere ... si quieren seleccionar varios ... así como funciona bypass bpm"
- S2 (L2, decision): option 2: "El servicio en segundo plano (root) escucha pedidos del ícono. Marcás casillas sin que te pida contraseña, como VPN Bypass ... restringida a los usuarios administradores de la Mac."
- S3 (AGENTS.md hard rule 4): "Fail closed. When the VPN interface is unknown or the rules cannot be verified, protected traffic must be blocked, never allowed."
- S4 (L3, decision): the menu-bar app is pure Go (systray), a separate binary from the CLI so the CLI stays cgo-free.

## Design (parent decision)

- Daemon: the LaunchDaemon runs `leakguard serve` (KeepAlive, RunAtLoad) instead of a periodic `apply`. `serve` applies the saved config at start and every 30 s, and listens on `/var/run/leakguard.sock`.
- Authorization: the socket is created by root with owner `root`, group `admin` (gid 80) and mode `0660`. macOS checks write permission on `connect()`, so only administrators can talk to the daemon. The server also checks the peer credentials (`LOCAL_PEERCRED`) and refuses peers that are not uid 0 or members of group 80. Both checks are required (defense in depth).
- Protocol (package `internal/ipc`): one JSON request and one JSON response per connection, newline-terminated, at most 64 KiB, 5 s deadline. Requests: `{"cmd":"status"}`, `{"cmd":"set","vpn_interface":"ipsec0","services":["anthropic"]}`, `{"cmd":"disable"}`. Unknown fields or commands are rejected. Response: `{"ok":true,"status":{...}}` or `{"ok":false,"error":"..."}`. Status fields: `protected` (bool, verified as root: pf enabled + anchor verified), `reason`, `vpn_interface`, `vpn_connected`, `services` (selected ids), `catalog` (id, name, status for every service), `last_run`.
- `set` validates with `config.Validate` against the embedded catalog, saves, applies, verifies; on any failure the previous rules stay loaded (fail closed). `disable` from the app means "pause": flush the anchor, keep the daemon running, and save `paused: true` in the config so the 30 s loop does not re-apply; `set` clears the pause. The CLI `sudo leakguard disable` keeps uninstalling everything.
- One mutex serializes the apply loop and requests (no concurrent pfctl).
- The CLI keeps working as root without the socket. `leakguard status` without sudo asks the daemon over the socket when it is reachable, so it can report PROTECTED without sudo.
- App (`cmd/leakguard-menubar`, dependency `fyne.io/systray`): icon "protected" / "not protected" / "daemon not installed"; menu: status line, VPN interface submenu (VPN candidates), one checkbox per supported service (planned ones shown disabled with "coming soon"), "Pause protection" / "Resume", "Quit". Polls `status` every 3 s. If the daemon is not installed, a "Set up leakguard…" item runs `leakguard enable` once through an administrator prompt (`osascript ... with administrator privileges`).

## Tasks

| ID | Task | Specs | Route | Commit |
|---|---|---|---|---|
| T1 | `internal/ipc`: protocol types, client, server with peer check; tests with a temp socket | S2, S3 | worker | 4d12945, fix 803f2bd |
| T2 | `leakguard serve` + plist KeepAlive + pause flag + `status` via socket; docs | S2, S3 | worker | 1fcab4d |
| T3 | Native review + PR A | all | parent | verify (escalated item 2): S2/S3 pass; PR A |
| T4 | `cmd/leakguard-menubar` with systray; icons; docs; CI build on macOS | S1, S4 | worker | |
| T5 | Native review + PR B; owner live check | all | parent | |

## Log

- L1 (owner, 2026-11-15): original request, quoted in S1.
- L2 (owner, 2026-11-16): "si mergea y dale con lo recomendado" (merge PR #6, build the menu-bar app with option 2: the root daemon listens to the app, restricted to administrators).
- L3 (owner, 2026-11-15): tray app technology "Go puro: servicio + systray (Recomendado)".
- L4 (evidence): admin group gid is 80 on the owner's Mac; `fyne.io/systray` latest is v1.12.2.
- L5 (interruption, 2026-11-16): the first T1-T2 worker was interrupted when the parent session ended; a second worker audited its uncommitted output against every requirement and added 2 tests.
- L6 (verification, escalated as Task Size item 2): S2 and S3 pass, no blockers. Fixed in 803f2bd with RED->GREEN: a second `serve` took over a live socket (and closing one unlinked the other's), and the socket was created with the inherited umask (0777 under umask 000) before chmod. Notes kept as known limits: only the 16 groups in xucred are checked (fails closed); JSON keys are matched case-insensitively by encoding/json; `set` saves before applying; `sudo leakguard apply` ignores `paused`.
