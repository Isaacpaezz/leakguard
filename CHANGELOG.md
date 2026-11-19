# Changelog

All notable changes to leakguard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

The newest section is shown automatically on the README landing page.

## [Unreleased]

### Added
- `leakguard` CLI for macOS: `services`, `interfaces`, `enable`, `disable`, `status`, `test` and `apply`, with services taken from the catalog.
- `sudo leakguard enable --vpn ipsec0 anthropic` protects the chosen services and installs a LaunchDaemon that loads the rules at boot and verifies them every 30 seconds.
- `leakguard test` proves the protection: it connects to each protected address through your normal connection and expects a refusal.
- Service catalog (`catalog/services/*.json`) with Anthropic (Claude) supported and OpenAI planned.
- Self-updating README: the service table and this section are generated from the catalog and this file, and CI blocks changes that leave it stale.
- Contributor guide, issue and pull request templates, code owners, security policy and agent rules.
- macOS `pf` prototype that blocks Claude when the VPN is down.
- The background service now runs `leakguard serve`: it stays running, verifies the rules every 30 seconds and listens on `/var/run/leakguard.sock` for the menu-bar app. Only administrators can talk to it, and it can pause the protection without uninstalling.
- macOS menu-bar app (`leakguard-menubar`): a shield shows whether you are protected; tick services, choose the VPN interface, and pause or resume without a password. The first setup happens in the menu too: tick services, choose the VPN, and "Set up leakguard…" installs it with one administrator prompt, and updates an older install the same way.
- `leakguard status` without `sudo` asks the background service, which verifies the rules as root, so it reports PROTECTED or NOT PROTECTED without a password.
- Session stats: the menu shows how long the VPN has been connected ("VPN conectada hace 2 h 15 min") or disconnected, and today's blocks and VPN drops ("Hoy: 14 bloqueos · la VPN se cayó 2 veces"); the icon's tooltip adds today's time on the VPN. `leakguard status` prints the same. A block is one packet rejected by leakguard's rule, an approximate count of blocked connection attempts. "Today" starts at local midnight; the numbers are kept in `/Library/Application Support/leakguard/stats.json` and survive restarts. With no blocks or no drops today, `leakguard status` says "no blocks" and "VPN never dropped". The stats never delay the protection: the rules load before the stats file is read, a stats file that is not a regular file is ignored, and the file is saved in the background.

- macOS installer: `leakguard-VERSION-macos.dmg` on GitHub Releases with `leakguard.app` (universal for Apple silicon and Intel, macOS 13 or newer), an Applications shortcut and the guide "Cómo abrir leakguard" ([docs/install-macos.md](docs/install-macos.md)), plus a SHA-256 checksum file. Drag the app to Applications, allow it once ("Open Anyway"; it is not signed with an Apple certificate yet) and the 3-step setup does the rest, with no terminal. Releases are built by a workflow when the maintainer pushes a `v*` tag; `scripts/build-macos.sh VERSION` builds the same DMG locally.
- The menu-bar app opens at login when it runs from `leakguard.app` (a per-user LaunchAgent, no password), and "Open at login" in the menu turns that off. Opened from the disk image (or from a copy macOS moved aside), it never writes the login item and the menu says "Move leakguard to Applications so it opens at login" instead; setup and uninstall only ask you to move the app to Applications first. Turning "Open at login" on or off either fully works or changes nothing and says why.
- "Uninstall leakguard…" in the menu: one password prompt removes the protection rules and the background service, then the login item; cancelling changes nothing. Then drag the app to the Trash.
- `leakguard version`; the menu's tooltip shows the version too.
- If macOS keeps the download quarantine mark on the `leakguard` command inside the app, the app clears it from that one file before running it (only when it is a regular file inside the app, never through a symlink), or explains what to do; so does any failure to read the mark.

### Changed
- The background service checks the rules every 30 seconds and loads them again only when the check fails or the saved choice changed, instead of reloading them every time, so the firewall keeps its block counters.
- Menu-bar app: the first setup is a guided 3-step setup in native macOS dialogs, in the Mac's language (Spanish or English): choose the services, find your VPN by disconnecting and reconnecting it (no interface names: the app names its kind, such as "IPsec VPN", and you can choose another), and turn the protection on after a warning that the Mac will ask for your password once. Cancelling any step changes nothing; any other failure is explained in plain words in a dialog and on the menu. The setup opens by itself only when the app starts and leakguard is not set up or needs an update, never when the background service restarts later. Once set up, the menu shows a plain status, the services, "Change VPN…", pause or resume, and quit; the VPN interface submenu is gone.
- Menu-bar app: the VPN interface list shows only connected VPN interfaces, not idle system tunnels.
- `leakguard test` fails unless every domain of a protected service has a refused address, and reports a resolved address outside the catalog ranges as `NOT COVERED` (pf does not block it).
- `leakguard test` picks your real connection itself when the default route is the VPN, and stops with a clear message when the `--via` interface is not connected.
- `sudo leakguard status` reports NOT PROTECTED when pf is disabled, and `status` shows the last background run.
- The background service logs every run to `/Library/Logs/leakguard.log`, and `enable` waits for the old service to unload before loading the new one, retrying once.
- `sudo leakguard apply` and `sudo leakguard enable` end a pause from the menu-bar app, so the protection comes back after a reboot.
- The menu-bar app no longer gets stuck when the background service runs without a choice: choose the VPN interface first and tick a service, or tick a service and the only connected VPN is used.
- The menu-bar app clears the error line once the background service answers again, and shows why "Set up leakguard…" failed even when the prompt printed nothing.
- The background service's pause command is now `pause` instead of `disable`, so it never reads like `sudo leakguard disable`, which uninstalls. Apps ignore status fields they do not know, so a newer background service keeps working with an older app.
