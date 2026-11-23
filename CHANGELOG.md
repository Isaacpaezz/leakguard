# Changelog

All notable changes to leakguard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

The newest section is shown automatically on the README landing page.

## [Unreleased]

leakguard for Linux and Windows (pre-release). Their firewalls are tested
automatically with real nftables rules and real Windows Filtering Platform
filters, but the tray apps, the Windows installer on a real PC and a real VPN
drop have not yet been tried on a real Linux desktop or Windows PC: please
report any problem.

### Added
- Linux support: a `.deb` for Ubuntu, Debian and Mint (amd64 and arm64) and a `.tar.gz` for other distributions, each with a SHA-256 checksum and an install guide in Spanish and English ([docs/install-linux.md](docs/install-linux.md)). Removing the package also removes the rules and the background service; purging it also deletes your choices, the stats and the log. Upgrading the package restarts the background service with the new version, keeping your choices and the rules loaded.
- On Linux, an nftables firewall (table `inet leakguard`) rejects protected destinations outside the VPN at once, also for the traffic the computer forwards for containers and virtual machines (Docker, libvirt), and only real tunnels are accepted as the VPN: Ethernet, Wi-Fi, USB tethering, Docker, bridges and loopback never are.
- On Linux, a systemd service (`leakguard.service`) loads the rules before the network starts, checks them every 30 seconds and logs to `/var/log/leakguard.log` (rotated weekly, 4 weeks kept); only root and the administrators group (`sudo`, `wheel` or `admin`) can change the protection through it.
- On Linux, the tray app with the same menu, 3-step setup, session stats, "Open at login" and uninstall as on macOS, with zenity (or kdialog) windows and one administrator prompt per change through pkexec (never remembered for other programs).
- Windows support: `setup.exe` installers for Windows 10 and 11 (amd64 and arm64), each with a SHA-256 checksum and an install guide in Spanish and English ([docs/install-windows.md](docs/install-windows.md)). They always install to Program Files, which only administrators can change (another folder is refused), with a Start menu entry; uninstalling from Settings > Apps also removes the protection, and running a newer installer restarts the background service with the new version, keeping your choices. Not signed with a certificate yet, so Windows asks you to allow it once ("More info", then "Run anyway").
- On Windows, a Windows Filtering Platform firewall blocks protected destinations outside the VPN at once; its filters stay loaded across restarts of the background service, and only VPN adapters are accepted as the VPN: Ethernet, Wi-Fi, loopback and virtual machine adapters never are.
- On Windows, a Windows service (`leakguard`, run as SYSTEM, started at boot and restarted when it fails) checks the rules every 30 seconds and as soon as the VPN connects or drops, and logs to `C:\ProgramData\leakguard\leakguard.log`; only administrators can change the protection through it, also from the tray app without elevation.
- On Windows, the tray app with the same menu, 3-step setup, session stats, "Open at login" and uninstall as on macOS, in Spanish or English like Windows, with one administrator prompt (UAC) per change; when a change fails, it shows the reason. The blocks count is not shown on Windows yet.

### Changed
- Fail closed when the saved VPN turns out to be a real connection (for example a phone's USB tethering, which cannot be told apart from a VPN by its name while it is unplugged): the protected services are blocked on every interface until you choose your VPN again, instead of keeping rules that allowed it. `leakguard status` says why and `sudo leakguard apply` exits with an error.

## [0.1.0] - 2026-11-19

The first public version, for macOS (pre-release).

### Added
- `leakguard.app` for macOS 13 or newer (Apple silicon and Intel) in a DMG on GitHub Releases, with a SHA-256 checksum and an install guide in Spanish and English ([docs/install-macos.md](docs/install-macos.md)). It is not signed with an Apple certificate yet, so macOS asks you to allow it once ("Open Anyway").
- A shield in the menu bar shows whether you are protected. The menu has one checkbox per service, "Change VPN…", "Pause protection" and "Quit"; changes need no password.
- A guided 3-step setup in Spanish or English: choose what to protect, find your VPN by disconnecting and connecting it, and turn the protection on with one password prompt. No terminal needed; cancelling any step changes nothing.
- Protection for Anthropic (Claude), IPv4 and IPv6. When the VPN is down, Claude fails at once instead of using your real connection; the rest of the Mac keeps working. OpenAI is planned.
- Session stats in the menu and in `leakguard status`: "VPN connected for 2 h 15 min" and "Today: 14 blocks · VPN dropped 2 times".
- The app opens at login when it runs from Applications ("Open at login" in the menu turns that off), and "Uninstall leakguard…" removes the rules, the background service and the login item with one password prompt.
- A background service loads the rules at boot, checks them every 30 seconds, loads them again when the check fails, and logs to `/Library/Logs/leakguard.log`.
- `leakguard` command for macOS: `services`, `interfaces`, `enable`, `disable`, `status`, `test`, `apply` and `version`. `leakguard test` proves that each protected address is refused outside the VPN.
- Service catalog with sources for every range, a README that updates itself from the catalog and this file, a contributor guide, issue templates, a security policy and agent rules.
