# Changelog

All notable changes to leakguard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

The newest section is shown automatically on the README landing page.

## [Unreleased]

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
