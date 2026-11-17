# Changelog

All notable changes to leakguard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

The newest section is shown automatically on the README landing page.

## [Unreleased]

### Added
- `leakguard` CLI for macOS: `services`, `interfaces`, `enable`, `disable`, `status`, `test` and `apply`, with services taken from the catalog.
- `sudo leakguard enable --vpn ipsec0 anthropic` protects the chosen services and installs a LaunchDaemon that re-applies and verifies the rules at boot and every 30 seconds.
- `leakguard test` proves the protection: it connects to each protected address through your normal connection and expects a refusal.
- Service catalog (`catalog/services/*.json`) with Anthropic (Claude) supported and OpenAI planned.
- Self-updating README: the service table and this section are generated from the catalog and this file, and CI blocks changes that leave it stale.
- Contributor guide, issue and pull request templates, code owners, security policy and agent rules.
- macOS `pf` prototype that blocks Claude when the VPN is down.
- The background service now runs `leakguard serve`: it stays running, re-applies the rules every 30 seconds and listens on `/var/run/leakguard.sock` for the menu-bar app. Only administrators can talk to it, and it can pause the protection without uninstalling.
- macOS menu-bar app (`leakguard-menubar`): a shield shows whether you are protected; tick services, choose the VPN interface, and pause or resume without a password. The first setup happens in the menu too: tick services, choose the VPN, and "Set up leakguard…" installs it with one administrator prompt, and updates an older install the same way.
- `leakguard status` without `sudo` asks the background service, which verifies the rules as root, so it reports PROTECTED or NOT PROTECTED without a password.

### Changed
- `leakguard test` fails unless every domain of a protected service has a refused address, and reports a resolved address outside the catalog ranges as `NOT COVERED` (pf does not block it).
- `leakguard test` picks your real connection itself when the default route is the VPN, and stops with a clear message when the `--via` interface is not connected.
- `sudo leakguard status` reports NOT PROTECTED when pf is disabled, and `status` shows the last background run.
- The background service logs every run to `/Library/Logs/leakguard.log`, and `enable` waits for the old service to unload before loading the new one, retrying once.
