# Changelog

All notable changes to leakguard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

The newest section is shown automatically on the README landing page.

## [Unreleased]

### Added
- `leakguard` CLI for macOS: `services`, `interfaces`, `enable`, `disable`, `status`, `test` and `apply`, with services taken from the catalog.
- `sudo leakguard enable --vpn ipsec0 anthropic` protects the chosen services and installs a LaunchDaemon that re-applies and verifies the rules at boot and every minute.
- `leakguard test` proves the protection: it connects to each protected address through your normal connection and expects a refusal.
- Service catalog (`catalog/services/*.json`) with Anthropic (Claude) supported and OpenAI planned.
- Self-updating README: the service table and this section are generated from the catalog and this file, and CI blocks changes that leave it stale.
- Contributor guide, issue and pull request templates, code owners, security policy and agent rules.
- macOS `pf` prototype that blocks Claude when the VPN is down.
