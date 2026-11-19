# Feature: macOS installer (milestone 6, macOS part)

A `leakguard.app` that people download as a `.dmg` from GitHub Releases, drag to Applications, open once, and that stays in the menu bar after every login.
Branch `feat/macos-installer`; delivered as one PR to `main`. Publishing a release (pushing a `v*` tag) stays the maintainer's decision.

## Specs

- S1 (L1, owner choice): "DMG en GitHub Releases (Recomendado)": one `.dmg` per version with `leakguard.app` and an Applications shortcut; open, drag to Applications, done. A release workflow builds it when a `v*` tag is pushed and attaches it, with a SHA-256 checksum file, to the GitHub Release.
- S2 (L1, owner choice): "Sin firma por ahora (Recomendado)": the app is not signed with an Apple Developer ID yet. The README and a short guide inside the DMG explain the one-time "Abrir igualmente" step in plain words, for macOS 15 and later (System Settings > Privacy & Security > Open Anyway); signing can be added later without changing the bundle layout.
- S3 (prior owner request, milestone 6 in the roadmap and this session): the menu-bar icon must survive a restart: the app opens by itself at login. It is on by default and can be turned off from the menu ("Abrir al iniciar sesión"), with no password.
- S4 (setup-wizard S1-S3, simplicity): after dragging to Applications, opening the app starts the existing 3-step setup; the user never needs the terminal. The CLI ships inside the bundle next to the menu-bar binary, which `FindCLI` already uses on first run.
- S5 (normal users need a way out): the menu has "Desinstalar leakguard…", which explains what will happen, asks for the Mac password once (with a plain-language prompt) to remove the background service and the rules, removes the login item, and tells the user they can then move the app to the Trash. Cancel changes nothing.
- S6 (AGENTS.md rules 4 and 10): an unsigned or quarantined CLI that macOS refuses to run must produce a plain-language explanation, never a silent failure; protection is never removed except by an explicit uninstall. Agents never push release tags.

## Design (parent decision)

- Bundle: `leakguard.app/Contents/{Info.plist, MacOS/leakguard-menubar, MacOS/leakguard, Resources/AppIcon.icns}`. `LSUIElement` true (no Dock icon), bundle id `dev.leakguard.menubar`, minimum macOS 13, version from the tag. Universal binaries (arm64 + amd64, `lipo`), ad-hoc signed (`codesign -s -`).
- Build: a script (`scripts/build-macos.sh` or a Go tool under `tools/`) that builds both binaries with an injected version (`-ldflags -X`), assembles the bundle, makes the icon from the existing shield artwork, and creates the DMG with `hdiutil` (app, Applications symlink, the guide). Runs locally and in CI.
- Login item: a per-user LaunchAgent `~/Library/LaunchAgents/dev.leakguard.menubar.plist` (RunAtLoad, runs the app executable from wherever the bundle lives), written by the app on first launch and removed when the menu toggle is turned off or on uninstall. Pure plist rendering and decision logic in `internal/menubar`, tested.
- Quarantine: verify live whether `do shell script ... with administrator privileges` can run the quarantined CLI inside a downloaded bundle; if macOS refuses, the app clears the quarantine attribute on its own embedded CLI after the user opened the app (the user already approved the bundle) or explains the step; the chosen path is documented and tested.
- `leakguard version` and the menu tooltip show the version.
- Release workflow `.github/workflows/release.yml`: on `v*` tags, macOS runner, build, DMG, checksums, attach to the GitHub Release with notes from the newest CHANGELOG section; least-privilege permissions (`contents: write` only there); pinned action versions.

## Tasks

| ID | Task | Specs | Route | Commit |
|---|---|---|---|---|
| T1 | Version injection, bundle + icon + DMG build script, release workflow | S1, S2 | worker | c27a10f |
| T2 | Login item (LaunchAgent) with menu toggle; uninstall flow; quarantine handling | S3, S5, S6 | worker | cfbc8c1 + fix |
| T3 | Docs (README install section es/en with the Open Anyway steps, guide in the DMG, CHANGELOG, HANDOFF, roadmap) | S2, S4 | worker | c5cb602 |
| T4 | Verification (release workflow = delivery risk; root uninstall), local DMG build, owner live install from the DMG | all | parent | |

## Log

- L1 (owner, 2026-11-19): "si" to starting the macOS installer, then chose "Sin firma por ahora (Recomendado)" and "DMG en GitHub Releases (Recomendado)".
- L2 (evidence): the owner's Mac runs macOS 26 (Darwin 25); since macOS 15 the right-click > Open bypass for unsigned apps is gone, replaced by System Settings > Privacy & Security > Open Anyway.
- L3 (parent decisions): LaunchAgent instead of SMAppService (works without a Developer ID); universal binaries; uninstall in the menu; no tag is pushed by agents.
- L4 (verification, escalated items 5 and 2): no blockers. Release workflow scope, permissions, tag quoting, --verify-tag and the version guard in the build script held; a clean build produced a valid universal ad-hoc signed app and DMG. Fixed in the next commit with RED->GREEN: quarantine clearing followed symlinks (now Lstat + regular file inside the own bundle, `xattr -s`); the login item was written when the app ran from the DMG or App Translocation (now skipped there, with a "Move leakguard to Applications" hint); preference and agent reads blocked on a FIFO; unreadable quarantine state is explained. Notes kept: actions pinned by tag not SHA; 0.x releases are prereleases.
