# Feature: README landing redesign and release 0.1.0 prep

Make the repository front page explain leakguard at a glance, with animations, and prepare the first public release, 0.1.0.
Branch `docs/readme-landing`; one PR to `main`. The maintainer pushes the `v0.1.0` tag.

## Specs

- S1 (L1): "también hay que actualizar el readme y la pantalla principal del repo, sería bueno colocar animaciones etc.." The README shows, near the top, an animated illustration of the core idea: the VPN is connected and Claude works; the VPN drops; leakguard blocks Claude instead of letting it use the real connection, while the rest of the internet keeps working; the VPN comes back and Claude works again.
- S2 (L2, owner choice "0.1.0 ahora"): the README presents 0.1.0 as the first public version for macOS (pre-release): a clear "Download for macOS" call to action that links to the Releases page, and the roadmap points to the 1.0 milestone (issues #8, #14, #15, #16) with Windows and Linux after 1.0.
- S3 (setup-wizard S1-S3, session-stats S1-S3): the README shows what a normal user sees: the menu (status, "VPN connected for …", "Today: N blocks …", services, Change VPN, Pause) and the 3 setup steps, as illustrations that match the real texts in internal/menubar/i18n.go.
- S4 (audience, L1 of the project: Venezuela and other restricted countries): the Spanish section is complete enough for a non-technical Spanish speaker to install and use leakguard (neutral Spanish, "tú").
- S5 (AGENTS.md rule 5): generated sections stay between their markers and are regenerated with `go run ./tools/readmegen`; `-check` passes.
- S6 (release prep, release.yml requires it): CHANGELOG gets a `## [0.1.0] - 2026-11-19` section with today's unreleased changes, so `tools/releasenotes -version 0.1.0` succeeds and "What's new" shows v0.1.0.

## Design (parent decision)

- Animations are self-contained SVG files under `docs/assets/` using CSS keyframes inside the SVG (GitHub renders animated SVG in `<img>`), with light and dark variants selected through `<picture>` and `prefers-color-scheme`, a `prefers-reduced-motion` rule that shows a static final frame, an `alt` text that tells the whole story, and no external fonts or scripts (system font stack). Keep each file small (under ~40 KB).
- Assets: `hero` (the VPN-drop story, 8-12 s loop), `menu` (the menu-bar menu with the real Spanish or English strings; one language per file is fine, English in the main README and Spanish in the Spanish section), `setup` (the 3 steps as three small cards).
- Keep the existing README section order where it works; tighten copy; badges: CI, license, latest release (shields.io `github/v/release` with `include_prereleases`), platform "macOS".
- No invented features: everything shown exists in the code today.

## Tasks

| ID | Task | Specs | Route | Commit |
|---|---|---|---|---|
| T1 | Animated SVG assets (hero, menu, setup), light and dark | S1, S3 | worker | |
| T2 | README rewrite (English + complete Spanish section), CHANGELOG 0.1.0, roadmap with the 1.0 milestone | S2, S4, S5, S6 | worker | |
| T3 | Check rendering, PR | all | parent | |

## Log

- L1 (owner, 2026-11-19): "si todo esta perfecto.. que esta sea la version 1.0.0 o que nos falta para tener la version 1?? tambien hay que actualizar el readme y la pantalla principal de repo, seria bueno colocar animaciones etc.."
- L2 (owner, 2026-11-19): chose "0.1.0 ahora (Recomendado)". Milestone "1.0" created with #8 (menu polish), #14 (ChatGPT/OpenAI), #15 (sign and notarize), #16 (self-updating IP ranges); Windows and Linux follow in 1.1 and 1.2.
- L3 (evidence): PR #13 merged (08c5011); the owner installed from a quarantined DMG and sees real usage (18 blocks, 1 VPN drop today).
