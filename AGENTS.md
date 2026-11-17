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
| `cmd/leakguard` | The CLI: `services`, `interfaces`, `enable`, `disable`, `status`, `test`, `apply`, `serve` (the daemon). `main` is a thin wrapper over a testable `run` with an injected `Env`. |
| `internal/ipc` | Socket protocol between the root daemon and the apps: one JSON request and response per connection, strict decoding, peer check (root or group `admin` only). |
| `internal/catalog` | Loads and validates the catalog, embedded in the binary. The CLI and the future tray app reuse it. |
| `internal/config` | The user's VPN interface and services; load, save, validate, VPN interface candidates. |
| `internal/pf` | macOS `pf` backend: renders, applies, flushes and verifies the `com.apple/250.leakguard` anchor. |
| `cmd/leakguard-menubar` | macOS menu-bar app (`fyne.io/systray`, needs cgo): draws `internal/menubar`, polls the daemon every 3 s, embeds the template icons made by `gen_icons.go`. Other systems get a stub that exits 1. The CLI must never import systray. |
| `internal/menubar` | The menu-bar app's logic without a GUI: status to menu description, clicks to `set`/`disable` requests, the first-run draft (clicks before setup stay local), plain-language errors, the validated and quoted "Set up" AppleScript. |
| `internal/daemon` | macOS LaunchDaemon `dev.leakguard` (runs `leakguard serve`, KeepAlive): root-owned binary copy, plist, `launchctl`. |
| `internal/probe` | `leakguard test`: connects to protected addresses outside the VPN and expects a refusal. |
| `internal/readme`, `tools/readmegen` | Generate the README landing sections. |
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
10. The maintainer decides what gets merged. Do not merge, push to `main`, publish releases or change repository settings.

## Skills

| Skill | Use it when |
|---|---|
| [`skills/add-service`](skills/add-service/SKILL.md) | Adding a service or updating its ranges or domains. |
