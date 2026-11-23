# Contributing to leakguard

Thanks for helping. leakguard protects people whose real IP must never reach
certain services, so we put **correctness before features**. You can write
issues and pull requests in English or Spanish.

## TL;DR

1. Open or pick an issue first. For anything beyond a typo, wait for a 👍 from the maintainer.
2. Branch from `main`: `type/short-description` (for example `catalog/add-gemini`).
3. Make the change with its tests and docs. Run the checks below.
4. Open a pull request with the template and link the issue (`Closes #N`).
5. The maintainer reviews and decides. CI must be green.

## Who decides

leakguard has one maintainer ([@Isaacpaezz](https://github.com/Isaacpaezz)).
Every pull request needs their approval: `.github/CODEOWNERS` requests their
review automatically, and branch protection blocks merges without it. A
pull request can be declined even if it works, for example when it adds
complexity that goes against the "simple like VPN Bypass" goal. Opening an
issue first avoids that disappointment.

## Ways to help

| Contribution | Where | Notes |
|---|---|---|
| Add or update a service | `catalog/services/<id>.json` | The most valuable contribution. See [the skill](skills/add-service/SKILL.md). |
| Report a bug | [Bug report](https://github.com/Isaacpaezz/leakguard/issues/new?template=bug_report.yml) | Remove private IPs and server names. |
| Report a leak or vulnerability | [Private advisory](https://github.com/Isaacpaezz/leakguard/security/advisories/new) | Never in a public issue. See [SECURITY.md](SECURITY.md). |
| Test on your OS or VPN | Issues | Reports from Linux, Windows and other VPN clients help a lot. |
| Code | Pull request | Start from an issue labeled `status:approved`. |

## Development setup

You need [Go](https://go.dev/dl/) (the version in `go.mod` or newer).

```sh
go test ./...                    # unit tests
go vet ./...                     # static checks
gofmt -l .                       # must print nothing
go run ./tools/readmegen         # regenerate the README landing sections
go run ./tools/readmegen -check  # what CI runs
```

## Build the macOS app

On macOS with Go and the Xcode command line tools (`xcode-select --install`):

```sh
scripts/build-macos.sh 0.0.0-local
```

It builds `dist/leakguard.app` (universal for Apple silicon and Intel,
ad-hoc signed) and `dist/leakguard-0.0.0-local-macos.dmg` with its `.sha256`
file. `dist/` is ignored by git; never commit it. CI runs the same script on
every pull request without uploading anything.

## Build the Linux packages

On Linux with Go, GNU tar, `dpkg-deb` 1.19 or newer and `sha256sum` (any
Debian or Ubuntu has them):

```sh
scripts/build-linux.sh 0.0.0-local
```

On macOS, run it in Docker:

```sh
docker run --rm -v "$PWD":/src -w /src -e GOFLAGS=-buildvcs=false golang:1.25 scripts/build-linux.sh 0.0.0-local
```

For `amd64` and `arm64` it builds `dist/leakguard_0.0.0-local_ARCH.deb` and
`dist/leakguard-0.0.0-local-linux-ARCH.tar.gz` (static `leakguard` and
`leakguard-tray`, the `.desktop` file, the icon, the guide and the license),
each with its `.sha256`.

## Build the Windows installers

On Linux or macOS with Go, `makensis` (NSIS 3.04 or newer: `apt-get install
nsis` or `brew install makensis`) and `sha256sum` or `shasum`:

```sh
scripts/build-windows.sh 0.0.0-local
```

For `amd64` and `arm64` it builds the NSIS installer
`dist/leakguard-0.0.0-local-windows-ARCH-setup.exe` (the `leakguard.exe` CLI
and the `leakguard-tray.exe` tray app), each with its `.sha256`. The tray's
Windows resources are generated with go-winres during the build and removed
afterwards; never commit them.

Releases: only the maintainer pushes `v*` tags. Before tagging `vX.Y.Z`, the
newest section of `CHANGELOG.md` must be `## [X.Y.Z] - DATE`; the release
workflow (`.github/workflows/release.yml`) then tests, builds the DMG, the
Linux packages and the Windows installers, and creates the GitHub Release with that section as notes (versions below 1.0
are marked as pre-releases). Contributors and AI agents never push tags.

## The README updates itself

The landing page has generated sections between
`<!-- BEGIN GENERATED: ... -->` and `<!-- END GENERATED: ... -->` markers:

| Section | Source |
|---|---|
| Supported services | `catalog/services/*.json` |
| What's new | The newest section of `CHANGELOG.md` |

Do not edit inside those markers. Edit the source and run
`go run ./tools/readmegen`. CI fails any pull request whose README is stale,
so nothing reaches `main` without an up-to-date landing page.

## Catalog rules

A wrong range either leaks (missing range) or breaks unrelated sites (extra
range). That is why a catalog change is accepted only when:

- every range is canonical CIDR and has a **source** (official list, ASN prefixes, documentation);
- a `supported` service has IPv4 **and** IPv6 ranges, since a missing IPv6 range is a leak;
- `verified` is the date you checked the sources (`YYYY-MM-DD`);
- shared CDN addresses (Cloudflare, Google Cloud, Akamai, Fastly) are **not** added as ranges. Mark the service `planned` and explain why in `notes`.

`go test ./...` and `readmegen` validate the format; the maintainer checks the sources.

## Commits and pull requests

- [Conventional Commits](https://www.conventionalcommits.org/):
  `feat:`, `fix:`, `catalog:`, `docs:`, `test:`, `refactor:`, `ci:`, `chore:`.
- One logical change per pull request. Keep it around **400 changed lines or
  fewer** so it can be reviewed carefully. Split larger work into several
  pull requests, or explain in the description why it cannot be split.
- Tests and docs travel with the code they describe.
- Add a line under `[Unreleased]` in `CHANGELOG.md` for user-visible changes.

## AI-assisted contributions

AI tools are welcome. You remain the author: you must understand and be able
to explain every line, and you must say in the pull request which tool
helped. Agents must follow [AGENTS.md](AGENTS.md). Pull requests that look
generated and unreviewed, especially catalog ranges without sources, will be
closed.

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). Be kind and
assume good intent.
