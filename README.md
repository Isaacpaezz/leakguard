<a id="top"></a>

<h1 align="center">🛡️ leakguard</h1>

<p align="center"><strong>When your VPN drops, the services you choose, such as Claude, go offline instead of leaking through your real connection.</strong></p>

<p align="center">
  <a href="https://github.com/Isaacpaezz/leakguard/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Isaacpaezz/leakguard/ci.yml?branch=main&style=for-the-badge&label=CI" alt="CI status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-2ea44f?style=for-the-badge" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/macOS%20·%20Linux%20·%20Windows-planned-blue?style=for-the-badge" alt="Platforms">
</p>

<p align="center">
  <a href="#how-it-works">How it works</a> ·
  <a href="#supported-services">Services</a> ·
  <a href="#whats-new">What's new</a> ·
  <a href="#roadmap">Roadmap</a> ·
  <a href="CONTRIBUTING.md">Contribute</a> ·
  <a href="#en-español">Español</a>
</p>

---

## The problem

In countries like Venezuela, many AI services (Claude, OpenAI and others) are
restricted, so people reach them through a VPN. Tools such as VPN Bypass send
**only** that traffic through the VPN and leave everything else on the normal
connection (*split tunneling*).

The risk shows up when the VPN drops. The operating system quietly falls
back to the real connection, and the service sees your real IP address.

## The idea

leakguard is a **kill switch for the services you choose**, not for the whole
computer:

- ✅ You pick what to protect: Claude, OpenAI, or several services at once.
- 🔒 Those services can **only** be reached through the VPN.
- 📴 If the VPN drops, those services act as if there were no internet. They
  never try your real connection.
- 🌐 Everything else (email, YouTube, banking) keeps working normally.

The goal is something as simple as VPN Bypass: an icon in the menu bar or
system tray that shows whether you are protected, and a list of services you
can tick on and off.

## How it works

leakguard does **not** wait to "notice" that the VPN dropped. That approach would
leave a window where traffic could leak. Instead, the firewall allows packets
to the protected services **only** on the VPN interface:

```
pass  out quick on <vpn-interface> to <protected-services> keep state
block return out quick to <protected-services>
```

If the VPN interface is gone, no allowed path is left and the connection fails
immediately: in about 8 ms in our macOS tests. No detection race, and no leak.

| OS      | Firewall used                                           | Status       |
|---------|---------------------------------------------------------|--------------|
| macOS   | `pf` anchor + LaunchDaemon                              | 🚧 In review |
| Linux   | `nftables` table: drop to the set when `oifname` ≠ VPN  | 🗓️ Planned   |
| Windows | Windows Filtering Platform / Windows Firewall rules     | 🗓️ Planned   |

## Supported services

IP ranges live in [`catalog/services/`](catalog/services/), one file per
service, each with the sources that prove its ranges. This table is generated
from that catalog, so it is always current.

<!-- BEGIN GENERATED: services -->
| Service | Profile | Status | IPv4 ranges | IPv6 ranges | Last verified |
|---|---|---|---|---|---|
| Anthropic (Claude) | `anthropic` | ✅ Supported | 5 | 1 | 2026-11-15 |
| OpenAI (ChatGPT, Codex) | `openai` | 🗓️ Planned | – | – | – |
<!-- END GENERATED: services -->

Missing a service? [Request it](https://github.com/Isaacpaezz/leakguard/issues/new?template=service_request.yml).

## What's new

<!-- BEGIN GENERATED: whats-new -->
**Not released yet** · changes on `main`

**Added**
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

**Changed**
- Menu-bar app: the first setup is a guided 3-step setup in native macOS dialogs, in the Mac's language (Spanish or English): choose the services, find your VPN by disconnecting and reconnecting it (no interface names), and turn the protection on after a warning that the Mac will ask for your password once. Cancelling any step changes nothing. Once set up, the menu shows a plain status, the services, "Change VPN…", pause or resume, and quit; the VPN interface submenu is gone.
- Menu-bar app: the VPN interface list shows only connected VPN interfaces, not idle system tunnels.
- `leakguard test` fails unless every domain of a protected service has a refused address, and reports a resolved address outside the catalog ranges as `NOT COVERED` (pf does not block it).
- `leakguard test` picks your real connection itself when the default route is the VPN, and stops with a clear message when the `--via` interface is not connected.
- `sudo leakguard status` reports NOT PROTECTED when pf is disabled, and `status` shows the last background run.
- The background service logs every run to `/Library/Logs/leakguard.log`, and `enable` waits for the old service to unload before loading the new one, retrying once.
- `sudo leakguard apply` and `sudo leakguard enable` end a pause from the menu-bar app, so the protection comes back after a reboot.
- The menu-bar app no longer gets stuck when the background service runs without a choice: choose the VPN interface first and tick a service, or tick a service and the only connected VPN is used.
- The menu-bar app clears the error line once the background service answers again, and shows why "Set up leakguard…" failed even when the prompt printed nothing.
- The background service's pause command is now `pause` instead of `disable`, so it never reads like `sudo leakguard disable`, which uninstalls. Apps ignore status fields they do not know, so a newer background service keeps working with an older app.
<!-- END GENERATED: whats-new -->

Full history: [CHANGELOG.md](CHANGELOG.md).

## Try it today (macOS)

> ⚠️ Early stage. macOS only. Needs [Go](https://go.dev/dl/) 1.25 or newer.

```sh
go install github.com/Isaacpaezz/leakguard/cmd/leakguard@latest
# or, from a clone of this repository: go build ./cmd/leakguard

leakguard services                             # what you can protect
leakguard interfaces                           # find your VPN interface (connect the VPN first)
sudo leakguard enable --vpn ipsec0 anthropic   # protect Claude through ipsec0
leakguard status                               # what is protected (sudo also verifies the rules)
leakguard test                                 # prove Claude is refused outside the VPN
sudo leakguard disable                         # turn it off; your choices are kept
```

`enable` loads the firewall rules and installs a background service
(`leakguard serve`, run by macOS as root) that re-applies them at boot and
every 30 seconds and logs each run to `/Library/Logs/leakguard.log`. The same
service also listens on `/var/run/leakguard.sock` for the menu-bar
app, so you can change services without typing your password each time. Only
administrators of the Mac can talk to it: the socket belongs to the `admin`
group, and the service checks who is calling and refuses everyone else.
`leakguard status` asks it, so it can tell you PROTECTED without `sudo`.
If the VPN interface goes down, the protected
services stop working until it is back. `test` connects through your real
connection (Wi-Fi or Ethernet) and finds it by itself even when the default
route is the VPN; name it with `--via IFACE` if you have several. Run
`leakguard help` for every option.

The earlier shell prototype in [`prototypes/macos-pf`](prototypes/macos-pf/README.md)
is kept as a legacy reference. If you installed it, remove it with
`sudo prototypes/macos-pf/uninstall.sh` before using `leakguard`.

## Menu-bar app (macOS)

> ⚠️ Early stage. Build it from a clone of this repository; it needs the
> Xcode command line tools (`xcode-select --install`).

```sh
go build -o leakguard ./cmd/leakguard
go build -o leakguard-menubar ./cmd/leakguard-menubar && ./leakguard-menubar
```

A shield appears in the menu bar:

| Icon | Meaning |
|---|---|
| Filled shield | Protected: the ticked services can only use the VPN. |
| Shield outline | Not protected, or paused. The first line of the menu says why. |
| Shield with a slash | leakguard is not set up on this Mac (its background service is not running). |

The first time, no terminal is needed: the app opens a guided setup by
itself, in your Mac's language (Spanish when your first preferred language is
Spanish, English otherwise). You can also open it from "Set up leakguard
(3 steps)…" in the menu. Each window is titled "Step N of 3":

1. Choose what to protect. Services that are not supported yet are listed as
   "coming soon" and cannot be chosen.
2. Find your VPN: disconnect it and click Next, then connect it again and
   click Next. The VPN is the connection that appeared; you never need to
   know names like `utun4` or `ipsec0`. If none appeared, retry or choose
   from a list; if several appeared, you choose.
3. Turn the protection on. The window tells you first that your Mac will ask
   for your login password, once, to install the background service; then
   the macOS password prompt says why. It runs
   `leakguard enable --vpn IFACE SERVICE...` once as administrator.

Cancelling any step changes nothing. A last window confirms what is protected.
Upgrading from an older leakguard (one installed before the menu-bar app,
whose background service only re-applied the rules) uses the same setup with
the `leakguard` command next to the app (build it as above); if there is none,
the app tells you to put it there or run `sudo leakguard enable`.

Once set up, the menu shows a plain status ("Protected", "Paused", ...), one
checkbox per service, "Change VPN…" (step 2 again, no password), "Pause
protection" or "Resume protection", and "Quit". Changes need no password: the
background service only listens to administrators of the Mac, so the app must
run in an administrator's account. Unticking the last service pauses the
protection. Technical details, such as the VPN interface name, are in the
icon's tooltip. `sudo leakguard enable` and `sudo leakguard apply` also end a
pause.

Anything run as administrator uses the installed copy
`/usr/local/libexec/leakguard/leakguard` only when it is current and it, and
every folder above it, belongs to root and nobody else can change it;
otherwise the app refuses and asks you to reinstall with
`sudo leakguard enable`. The `leakguard` next to the app is used only for the
first install or to update an older one.

"Quit" closes only the menu-bar app; the protection keeps running in the
background. To turn it off, use "Pause protection" or `sudo leakguard disable`.

## Roadmap

| # | Milestone | Status |
|---|-----------|--------|
| 0 | Open source foundation: contributing rules, self-updating README | ✅ Done |
| 1 | Go CLI for macOS: profiles from the catalog, `enable`, `disable`, `status`, `test` | 🚧 In review |
| 2 | Menu-bar app on macOS: protection status and service checkboxes | 🚧 In progress |
| 3 | Linux backend (`nftables`) and tray app | 🗓️ Planned |
| 4 | Windows backend and tray app | 🗓️ Planned |
| 5 | Self-updating IP catalog and domain-aware blocking for CDN-hosted services | 🗓️ Planned |
| 6 | Installers and releases (Homebrew, winget, packages) | 🗓️ Planned |

Design notes and lessons learned: [docs/HANDOFF.md](docs/HANDOFF.md).

## Contributing

Contributions are welcome. The most valuable one today is **keeping service IP
ranges accurate**. Read [CONTRIBUTING.md](CONTRIBUTING.md) to get started.
Using an AI assistant? Read [AGENTS.md](AGENTS.md) too.

- 🐛 [Report a bug](https://github.com/Isaacpaezz/leakguard/issues/new?template=bug_report.yml)
- ➕ [Request or update a service](https://github.com/Isaacpaezz/leakguard/issues/new?template=service_request.yml)
- 💡 [Suggest a feature](https://github.com/Isaacpaezz/leakguard/issues/new?template=feature_request.yml)
- 🔐 Found a leak or a security problem? Follow [SECURITY.md](SECURITY.md), not a public issue.

## Responsible use

leakguard is privacy and leak-prevention software. You are responsible for
following the terms of use of your VPN provider, your employer and every
service you protect.

## En español

**leakguard** bloquea Claude, OpenAI o los servicios que elijas cuando tu VPN
se cae. En lugar de usar tu conexión real y exponer tu IP, esos servicios
quedan sin internet hasta que la VPN vuelve. El resto de tu computadora sigue
funcionando con normalidad.

Está pensado para países como Venezuela, donde estos servicios están
restringidos y se usan a través de una VPN con *split tunneling* (por ejemplo,
VPN Bypass). La meta es que sea igual de sencillo: un ícono en la barra de
estado que te dice si estás protegido y una lista de servicios para marcar.

El proyecto está en una etapa temprana. Hoy existe una herramienta de línea
de comandos para macOS (ver "Try it today"). ¿Quieres colaborar? Lee [CONTRIBUTING.md](CONTRIBUTING.md); puedes
abrir issues en español.

## License

[MIT](LICENSE) © 2026 Isaac Paez

<p align="right"><a href="#top">Back to top ↑</a></p>
