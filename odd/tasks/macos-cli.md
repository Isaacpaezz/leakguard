# Feature: macOS CLI (milestone 1)

Port the macOS pf prototype into a Go CLI whose services come from the catalog.
Branch `feat/macos-cli`; delivered as a PR to `main`. Tracking for the parent session.

## Specs

- S1 (L1, HANDOFF milestone 1): "Port the macOS prototype into the Go CLI. Profiles come from `internal/catalog`. Commands: `enable`, `disable`, `status`, `test`."
- S2 (L1): "que el usuario pueda configurar que quiere bloquear cloud, que quiere bloquear open I o cualquier otro" / "si quieren seleccionar varios": the user picks one or more catalog services; only `supported` services can be enabled.
- S3 (L1): "Que si la bpn se cae, entonces cloud no conecte internet. No intente ni siquiera conectarse a la IP real": traffic to selected services may leave only through the VPN interface; with the VPN down it is rejected immediately. Fail closed: rules must load even when the VPN interface does not exist.
- S4 (HANDOFF lesson 5): "Re-apply them on boot and periodically, and verify after applying." LaunchDaemon with RunAtLoad and a periodic re-apply.
- S5 (HANDOFF): "`test` reproduces the proof from the prototype: connect to each protected destination through the non-VPN interface and expect a refusal."
- S6 (HANDOFF lesson 3): "The VPN interface name varies ... The tool needs detection plus explicit configuration."
- S7 (L1): "debe ser un sistema muy sencillo muy fácil de usar".

## Tasks

| ID | Task | Specs | Route | Commit |
|---|---|---|---|---|
| T1 | Embed catalog in the binary (`catalog` package, `LoadFS`) | S1 | inline | |
| T2 | `internal/config`: load/save/validate, VPN interface candidates | S2, S6 | inline | |
| T3 | `internal/pf`: render anchor rules, apply/flush/status via pfctl runner, real `pfctl -n` syntax test on macOS | S3, S4 | inline | |
| T4 | `cmd/leakguard`: services, enable, disable, apply, status; LaunchDaemon install | S1, S2, S4, S6, S7 | inline | |
| T5 | `leakguard test`: off-VPN refusal probe via IP_BOUND_IF | S5 | inline | |
| T6 | Docs: README quickstart, CHANGELOG, HANDOFF, AGENTS layout; CI macOS job | S1, S7 | inline | |
| T7 | Independent verification (Risk item 2: root daemon, firewall) | all | gentle-ai-verify | |

## Log

- L1 (user, 2026-11-15): "Read README.md and docs/HANDOFF.md. Continue with the next milestone. ... El propósito principal de este proyecto es poder bloquear el cloud. Que si la bpn se cae, entonces cloud no conecte internet. No intente ni siquiera conectarse a la IP real, sino que detectó el sistema, que se cayó el BPN, lo que hace es que se cae el internet para ciertas IP. Entonces la idea es configurar que el usuario pueda configurar que quiere bloquear cloud, que quiere bloquear open I o cualquier otro. ... debe ser un sistema muy sencillo muy fácil de usar que aparezca como en la barra de estado ..."
- L2 (user, 2026-11-15): "si dale con lo siguiente" (start milestone 1 after publishing the repo).
- L3 (evidence): `pfctl -n` accepts `pass out quick on <missing-interface>` (exit 0), so rules load with the VPN down. `pfctl -n` works without root. Prototype daemon `com.isaacpaezz.anthropic-killswitch` is installed on the owner's Mac. Passwordless sudo is not available, so live `enable` must be run by the owner.
