# Feature: session stats in the menu

Show how the current session is going: how long the VPN has been connected, how many times leakguard blocked the protected services, and how often the VPN dropped today.
Branch `feat/session-stats`; delivered as one PR to `main`.

## Specs

- S1 (L1): "quiero que muestre algo así como cuánto tiempo tiene enrutado o conectado". The menu shows the current VPN session in plain words: "VPN conectada hace 2 h 15 min" / "VPN connected for 2 h 15 min", or when it is down "VPN desconectada hace 3 min" / "VPN disconnected for 3 min". A session starts when the saved VPN interface becomes connected and ends when it disconnects.
- S2 (L1): "cuántas veces bloqueó que claude o la herramienta hiciera el trabajo". The menu shows how many times leakguard blocked the protected services today, for example "Hoy: 14 bloqueos · la VPN se cayó 2 veces" / "Today: 14 blocks · VPN dropped 2 times". A block is one packet matched by leakguard's block rule (pf rule counters); the docs say it is an approximate count of blocked connection attempts, not of requests.
- S3 (L1): "y así saber cómo va la sesión, etc". The stats also appear in `leakguard status` (with and without sudo) and in the menu tooltip, plus today's time on the VPN ("Hoy: 5 h 20 min por la VPN"). "Today" resets at local midnight.
- S4 (AGENTS.md rule 4, fail closed): stats never change protection. A failure to read counters or to save stats is logged and ignored; it never skips or delays applying rules.
- S5 (counters survive reloads): pf resets rule counters when the anchor is reloaded, and today the daemon reloads every 30 s. The daemon must (a) reload only when verification fails or the configuration changes, and (b) read and add the block counter before any reload or flush, so no blocks are lost. Totals persist across daemon restarts in `/Library/Application Support/leakguard/stats.json` (root-owned, 0644).
- S6 (S5 of setup-wizard, simplicity): every new menu line fits `MenuLineLength` in both languages, uses no interface names, and adds no new clicks.

## Design (parent decision)

- `internal/stats` (pure): a `Tracker` fed with samples (`now`, VPN connected bool, block counter reading) that keeps the current session start, today's VPN time, today's drops (connected -> disconnected transitions), today's blocks (sum of non-negative counter deltas; a counter that goes down means it was reset, so the new value is the delta), and the day; it resets the daily totals at local midnight. Load/Save JSON with an injectable path and clock.
- Daemon (`serve`): sample the VPN state every 5 s (cheap, `net.Interfaces`) and the block counter on the existing 30 s tick and before every reload/flush (`pfctl -a <anchor> -s rules -v`, parse `Packets:` of the `block return` rule in `internal/pf`). Replace "re-apply every 30 s" with "verify every 30 s, reload only if verification fails". Save stats at most once a minute and on shutdown.
- Protocol: `ipc.Status` gets an optional `stats` object (session start or end time, connected, today's VPN seconds, today's blocks, today's drops, day). Responses are already decoded tolerantly by the app.
- Menu: two lines under the status (session line, today line) and the tooltip; `leakguard status` prints the same in plain text.

## Tasks

| ID | Task | Specs | Route | Commit |
|---|---|---|---|---|
| T1 | `internal/stats` tracker + persistence; `internal/pf` block counter parsing | S2, S3, S5 | worker | 4e0cd27 |
| T2 | Daemon: 5 s VPN sampling, verify-then-reload loop, counter read before reload/flush, stats in `ipc.Status`, `leakguard status` output | S1-S5 | worker | b28388a + fix |
| T3 | Menu lines and tooltip in es/en; docs | S1, S3, S6 | worker | f86e405 |
| T4 | Verification (protection loop changed), review, PR | all | parent | |

## Log

- L1 (owner, 2026-11-18): "si perfecto.. quyiero que muestre algo asi como cuanto tiempo tiene enrutado o conectado, cuantas veces bloqueo que claude o la herramienta hiciera el trabajo y asi saber como va la sesion, etc"
- L2 (owner, 2026-11-18): "si perfecto" also approved the setup wizard; PR #11 merged.
- L3 (parent decisions): "session" = since the saved VPN last connected; daily totals reset at local midnight; blocks counted from pf's block-rule packet counter (approximate, documented); stats live in the daemon so they keep counting when the menu app is closed.
- L4 (evidence): `cmd/leakguard/serve.go` `applySaved` calls `pf.Firewall.Apply` (anchor reload) every 30 s, which would reset pf counters every 30 s.
- L5 (verification, escalated item 4): no blockers; lock order, shutdown and reload-on-failed-verification hold (20x race runs). Should-fix F1 (a stats file that blocks on read delayed the forced load), F2 (fsync on the tick goroutine) and F3 (blocks lost between `set` and the load) fixed in the next commit with RED->GREEN, plus the verifier's eight probes as regression tests. Known limit: a reload that fails after pf loaded the anchor can undercount (never overcount).
- L6 (owner live check, 2026-11-19): daemon updated through the admin prompt (`enable_exit=0`); `leakguard status` without sudo showed `Session: VPN connected for 40 s` and `Today: no blocks · VPN never dropped`; `stats.json` root:admin 0644. `leakguard test` sent 4 off-VPN attempts (one per anthropic domain over IPv4) and the real pf counter reported exactly `4 blocks`; no counter or stats errors in /Library/Logs/leakguard.log. This confirms the `pfctl -s rules -v` parsing on macOS.
