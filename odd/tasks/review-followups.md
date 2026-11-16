# Feature: review follow-ups before the first release (issue #5)

Close the non-blocking findings from the native reviews of the macOS CLI, plus one found in the owner's live run.
Branch `fix/review-followups`; delivered as a PR to `main` that closes #5.

## Specs

- S1 (issue #5): "`leakguard test` passes with partly untested domains. `probe.Check` accepts a service once one address is blocked, even when another domain is untested or resolves to addresses outside the catalog ranges (those are not blocked by pf). It should fail, or at least warn, when any domain of a protected service is untested or resolves outside the catalog."
- S2 (issue #5): "`status` ignores whether pf is enabled. `sudo leakguard status` says PROTECTED from the anchor contents only. If another tool runs `pfctl -d`, nothing filters until the next daemon run. Check `pfctl -s info` for `Status: Enabled`."
- S3 (issue #5): "`launchctl bootout` / `bootstrap` race. Re-running `sudo leakguard enable` can fail with `Bootstrap failed: 5` because bootout returns before launchd tears the job down, leaving the daemon unloaded while the plist stays. Wait for the job to disappear (`launchctl print system/dev.leakguard`) or retry."
- S4 (issue #5): "Daemon failures are not logged. The plist has no `StandardOutPath` / `StandardErrorPath`, so failing `apply` runs at boot leave no diagnostic. Log to `/Library/Logs/leakguard.log` and show the last error in `status`."
- S5 (issue #5 comment, live run): "`leakguard test` should pick the physical interface itself when the default route is the VPN (the default route was `ipsec0`, and `--via en0` pointed at an unplugged Ethernet port), and it should say clearly when the `--via` interface is inactive instead of reporting \"network is unreachable\"."

## Tasks

| ID | Task | Specs | Route | Commit |
|---|---|---|---|---|
| T1 | Probe strictness: every domain needs a blocked address; resolved addresses outside the catalog fail as possible leaks | S1 | worker | |
| T2 | `test` interface choice: auto-pick the connected physical interface when the default route is a VPN; clear error for an inactive `--via` | S5 | worker | |
| T3 | `status` checks pf is enabled | S2 | worker | |
| T4 | Daemon: wait for bootout before bootstrap (bounded); plist logs to `/Library/Logs/leakguard.log`; `status` shows the last log line | S3, S4 | worker | |
| T5 | Native review of the slice, PR closing #5 | all | parent | |

## Log

- L1 (user, 2026-11-16): "si dale continua" (after merging PRs #3 and #4; continue with the next step: issue #5 before the first release).
- L2 (evidence, live run 2026-11-16): owner's Mac: en0 = unplugged Ethernet, en1 = Wi-Fi (real connection, IPv4 only), default route = ipsec0. `test --via en1`: anthropic.com 160.79.104.10 `OK blocked`, 2607:6bc0::10 untested (no IPv6 route on Wi-Fi). Rules for anthropic are loaded on that Mac right now.
- L3 (design note): an address untested only because the real interface has no route for that address family (IPv6 on an IPv4-only Wi-Fi) is not a leak; it stays reported as untested but must not fail a domain that has a blocked address. A whole domain with no blocked address fails. A resolved address outside the catalog ranges fails (pf does not cover it).
