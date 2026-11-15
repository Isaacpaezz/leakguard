# Security policy

leakguard exists to stop traffic from leaking outside a VPN. A leak is a
security problem, even if it looks like an ordinary bug.

## Report privately

Use [GitHub private vulnerability reporting](https://github.com/Isaacpaezz/leakguard/security/advisories/new).
Do **not** open a public issue for:

- traffic reaching a protected service outside the VPN;
- rules that disappear and leave a service unprotected without warning;
- anything that lets another user or process change or disable the rules.

Include your OS, VPN client, leakguard version and the steps that reproduce
the problem. Remove your real IP address and VPN server names.

You can expect a first answer within 7 days. Fixes for confirmed leaks take
priority over any other work.

## Supported versions

Only the latest release and `main` receive fixes while the project is below 1.0.
