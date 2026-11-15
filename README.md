# leakguard

**A destination-scoped VPN kill switch for macOS, Linux and Windows.**

Most VPN kill switches cut the whole machine when the tunnel drops. leakguard
does something narrower: you choose a list of destinations (services, domains,
IP ranges), and traffic to them may only leave through your VPN interface. If
the tunnel drops, those destinations behave as if the internet were down,
while everything else keeps working over your normal connection.

Use it when you split-tunnel (only some traffic goes through the VPN) and a
dropped tunnel must never send that traffic over your real connection.

> **Status:** early stage. Only a working macOS prototype exists
> (`prototypes/macos-pf/`). The cross-platform tool is being designed.
> See [docs/HANDOFF.md](docs/HANDOFF.md).

## How it works (macOS prototype)

```
pass  out quick on <vpn-interface> to <protected> keep state
block return out quick to <protected>
```

Packets to the protected set are allowed only on the VPN interface and
rejected immediately everywhere else (real NIC, Tailscale, etc.), so apps fail
fast instead of leaking.

## Planned platforms

| OS      | Mechanism                                              |
|---------|--------------------------------------------------------|
| macOS   | `pf` anchor under `com.apple/*` + LaunchDaemon         |
| Linux   | `nftables` table: drop to the set when `oifname` ≠ VPN |
| Windows | Windows Filtering Platform / Windows Firewall rules    |

## Responsible use

leakguard is privacy and leak-prevention tooling. You are responsible for
complying with your VPN provider's, your employer's and each protected
service's terms of use.

## License

[MIT](LICENSE)
