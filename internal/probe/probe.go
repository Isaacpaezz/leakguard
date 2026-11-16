// Package probe proves that protected services are unreachable outside the
// VPN: it connects to each protected address through the real (non-VPN)
// interface and expects the connection to fail.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/config"
)

// Port is the port probed on every protected address (HTTPS).
const Port = 443

// DefaultTimeout bounds each resolution and connection attempt.
const DefaultTimeout = 3 * time.Second

// ErrNotSupported means this OS cannot bind a connection to an interface.
var ErrNotSupported = errors.New("binding a connection to an interface is not supported on this OS")

// Outcome is the result of probing one address.
type Outcome string

const (
	// Blocked means the connection was refused, unreachable or timed out.
	Blocked Outcome = "OK blocked"
	// Leak means the connection succeeded outside the VPN.
	Leak Outcome = "LEAK"
	// Untested means nothing could be proven; it never counts as a pass.
	Untested Outcome = "untested"
)

// Resolver looks up the addresses of a host; *net.Resolver implements it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Dialer opens a TCP connection to addr bound to iface and closes it.
// It returns nil only when the connection succeeded.
type Dialer func(ctx context.Context, iface string, addr netip.AddrPort) error

// Result is the outcome for one address, or for a domain with no testable address.
type Result struct {
	Service string
	Domain  string
	Addr    netip.AddrPort // zero when nothing could be dialed
	Outcome Outcome
	Err     error
}

// Prober runs the off-VPN test.
type Prober struct {
	Resolver Resolver
	Dial     Dialer
	Timeout  time.Duration // zero means DefaultTimeout
}

// Run resolves each service's domains, keeps only the addresses inside the
// service's catalog ranges, and dials them through iface in parallel.
func (p Prober) Run(ctx context.Context, iface string, services []catalog.Service) []Result {
	timeout := p.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	var results []Result
	for _, svc := range services {
		ranges := prefixes(svc)
		seen := map[netip.Addr]bool{}
		for _, domain := range svc.Domains {
			rctx, cancel := context.WithTimeout(ctx, timeout)
			addrs, err := p.Resolver.LookupNetIP(rctx, "ip", domain)
			cancel()
			found := false
			for _, a := range addrs {
				a = a.Unmap()
				if !inside(a, ranges) {
					continue
				}
				found = true
				if seen[a] {
					continue
				}
				seen[a] = true
				results = append(results, Result{Service: svc.ID, Domain: domain, Addr: netip.AddrPortFrom(a, Port)})
			}
			if !found {
				if err == nil {
					err = errors.New("resolves only to addresses outside the catalog ranges")
				}
				results = append(results, Result{Service: svc.ID, Domain: domain, Outcome: Untested, Err: err})
			}
		}
	}
	var wg sync.WaitGroup
	for i := range results {
		if results[i].Outcome == Untested {
			continue
		}
		wg.Add(1)
		go func(r *Result) {
			defer wg.Done()
			dctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			r.Err = p.Dial(dctx, iface, r.Addr)
			r.Outcome = classify(r.Err)
		}(&results[i])
	}
	wg.Wait()
	return results
}

func classify(err error) Outcome {
	if err == nil {
		return Leak
	}
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED),
		errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, os.ErrDeadlineExceeded),
		errors.As(err, &ne) && ne.Timeout():
		return Blocked
	}
	return Untested
}

// Check fails when any address leaked or when a service has no blocked address.
func Check(results []Result, services []catalog.Service) error {
	blocked := map[string]bool{}
	for _, r := range results {
		switch r.Outcome {
		case Leak:
			return fmt.Errorf("%s is reachable outside the VPN at %s", r.Service, r.Addr.Addr())
		case Blocked:
			blocked[r.Service] = true
		}
	}
	for _, s := range services {
		if !blocked[s.ID] {
			return fmt.Errorf("%s could not be tested; this is not a pass", s.ID)
		}
	}
	return nil
}

// ParseDefaultRoute reads the interface from "route -n get default" output.
func ParseDefaultRoute(out string) (string, error) {
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || key != "interface" {
			continue
		}
		name := strings.TrimSpace(value)
		if !config.ValidInterfaceName(name) {
			return "", fmt.Errorf("default route has an invalid interface name %q", name)
		}
		return name, nil
	}
	return "", errors.New("no default route found")
}

func prefixes(s catalog.Service) []netip.Prefix {
	var out []netip.Prefix
	for _, r := range append(append([]string{}, s.IPv4...), s.IPv6...) {
		if p, err := netip.ParsePrefix(r); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func inside(a netip.Addr, ranges []netip.Prefix) bool {
	for _, p := range ranges {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
