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
	// Blocked means the connection was refused immediately, as pf's block rule does.
	Blocked Outcome = "OK blocked"
	// Leak means the connection succeeded outside the VPN.
	Leak Outcome = "LEAK"
	// Untested means nothing could be proven; it never counts as a pass.
	Untested Outcome = "untested"
	// NotCovered means a domain resolved outside the catalog ranges, which pf
	// does not block; it is never dialed and always fails the test.
	NotCovered Outcome = "NOT COVERED"
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

// errNotCovered explains a NotCovered result.
var errNotCovered = errors.New("outside the catalog ranges; pf does not protect it")

// Run resolves each service's domains and dials, through iface and in
// parallel, every resolved address inside the service's catalog ranges.
// Addresses outside the ranges are reported as NotCovered and never dialed.
// Each domain gets its own results, even when domains share an address,
// because every domain needs its own proof.
func (p Prober) Run(ctx context.Context, iface string, services []catalog.Service) []Result {
	timeout := p.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	var results []Result
	for _, svc := range services {
		ranges := prefixes(svc)
		for _, domain := range svc.Domains {
			rctx, cancel := context.WithTimeout(ctx, timeout)
			addrs, err := p.Resolver.LookupNetIP(rctx, "ip", domain)
			cancel()
			seen := map[netip.Addr]bool{}
			for _, a := range addrs {
				a = a.Unmap()
				if seen[a] {
					continue
				}
				seen[a] = true
				r := Result{Service: svc.ID, Domain: domain, Addr: netip.AddrPortFrom(a, Port)}
				if !inside(a, ranges) {
					r.Outcome, r.Err = NotCovered, errNotCovered
				}
				results = append(results, r)
			}
			if len(seen) == 0 {
				if err == nil {
					err = errors.New("resolves to no address")
				}
				results = append(results, Result{Service: svc.ID, Domain: domain, Outcome: Untested, Err: err})
			}
		}
	}
	var wg sync.WaitGroup
	for i := range results {
		if results[i].Outcome != "" {
			continue
		}
		wg.Add(1)
		go func(r *Result) {
			defer wg.Done()
			dctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			r.Err = p.Dial(dctx, iface, r.Addr)
			r.Outcome, r.Err = classify(r.Err)
		}(&results[i])
	}
	wg.Wait()
	return results
}

// classify maps a dial error to an outcome. leakguard's pf rule uses
// "block return", so a real block is always an immediate refusal. Unreachable
// networks and timeouts also happen when the real connection is offline and
// no rule is loaded, so they are untested, never blocked.
func classify(err error) (Outcome, error) {
	if err == nil {
		return Leak, nil
	}
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return Blocked, err
	case errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, os.ErrDeadlineExceeded),
		errors.As(err, &ne) && ne.Timeout():
		return Untested, fmt.Errorf("no refusal (%w); is the real connection online?", err)
	}
	return Untested, err
}

// Check fails when any address leaked, when any resolved address is outside
// the catalog ranges, or when any domain of a service has no blocked address.
// An untested address does not fail a domain that has a blocked address: the
// real connection may simply have no route for that address family.
func Check(results []Result, services []catalog.Service) error {
	type key struct{ service, domain string }
	blocked := map[key]bool{}
	for _, r := range results {
		if r.Outcome == Leak {
			return fmt.Errorf("%s is reachable outside the VPN at %s", r.Service, r.Addr.Addr())
		}
	}
	for _, r := range results {
		switch r.Outcome {
		case NotCovered:
			return fmt.Errorf("%s: %s resolves to %s, %v", r.Service, r.Domain, r.Addr.Addr(), errNotCovered)
		case Blocked:
			blocked[key{r.Service, r.Domain}] = true
			blocked[key{r.Service, ""}] = true
		}
	}
	for _, s := range services {
		if !blocked[key{s.ID, ""}] {
			return fmt.Errorf("%s could not be tested; this is not a pass", s.ID)
		}
		for _, d := range s.Domains {
			if !blocked[key{s.ID, d}] {
				return fmt.Errorf("%s: %s could not be tested; this is not a pass", s.ID, d)
			}
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
