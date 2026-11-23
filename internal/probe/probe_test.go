package probe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
)

var anthropic = catalog.Service{
	ID:      "anthropic",
	IPv4:    []string{"160.79.104.0/23"},
	IPv6:    []string{"2607:6bc0::/48"},
	Domains: []string{"api.anthropic.com", "claude.ai"},
}

type fakeResolver map[string][]string

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	raw, ok := f[host]
	if !ok {
		return nil, fmt.Errorf("lookup %s: no such host", host)
	}
	var out []netip.Addr
	for _, r := range raw {
		out = append(out, netip.MustParseAddr(r))
	}
	return out, nil
}

type dialLog struct {
	mu    sync.Mutex
	iface string
	addrs []string
}

func fakeDialer(log *dialLog, results map[string]error) Dialer {
	return func(_ context.Context, iface string, addr netip.AddrPort) error {
		log.mu.Lock()
		defer log.mu.Unlock()
		log.iface = iface
		log.addrs = append(log.addrs, addr.String())
		return results[addr.String()]
	}
}

func lines(results []Result) string {
	var b strings.Builder
	for _, r := range results {
		fmt.Fprintf(&b, "%s %s %s %s\n", r.Service, r.Domain, r.Addr, r.Outcome)
	}
	return b.String()
}

func TestRunClassifiesOutcomes(t *testing.T) {
	res := fakeResolver{
		"api.anthropic.com": {"160.79.104.10", "2607:6bc0::10"},
		"claude.ai":         {"160.79.104.11"},
	}
	log := &dialLog{}
	dial := fakeDialer(log, map[string]error{
		"160.79.104.10:443":   syscall.ECONNREFUSED,
		"[2607:6bc0::10]:443": nil, // connected: a leak
		"160.79.104.11:443":   os.ErrDeadlineExceeded,
	})
	p := Prober{Resolver: res, Dial: dial, Timeout: time.Second}
	got := lines(p.Run(context.Background(), "en0", []catalog.Service{anthropic}))
	want := "anthropic api.anthropic.com 160.79.104.10:443 OK blocked\n" +
		"anthropic api.anthropic.com [2607:6bc0::10]:443 LEAK\n" +
		"anthropic claude.ai 160.79.104.11:443 untested\n"
	if got != want {
		t.Fatalf("Run() =\n%s\nwant\n%s", got, want)
	}
	if log.iface != "en0" {
		t.Fatalf("dialed through %q, want en0", log.iface)
	}
}

// pf's "block return" always answers with an immediate refusal. Unreachable
// networks and timeouts also happen when the real connection is offline and
// no rule is loaded, so they prove nothing.
func TestRunNeverPassesUnreachableOrTimeout(t *testing.T) {
	for _, err := range []error{syscall.EHOSTUNREACH, syscall.ENETUNREACH, context.DeadlineExceeded, os.ErrDeadlineExceeded} {
		res := fakeResolver{"api.anthropic.com": {"160.79.104.10"}}
		p := Prober{Resolver: res, Dial: fakeDialer(&dialLog{}, map[string]error{"160.79.104.10:443": err})}
		svc := anthropic
		svc.Domains = []string{"api.anthropic.com"}
		r := p.Run(context.Background(), "en0", []catalog.Service{svc})
		if len(r) != 1 || r[0].Outcome != Untested || !errors.Is(r[0].Err, err) ||
			!strings.Contains(r[0].Err.Error(), "no refusal") {
			t.Errorf("error %v: results = %+v, want untested explaining no refusal", err, r)
		}
		if Check(r, []catalog.Service{svc}) == nil {
			t.Errorf("error %v: Check() = nil, want failure", err)
		}
	}
}

func TestRunNeverPassesUnknownErrors(t *testing.T) {
	res := fakeResolver{"api.anthropic.com": {"160.79.104.10"}}
	p := Prober{Resolver: res, Dial: fakeDialer(&dialLog{}, map[string]error{"160.79.104.10:443": ErrNotSupported})}
	svc := anthropic
	svc.Domains = []string{"api.anthropic.com"}
	r := p.Run(context.Background(), "en0", []catalog.Service{svc})
	if len(r) != 1 || r[0].Outcome != Untested || !errors.Is(r[0].Err, ErrNotSupported) {
		t.Fatalf("results = %+v, want untested", r)
	}
}

// pf only blocks the catalog ranges, so a resolved address outside them is
// reported as not covered and never dialed.
func TestRunReportsAddressesOutsideTheCatalogRanges(t *testing.T) {
	res := fakeResolver{
		"api.anthropic.com": {"160.79.104.10", "104.18.0.1"},
		"claude.ai":         {"104.18.0.2"},
	}
	log := &dialLog{}
	p := Prober{Resolver: res, Dial: fakeDialer(log, map[string]error{"160.79.104.10:443": syscall.ECONNREFUSED})}
	r := p.Run(context.Background(), "en0", []catalog.Service{anthropic})
	want := "anthropic api.anthropic.com 160.79.104.10:443 OK blocked\n" +
		"anthropic api.anthropic.com 104.18.0.1:443 NOT COVERED\n" +
		"anthropic claude.ai 104.18.0.2:443 NOT COVERED\n"
	if got := lines(r); got != want {
		t.Fatalf("Run() =\n%s\nwant\n%s", got, want)
	}
	if !strings.Contains(r[1].Err.Error(), "outside the catalog ranges; pf does not protect it") {
		t.Fatalf("err = %v", r[1].Err)
	}
	if strings.Join(log.addrs, ",") != "160.79.104.10:443" {
		t.Fatalf("dialed %v; must never dial outside the catalog ranges", log.addrs)
	}
	err := Check(r, []catalog.Service{anthropic})
	if err == nil || !strings.Contains(err.Error(), "anthropic: api.anthropic.com resolves to 104.18.0.1, outside the catalog ranges; pf does not protect it") {
		t.Fatalf("Check() = %v, want a not covered failure", err)
	}
}

// Two domains may share an address; each domain still needs its own proof.
func TestRunProbesSharedAddressesForEveryDomain(t *testing.T) {
	res := fakeResolver{
		"api.anthropic.com": {"160.79.104.10"},
		"claude.ai":         {"160.79.104.10"},
	}
	p := Prober{Resolver: res, Dial: fakeDialer(&dialLog{}, map[string]error{"160.79.104.10:443": syscall.ECONNREFUSED})}
	r := p.Run(context.Background(), "en0", []catalog.Service{anthropic})
	want := "anthropic api.anthropic.com 160.79.104.10:443 OK blocked\n" +
		"anthropic claude.ai 160.79.104.10:443 OK blocked\n"
	if got := lines(r); got != want {
		t.Fatalf("Run() =\n%s\nwant\n%s", got, want)
	}
	if err := Check(r, []catalog.Service{anthropic}); err != nil {
		t.Fatalf("Check() = %v", err)
	}
}

func TestRunReportsResolutionFailureAsUntested(t *testing.T) {
	p := Prober{Resolver: fakeResolver{}, Dial: fakeDialer(&dialLog{}, nil)}
	r := p.Run(context.Background(), "en0", []catalog.Service{anthropic})
	if len(r) != 2 || r[0].Outcome != Untested || r[1].Outcome != Untested {
		t.Fatalf("results = %+v, want two untested", r)
	}
	if !strings.Contains(r[0].Err.Error(), "no such host") {
		t.Fatalf("err = %v", r[0].Err)
	}
}

func TestCheck(t *testing.T) {
	other := catalog.Service{ID: "example", Domains: []string{"example.com"}}
	api := Result{Service: "anthropic", Domain: "api.anthropic.com", Outcome: Blocked}
	claude := Result{Service: "anthropic", Domain: "claude.ai", Outcome: Blocked}
	example := Result{Service: "example", Domain: "example.com", Outcome: Blocked}
	cases := []struct {
		name    string
		results []Result
		want    string
	}{
		{"all blocked", []Result{api, claude, example}, ""},
		// An address the real connection has no route for (IPv6 on an IPv4
		// Wi-Fi) is not a leak when its domain has a blocked address.
		{"address untested in a blocked domain", []Result{api, {Service: "anthropic", Domain: "api.anthropic.com", Outcome: Untested}, claude, example}, ""},
		{"domain untested", []Result{api, {Service: "anthropic", Domain: "claude.ai", Outcome: Untested}, example}, "anthropic: claude.ai could not be tested; this is not a pass"},
		{"domain missing", []Result{api, example}, "anthropic: claude.ai could not be tested; this is not a pass"},
		{"not covered", []Result{api, claude, {Service: "anthropic", Domain: "claude.ai", Addr: netip.MustParseAddrPort("104.18.0.2:443"), Outcome: NotCovered}, example}, "anthropic: claude.ai resolves to 104.18.0.2, outside the catalog ranges; pf does not protect it"},
		{"leak", []Result{api, claude, {Service: "example", Domain: "example.com", Outcome: Leak}}, "example is reachable outside the VPN"},
		{"service untested", []Result{api, claude, {Service: "example", Domain: "example.com", Outcome: Untested}}, "example could not be tested; this is not a pass"},
		{"nothing", nil, "anthropic could not be tested; this is not a pass"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Check(tc.results, []catalog.Service{anthropic, other})
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Check() = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Check() = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestParseDefaultRoute(t *testing.T) {
	out := `   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
`
	if got, err := ParseDefaultRoute(out); err != nil || got != "en0" {
		t.Fatalf("ParseDefaultRoute() = %q, %v", got, err)
	}
	if _, err := ParseDefaultRoute("route: writing to routing socket: not in table\n"); err == nil {
		t.Fatal("ParseDefaultRoute() without interface = nil error")
	}
	if _, err := ParseDefaultRoute(invalidRouteLine(runtime.GOOS)); err == nil {
		t.Fatal("ParseDefaultRoute() accepted an invalid interface name")
	}
}

// invalidRouteLine is a default-route line whose interface name the host's
// rules refuse. A Windows adapter alias may hold ";" (any character but a
// control one), so there the name holds a control character instead.
func invalidRouteLine(goos string) string {
	if goos == "windows" {
		return "  interface: en0\x7frm\n"
	}
	return "  interface: en0;rm\n"
}
