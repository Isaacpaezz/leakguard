package wfp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// absentVPN names no adapter, like a VPN that is down.
const absentVPN = "leakguard test absent VPN"

// TestIntegrationRealFilters loads real WFP filters and probes them. It
// needs an elevated shell and LEAKGUARD_WFP_INTEGRATION=1, and fails rather
// than skips when the shell is not elevated. It removes every leakguard
// filter, the sublayer and the provider before and after.
//
// The protected ranges are 127.0.0.2/32 and ::1/128, each with a listener,
// plus 192.0.2.1/32 (TEST-NET-1, never answers). Their filters load and
// verify at ALE_AUTH_CONNECT and IPFORWARD. It proves the arbitration,
// not only the bookkeeping: with the loopback adapter as the VPN the permit
// outweighs the block and the connects succeed; with the VPN adapter absent
// only the blocks load and every connect fails at once with WSAEACCES. On
// any failure it prints every ALE_AUTH_CONNECT filter as the engine stores
// it (weight and effective weight included).
func TestIntegrationRealFilters(t *testing.T) {
	if os.Getenv("LEAKGUARD_WFP_INTEGRATION") != "1" {
		t.Skip("set LEAKGUARD_WFP_INTEGRATION=1 in an elevated shell to load real WFP filters")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("LEAKGUARD_WFP_INTEGRATION=1 needs an elevated (administrator) shell")
	}
	f := Firewall{Check: func(string) error { return nil }} // config refuses loopback
	if ok, err := f.Enabled(); !ok || err != nil {
		t.Fatalf("Enabled() = %v, %v", ok, err)
	}
	if err := f.Flush(); err != nil {
		t.Fatalf("Flush before the test: %v", err)
	}
	t.Cleanup(func() {
		if err := f.Flush(); err != nil {
			t.Errorf("Flush after the test: %v", err)
		}
		nothingLeft(t)
	})
	dumped := false
	fail := func(format string, a ...any) {
		t.Helper()
		t.Errorf(format, a...)
		if !dumped {
			dumped = true
			dumpFilters(t)
		}
	}

	alias, luid := loopback(t)
	t.Logf("loopback adapter %q, LUID %#x", alias, luid)
	addr4 := listen(t, "tcp4", "127.0.0.2:0")
	addr6 := listen(t, "tcp6", "[::1]:0")
	services := []catalog.Service{{ID: "test", IPv4: []string{"127.0.0.2/32", "192.0.2.1/32"}, IPv6: []string{"::1/128"}}}
	targets := []string{addr4, addr6}

	// VPN = loopback: the stored weights read back as written, and the
	// permit for its LUID wins over the block.
	if err := f.Apply(alias, services); err != nil {
		fail("Apply(%q): %v", alias, err)
		t.FailNow()
	}
	weights(t, fail)
	if err := f.Verify(alias, services); err != nil {
		fail("Verify(%q): %v", alias, err)
	}
	for _, a := range targets {
		if err := connect(a, 2*time.Second); err != nil {
			fail("through the VPN (loopback), connect %s: %s; want connected: the permit must outweigh the block", a, classify(err))
		}
	}

	// The VPN is down (its adapter is gone): the blocks only, a success,
	// and every connect fails at once with WSAEACCES.
	if err := f.Apply(absentVPN, services); err != nil {
		fail("Apply(%q) = %v, want nil with the blocks loaded", absentVPN, err)
	}
	for _, v := range []string{absentVPN, ""} {
		if err := f.Verify(v, services); err != nil {
			fail("Verify(%q) with the blocks loaded: %v", v, err)
		}
	}
	for _, a := range append(targets, "192.0.2.1:443") {
		start := time.Now()
		err := connect(a, 5*time.Second)
		took := time.Since(start)
		t.Logf("blocked connect %s after %v: %s", a, took.Round(time.Millisecond), classify(err))
		switch {
		case err == nil:
			fail("connect %s succeeded with the VPN down", a)
		case !errors.Is(err, windows.WSAEACCES):
			fail("connect %s failed with %s, want WSAEACCES (10013)", a, classify(err))
		case took > 1500*time.Millisecond:
			fail("connect %s took %v: blocked connects must fail at once, not time out", a, took)
		}
	}

	// Verify notices a deleted filter.
	if err := f.Apply(alias, services); err != nil {
		t.Fatalf("Apply(%q) again: %v", alias, err)
	}
	deleteOne(t)
	if err := f.Verify(alias, services); err == nil || !strings.Contains(err.Error(), "1 missing") {
		t.Errorf("Verify after deleting a filter = %v, want 1 missing", err)
	}

	// Flush restores connectivity.
	if err := f.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := f.Verify(alias, services); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("Verify after Flush = %v, want ErrNotLoaded", err)
	}
	for _, a := range targets {
		if err := connect(a, 2*time.Second); err != nil {
			t.Errorf("after Flush, connect %s: %s", a, classify(err))
		}
	}
	start := time.Now()
	err := connect("192.0.2.1:443", time.Second)
	t.Logf("unprotected connect 192.0.2.1:443 after %v: %s", time.Since(start).Round(time.Millisecond), classify(err))
	if errors.Is(err, windows.WSAEACCES) {
		t.Errorf("after Flush, 192.0.2.1 still fails with WSAEACCES")
	}
}

// weights checks that each leakguard filter reads back with the weight
// Rules gives it, nothing else, at each of the four layers, and logs them.
func weights(t *testing.T, fail func(string, ...any)) {
	t.Helper()
	e, err := openEngine()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	fs, err := e.Filters()
	if err != nil {
		t.Fatalf("Filters() = %v", err)
	}
	at := map[Layer]int{}
	for _, x := range fs {
		at[x.Rule.Layer]++
	}
	for _, l := range filterLayers {
		if at[l] == 0 {
			fail("no leakguard filter read back at %s: %v", l, at)
		}
	}
	for _, x := range fs {
		want := BlockWeight
		if x.Rule.Action == ActionPermit {
			want = PermitWeight
		}
		t.Logf("read back %s", x.Rule)
		if x.Rule.Weight != want || x.Rule.Other != "" {
			fail("filter %s read back as %s, want weight %d", x.Key, x.Rule, want)
		}
	}
}

// listen accepts and closes connections on addr until the test ends, and
// returns the address it listens on.
func listen(t *testing.T, network, addr string) string {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Fatalf("listen %s %s: %v", network, addr, err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln.Addr().String()
}

func connect(addr string, timeout time.Duration) error {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	return c.Close()
}

// classify names the Windows error code behind a failed connect.
func classify(err error) string {
	var errno syscall.Errno
	switch {
	case err == nil:
		return "connected"
	case errors.Is(err, windows.WSAEACCES):
		return "WSAEACCES (10013): " + err.Error()
	case errors.As(err, &errno):
		return "errno " + errno.Error() + ": " + err.Error()
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout: " + err.Error()
	}
	return "other: " + err.Error()
}

// deleteOne deletes one leakguard filter behind the Firewall's back.
func deleteOne(t *testing.T) {
	t.Helper()
	e, err := openEngine()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	fs, err := e.Filters()
	if err != nil || len(fs) == 0 {
		t.Fatalf("Filters() = %v, %v", fs, err)
	}
	if err := e.Delete(fs[0].Key); err != nil {
		t.Fatal(err)
	}
}

// dumpFilters logs every ALE_AUTH_CONNECT filter as the engine stores it.
func dumpFilters(t *testing.T) {
	t.Helper()
	e, err := openEngine()
	if err != nil {
		t.Log(err)
		return
	}
	defer e.Close()
	lines, err := e.(session).dump()
	for _, l := range lines {
		t.Log(l)
	}
	if err != nil {
		t.Logf("cannot list the filters: %v", err)
	}
}

// nothingLeft fails when a leakguard filter, the sublayer or the provider
// is still there.
func nothingLeft(t *testing.T) {
	t.Helper()
	e, err := openEngine()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if ok, err := e.Installed(); ok || err != nil {
		t.Errorf("sublayer left behind: %v, %v", ok, err)
	}
	if fs, err := e.Filters(); len(fs) > 0 || err != nil {
		t.Errorf("filters left behind: %v, %v", fs, err)
	}
	s := e.(session).s
	ps, err := s.Providers()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		if GUID(p.ID) == ProviderKey {
			t.Error("provider left behind")
		}
	}
}

// The provider, sublayer and filters of another program.
var (
	foreignProvider = GUID{0x7E57F0E1, 0x6E1A, 0x4B2D, [8]byte{0x9C, 0x31, 0x0A, 0x5B, 0x6D, 0x7E, 0x8F, 0x01}}
	foreignSublayer = GUID{0x7E57F0E1, 0x6E1A, 0x4B2D, [8]byte{0x9C, 0x31, 0x0A, 0x5B, 0x6D, 0x7E, 0x8F, 0x02}}
	foreignFilters  = []GUID{
		{0x7E57F0E1, 0x6E1A, 0x4B2D, [8]byte{0x9C, 0x31, 0x0A, 0x5B, 0x6D, 0x7E, 0x8F, 0x03}},
		{0x7E57F0E1, 0x6E1A, 0x4B2D, [8]byte{0x9C, 0x31, 0x0A, 0x5B, 0x6D, 0x7E, 0x8F, 0x04}},
		{0x7E57F0E1, 0x6E1A, 0x4B2D, [8]byte{0x9C, 0x31, 0x0A, 0x5B, 0x6D, 0x7E, 0x8F, 0x05}},
	}
)

// TestIntegrationForeignFilters (SF3) adds another program's filters at
// three of leakguard's layers, with a condition leakguard never writes and
// one without any provider, then proves they are never read: the engine
// lists them when asked for every provider, never when asked for
// leakguard's; Apply, Verify and Flush succeed; and Flush leaves them and
// their provider in place. It removes them at the end. It needs an
// elevated shell and LEAKGUARD_WFP_INTEGRATION=1.
func TestIntegrationForeignFilters(t *testing.T) {
	if os.Getenv("LEAKGUARD_WFP_INTEGRATION") != "1" {
		t.Skip("set LEAKGUARD_WFP_INTEGRATION=1 in an elevated shell to load real WFP filters")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("LEAKGUARD_WFP_INTEGRATION=1 needs an elevated (administrator) shell")
	}
	f := Firewall{Check: func(string) error { return nil }}
	if err := f.Flush(); err != nil {
		t.Fatalf("Flush before the test: %v", err)
	}
	removeForeign(t)
	t.Cleanup(func() {
		if err := f.Flush(); err != nil {
			t.Errorf("Flush after the test: %v", err)
		}
		nothingLeft(t)
		removeForeign(t)
	})

	e, err := openEngine()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	s := e.(session)
	if err := s.s.AddProvider(&wf.Provider{ID: wf.ProviderID(foreignProvider), Name: "leakguard test: another program"}); err != nil {
		t.Fatalf("add the foreign provider: %v", err)
	}
	if err := s.s.AddSublayer(&wf.Sublayer{ID: wf.SublayerID(foreignSublayer), Name: "leakguard test: another program", Provider: wf.ProviderID(foreignProvider), Weight: 1}); err != nil {
		t.Fatalf("add the foreign sublayer: %v", err)
	}
	for _, r := range []*wf.Rule{
		{ID: wf.RuleID(foreignFilters[0]), Name: "leakguard test: foreign permit", Layer: wf.LayerALEAuthConnectV4, Sublayer: wf.SublayerID(foreignSublayer), Provider: wf.ProviderID(foreignProvider), Weight: 5, Action: wf.ActionPermit,
			Conditions: []*wf.Match{
				{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("203.0.113.7/32")},
				{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(443)},
			}},
		{ID: wf.RuleID(foreignFilters[1]), Name: "leakguard test: foreign forward block", Layer: wf.LayerIPForwardV4, Sublayer: wf.SublayerID(foreignSublayer), Provider: wf.ProviderID(foreignProvider), Weight: 3, Action: wf.ActionBlock,
			Conditions: []*wf.Match{{Field: wf.FieldIPDestinationAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("203.0.113.0/24")}}},
		{ID: wf.RuleID(foreignFilters[2]), Name: "leakguard test: filter without a provider", Layer: wf.LayerALEAuthConnectV6, Sublayer: wf.SublayerID(foreignSublayer), Weight: 2, Action: wf.ActionPermit,
			Conditions: []*wf.Match{{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("2001:db8::/32")}}},
	} {
		if err := s.s.AddRule(r); err != nil {
			t.Fatalf("add %s: %v", r.Name, err)
		}
	}
	// They are there to be read: listing every provider's filters finds
	// them.
	all := listed(t, s, nil)
	for _, k := range foreignFilters {
		if _, ok := all[k]; !ok {
			t.Fatalf("foreign filter %s not listed among every provider's filters: %v", k, all)
		}
	}

	alias, _ := loopback(t)
	services := []catalog.Service{{ID: "test", IPv4: []string{"127.0.0.2/32", "192.0.2.1/32"}, IPv6: []string{"::1/128"}}}
	if err := f.Apply(alias, services); err != nil {
		t.Fatalf("Apply(%q) with foreign filters loaded: %v", alias, err)
	}
	if err := f.Verify(alias, services); err != nil {
		t.Errorf("Verify(%q) with foreign filters loaded: %v", alias, err)
	}
	ours := listed(t, s, &ProviderKey)
	if want := 2 * 2 * 3; len(ours) != want { // block and permit, 2 layers, 3 ranges
		t.Errorf("listed %d filters of the leakguard provider, want %d: %v", len(ours), want, ours)
	}
	for k, provider := range ours {
		if provider != ProviderKey.String() {
			t.Errorf("asked for leakguard's filters, the engine listed %s of provider %s", k, provider)
		}
		if _, ok := generation(k); !ok {
			t.Errorf("listed filter %s is not a leakguard key", k)
		}
	}
	if err := f.Apply(absentVPN, services); err != nil {
		t.Errorf("Apply(%q) with foreign filters loaded: %v", absentVPN, err)
	}
	if err := f.Verify("", services); err != nil {
		t.Errorf("Verify(\"\") with foreign filters loaded: %v", err)
	}
	if err := f.Flush(); err != nil {
		t.Fatalf("Flush with foreign filters loaded: %v", err)
	}
	if err := f.Verify(alias, services); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("Verify after Flush = %v, want ErrNotLoaded", err)
	}
	all = listed(t, s, nil)
	for _, k := range foreignFilters {
		if _, ok := all[k]; !ok {
			t.Errorf("Flush deleted foreign filter %s", k)
		}
	}
	ps, err := s.s.Providers()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(ps, func(p *wf.Provider) bool { return GUID(p.ID) == foreignProvider }) {
		t.Error("Flush deleted the foreign provider")
	}
}

// listed returns the keys and providers of the filters the engine lists for
// provider (every provider's when nil) at leakguard's layers.
func listed(t *testing.T, s session, provider *GUID) map[GUID]string {
	t.Helper()
	out := map[GUID]string{}
	for _, l := range filterLayers {
		err := s.enum(provider, l, func(f *fwpmFilter0) {
			p := "none"
			if f.ProviderKey != nil {
				p = f.ProviderKey.String()
			}
			out[f.FilterKey] = p
		})
		if err != nil {
			t.Fatalf("enum(%v, %s): %v", provider, l, err)
		}
	}
	return out
}

// removeForeign deletes what TestIntegrationForeignFilters adds.
func removeForeign(t *testing.T) {
	t.Helper()
	e, err := openEngine()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	s := e.(session)
	for _, k := range foreignFilters {
		if err := s.s.DeleteRule(wf.RuleID(k)); err != nil && !is(err, windows.FWP_E_FILTER_NOT_FOUND) {
			t.Errorf("delete foreign filter %s: %v", k, err)
		}
	}
	if err := s.s.DeleteSublayer(wf.SublayerID(foreignSublayer)); err != nil && !is(err, windows.FWP_E_SUBLAYER_NOT_FOUND) {
		t.Errorf("delete the foreign sublayer: %v", err)
	}
	if err := s.s.DeleteProvider(wf.ProviderID(foreignProvider)); err != nil && !is(err, windows.FWP_E_PROVIDER_NOT_FOUND) {
		t.Errorf("delete the foreign provider: %v", err)
	}
}

// forwardTarget is a public address that answers on 443. The forwarded
// traffic test protects it, so only the test's own connections to it are
// ever blocked, and only while the test runs.
const forwardTarget = "1.1.1.1:443"

// TestIntegrationForwardedTraffic (SF2) probes protected traffic that
// does not start in this computer's own processes, from Windows containers
// on Docker's nat network. The test copies its own binary into a Nano
// Server container and runs TestForwardProbe there to connect to
// forwardTarget, protected for the test. The binary goes in with docker cp
// into the created, not yet started, container, never through a bind
// mount: a mounted host folder keeps the host's ACL, which the container's
// account cannot use (CreateProcess fails with ERROR_ACCESS_DENIED). The
// log names the container's isolation, network and addresses.
//
// A process-isolated container shares this kernel: CI (run 45125443458,
// Server 2025) showed its connects are authorized at this computer's
// ALE_AUTH_CONNECT and never pass IPFORWARD. So the test asserts:
//
//   - nothing loaded: the container connects (positive control, retried;
//     failing it is the environment, not a filter);
//   - Apply with the VPN down: the container's connect fails at once with
//     WSAEACCES, and so does this computer's;
//   - after Flush: the container connects again.
//
// With the adapter the route leaves on as the VPN, the container is still
// blocked (its ALE local interface is its own vNIC, never the VPN's): that
// over-blocking fails closed and is logged, not judged.
//
// A Hyper-V isolated container has its own kernel, like WSL2 and virtual
// machines, so only forwarding on this computer can see its packets. When
// the runner can start one, the test asserts that with the VPN down its
// connect times out or is refused (IPFORWARD drops it) and that Flush
// restores it; when it cannot (no nested virtualization), it logs that
// IPFORWARD for Hyper-V isolated guests is unverified and does not fail.
//
// A negative phase passes only on its expected outcome; any other one is
// inconclusive and fails. It needs an elevated shell, Docker with Windows
// containers and LEAKGUARD_WFP_FORWARD_INTEGRATION=1, and fails rather
// than skips when one is missing.
func TestIntegrationForwardedTraffic(t *testing.T) {
	if os.Getenv("LEAKGUARD_WFP_FORWARD_INTEGRATION") != "1" {
		t.Skip("set LEAKGUARD_WFP_FORWARD_INTEGRATION=1 in an elevated shell with Docker (Windows containers) to probe forwarded traffic")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("LEAKGUARD_WFP_FORWARD_INTEGRATION=1 needs an elevated (administrator) shell")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatalf("environment: LEAKGUARD_WFP_FORWARD_INTEGRATION=1 needs Docker with Windows containers: %v", err)
	}
	image := nanoserverImage(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := containers{t: t, docker: docker, image: image, exe: exe}
	c.pull()
	info, err := c.do("info", "--format", "default isolation {{.Isolation}}, OS {{.OperatingSystem}} {{.KernelVersion}}")
	t.Logf("docker: %s (%v)", info, err)
	info, err = c.do("network", "inspect", "nat", "--format", "network nat: driver {{.Driver}}, IPAM {{json .IPAM.Config}}")
	t.Logf("docker: %s (%v)", info, err)

	f := Firewall{Check: func(string) error { return nil }} // config refuses Ethernet as the VPN
	if err := f.Flush(); err != nil {
		t.Fatalf("Flush before the test: %v", err)
	}
	t.Cleanup(func() {
		if err := f.Flush(); err != nil {
			t.Errorf("Flush after the test: %v", err)
		}
		nothingLeft(t)
	})
	services := []catalog.Service{{ID: "forward-test", IPv4: []string{"1.1.1.1/32"}}}
	route := routeTo(t, [4]byte{1, 1, 1, 1})
	t.Logf("the route to %s leaves on %q, LUID %#x", forwardTarget, route.Alias, route.LUID)

	// Process isolation: this computer's ALE_AUTH_CONNECT.
	const process = "process"
	if r := c.reach(process, "nothing loaded"); !r.ran || r.outcome != outConnected {
		t.Fatalf("environment: with no filter loaded a process-isolated container cannot reach %s after %d tries (last: %s); nothing about the filters was tested", forwardTarget, reachTries, r)
	}
	if err := f.Apply(absentVPN, services); err != nil {
		t.Fatalf("Apply(%q): %v", absentVPN, err)
	}
	if err := f.Verify(absentVPN, services); err != nil {
		t.Errorf("Verify(%q): %v", absentVPN, err)
	}
	c.expectDenied(c.probe(process, "Apply with the VPN down"))
	if err := connect(forwardTarget, 5*time.Second); !errors.Is(err, windows.WSAEACCES) {
		t.Errorf("filter: with the VPN down, this computer's connect to %s: %s; want WSAEACCES", forwardTarget, classify(err))
	}
	if err := f.Apply(route.Alias, services); err != nil {
		t.Fatalf("Apply(%q): %v", route.Alias, err)
	}
	if r := c.probe(process, "Apply with "+route.Alias+" as the VPN"); r.outcome == outConnected {
		t.Logf("diagnostic, not judged: with %q as the VPN a process-isolated container connected", route.Alias)
	} else {
		t.Logf("diagnostic, not judged (over-blocking, fails closed): with %q as the VPN a process-isolated container is still blocked (%s): its connects are authorized at this computer's ALE_AUTH_CONNECT with the container's own vNIC as the local interface, never the VPN's", route.Alias, r)
	}
	if err := f.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if r := c.reach(process, "after Flush"); !r.ran || r.outcome != outConnected {
		t.Errorf("after Flush a process-isolated container cannot reach %s after %d tries (last: %s): a filter was left behind, or the environment failed", forwardTarget, reachTries, r)
	}

	// Hyper-V isolation: its own kernel, so only IPFORWARD can see it.
	const hyperv = "hyperv"
	r := c.probe(hyperv, "Hyper-V isolation, nothing loaded")
	if !r.ran {
		t.Logf("IPFORWARD for Hyper-V isolated guests (WSL2, VMs) is unverified on this runner: a Hyper-V isolated container cannot start here (%s)", r.failure)
		return
	}
	if r.outcome != outConnected {
		if r = c.reach(hyperv, "Hyper-V isolation, nothing loaded"); !r.ran || r.outcome != outConnected {
			t.Fatalf("environment: with no filter loaded a Hyper-V isolated container cannot reach %s after %d more tries (last: %s); IPFORWARD was not tested", forwardTarget, reachTries, r)
		}
	}
	if err := f.Apply(absentVPN, services); err != nil {
		t.Fatalf("Apply(%q): %v", absentVPN, err)
	}
	c.expectDropped(c.probe(hyperv, "Hyper-V isolation, Apply with the VPN down"))
	if err := f.Apply(route.Alias, services); err != nil {
		t.Fatalf("Apply(%q): %v", route.Alias, err)
	}
	t.Logf("diagnostic, not judged: with %q as the VPN a Hyper-V isolated container: %s", route.Alias, c.probe(hyperv, "Hyper-V isolation, Apply with "+route.Alias+" as the VPN"))
	if err := f.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if r := c.reach(hyperv, "Hyper-V isolation, after Flush"); !r.ran || r.outcome != outConnected {
		t.Errorf("after Flush a Hyper-V isolated container cannot reach %s after %d tries (last: %s): a filter was left behind, or the environment failed", forwardTarget, reachTries, r)
	}
}

// The outcomes TestForwardProbe reports, first word of its result line.
const (
	outConnected = "connected"
	outDenied    = "WSAEACCES" // refused by a WFP filter at ALE
	outTimeout   = "timeout"   // the packets were dropped
	outRefused   = "refused"   // WSAECONNREFUSED
	outOther     = "other"
)

// outcome classifies a connect's result for TestForwardProbe.
func outcome(err error) string {
	var ne net.Error
	switch {
	case err == nil:
		return outConnected
	case errors.Is(err, windows.WSAEACCES):
		return outDenied
	case errors.Is(err, windows.WSAECONNREFUSED):
		return outRefused
	case errors.As(err, &ne) && ne.Timeout():
		return outTimeout
	}
	return outOther
}

// reachTries is how often a positive control is tried before the
// environment is blamed.
const reachTries = 3

// containers runs TestForwardProbe in Nano Server containers.
type containers struct {
	t                  *testing.T
	docker, image, exe string
	described          map[string]bool
}

// probeResult is what one container run reported.
type probeResult struct {
	ran     bool          // the probe printed its result
	outcome string        // outConnected, outDenied, ...
	took    time.Duration // as the probe measured the connect
	detail  string
	failure string // why the probe did not run
}

func (r probeResult) String() string {
	if !r.ran {
		return "the probe did not run: " + r.failure
	}
	return fmt.Sprintf("%s after %v: %s", r.outcome, r.took, r.detail)
}

// do runs docker, giving up after 10 minutes (a Hyper-V isolated
// container that cannot start must not hang the step).
func (c *containers) do(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, c.docker, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// pull pulls the image, retrying, and fails blaming the environment.
func (c *containers) pull() {
	c.t.Helper()
	var out string
	var err error
	for i := 1; i <= reachTries; i++ {
		start := time.Now()
		if out, err = c.do("pull", c.image); err == nil {
			c.t.Logf("pulled %s in %v", c.image, time.Since(start).Round(time.Second))
			return
		}
		c.t.Logf("docker pull %s, try %d: %v\n%s", c.image, i, err, out)
		time.Sleep(10 * time.Second)
	}
	c.t.Fatalf("environment: cannot pull %s after %d tries: %v\n%s", c.image, reachTries, err, out)
}

// reach probes until the container connects, at most reachTries times.
func (c *containers) reach(isolation, phase string) probeResult {
	c.t.Helper()
	var r probeResult
	for i := 1; i <= reachTries; i++ {
		if r = c.probe(isolation, fmt.Sprintf("%s (try %d)", phase, i)); r.ran && r.outcome == outConnected {
			return r
		}
		time.Sleep(5 * time.Second)
	}
	return r
}

// expectDenied passes only when the connect failed at once with
// WSAEACCES, which a WFP filter at ALE_AUTH_CONNECT returns.
func (c *containers) expectDenied(r probeResult) {
	c.t.Helper()
	switch {
	case !r.ran:
		c.t.Errorf("inconclusive: %s", r)
	case r.outcome == outConnected:
		c.t.Errorf("filter: with the VPN down the container reached %s: %s", forwardTarget, r)
	case r.outcome != outDenied || r.took > 1500*time.Millisecond:
		c.t.Errorf("inconclusive: with the VPN down the container's connect %s; want WSAEACCES at once", r)
	}
}

// expectDropped passes only when the connect timed out or was refused:
// IPFORWARD drops the guest's packets, so its own kernel gives up.
func (c *containers) expectDropped(r probeResult) {
	c.t.Helper()
	switch {
	case !r.ran:
		c.t.Errorf("inconclusive: %s", r)
	case r.outcome == outConnected:
		c.t.Errorf("filter: with the VPN down the Hyper-V isolated container reached %s: IPFORWARD did not block it: %s", forwardTarget, r)
	case r.outcome != outTimeout && r.outcome != outRefused:
		c.t.Errorf("inconclusive: with the VPN down the Hyper-V isolated container's connect %s; want a timeout or a refusal", r)
	}
}

// probe runs TestForwardProbe once in a new container with this isolation
// and logs what it reports.
func (c *containers) probe(isolation, phase string) probeResult {
	c.t.Helper()
	start := time.Now()
	out, err := c.do("create", "--isolation="+isolation, "--network=nat", "--user=ContainerAdministrator",
		"-e", "LEAKGUARD_FORWARD_PROBE="+forwardTarget,
		c.image, `C:\probe.exe`, "-test.run=^TestForwardProbe$", "-test.v")
	if err != nil {
		r := probeResult{failure: fmt.Sprintf("docker create: %v: %s", err, out)}
		c.t.Logf("%s: %s", phase, r)
		return r
	}
	fields := strings.Fields(out)
	id := fields[len(fields)-1]
	defer c.do("rm", "--force", id)
	if out, err := c.do("cp", c.exe, id+`:C:\probe.exe`); err != nil {
		r := probeResult{failure: fmt.Sprintf("docker cp the probe into the container: %v: %s", err, out)}
		c.t.Logf("%s: %s", phase, r)
		return r
	}
	if c.described == nil {
		c.described = map[string]bool{}
	}
	if !c.described[isolation] {
		c.described[isolation] = true
		out, err := c.do("inspect", "--format", "isolation {{.HostConfig.Isolation}}, network mode {{.HostConfig.NetworkMode}}, user {{.Config.User}}", id)
		c.t.Logf("container: %s (%v)", out, err)
	}
	out, err = c.do("start", "--attach", id)
	r := probeResult{failure: fmt.Sprintf("docker start: %v: %s", err, out)}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if info, ok := strings.CutPrefix(l, "LEAKGUARD-PROBE-INFO: "); ok {
			c.t.Logf("%s: in the container: %s", phase, info)
		}
		if res, ok := strings.CutPrefix(l, "LEAKGUARD-PROBE: "); ok {
			parts := strings.SplitN(res, " ", 3)
			if len(parts) == 3 {
				ms, _ := strconv.Atoi(parts[1])
				r = probeResult{ran: true, outcome: parts[0], took: time.Duration(ms) * time.Millisecond, detail: parts[2]}
			}
		}
	}
	c.t.Logf("%s (%s isolation, %v in all): container connect %s: %s", phase, isolation, time.Since(start).Round(time.Millisecond), forwardTarget, r)
	return r
}

// TestForwardProbe is not a test of its own: TestIntegrationForwardedTraffic
// runs this binary inside a Windows container, where it connects to the
// address in LEAKGUARD_FORWARD_PROBE and prints "LEAKGUARD-PROBE: <outcome>
// <milliseconds> <detail>".
func TestForwardProbe(t *testing.T) {
	target := os.Getenv("LEAKGUARD_FORWARD_PROBE")
	if target == "" {
		t.Skip("run by TestIntegrationForwardedTraffic inside a Windows container")
	}
	var addrs []string
	if as, err := net.InterfaceAddrs(); err != nil {
		addrs = append(addrs, err.Error())
	} else {
		for _, a := range as {
			addrs = append(addrs, a.String())
		}
	}
	fmt.Printf("LEAKGUARD-PROBE-INFO: addresses %s\n", strings.Join(addrs, ", "))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	took := time.Since(start)
	if err == nil {
		fmt.Printf("LEAKGUARD-PROBE-INFO: connected from %s to %s\n", conn.LocalAddr(), conn.RemoteAddr())
		conn.Close()
	}
	fmt.Printf("LEAKGUARD-PROBE: %s %d %s\n", outcome(err), took.Milliseconds(), classify(err))
}

// nanoserverImage is the Nano Server image a process-isolated container
// needs on this Windows build.
func nanoserverImage(t *testing.T) string {
	t.Helper()
	build := windows.RtlGetVersion().BuildNumber
	tag, ok := map[uint32]string{17763: "ltsc2019", 20348: "ltsc2022", 26100: "ltsc2025"}[build]
	if !ok {
		t.Fatalf("no Nano Server image is known for Windows build %d", build)
	}
	return "mcr.microsoft.com/windows/nanoserver:" + tag
}

// routeTo returns the adapter the best route to ip leaves on.
func routeTo(t *testing.T, ip [4]byte) Adapter {
	t.Helper()
	var index uint32
	if err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: ip}, &index); err != nil {
		t.Fatalf("GetBestInterfaceEx: %v", err)
	}
	as, err := adapters()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range as {
		if a.Index == index {
			return a
		}
	}
	t.Fatalf("no adapter has interface index %d: %v", index, as)
	return Adapter{}
}
