package wfp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
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

// TestIntegrationForwardedTraffic (SF2) proves the IPFORWARD filters on
// traffic this computer forwards for others. A Windows container on
// Docker's nat network reaches the internet through WinNAT on the host, so
// the host forwards its packets from the vEthernet (nat) adapter to the
// real one. The test copies its own binary into a Nano Server container
// matching this Windows build and runs TestForwardProbe there to connect to
// forwardTarget, protected for the test. The binary goes in with docker cp
// into the created, not yet started, container, never through a bind
// mount: a mounted host folder keeps the host's ACL, which the container's
// account cannot use (CreateProcess fails with ERROR_ACCESS_DENIED), while
// a copied file inherits the container's own C:\ ACL. The probe also runs
// as ContainerAdministrator. The log names the container's isolation,
// network and addresses, so it shows whether its traffic is NAT-forwarded.
// Phases:
//
//   - nothing loaded: the container connects (the network works);
//   - IPFORWARD blocks only: the container cannot connect, while this
//     computer still can (forwarded traffic is filtered at IPFORWARD, and
//     IPFORWARD never touches this computer's own connections);
//   - IPFORWARD blocks and permits for the adapter the route leaves on (the
//     VPN's role here): the container connects again (the permit matches
//     the interface packets are forwarded to);
//   - Apply with the VPN down (every block): the container cannot connect
//     and this computer gets WSAEACCES;
//   - after Flush: the container connects.
//
// It also logs, without judging, what ALE alone and a full Apply with that
// adapter as the VPN do to the container: a process-isolated container
// shares this kernel, so its own connects may meet ALE_AUTH_CONNECT too.
// It needs an elevated shell, Docker with Windows containers and
// LEAKGUARD_WFP_FORWARD_INTEGRATION=1, and fails rather than skips when
// one is missing.
func TestIntegrationForwardedTraffic(t *testing.T) {
	if os.Getenv("LEAKGUARD_WFP_FORWARD_INTEGRATION") != "1" {
		t.Skip("set LEAKGUARD_WFP_FORWARD_INTEGRATION=1 in an elevated shell with Docker (Windows containers) to probe forwarded traffic")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("LEAKGUARD_WFP_FORWARD_INTEGRATION=1 needs an elevated (administrator) shell")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatalf("LEAKGUARD_WFP_FORWARD_INTEGRATION=1 needs Docker with Windows containers: %v", err)
	}
	image := nanoserverImage(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dockerDo := func(args ...string) (string, error) {
		out, err := exec.Command(docker, args...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	start := time.Now()
	if out, err := dockerDo("pull", image); err != nil {
		t.Fatalf("docker pull %s: %v\n%s", image, err, out)
	}
	t.Logf("pulled %s in %v", image, time.Since(start).Round(time.Second))
	info, err := dockerDo("info", "--format", "default isolation {{.Isolation}}, OS {{.OperatingSystem}} {{.KernelVersion}}")
	t.Logf("docker: %s (%v)", info, err)
	info, err = dockerDo("network", "inspect", "nat", "--format", "network nat: driver {{.Driver}}, IPAM {{json .IPAM.Config}}, options {{json .Options}}")
	t.Logf("docker: %s (%v)", info, err)
	described := false
	probe := func(phase string) bool {
		t.Helper()
		start := time.Now()
		out, err := dockerDo("create", "--isolation=process", "--network=nat", "--user=ContainerAdministrator",
			"-e", "LEAKGUARD_FORWARD_PROBE="+forwardTarget,
			image, `C:\probe.exe`, "-test.run=^TestForwardProbe$", "-test.v")
		if err != nil {
			t.Fatalf("%s: docker create: %v\n%s", phase, err, out)
		}
		lines := strings.Fields(out)
		id := lines[len(lines)-1]
		defer dockerDo("rm", "--force", id)
		if out, err := dockerDo("cp", exe, id+`:C:\probe.exe`); err != nil {
			t.Fatalf("%s: docker cp the probe into the container: %v\n%s", phase, err, out)
		}
		if !described {
			described = true
			out, err := dockerDo("inspect", "--format", "isolation {{.HostConfig.Isolation}}, network mode {{.HostConfig.NetworkMode}}, user {{.Config.User}}", id)
			t.Logf("container: %s (%v)", out, err)
		}
		out, err = dockerDo("start", "--attach", id)
		var result string
		ran := false
		for _, l := range strings.Split(out, "\n") {
			l = strings.TrimSpace(l)
			if info, ok := strings.CutPrefix(l, "LEAKGUARD-PROBE-INFO: "); ok {
				t.Logf("%s: in the container: %s", phase, info)
			}
			if r, ok := strings.CutPrefix(l, "LEAKGUARD-PROBE: "); ok {
				result, ran = r, true
			}
		}
		if !ran {
			t.Fatalf("%s: the probe did not run in the container (%v):\n%s", phase, err, out)
		}
		t.Logf("%s: container connect %s after %v: %s", phase, forwardTarget, time.Since(start).Round(time.Millisecond), result)
		return result == "connected"
	}

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
	only := func(luid uint64, forward bool) []Rule {
		t.Helper()
		rules, err := Rules(luid, services)
		if err != nil {
			t.Fatal(err)
		}
		return slices.DeleteFunc(rules, func(r Rule) bool { return r.Layer.Forward() != forward })
	}
	out := routeTo(t, [4]byte{1, 1, 1, 1})
	t.Logf("the route to %s leaves on %q, LUID %#x", forwardTarget, out.Alias, out.LUID)

	if !probe("nothing loaded") {
		t.Fatalf("with no filter loaded the container cannot reach %s: the runner's container network does not work, nothing was proven", forwardTarget)
	}

	if err := f.load(only(0, true)); err != nil {
		t.Fatalf("load the IPFORWARD blocks: %v", err)
	}
	if probe("IPFORWARD blocks only") {
		t.Errorf("forwarded traffic to %s passed the IPFORWARD block", forwardTarget)
	}
	if err := connect(forwardTarget, 5*time.Second); err != nil {
		t.Errorf("with IPFORWARD filters only, this computer's own connect to %s: %s; IPFORWARD must not touch it", forwardTarget, classify(err))
	}

	if err := f.load(only(out.LUID, true)); err != nil {
		t.Fatalf("load the IPFORWARD blocks and permits: %v", err)
	}
	if !probe("IPFORWARD blocks and permits for " + out.Alias) {
		t.Errorf("forwarded traffic to %s leaving on %q (LUID %#x) was blocked: the permit must match the interface packets are forwarded to", forwardTarget, out.Alias, out.LUID)
	}

	if err := f.load(only(0, false)); err != nil {
		t.Fatalf("load the ALE blocks: %v", err)
	}
	t.Logf("diagnostic, not judged: with ALE_AUTH_CONNECT blocks only, the container connected = %v", probe("ALE blocks only"))

	if err := f.Apply(absentVPN, services); err != nil {
		t.Fatalf("Apply(%q): %v", absentVPN, err)
	}
	if err := f.Verify(absentVPN, services); err != nil {
		t.Errorf("Verify(%q): %v", absentVPN, err)
	}
	if probe("Apply with the VPN down") {
		t.Errorf("with the VPN down, forwarded traffic to %s passed", forwardTarget)
	}
	if err := connect(forwardTarget, 5*time.Second); !errors.Is(err, windows.WSAEACCES) {
		t.Errorf("with the VPN down, this computer's connect to %s: %s; want WSAEACCES", forwardTarget, classify(err))
	}

	if err := f.Apply(out.Alias, services); err != nil {
		t.Fatalf("Apply(%q): %v", out.Alias, err)
	}
	t.Logf("diagnostic, not judged: with every filter and %q as the VPN, the container connected = %v", out.Alias, probe("Apply with "+out.Alias+" as the VPN"))

	if err := f.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if !probe("after Flush") {
		t.Errorf("after Flush the container cannot reach %s", forwardTarget)
	}
}

// TestForwardProbe is not a test of its own: TestIntegrationForwardedTraffic
// runs this binary inside a Windows container, where it connects to the
// address in LEAKGUARD_FORWARD_PROBE and prints the outcome.
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
	c, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err == nil {
		fmt.Printf("LEAKGUARD-PROBE-INFO: connected from %s to %s\n", c.LocalAddr(), c.RemoteAddr())
		c.Close()
	}
	fmt.Printf("LEAKGUARD-PROBE: %s\n", classify(err))
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
