package wfp

import (
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
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
// plus 192.0.2.1/32 (TEST-NET-1, never answers). It proves the arbitration,
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
// Rules gives it, and logs them.
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
