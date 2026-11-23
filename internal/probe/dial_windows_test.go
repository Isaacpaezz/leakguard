//go:build windows

package probe

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// loopbackName returns the name of Windows' loopback interface
// ("Loopback Pseudo-Interface 1" in English).
func loopbackName(t *testing.T) string {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagLoopback != 0 && ifi.Flags&net.FlagUp != 0 {
			return ifi.Name
		}
	}
	t.Fatal("no loopback interface is up")
	return ""
}

// S1: the probe bound to an interface with IP_UNICAST_IF reaches a listener
// through it, fails for a missing interface, and a closed port is a refusal
// that counts as blocked.
func TestBoundDialUsesTheGivenInterfaceOnWindows(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	lo := loopbackName(t)
	addr := netip.MustParseAddrPort(ln.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := BoundDial(ctx, lo, addr); err != nil {
		t.Fatalf("BoundDial(%q) = %v, want a connection", lo, err)
	}
	if err := BoundDial(ctx, "leakguard-missing-adapter", addr); err == nil {
		t.Fatal("BoundDial(missing adapter) = nil, want an error")
	}
	ln.Close()
	// Windows retries a refused loopback SYN for about two seconds.
	rctx, rcancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer rcancel()
	err = BoundDial(rctx, lo, addr)
	if o, _ := classify(err); o != Blocked {
		t.Fatalf("BoundDial to a closed port = %v (%v), want a refusal classified as blocked", err, o)
	}
}

// S1: the IPv6 option (host-order index) also binds the probe.
func TestBoundDialIPv6OnWindows(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := BoundDial(ctx, loopbackName(t), netip.MustParseAddrPort(ln.Addr().String())); err != nil {
		t.Fatalf("BoundDial over IPv6 = %v, want a connection", err)
	}
}
