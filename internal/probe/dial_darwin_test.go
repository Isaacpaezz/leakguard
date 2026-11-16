//go:build darwin

package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

func TestBoundDialUsesTheGivenInterface(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
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
	addr := netip.MustParseAddrPort(ln.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := BoundDial(ctx, "lo0", addr); err != nil {
		t.Fatalf("BoundDial(lo0) = %v, want a connection", err)
	}
	if err := BoundDial(ctx, "utun999", addr); err == nil {
		t.Fatal("BoundDial(utun999) = nil, want an error for a missing interface")
	}
	ln.Close()
	if err := BoundDial(ctx, "lo0", addr); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("BoundDial to a closed port = %v, want connection refused", err)
	}
}
