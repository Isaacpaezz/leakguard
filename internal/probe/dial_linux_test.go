//go:build linux

package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestBoundDialUsesTheGivenInterfaceOnLinux(t *testing.T) {
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
	err = BoundDial(ctx, "lo", addr)
	if errors.Is(err, syscall.EPERM) {
		t.Skipf("this kernel needs root for SO_BINDTODEVICE: %v", err)
	}
	if err != nil {
		t.Fatalf("BoundDial(lo) = %v, want a connection", err)
	}
	if err := BoundDial(ctx, "tun999", addr); err == nil {
		t.Fatal("BoundDial(tun999) = nil, want an error for a missing interface")
	}
	ln.Close()
	if err := BoundDial(ctx, "lo", addr); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("BoundDial to a closed port = %v, want connection refused", err)
	}
}

// Old kernels refuse SO_BINDTODEVICE without root; the error says what to do.
func TestBindErrorAsksForSudo(t *testing.T) {
	err := bindError("eth0", syscall.EPERM)
	if err == nil || !errors.Is(err, syscall.EPERM) || !strings.Contains(err.Error(), "run the test with sudo") {
		t.Fatalf("bindError(EPERM) = %v", err)
	}
	if bindError("eth0", nil) != nil {
		t.Fatal("bindError(nil) != nil")
	}
	err = bindError("eth0", syscall.ENODEV)
	if err == nil || !errors.Is(err, syscall.ENODEV) || strings.Contains(err.Error(), "sudo") {
		t.Fatalf("bindError(ENODEV) = %v", err)
	}
	// Never counted as blocked: only a refusal proves the rule.
	if o, _ := classify(err); o != Untested {
		t.Fatalf("classify(bind error) = %v, want untested", o)
	}
}
