package nft

import (
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
)

// TestIntegrationRealRules loads real rules into the kernel and probes them
// with a local TCP listener (S4). It needs root and nftables:
//
//	LEAKGUARD_NFT_INTEGRATION=1 go test -run Integration ./internal/nft/
func TestIntegrationRealRules(t *testing.T) {
	if os.Getenv("LEAKGUARD_NFT_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("set LEAKGUARD_NFT_INTEGRATION=1 and run as root")
	}
	if _, err := Find(func(p string) bool { _, err := os.Stat(p); return err == nil }); err != nil {
		t.Skip(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
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
	connect := func() error {
		d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}}
		c, err := d.Dial("tcp", ln.Addr().String())
		if err == nil {
			c.Close()
		}
		return err
	}
	// The listener's address is protected and the dialer's is not, as on a
	// real machine: the reset that refuses the connect goes to the dialer.
	// Nested, touching and non-prefix ranges must load and verify too.
	protected := []catalog.Service{{ID: "local",
		IPv4: []string{"127.0.0.2/32", "198.51.100.0/24", "198.51.100.64/26", "203.0.113.0/25", "203.0.113.128/25"},
		IPv6: []string{"::1/128", "2001:db8::/127", "2001:db8::2/128"}}}
	check := func(name string) error {
		if name == "lo" || name == "tun9" {
			return nil
		}
		return errors.New(name + " is not a VPN interface")
	}
	fw := Firewall{Runner: ExecRunner{}, Check: check}
	defer fw.Flush()

	if err := fw.Apply("lo", protected); err != nil {
		t.Fatalf("Apply(lo) = %v", err)
	}
	if err := connect(); err != nil {
		t.Fatalf("connect with VPN lo = %v, want success", err)
	}

	if err := fw.Apply("tun9", protected); err != nil {
		t.Fatalf("Apply(tun9) = %v", err)
	}
	if err := fw.Verify("tun9", protected); err != nil {
		t.Fatalf("Verify(tun9) = %v", err)
	}
	start := time.Now()
	if err := connect(); !errors.Is(err, syscall.ECONNREFUSED) || time.Since(start) > time.Second {
		t.Fatalf("connect with VPN tun9 = %v after %v, want a quick ECONNREFUSED", err, time.Since(start))
	}
	if n, err := fw.BlockCount(); err != nil || n == 0 {
		t.Fatalf("BlockCount() = %d, %v, want > 0", n, err)
	}
	if _, err := (ExecRunner{}).Run("", "flush", "chain", "inet", Table, Chain); err != nil {
		t.Fatal(err)
	}
	if err := fw.Verify("tun9", protected); err == nil {
		t.Fatal("Verify() after flushing the chain = nil, want an error")
	}

	// S7: a refused VPN loads rules that allow no interface.
	err = fw.Apply("eth0", protected)
	if err == nil || !strings.Contains(err.Error(), "eth0 is not a VPN interface") {
		t.Fatalf("Apply(eth0) = %v, want the refusal", err)
	}
	if err := connect(); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("connect with a refused VPN = %v, want ECONNREFUSED", err)
	}
	if err := fw.Verify("lo", protected); err == nil || !strings.Contains(err.Error(), "allow no interface") {
		t.Fatalf("Verify(lo) after a refused VPN = %v, want block-all rules", err)
	}

	if err := fw.Flush(); err != nil {
		t.Fatalf("Flush() = %v", err)
	}
	if err := fw.Flush(); err != nil {
		t.Fatalf("Flush() without a table = %v", err)
	}
	if err := fw.Verify("lo", protected); !errors.Is(err, ErrNotLoaded) {
		t.Fatalf("Verify() after Flush = %v, want ErrNotLoaded", err)
	}
	if err := connect(); err != nil {
		t.Fatalf("connect after Flush = %v, want success", err)
	}
}
