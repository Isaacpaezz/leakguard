package nft

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"testing"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
)

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// findNft is Find on the real file system.
func findNft() error { _, err := Find(fileExists); return err }

// requireIntegration skips unless LEAKGUARD_NFT_INTEGRATION=1 and fails
// when that run lacks root or a tool, so it never passes without probing.
func requireIntegration(t *testing.T, finds ...func() error) {
	t.Helper()
	run, err := integrationGate(os.Getenv("LEAKGUARD_NFT_INTEGRATION"), os.Geteuid(), append([]func() error{findNft}, finds...)...)
	if err != nil {
		t.Fatal(err)
	}
	if !run {
		t.Skip("set LEAKGUARD_NFT_INTEGRATION=1 and run as root")
	}
}

// TestIntegrationRealRules loads real rules into the kernel and probes them
// with a local TCP listener (S4). It needs root and nftables:
//
//	LEAKGUARD_NFT_INTEGRATION=1 go test -run Integration ./internal/nft/
func TestIntegrationRealRules(t *testing.T) {
	requireIntegration(t)
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
	// An empty VPN asks for the same block-all rules, and they verify.
	if err := fw.Apply("", protected); err != nil {
		t.Fatalf("Apply(\"\") = %v", err)
	}
	if err := fw.Verify("", protected); err != nil {
		t.Fatalf("Verify(\"\") = %v", err)
	}
	if err := connect(); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("connect with no VPN = %v, want ECONNREFUSED", err)
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

// ipPaths are where iproute2's ip may live.
var ipPaths = []string{"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"}

func findIP() (string, error) {
	for _, p := range ipPaths {
		if fileExists(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("ip not found at %s; install iproute2", strings.Join(ipPaths, ", "))
}

// netnsRunner runs nft inside a named network namespace.
type netnsRunner struct{ ip, ns string }

func (r netnsRunner) Run(stdin string, args ...string) (string, error) {
	nft, err := Find(fileExists)
	if err != nil {
		return "", err
	}
	cmd := exec.Command(r.ip, append([]string{"netns", "exec", r.ns, nft}, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("nft %s in %s: %v: %s", strings.Join(args, " "), r.ns, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// inNetns runs f on a thread moved into the named network namespace, so the
// sockets f creates live there. The thread is never unlocked: it ends with
// the goroutine instead of going back to the scheduler in that namespace.
func inNetns(ns string, f func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		fd, err := syscall.Open("/run/netns/"+ns, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			done <- err
			return
		}
		defer syscall.Close(fd)
		// unix.Setns: the syscall package has no SYS_SETNS on amd64.
		if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
			done <- fmt.Errorf("setns %s: %w", ns, err)
			return
		}
		done <- f()
	}()
	return <-done
}

// TestIntegrationForwardedTraffic routes a client through this computer, as
// rootful Docker and libvirt NAT do, and checks that the forward chain holds
// that traffic to the same rules (S7). Three network namespaces stand in for
// the container, this computer and the service:
//
//	client 10.231.1.2 --cr/rc-- router (forwarding, leakguard) --rs/sr-- server 10.231.2.2
//
// The router's rs plays the VPN when it is allowed and the real connection
// when it is not. It needs root, nftables and iproute2:
//
//	LEAKGUARD_NFT_INTEGRATION=1 go test -run Integration ./internal/nft/
func TestIntegrationForwardedTraffic(t *testing.T) {
	requireIntegration(t, func() error { _, err := findIP(); return err })
	ipPath, _ := findIP()
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(ipPath, args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	id := strconv.Itoa(os.Getpid())
	router, client, server := "lgr"+id, "lgc"+id, "lgs"+id
	for _, ns := range []string{router, client, server} {
		ip("netns", "add", ns)
		t.Cleanup(func() { exec.Command(ipPath, "netns", "del", ns).Run() })
	}
	ip("-n", router, "link", "add", "rc", "type", "veth", "peer", "name", "cr", "netns", client)
	ip("-n", router, "link", "add", "rs", "type", "veth", "peer", "name", "sr", "netns", server)
	for _, a := range [][3]string{{router, "10.231.1.1/24", "rc"}, {router, "10.231.2.1/24", "rs"}, {client, "10.231.1.2/24", "cr"}, {server, "10.231.2.2/24", "sr"}} {
		ip("-n", a[0], "addr", "add", a[1], "dev", a[2])
	}
	for _, l := range [][2]string{{router, "lo"}, {router, "rc"}, {router, "rs"}, {client, "lo"}, {client, "cr"}, {server, "lo"}, {server, "sr"}} {
		ip("-n", l[0], "link", "set", l[1], "up")
	}
	ip("-n", client, "route", "add", "default", "via", "10.231.1.1")
	ip("-n", server, "route", "add", "default", "via", "10.231.2.1")
	ip("netns", "exec", router, "sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward")

	var ln net.Listener
	if err := inNetns(server, func() (err error) { ln, err = net.Listen("tcp", "10.231.2.2:0"); return err }); err != nil {
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
		return inNetns(client, func() error {
			c, err := (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp", ln.Addr().String())
			if err == nil {
				c.Close()
			}
			return err
		})
	}
	if err := connect(); err != nil {
		t.Fatalf("forwarded connect without rules = %v, want success", err)
	}

	protected := []catalog.Service{{ID: "server", IPv4: []string{"10.231.2.2/32"}, IPv6: []string{"2001:db8::/64"}}}
	check := func(name string) error {
		if name == "rs" || name == "tun9" {
			return nil
		}
		return errors.New(name + " is not a VPN interface")
	}
	fw := Firewall{Runner: netnsRunner{ipPath, router}, Check: check}
	defer fw.Flush()

	if err := fw.Apply("rs", protected); err != nil {
		t.Fatalf("Apply(rs) = %v", err)
	}
	if err := connect(); err != nil {
		t.Fatalf("forwarded connect through the VPN rs = %v, want success", err)
	}

	if err := fw.Apply("tun9", protected); err != nil {
		t.Fatalf("Apply(tun9) = %v", err)
	}
	start := time.Now()
	if err := connect(); !errors.Is(err, syscall.ECONNREFUSED) || time.Since(start) > time.Second {
		t.Fatalf("forwarded connect with VPN tun9 = %v after %v, want a quick ECONNREFUSED", err, time.Since(start))
	}
	if n, err := fw.BlockCount(); err != nil || n == 0 {
		t.Fatalf("BlockCount() = %d, %v, want > 0 from the forward chain", n, err)
	}
	if err := fw.Verify("tun9", protected); err != nil {
		t.Fatalf("Verify(tun9) = %v", err)
	}
	if _, err := fw.Runner.Run("", "flush", "chain", "inet", Table, ForwardChain); err != nil {
		t.Fatal(err)
	}
	if err := fw.Verify("tun9", protected); err == nil || !strings.Contains(err.Error(), "not loaded in chain forward") {
		t.Fatalf("Verify() after flushing the forward chain = %v, want an error", err)
	}

	// S7: the block-all rules hold forwarded traffic too.
	if err := fw.Apply("", protected); err != nil {
		t.Fatalf("Apply(\"\") = %v", err)
	}
	if err := connect(); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("forwarded connect with no VPN = %v, want ECONNREFUSED", err)
	}

	if err := fw.Flush(); err != nil {
		t.Fatalf("Flush() = %v", err)
	}
	if err := connect(); err != nil {
		t.Fatalf("forwarded connect after Flush = %v, want success", err)
	}
}
