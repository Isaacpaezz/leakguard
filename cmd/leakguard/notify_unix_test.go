//go:build unix

package main

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/firewall"
)

// listenNotify is a stand-in for systemd's $NOTIFY_SOCKET.
func listenNotify(t *testing.T) (string, *net.UnixConn) {
	t.Helper()
	path := shortSocket(t)
	l, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return path, l
}

// readNotify returns the next datagram, or "" when none arrives in wait.
func readNotify(t *testing.T, l *net.UnixConn, wait time.Duration) string {
	t.Helper()
	l.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 256)
	n, err := l.Read(buf)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n])
}

// orderedFirewall checks, on each Apply, that systemd was not told yet.
type orderedFirewall struct {
	firewall.Firewall
	t       *testing.T
	l       *net.UnixConn
	applied chan struct{}
}

func (f orderedFirewall) Apply(vpn string, s []catalog.Service) error {
	if got := readNotify(f.t, f.l, time.Millisecond); got != "" {
		f.t.Errorf("systemd was told %q before the rules were loaded", got)
	}
	select {
	case f.applied <- struct{}{}:
	default:
	}
	return f.Firewall.Apply(vpn, s)
}

// S1, S7: serve reaches network-pre.target only once the rules are loaded,
// and says so exactly once.
func TestServeNotifiesSystemdOnceTheRulesAreLoaded(t *testing.T) {
	h := newHarness(t, true)
	h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}})
	path, l := listenNotify(t)
	h.env.NotifySocket = path
	applied := make(chan struct{}, 1)
	h.env.Firewall = func(e Env) firewall.Firewall {
		return orderedFirewall{Firewall: pfFirewall(e), t: t, l: l, applied: applied}
	}
	s := startServe(t, h)
	select {
	case <-applied:
	default:
		t.Fatal("serve did not load the rules at start")
	}
	if got := readNotify(t, l, 5*time.Second); got != "READY=1" {
		t.Fatalf("notification = %q, want READY=1", got)
	}
	if got := readNotify(t, l, 50*time.Millisecond); got != "" {
		t.Errorf("second notification %q, want none", got)
	}
	if code := s.stop(t); code != 0 {
		t.Fatalf("serve exit code = %d: %s", code, s.stderr.String())
	}
}

// S7: a failed first load still lets the boot go on; what loaded (or
// nothing) is what fails closed.
func TestServeNotifiesSystemdWhenTheFirstLoadFails(t *testing.T) {
	h := newHarness(t, true) // not configured: the first load fails
	path, l := listenNotify(t)
	h.env.NotifySocket = path
	startServe(t, h)
	if got := readNotify(t, l, 5*time.Second); got != "READY=1" {
		t.Fatalf("notification = %q, want READY=1", got)
	}
}

func TestNotifyReady(t *testing.T) {
	if err := notifyReady(""); err != nil {
		t.Errorf("notifyReady(\"\") = %v, want a no-op", err)
	}
	path, l := listenNotify(t)
	if err := notifyReady(path); err != nil {
		t.Fatalf("notifyReady() = %v", err)
	}
	if got := readNotify(t, l, 5*time.Second); got != "READY=1" {
		t.Fatalf("notification = %q, want READY=1", got)
	}
	l.Close()
	os.Remove(path)
	if err := notifyReady(path); err == nil {
		t.Error("notifyReady() without a listener = nil, want an error")
	}
}
