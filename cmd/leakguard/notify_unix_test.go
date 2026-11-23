//go:build unix

package main

import (
	"errors"
	"net"
	"os"
	"syscall"
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

// applyRecord is what orderedFirewall saw on one Apply: whether systemd had
// been told anything yet.
type applyRecord struct {
	notified bool
	err      error
}

// orderedFirewall records, on each Apply, whether a notification waits on
// the stand-in socket. It only peeks, so it never takes the datagram the
// test reads, and it never fails the test from serve's goroutine: the test
// checks the records.
type orderedFirewall struct {
	firewall.Firewall
	l       *net.UnixConn
	applies chan<- applyRecord
}

func (f orderedFirewall) Apply(vpn string, s []catalog.Service) error {
	notified, err := pending(f.l)
	select {
	case f.applies <- applyRecord{notified, err}:
	default:
	}
	return f.Firewall.Apply(vpn, s)
}

// pending reports whether a datagram waits on l, without reading it.
func pending(l *net.UnixConn) (bool, error) {
	raw, err := l.SyscallConn()
	if err != nil {
		return false, err
	}
	var rerr error
	if err := raw.Control(func(fd uintptr) {
		_, _, rerr = syscall.Recvfrom(int(fd), make([]byte, 1), syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
	}); err != nil {
		return false, err
	}
	if errors.Is(rerr, syscall.EAGAIN) {
		return false, nil
	}
	return rerr == nil, rerr
}

// S1, S7: serve reaches network-pre.target only once the rules are loaded,
// and says so exactly once.
func TestServeNotifiesSystemdOnceTheRulesAreLoaded(t *testing.T) {
	h := newHarness(t, true)
	h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}})
	path, l := listenNotify(t)
	h.env.NotifySocket = path
	applies := make(chan applyRecord, 16)
	h.env.Firewall = func(e Env) firewall.Firewall {
		return orderedFirewall{Firewall: pfFirewall(e), l: l, applies: applies}
	}
	s := startServe(t, h)
	select {
	case first := <-applies:
		if first.err != nil || first.notified {
			t.Fatalf("first Apply saw notified %v, error %v; want the rules loaded before systemd is told", first.notified, first.err)
		}
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

// pending sees a notification without taking it.
func TestPendingPeeksWithoutReading(t *testing.T) {
	path, l := listenNotify(t)
	if got, err := pending(l); got || err != nil {
		t.Fatalf("pending() on an empty socket = %v, %v", got, err)
	}
	if err := notifyReady(path); err != nil {
		t.Fatal(err)
	}
	if got, err := pending(l); !got || err != nil {
		t.Fatalf("pending() after a notification = %v, %v", got, err)
	}
	if got := readNotify(t, l, 5*time.Second); got != "READY=1" {
		t.Fatalf("notification = %q after pending(), want READY=1", got)
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
