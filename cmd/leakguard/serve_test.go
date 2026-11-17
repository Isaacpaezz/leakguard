package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/daemon"
	"github.com/Isaacpaezz/leakguard/internal/ipc"
	"github.com/Isaacpaezz/leakguard/internal/pf"
)

// syncBuffer is a bytes.Buffer that the daemon goroutines and the test can
// share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// shortSocket returns a socket path under the 104-byte macOS limit.
func shortSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "lg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "d.sock")
}

func allowAll(net.Conn) error { return nil }

// serving is a running "leakguard serve".
type serving struct {
	stdout, stderr syncBuffer
	cancel         context.CancelFunc
	done           chan int
	client         ipc.Client
}

// startServe runs "serve" as root with a test socket, a no-op chown and an
// accept-all peer check, and waits until the socket answers.
func startServe(t *testing.T, h *harness) *serving {
	t.Helper()
	s := &serving{done: make(chan int, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	h.env.Socket = shortSocket(t)
	h.env.ChownSocket = func(string, int, int) error { return nil }
	if h.env.Authorize == nil {
		h.env.Authorize = allowAll
	}
	if h.env.ApplyEvery == 0 {
		h.env.ApplyEvery = time.Hour
	}
	h.env.ServeContext = func() (context.Context, context.CancelFunc) { return ctx, cancel }
	s.client = ipc.Client{Path: h.env.Socket}
	go func() { s.done <- run([]string{"serve"}, &s.stdout, &s.stderr, h.env) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Lstat(h.env.Socket); err == nil {
			break
		}
		select {
		case code := <-s.done:
			t.Fatalf("serve exited with %d before listening\nstdout: %s\nstderr: %s", code, s.stdout.String(), s.stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("serve never created its socket")
		}
		time.Sleep(time.Millisecond)
	}
	t.Cleanup(func() { s.stop(t) })
	return s
}

// stop cancels serve and returns its exit code. The harness fakes may be
// read only after stop.
func (s *serving) stop(t *testing.T) int {
	t.Helper()
	s.cancel()
	select {
	case code := <-s.done:
		s.done <- code
		return code
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop after cancel")
	}
	return -1
}

func (s *serving) waitFor(t *testing.T, want string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for strings.Count(s.stdout.String(), want) < n {
		if time.Now().After(deadline) {
			t.Fatalf("stdout has fewer than %d %q lines:\n%s", n, want, s.stdout.String())
		}
		time.Sleep(time.Millisecond)
	}
}

func countCalls(calls []string, call string) int {
	n := 0
	for _, c := range calls {
		if c == call {
			n++
		}
	}
	return n
}

const loadAnchor = "-a " + pf.Anchor + " -f -"
const flushAnchor = "-a " + pf.Anchor + " -F all"

var anthropicConfig = config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}}

func TestServeRequiresRoot(t *testing.T) {
	h := newHarness(t, false)
	h.env.Socket = shortSocket(t)
	code, out, errOut := h.run("serve")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: run with sudo: sudo leakguard serve"})
	if exists(h.env.Socket) || len(h.pfctl.calls) != 0 {
		t.Fatal("serve did something without root")
	}
	code, out, errOut = h.run("serve", "extra")
	expect(t, code, out, errOut, 2, nil, []string{"leakguard: serve takes no arguments"})
}

func TestServeAppliesAtStartAndPeriodically(t *testing.T) {
	h := newHarness(t, true)
	h.saveConfig(t, anthropicConfig)
	h.env.ApplyEvery = 5 * time.Millisecond
	s := startServe(t, h)
	s.waitFor(t, "2026-11-16T15:00:00Z Protected through ipsec0: anthropic\n", 3)
	if code := s.stop(t); code != 0 {
		t.Fatalf("serve exit code = %d, stderr: %s", code, s.stderr.String())
	}
	if exists(h.env.Socket) {
		t.Fatal("serve left its socket behind")
	}
	if countCalls(h.pfctl.calls, flushAnchor) != 0 {
		t.Fatalf("serve flushed the rules: %v", h.pfctl.calls)
	}
}

// S3: a failed apply is logged and never flushes the loaded rules.
func TestServeLogsFailuresAndKeepsRunning(t *testing.T) {
	h := newHarness(t, true)
	s := startServe(t, h)
	st, err := s.client.Status()
	if err != nil || st.Protected || st.Reason != ipc.ReasonNotConfigured {
		t.Fatalf("Status() = %+v, %v; want not configured", st, err)
	}
	s.stop(t)
	if got := s.stderr.String(); got != "2026-11-16T15:00:00Z leakguard: not configured yet; run: sudo leakguard enable --vpn IFACE SERVICE...\n" {
		t.Fatalf("stderr = %q", got)
	}
	if len(h.pfctl.calls) != 0 {
		t.Fatalf("pfctl ran without a configuration: %v", h.pfctl.calls)
	}
}

func TestServeStatusVerifiesAsRoot(t *testing.T) {
	h := newHarness(t, true)
	h.saveConfig(t, anthropicConfig)
	log := h.path(daemon.LogPath)
	os.MkdirAll(filepath.Dir(log), 0o755)
	os.WriteFile(log, []byte("2026-11-16T14:59:30Z Protected through ipsec0: anthropic\n"), 0o644)
	s := startServe(t, h)
	st, err := s.client.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Protected || st.Reason != "" || st.VPNInterface != "ipsec0" || !st.VPNConnected ||
		strings.Join(st.Services, ",") != "anthropic" || st.LastRun != "2026-11-16T14:59:30Z Protected through ipsec0: anthropic" {
		t.Fatalf("Status() = %+v", st)
	}
	var cat []string
	for _, c := range st.Catalog {
		cat = append(cat, c.ID+"="+c.Name+"="+c.Status)
	}
	if got := strings.Join(cat, "|"); !strings.Contains(got, "anthropic=Anthropic (Claude)=supported") || !strings.Contains(got, "openai=") || !strings.Contains(got, "=planned") {
		t.Fatalf("catalog = %s", got)
	}
}

// S3: "protected" needs pf enabled and the anchor verified.
func TestServeStatusIsNotProtectedUnlessVerified(t *testing.T) {
	for _, tc := range []struct {
		name, key, value, reason string
	}{
		{"rules missing", "-a " + pf.Anchor + " -s rules", "", "leakguard rules are not loaded"},
		{"pf disabled", "-s info", "Status: Disabled for 0 days\n", "pf is disabled; turn it back on with: sudo leakguard apply"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, true)
			h.saveConfig(t, anthropicConfig)
			h.pfctl.outputs[tc.key] = tc.value
			s := startServe(t, h)
			st, err := s.client.Status()
			if err != nil || st.Protected || st.Reason != tc.reason {
				t.Fatalf("Status() = %+v, %v; want reason %q", st, err, tc.reason)
			}
		})
	}
}

func TestServeSetSavesAndApplies(t *testing.T) {
	h := newHarness(t, true)
	h.saveConfig(t, config.Config{VPNInterface: "utun9", Services: []string{"anthropic"}, Paused: true})
	s := startServe(t, h)
	st, err := s.client.Set("ipsec0", []string{"anthropic"})
	if err != nil || !st.Protected || st.VPNInterface != "ipsec0" {
		t.Fatalf("Set() = %+v, %v", st, err)
	}
	got, err := h.loadConfig(t)
	if err != nil || got.VPNInterface != "ipsec0" || got.Paused || strings.Join(got.Services, ",") != "anthropic" {
		t.Fatalf("saved config = %+v, %v; want ipsec0, unpaused", got, err)
	}
	s.stop(t)
	if countCalls(h.pfctl.calls, loadAnchor) != 1 {
		t.Fatalf("pfctl calls = %v, want one load (none at start while paused)", h.pfctl.calls)
	}
	if !strings.Contains(s.stdout.String(), "2026-11-16T15:00:00Z Protected through ipsec0: anthropic\n") {
		t.Fatalf("set was not logged:\n%s", s.stdout.String())
	}
}

func TestServeSetRejectsInvalidChoicesWithoutChanges(t *testing.T) {
	cases := []struct {
		vpn      string
		services []string
		want     string
	}{
		{"ipsec0", []string{"openai"}, `service "openai" is not supported yet`},
		{"ipsec0", []string{"gemini"}, `unknown service "gemini"`},
		{"en0", []string{"anthropic"}, `"en0" is not a VPN interface; it carries your real connection`},
		{"ipsec0", nil, "no services selected"},
		{"ipsec0 all", []string{"anthropic"}, `"ipsec0 all" is not a valid interface name`},
	}
	h := newHarness(t, true)
	h.saveConfig(t, anthropicConfig)
	before, _ := os.ReadFile(h.path(config.DefaultPath))
	s := startServe(t, h)
	for _, tc := range cases {
		if _, err := s.client.Set(tc.vpn, tc.services); err == nil || err.Error() != tc.want {
			t.Errorf("Set(%q, %v) = %v, want %q", tc.vpn, tc.services, err, tc.want)
		}
	}
	s.stop(t)
	if after, _ := os.ReadFile(h.path(config.DefaultPath)); !bytes.Equal(before, after) {
		t.Fatalf("an invalid set changed the config:\n%s", after)
	}
	if countCalls(h.pfctl.calls, loadAnchor) != 1 || countCalls(h.pfctl.calls, flushAnchor) != 0 {
		t.Fatalf("pfctl calls = %v, want only the start apply", h.pfctl.calls)
	}
}

// S3: when the new rules fail, the old ones stay loaded.
func TestServeSetKeepsRulesWhenApplyFails(t *testing.T) {
	h := newHarness(t, true)
	h.pfctl.fail = map[string]error{loadAnchor: errors.New("pfctl: syntax error")}
	s := startServe(t, h)
	_, err := s.client.Set("ipsec0", []string{"anthropic"})
	if err == nil || err.Error() != "could not apply the firewall rules: pfctl: syntax error" {
		t.Fatalf("Set() = %v", err)
	}
	s.stop(t)
	if countCalls(h.pfctl.calls, flushAnchor) != 0 {
		t.Fatalf("a failed set flushed the rules: %v", h.pfctl.calls)
	}
	if !strings.Contains(s.stderr.String(), "2026-11-16T15:00:00Z leakguard: pfctl: syntax error\n") {
		t.Fatalf("the failure was not logged:\n%s", s.stderr.String())
	}
}

func TestServeDisablePausesWithoutStopping(t *testing.T) {
	h := newHarness(t, true)
	h.saveConfig(t, anthropicConfig)
	h.env.ApplyEvery = 5 * time.Millisecond
	s := startServe(t, h)
	st, err := s.client.Pause()
	if err != nil || st.Protected || st.Reason != ipc.ReasonPaused || strings.Join(st.Services, ",") != "anthropic" {
		t.Fatalf("Pause() = %+v, %v", st, err)
	}
	got, err := h.loadConfig(t)
	if err != nil || !got.Paused || got.VPNInterface != "ipsec0" || strings.Join(got.Services, ",") != "anthropic" {
		t.Fatalf("saved config = %+v, %v; want paused with the services kept", got, err)
	}
	s.waitFor(t, "Protection paused\n", 1)
	applies := strings.Count(s.stdout.String(), "Protected through")
	time.Sleep(50 * time.Millisecond)
	if st, err := s.client.Status(); err != nil || st.Reason != ipc.ReasonPaused {
		t.Fatalf("Status() after pause = %+v, %v; the daemon must keep answering", st, err)
	}
	s.stop(t)
	if n := strings.Count(s.stdout.String(), "Protected through"); n != applies {
		t.Fatalf("the loop re-applied while paused (%d applies, then %d):\n%s", applies, n, s.stdout.String())
	}
	if countCalls(h.pfctl.calls, flushAnchor) != 1 {
		t.Fatalf("pfctl calls = %v, want one flush", h.pfctl.calls)
	}
}

// S3: if the rules cannot be removed, the pause is not saved.
func TestServeDisableFailsWhenFlushFails(t *testing.T) {
	h := newHarness(t, true)
	h.saveConfig(t, anthropicConfig)
	h.pfctl.fail = map[string]error{flushAnchor: errors.New("pfctl: device busy")}
	s := startServe(t, h)
	if _, err := s.client.Pause(); err == nil || err.Error() != "could not remove the firewall rules: pfctl: device busy" {
		t.Fatalf("Pause() = %v", err)
	}
	if got, _ := h.loadConfig(t); got.Paused {
		t.Fatal("pause saved although the rules are still loaded")
	}
}

// S2: only administrators may talk to the daemon.
func TestServeRefusesUnauthorizedPeers(t *testing.T) {
	h := newHarness(t, true)
	h.saveConfig(t, anthropicConfig)
	h.env.Authorize = func(net.Conn) error { return errors.New("uid 501 is not an administrator") }
	s := startServe(t, h)
	for _, call := range []func() (ipc.Status, error){
		s.client.Status, s.client.Pause,
		func() (ipc.Status, error) { return s.client.Set("utun9", []string{"anthropic"}) },
	} {
		if _, err := call(); err == nil || err.Error() != "not authorized" {
			t.Fatalf("request from an unauthorized peer = %v", err)
		}
	}
	s.stop(t)
	if got, _ := h.loadConfig(t); got.Paused || got.VPNInterface != "ipsec0" {
		t.Fatalf("an unauthorized peer changed the config: %+v", got)
	}
	if countCalls(h.pfctl.calls, flushAnchor) != 0 || countCalls(h.pfctl.calls, loadAnchor) != 1 {
		t.Fatalf("pfctl calls = %v, want only the start apply", h.pfctl.calls)
	}
}

func TestServeFailsWhenTheSocketCannotBeCreated(t *testing.T) {
	h := newHarness(t, true)
	h.saveConfig(t, anthropicConfig)
	h.env.Socket = shortSocket(t)
	os.WriteFile(h.env.Socket, []byte("not a socket"), 0o644)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.env.ServeContext = func() (context.Context, context.CancelFunc) { return ctx, cancel }
	h.env.ChownSocket = func(string, int, int) error { return nil }
	code, out, errOut := h.run("serve")
	expect(t, code, out, errOut, 1, []string{"Protected through ipsec0"}, []string{"leakguard: refusing to replace " + h.env.Socket + ": it is not a socket"})
}

// fakeDaemon answers status requests with st on a test socket.
func fakeDaemon(t *testing.T, st ipc.Status) string {
	t.Helper()
	path := shortSocket(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	srv := &ipc.Server{Path: path, Authorize: allowAll, Chown: func(string, int, int) error { return nil },
		Handler: func(ipc.Request) ipc.Response { return ipc.Response{OK: true, Status: &st} }}
	go func() { srv.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	for i := 0; ; i++ {
		if _, err := (ipc.Client{Path: path}).Status(); err == nil {
			return path
		}
		if i > 5000 {
			t.Fatal("fake daemon never answered")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestStatusAsksTheDaemonWithoutRoot(t *testing.T) {
	h := newHarness(t, false)
	h.env.Socket = fakeDaemon(t, ipc.Status{Protected: true, VPNInterface: "ipsec0", VPNConnected: true,
		Services: []string{"anthropic"}, LastRun: "2026-11-16T14:59:30Z Protected through ipsec0: anthropic"})
	code, out, errOut := h.run("status")
	expect(t, code, out, errOut, 0, nil, nil)
	want := "VPN interface:       ipsec0 (connected)\n" +
		"Services:            anthropic\n" +
		"Background service:  running\n" +
		"Last background run: 2026-11-16T14:59:30Z Protected through ipsec0: anthropic\n" +
		"Firewall:            PROTECTED\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	if len(h.pfctl.calls) != 0 {
		t.Fatalf("status ran pfctl without root: %v", h.pfctl.calls)
	}
}

func TestStatusFromTheDaemonWhenNotProtected(t *testing.T) {
	for _, tc := range []struct {
		reason, want string
	}{
		{"leakguard rules are not loaded", "Firewall:           NOT PROTECTED: leakguard rules are not loaded\n"},
		{ipc.ReasonPaused, "Firewall:           NOT PROTECTED: paused\n"},
	} {
		h := newHarness(t, false)
		h.env.Socket = fakeDaemon(t, ipc.Status{Reason: tc.reason, VPNInterface: "utun9", Services: []string{"anthropic"}})
		code, out, errOut := h.run("status")
		expect(t, code, out, errOut, 1, []string{"VPN interface:      utun9 (not connected)\n", "Background service: running\n", tc.want}, nil)
		if strings.Contains(out, "Last background run") {
			t.Fatalf("status shows an empty last run:\n%s", out)
		}
	}
	h := newHarness(t, false)
	h.env.Socket = fakeDaemon(t, ipc.Status{Reason: ipc.ReasonNotConfigured})
	code, out, errOut := h.run("status")
	expect(t, code, out, errOut, 0, []string{"leakguard is not configured yet.\n", "sudo leakguard enable --vpn IFACE SERVICE..."}, nil)
}

// Without an answering daemon, status reads the files as before.
func TestStatusFallsBackWhenTheDaemonDoesNotAnswer(t *testing.T) {
	h := newHarness(t, false)
	h.saveConfig(t, anthropicConfig)
	h.env.Socket = shortSocket(t) // nothing listens there
	code, out, errOut := h.run("status")
	expect(t, code, out, errOut, 0, []string{"ipsec0 (connected)", "not installed", `run "sudo leakguard status" to verify`}, nil)
}

// A user outside group admin gets "not authorized" from the daemon, so status
// reads the files as before.
func TestStatusFallsBackWhenTheDaemonRefusesTheUser(t *testing.T) {
	h := newHarness(t, false)
	h.saveConfig(t, anthropicConfig)
	path := shortSocket(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	srv := &ipc.Server{Path: path, Chown: func(string, int, int) error { return nil },
		Authorize: func(net.Conn) error { return errors.New("uid 502 is not an administrator") },
		Handler:   func(ipc.Request) ipc.Response { return ipc.Response{OK: true, Status: &ipc.Status{Protected: true}} }}
	go func() { srv.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	for i := 0; ; i++ {
		if _, err := (ipc.Client{Path: path}).Status(); err != nil && err.Error() == "not authorized" {
			break
		}
		if i > 5000 {
			t.Fatal("fake daemon never answered")
		}
		time.Sleep(time.Millisecond)
	}
	h.env.Socket = path
	code, out, errOut := h.run("status")
	expect(t, code, out, errOut, 0, []string{"ipsec0 (connected)", "not installed", `run "sudo leakguard status" to verify`}, nil)
	if strings.Contains(out, "PROTECTED") {
		t.Fatalf("status trusted a refused daemon:\n%s", out)
	}
}

// overlapPfctl records the most pfctl runs in flight at once.
type overlapPfctl struct {
	mu        sync.Mutex
	inner     *fakePfctl
	inFlight  int
	maxFlight int
}

func (o *overlapPfctl) Run(stdin string, args ...string) (string, error) {
	o.mu.Lock()
	o.inFlight++
	if o.inFlight > o.maxFlight {
		o.maxFlight = o.inFlight
	}
	o.mu.Unlock()
	time.Sleep(200 * time.Microsecond)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.inFlight--
	return o.inner.Run(stdin, args...)
}

// One mutex serializes the apply loop and every request: pfctl never runs
// twice at once.
func TestServeNeverRunsPfctlConcurrently(t *testing.T) {
	h := newHarness(t, true)
	h.saveConfig(t, anthropicConfig)
	fw := &overlapPfctl{inner: h.pfctl}
	h.env.Pfctl = fw
	h.env.ApplyEvery = time.Millisecond
	s := startServe(t, h)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				switch (i + j) % 3 {
				case 0:
					s.client.Status()
				case 1:
					s.client.Set("ipsec0", []string{"anthropic"})
				default:
					s.client.Pause()
				}
			}
		}(i)
	}
	wg.Wait()
	s.stop(t)
	if fw.maxFlight != 1 {
		t.Fatalf("pfctl ran %d times at once, want 1", fw.maxFlight)
	}
}

// With sudo, status keeps verifying the rules itself.
func TestStatusWithRootIgnoresTheDaemon(t *testing.T) {
	h := newHarness(t, true)
	h.saveConfig(t, anthropicConfig)
	h.env.Socket = fakeDaemon(t, ipc.Status{Reason: "from the daemon"})
	code, out, errOut := h.run("status")
	expect(t, code, out, errOut, 0, []string{"Firewall:           PROTECTED\n"}, nil)
	if strings.Contains(out, "from the daemon") || len(h.pfctl.calls) == 0 {
		t.Fatalf("root status used the daemon:\n%s", out)
	}
}
