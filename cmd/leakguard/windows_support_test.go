package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/daemon"
)

// S1: the Windows help names the Windows firewall, paths and pipe, and an
// administrator terminal instead of sudo.
func TestUsageOnWindows(t *testing.T) {
	got := usageFor("windows")
	for _, want := range []string{
		"Commands marked (admin) need an administrator terminal",
		"  leakguard enable [--vpn ADAPTER] SERVICE...   (admin)\n",
		"  leakguard disable   (admin)\n",
		"  leakguard apply   (admin)\n",
		"  leakguard serve   (admin)\n",
		"service, which verifies as SYSTEM that the Windows Filtering\n      Platform rules are loaded;",
		`%ProgramData%\leakguard\leakguard.log`,
		`%ProgramData%\leakguard\stats.json`,
		`\\.\pipe\leakguard`,
		"It also ends a pause from the tray app.",
		"checks them\n      every 30 seconds and as soon as the VPN connects or drops,",
		`  leakguard enable --vpn "WireGuard Tunnel" anthropic   (admin)` + "\n",
		"Exit status: 0 on success, 1 on failure, 2 on a usage error.\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Windows usage lacks %q", want)
		}
	}
	for _, bad := range []string{"sudo", "pf ", "/Library", "/var", "/run", "launchd", "LaunchDaemon", "systemd", "nftables", "menu-bar", "ipsec0", "wg0"} {
		if strings.Contains(got, bad) {
			t.Errorf("Windows usage names %q", bad)
		}
	}
	for _, cmd := range commands {
		if cmd.name != "reinstall-service" && !strings.Contains(got, "\n  leakguard "+cmd.name) {
			t.Errorf("Windows usage lacks the %s command", cmd.name)
		}
	}
	if runtime.GOOS == "windows" && usage != got {
		t.Error("usage on Windows is not the Windows text")
	}
	// macOS and Linux keep theirs.
	if usageFor("darwin") == got || usageFor("linux") == got {
		t.Error("the Windows text replaced another system's")
	}
}

func TestViaExampleOnWindows(t *testing.T) {
	if got := viaExampleFor("windows"); got != "Wi-Fi" {
		t.Errorf("viaExampleFor(windows) = %q, want Wi-Fi", got)
	}
}

// wordsChosen is set while a test chose the wording itself, so the
// harness keeps it (see simulateMacOS).
var wordsChosen bool

// withAdminHint makes the "run as administrator" message that of goos.
func withAdminHint(t *testing.T, goos string) {
	t.Helper()
	old, oldChosen := needAdmin, wordsChosen
	needAdmin, wordsChosen = needAdminFor(goos), true
	t.Cleanup(func() { needAdmin, wordsChosen = old, oldChosen })
}

// S1, S8: on Windows a change needs an elevated token (IsRoot), and the
// refusal names an administrator terminal; macOS and Linux keep sudo.
func TestRequireRootOnWindows(t *testing.T) {
	withAdminHint(t, "windows")
	for _, args := range [][]string{{"enable", "--vpn", "ipsec0", "anthropic"}, {"disable"}, {"apply"}, {"serve"}} {
		h := newHarness(t, false)
		code, out, errOut := h.run(args...)
		expect(t, code, out, errOut, 1, nil, []string{"leakguard: run from an administrator terminal: leakguard " + args[0] + "\n"})
		if len(h.pfctl.calls) != 0 || len(h.launchctl.calls) != 0 {
			t.Errorf("%v changed the system unelevated", args)
		}
	}
	h := newHarness(t, true)
	code, out, errOut := h.run("enable", "--vpn", "ipsec0", "anthropic")
	expect(t, code, out, errOut, 0, []string{"Protected through ipsec0"}, nil)
	for _, goos := range []string{"darwin", "linux"} {
		if got := needAdminFor(goos)("enable"); got != "run with sudo: sudo leakguard enable" {
			t.Errorf("needAdminFor(%s) = %q", goos, got)
		}
	}
}

// fakeServices is a Windows Service Control Manager for the CLI tests.
type fakeServices struct {
	mu    sync.Mutex
	calls []string
	info  *daemon.ServiceInfo
}

func (f *fakeServices) record(c string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
}

func (f *fakeServices) Query(name string) (daemon.ServiceInfo, error) {
	f.record("Query " + name)
	if f.info == nil {
		return daemon.ServiceInfo{}, daemon.ErrServiceNotInstalled
	}
	return *f.info, nil
}

func (f *fakeServices) Create(name string, c daemon.ServiceConfig) error {
	f.record(fmt.Sprintf("Create %s %+v", name, c))
	f.info = &daemon.ServiceInfo{Command: c.Command}
	return nil
}

func (f *fakeServices) Update(name string, c daemon.ServiceConfig) error {
	f.record("Update " + name)
	f.info.Command = c.Command
	return nil
}

func (f *fakeServices) SetRecovery(name string, r daemon.Recovery) error {
	f.record(fmt.Sprintf("SetRecovery %s %+v", name, r))
	return nil
}

func (f *fakeServices) Start(name string) error {
	f.record("Start " + name)
	f.info.State = daemon.ServiceRunning
	return nil
}

func (f *fakeServices) Stop(name string) error {
	f.record("Stop " + name)
	f.info.State = daemon.ServiceStopped
	return nil
}

func (f *fakeServices) Delete(name string) error {
	f.record("Delete " + name)
	f.info = nil
	return nil
}

// S1: enable, status and disable drive the Windows service through
// Env.SCM; the service runs the copy in %ProgramFiles% with "serve".
func TestWindowsServicesThroughTheCLI(t *testing.T) {
	h := newHarness(t, true)
	scm := &fakeServices{}
	h.env.SCM = scm
	h.env.Services = windowsServices
	code, out, errOut := h.run("enable", "--vpn", "ipsec0", "anthropic")
	expect(t, code, out, errOut, 0, []string{"Protected through ipsec0"}, nil)
	copyPath := rooted(h.env.Root, daemon.WindowsBinaryPath)
	if data, err := os.ReadFile(copyPath); err != nil || string(data) != "leakguard-binary" {
		t.Fatalf("binary copy = %q, %v", data, err)
	}
	code, out, errOut = h.run("status")
	expect(t, code, out, errOut, 0, []string{"Background service: installed"}, nil)
	code, out, errOut = h.run("disable")
	expect(t, code, out, errOut, 0, []string{"Protection disabled."}, nil)
	cfg := daemon.ServiceConfig{DisplayName: "leakguard", Command: daemon.ServiceCommand(daemon.WindowsBinaryPath), AutoStart: true, Account: "LocalSystem"}
	want := []string{
		"Query leakguard", fmt.Sprintf("Create leakguard %+v", cfg),
		"SetRecovery leakguard {RestartDelay:5s ResetPeriod:24h0m0s}", "Start leakguard",
		"Query leakguard", // status
		"Query leakguard", "Stop leakguard", "Delete leakguard",
	}
	if !reflect.DeepEqual(scm.calls, want) {
		t.Errorf("SCM calls = %q\nwant        %q", scm.calls, want)
	}
	if _, err := os.Stat(copyPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the copy is still there: %v", err)
	}
	if len(h.launchctl.calls) != 0 {
		t.Errorf("launchd was used: %v", h.launchctl.calls)
	}
}

// rooted keeps a Windows path inside a test root on every system.
func TestRooted(t *testing.T) {
	if got := rooted("", `C:\Program Files\leakguard\leakguard.exe`); got != `C:\Program Files\leakguard\leakguard.exe` {
		t.Errorf("rooted(\"\") = %q", got)
	}
	if got := rooted("/tmp/x", "/Library/Logs/leakguard.log"); got != filepath.Join("/tmp/x", "/Library/Logs/leakguard.log") {
		t.Errorf("rooted() = %q", got)
	}
	if got := rooted("/tmp/x", `C:\a`); !strings.HasPrefix(got, filepath.Join("/tmp/x", "")) {
		t.Errorf("rooted() = %q, want it under the root", got)
	}
}

// waitStates waits until the reported states are want.
func waitStates(t *testing.T, mu *sync.Mutex, got *[]scmState, want ...scmState) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		same := reflect.DeepEqual(*got, want)
		snapshot := append([]scmState(nil), *got...)
		mu.Unlock()
		if same {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("states = %v, want %v", snapshot, want)
		}
		time.Sleep(time.Millisecond)
	}
}

type scmRun struct {
	mu     sync.Mutex
	states []scmState
	reqs   chan scmRequest
	done   chan uint32
	ctx    chan context.Context
}

// startSCMRun runs runUnderSCM with serve, recording the reported states.
func startSCMRun(serve func(ctx context.Context, ready func()) int) *scmRun {
	r := &scmRun{reqs: make(chan scmRequest), done: make(chan uint32, 1)}
	report := func(s scmState) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.states = append(r.states, s)
	}
	go func() { r.done <- runUnderSCM(r.reqs, report, serve) }()
	return r
}

func (r *scmRun) wait(t *testing.T) uint32 {
	t.Helper()
	select {
	case code := <-r.done:
		return code
	case <-time.After(5 * time.Second):
		t.Fatal("runUnderSCM did not return")
	}
	return 0
}

// S1: under the Service Control Manager, serve reports StartPending, then
// Running once the rules are loaded, answers Interrogate, and on Stop
// reports StopPending and cancels serve, which then flushes and returns.
func TestRunUnderSCMStartsAndStops(t *testing.T) {
	stopped := make(chan struct{})
	r := startSCMRun(func(ctx context.Context, ready func()) int {
		ready()
		ready() // reported once
		<-ctx.Done()
		close(stopped)
		return 0
	})
	waitStates(t, &r.mu, &r.states, scmStartPending, scmRunning)
	r.reqs <- scmInterrogate
	waitStates(t, &r.mu, &r.states, scmStartPending, scmRunning, scmRunning)
	r.reqs <- scmStop
	if code := r.wait(t); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	<-stopped
	waitStates(t, &r.mu, &r.states, scmStartPending, scmRunning, scmRunning, scmStopPending)
}

// Shutdown stops serve like Stop. A requested stop always ends with exit
// code 0, even when serve's shutdown failed, so Windows' recovery never
// restarts a service that was stopped on purpose.
func TestRunUnderSCMShutdown(t *testing.T) {
	r := startSCMRun(func(ctx context.Context, ready func()) int {
		ready()
		<-ctx.Done()
		return 1
	})
	waitStates(t, &r.mu, &r.states, scmStartPending, scmRunning)
	r.reqs <- scmShutdown
	if code := r.wait(t); code != 0 {
		t.Fatalf("exit code = %d, want 0 after a requested stop", code)
	}
	waitStates(t, &r.mu, &r.states, scmStartPending, scmRunning, scmStopPending)
}

// Stop and Shutdown are accepted from the start (a disable right after an
// enable or a boot), with a wait hint while a state is pending.
func TestSCMStatesAcceptStopFromTheStart(t *testing.T) {
	for _, tc := range []struct {
		state   scmState
		accepts bool
		pending bool
	}{
		{scmStartPending, true, true},
		{scmRunning, true, false},
		{scmStopPending, false, true},
	} {
		if got := tc.state.acceptsStop(); got != tc.accepts {
			t.Errorf("state %d: acceptsStop() = %v, want %v", tc.state, got, tc.accepts)
		}
		if got := tc.state.waitHint(); (got > 0) != tc.pending || got > time.Minute {
			t.Errorf("state %d: waitHint() = %v, want a hint only while pending", tc.state, got)
		}
	}
}

// A serve that fails on its own ends the service with its exit code, so
// Windows restarts it (recovery on non-crash failures).
func TestRunUnderSCMServeFails(t *testing.T) {
	r := startSCMRun(func(ctx context.Context, ready func()) int { return 1 })
	if code := r.wait(t); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	waitStates(t, &r.mu, &r.states, scmStartPending)
}

// A stop that arrives before the rules are loaded still stops serve, with
// exit code 0.
func TestRunUnderSCMStopWhileStarting(t *testing.T) {
	r := startSCMRun(func(ctx context.Context, ready func()) int {
		<-ctx.Done()
		return 1
	})
	waitStates(t, &r.mu, &r.states, scmStartPending)
	r.reqs <- scmStop
	if code := r.wait(t); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	waitStates(t, &r.mu, &r.states, scmStartPending, scmStopPending)
}

// serve calls Env.Ready once, after it loaded the rules: the Windows
// service reports Running only then.
func TestServeCallsReadyAfterTheFirstLoad(t *testing.T) {
	h, p := statefulHarness(t)
	var mu sync.Mutex
	readyLoads := []int{}
	h.env.Ready = func() {
		mu.Lock()
		defer mu.Unlock()
		readyLoads = append(readyLoads, p.count(loadAnchor))
	}
	s := startServe(t, h)
	if code := s.stop(t); code != 0 {
		t.Fatalf("serve exit code = %d: %s", code, s.stderr.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(readyLoads, []int{1}) {
		t.Fatalf("Ready calls saw %v loads, want one call after one load", readyLoads)
	}
}

// S1: "leakguard test" finds the real connection on Windows from the route
// table: the IPv4 default route with the lowest metric (route metric plus
// interface metric, as Windows ranks them), else the IPv6 one.
func TestWindowsDefaultInterface(t *testing.T) {
	aliases := map[uint32]string{7: "Wi-Fi", 9: "Ethernet", 12: "WireGuard Tunnel", 15: "Conexión de área local"}
	alias := func(i uint32) (string, error) {
		if a, ok := aliases[i]; ok {
			return a, nil
		}
		return "", errors.New("Element not found.")
	}
	table := func(v4, v6 []routeRow, v4err error) func(bool) ([]routeRow, error) {
		return func(ipv6 bool) ([]routeRow, error) {
			if ipv6 {
				return v6, nil
			}
			return v4, v4err
		}
	}
	for _, tc := range []struct {
		name   string
		routes func(bool) ([]routeRow, error)
		want   string
		err    string
	}{
		{"lowest metric", table([]routeRow{{0, 9, 25, 0}, {0, 7, 10, 0}, {24, 9, 1, 0}}, nil, nil), "Wi-Fi", ""},
		{"VPN default route", table([]routeRow{{0, 7, 35, 0}, {0, 12, 5, 0}}, nil, nil), "WireGuard Tunnel", ""},
		{"split routes are not the default", table([]routeRow{{1, 12, 0, 0}, {1, 12, 0, 0}, {0, 9, 50, 0}}, nil, nil), "Ethernet", ""},
		{"interface 0 is not a route", table([]routeRow{{0, 0, 0, 0}, {0, 15, 3, 0}}, nil, nil), "Conexión de área local", ""},
		{"IPv6 only", table(nil, []routeRow{{0, 9, 256, 0}}, nil), "Ethernet", ""},
		{"interface metric breaks a route metric tie", table([]routeRow{{0, 7, 0, 35}, {0, 9, 0, 25}}, nil, nil), "Ethernet", ""},
		{"route plus interface metric", table([]routeRow{{0, 7, 10, 50}, {0, 9, 25, 5}}, nil, nil), "Ethernet", ""},
		{"equal sums keep the first", table([]routeRow{{0, 7, 20, 10}, {0, 9, 10, 20}}, nil, nil), "Wi-Fi", ""},
		{"no overflow", table([]routeRow{{0, 7, 1, ^uint32(0)}, {0, 9, ^uint32(0), ^uint32(0)}}, nil, nil), "Wi-Fi", ""},
		{"no default route", table([]routeRow{{8, 7, 1, 0}}, []routeRow{{64, 7, 1, 0}}, nil), "", "no default route found"},
		{"unreadable", table(nil, nil, errors.New("GetIpForwardTable2: access denied")), "", "GetIpForwardTable2: access denied"},
		{"unnamed adapter", table([]routeRow{{0, 99, 1, 0}}, nil, nil), "", "cannot name the adapter of the default route (index 99): Element not found."},
	} {
		got, err := windowsDefaultInterfaceFrom(tc.routes, alias)
		if got != tc.want || (tc.err == "") != (err == nil) || (err != nil && err.Error() != tc.err) {
			t.Errorf("%s: windowsDefaultInterfaceFrom() = %q, %v; want %q, %q", tc.name, got, err, tc.want, tc.err)
		}
	}
}

// The service log is opened for appending inside a prepared directory.
func TestOpenServiceLog(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "leakguard")
	path := filepath.Join(dir, "leakguard.log")
	var prepared []string
	prepare := func(d string) error {
		prepared = append(prepared, d)
		return os.MkdirAll(d, 0o755)
	}
	for _, line := range []string{"one\n", "two\n"} {
		f, err := openServiceLog(path, prepare)
		if err != nil {
			t.Fatalf("openServiceLog() = %v", err)
		}
		f.WriteString(line)
		f.Close()
	}
	if data, _ := os.ReadFile(path); string(data) != "one\ntwo\n" {
		t.Fatalf("log = %q", data)
	}
	if !reflect.DeepEqual(prepared, []string{dir, dir}) {
		t.Fatalf("prepared = %v", prepared)
	}
	if _, err := openServiceLog(path, func(string) error { return errors.New("access denied") }); err == nil || err.Error() != "access denied" {
		t.Fatalf("openServiceLog() with a failed prepare = %v", err)
	}
}
