package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSCM is a Service Control Manager that knows at most one service.
type fakeSCM struct {
	calls []string
	info  *ServiceInfo // nil: not installed
	fail  map[string]error
	// stopKeepsRunning leaves the service running when Stop fails.
	stopKeepsRunning bool
}

func (f *fakeSCM) call(format string, a ...any) error {
	c := fmt.Sprintf(format, a...)
	f.calls = append(f.calls, c)
	return f.fail[strings.Fields(c)[0]]
}

func (f *fakeSCM) Query(name string) (ServiceInfo, error) {
	if err := f.call("Query %s", name); err != nil {
		return ServiceInfo{}, err
	}
	if f.info == nil {
		return ServiceInfo{}, ErrServiceNotInstalled
	}
	return *f.info, nil
}

func (f *fakeSCM) Create(name string, c ServiceConfig) error {
	if err := f.call("Create %s %+v", name, c); err != nil {
		return err
	}
	f.info = &ServiceInfo{State: ServiceStopped, Command: c.Command}
	return nil
}

func (f *fakeSCM) Update(name string, c ServiceConfig) error {
	if err := f.call("Update %s %+v", name, c); err != nil {
		return err
	}
	f.info.Command = c.Command
	return nil
}

func (f *fakeSCM) SetRecovery(name string, r Recovery) error {
	return f.call("SetRecovery %s %+v", name, r)
}

func (f *fakeSCM) Start(name string) error {
	if err := f.call("Start %s", name); err != nil {
		return err
	}
	f.info.State = ServiceRunning
	return nil
}

func (f *fakeSCM) Stop(name string) error {
	if err := f.call("Stop %s", name); err != nil {
		if !f.stopKeepsRunning {
			f.info.State = ServiceStopped
		}
		return err
	}
	f.info.State = ServiceStopped
	return nil
}

func (f *fakeSCM) Delete(name string) error {
	if err := f.call("Delete %s", name); err != nil {
		return err
	}
	f.info = nil
	return nil
}

const winBinary = `C:\Program Files\leakguard\leakguard.exe`

var (
	wantCommand  = `"` + winBinary + `" serve`
	wantConfig   = fmt.Sprintf("%+v", ServiceConfig{DisplayName: "leakguard", Command: wantCommand, AutoStart: true, Account: "LocalSystem"})
	wantRecovery = "SetRecovery leakguard {RestartDelay:5s ResetPeriod:24h0m0s}"
)

// winHarness is a Windows service manager over a temporary directory. The
// SCM sees the real Windows binary path; the copy goes under the directory.
type winHarness struct {
	w   WindowsService
	scm *fakeSCM
	src string
}

func newWinHarness(t *testing.T, installed *ServiceInfo) *winHarness {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "new-leakguard.exe")
	if err := os.WriteFile(src, []byte("new binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	scm := &fakeSCM{info: installed, fail: map[string]error{}}
	return &winHarness{
		w: WindowsService{
			Binary:  filepath.Join(dir, "Program Files", "leakguard", "leakguard.exe"),
			Command: wantCommand,
			Log:     filepath.Join(dir, "ProgramData", "leakguard", "leakguard.log"),
			SCM:     scm,
			Sleep:   func(time.Duration) {},
		},
		scm: scm,
		src: src,
	}
}

func (h *winHarness) calls() string { return strings.Join(h.scm.calls, " | ") }

func (h *winHarness) binary(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(h.w.Binary)
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(data)
}

func (h *winHarness) writeBinary(t *testing.T, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(h.w.Binary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.w.Binary, []byte(data), 0o755); err != nil {
		t.Fatal(err)
	}
}

// noTemp checks that no temporary copy is left next to the binary.
func (h *winHarness) noTemp(t *testing.T) {
	t.Helper()
	entries, _ := os.ReadDir(filepath.Dir(h.w.Binary))
	for _, e := range entries {
		if e.Name() != filepath.Base(h.w.Binary) {
			t.Errorf("left %s next to the binary", e.Name())
		}
	}
}

func TestWindowsPaths(t *testing.T) {
	for _, tc := range []struct{ programFiles, programData, binary, log string }{
		{"", "", `C:\Program Files\leakguard\leakguard.exe`, `C:\ProgramData\leakguard\leakguard.log`},
		{`D:\Apps`, `E:\Data\`, `D:\Apps\leakguard\leakguard.exe`, `E:\Data\leakguard\leakguard.log`},
		{`D:\Apps\`, `E:\Data`, `D:\Apps\leakguard\leakguard.exe`, `E:\Data\leakguard\leakguard.log`},
	} {
		binary, log := WindowsPaths(tc.programFiles, tc.programData)
		if binary != tc.binary || log != tc.log {
			t.Errorf("WindowsPaths(%q, %q) = %q, %q; want %q, %q", tc.programFiles, tc.programData, binary, log, tc.binary, tc.log)
		}
	}
	// The binary path holds a space: it is quoted, or Windows could run
	// C:\Program.exe instead.
	if got := ServiceCommand(winBinary); got != wantCommand {
		t.Errorf("ServiceCommand() = %q, want %q", got, wantCommand)
	}
	if got := ServiceCommand(`D:\leakguard\leakguard.exe`); got != `"D:\leakguard\leakguard.exe" serve` {
		t.Errorf("ServiceCommand() = %q", got)
	}
	if ServiceName != "leakguard" {
		t.Errorf("ServiceName = %q", ServiceName)
	}
}

// S1: a first install copies the binary, creates the service (automatic,
// LocalSystem, "serve"), sets its recovery and starts it, in that order.
func TestWindowsInstallCreatesTheService(t *testing.T) {
	h := newWinHarness(t, nil)
	if err := h.w.Install(h.src); err != nil {
		t.Fatalf("Install() = %v", err)
	}
	want := "Query leakguard | Create leakguard " + wantConfig + " | " + wantRecovery + " | Start leakguard"
	if got := h.calls(); got != want {
		t.Fatalf("calls = %s\nwant    %s", got, want)
	}
	if got := h.binary(t); got != "new binary" {
		t.Fatalf("binary = %q", got)
	}
	h.noTemp(t)
	if !h.w.Installed() {
		t.Fatal("Installed() = false after Install")
	}
}

// An existing, stopped service is updated, not created again.
func TestWindowsInstallUpdatesAStoppedService(t *testing.T) {
	h := newWinHarness(t, &ServiceInfo{State: ServiceStopped, Command: `"C:\old\leakguard.exe" serve`})
	h.writeBinary(t, "old binary")
	if err := h.w.Install(h.src); err != nil {
		t.Fatalf("Install() = %v", err)
	}
	want := "Query leakguard | Update leakguard " + wantConfig + " | " + wantRecovery + " | Start leakguard"
	if got := h.calls(); got != want {
		t.Fatalf("calls = %s\nwant    %s", got, want)
	}
	if got := h.binary(t); got != "new binary" {
		t.Fatalf("binary = %q", got)
	}
}

// A running service holds its binary: the rename fails, so the service is
// stopped first and the rename tried again, then it starts the new binary.
func TestWindowsInstallStopsTheServiceWhenTheBinaryIsInUse(t *testing.T) {
	h := newWinHarness(t, &ServiceInfo{State: ServiceRunning, Command: wantCommand})
	h.writeBinary(t, "old binary")
	renames := 0
	h.w.Rename = func(oldpath, newpath string) error {
		renames++
		if h.scm.info.State == ServiceRunning {
			return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: errors.New("Access is denied.")}
		}
		return os.Rename(oldpath, newpath)
	}
	if err := h.w.Install(h.src); err != nil {
		t.Fatalf("Install() = %v", err)
	}
	want := "Query leakguard | Stop leakguard | Update leakguard " + wantConfig + " | " + wantRecovery + " | Start leakguard"
	if got := h.calls(); got != want || renames != 2 {
		t.Fatalf("calls = %s (%d renames)\nwant    %s (2 renames)", got, renames, want)
	}
	if got := h.binary(t); got != "new binary" {
		t.Fatalf("binary = %q", got)
	}
	h.noTemp(t)
}

// A running service whose binary could be replaced is restarted, so the
// new binary runs.
func TestWindowsInstallRestartsARunningService(t *testing.T) {
	h := newWinHarness(t, &ServiceInfo{State: ServiceRunning, Command: wantCommand})
	if err := h.w.Install(h.src); err != nil {
		t.Fatalf("Install() = %v", err)
	}
	want := "Query leakguard | Update leakguard " + wantConfig + " | " + wantRecovery + " | Stop leakguard | Start leakguard"
	if got := h.calls(); got != want {
		t.Fatalf("calls = %s\nwant    %s", got, want)
	}
}

// When the binary cannot be replaced and the service is not running,
// Install fails before it touches the service; the old binary stays.
func TestWindowsInstallFailsWhenTheBinaryCannotBeReplaced(t *testing.T) {
	h := newWinHarness(t, &ServiceInfo{State: ServiceStopped, Command: wantCommand})
	h.writeBinary(t, "old binary")
	h.w.Rename = func(oldpath, newpath string) error { return errors.New("Access is denied.") }
	err := h.w.Install(h.src)
	if err == nil || !strings.Contains(err.Error(), "Access is denied.") {
		t.Fatalf("Install() = %v", err)
	}
	if got := h.calls(); got != "Query leakguard" {
		t.Fatalf("calls = %s, want only the query", got)
	}
	if got := h.binary(t); got != "old binary" {
		t.Fatalf("binary = %q", got)
	}
	h.noTemp(t)
}

// A binary still in use after the stop fails Install, which starts the old
// binary again, so the rules keep being verified.
func TestWindowsInstallFailsWhenTheBinaryStaysInUse(t *testing.T) {
	h := newWinHarness(t, &ServiceInfo{State: ServiceRunning, Command: wantCommand})
	h.writeBinary(t, "old binary")
	h.w.Rename = func(oldpath, newpath string) error { return errors.New("Access is denied.") }
	err := h.w.Install(h.src)
	if err == nil || !strings.Contains(err.Error(), "Access is denied.") {
		t.Fatalf("Install() = %v", err)
	}
	if got := h.calls(); got != "Query leakguard | Stop leakguard | Start leakguard" {
		t.Fatalf("calls = %s", got)
	}
	if got := h.binary(t); got != "old binary" {
		t.Fatalf("binary = %q", got)
	}
	h.noTemp(t)
}

func TestWindowsInstallReportsAFailedStart(t *testing.T) {
	h := newWinHarness(t, nil)
	h.scm.fail["Start"] = errors.New("The service did not respond")
	err := h.w.Install(h.src)
	if err == nil || err.Error() != "the background service is not started: The service did not respond" {
		t.Fatalf("Install() = %v", err)
	}
}

// A service manager that cannot be asked fails Install before any change.
func TestWindowsInstallFailsWhenTheSCMCannotBeQueried(t *testing.T) {
	h := newWinHarness(t, nil)
	h.scm.fail["Query"] = errors.New("Access is denied.")
	err := h.w.Install(h.src)
	if err == nil || err.Error() != "cannot query the leakguard service: Access is denied." {
		t.Fatalf("Install() = %v", err)
	}
	if _, serr := os.Stat(h.w.Binary); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("Install() wrote the binary: %v", serr)
	}
}

func TestWindowsInstallReportsSetupFailures(t *testing.T) {
	for _, step := range []string{"Create", "SetRecovery"} {
		h := newWinHarness(t, nil)
		h.scm.fail[step] = errors.New("boom")
		if err := h.w.Install(h.src); err == nil || !strings.Contains(err.Error(), "boom") {
			t.Errorf("%s fails: Install() = %v", step, err)
		}
		if strings.Contains(h.calls(), "Start leakguard") {
			t.Errorf("%s fails: the service was started: %s", step, h.calls())
		}
	}
}

// S1: Uninstall stops and deletes the service and removes the copy.
func TestWindowsUninstallRemovesEverything(t *testing.T) {
	h := newWinHarness(t, &ServiceInfo{State: ServiceRunning, Command: wantCommand})
	h.writeBinary(t, "binary")
	if err := h.w.Uninstall(); err != nil {
		t.Fatalf("Uninstall() = %v", err)
	}
	if got, want := h.calls(), "Query leakguard | Stop leakguard | Delete leakguard"; got != want {
		t.Fatalf("calls = %s, want %s", got, want)
	}
	if _, err := os.Stat(filepath.Dir(h.w.Binary)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the program directory is still there: %v", err)
	}
	if h.w.Installed() {
		t.Fatal("Installed() = true after Uninstall")
	}
}

// A stopped service is deleted without a stop.
func TestWindowsUninstallOfAStoppedService(t *testing.T) {
	h := newWinHarness(t, &ServiceInfo{State: ServiceStopped, Command: wantCommand})
	if err := h.w.Uninstall(); err != nil {
		t.Fatalf("Uninstall() = %v", err)
	}
	if got, want := h.calls(), "Query leakguard | Delete leakguard"; got != want {
		t.Fatalf("calls = %s, want %s", got, want)
	}
}

// Nothing installed is fine; a leftover copy is still removed.
func TestWindowsUninstallToleratesNoService(t *testing.T) {
	h := newWinHarness(t, nil)
	h.writeBinary(t, "binary")
	if err := h.w.Uninstall(); err != nil {
		t.Fatalf("Uninstall() = %v", err)
	}
	if got := h.calls(); got != "Query leakguard" {
		t.Fatalf("calls = %s", got)
	}
	if _, err := os.Stat(h.w.Binary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("binary still there: %v", err)
	}
}

// A service that cannot be stopped and still runs fails Uninstall, which
// then removes nothing, so a running daemon is never orphaned.
func TestWindowsUninstallFailsWhenTheServiceKeepsRunning(t *testing.T) {
	h := newWinHarness(t, &ServiceInfo{State: ServiceRunning, Command: wantCommand})
	h.writeBinary(t, "binary")
	h.scm.fail["Stop"] = errors.New("The service cannot accept control messages at this time.")
	h.scm.stopKeepsRunning = true
	err := h.w.Uninstall()
	if err == nil || err.Error() != "could not stop the leakguard service: The service cannot accept control messages at this time." {
		t.Fatalf("Uninstall() = %v", err)
	}
	if got, want := h.calls(), "Query leakguard | Stop leakguard | Query leakguard"; got != want {
		t.Fatalf("calls = %s, want %s", got, want)
	}
	if got := h.binary(t); got != "binary" {
		t.Fatalf("binary = %q", got)
	}
}

// A failed stop is fine when the service did stop after all.
func TestWindowsUninstallWhenTheStopFailedButTheServiceStopped(t *testing.T) {
	h := newWinHarness(t, &ServiceInfo{State: ServiceRunning, Command: wantCommand})
	h.scm.fail["Stop"] = errors.New("timeout")
	if err := h.w.Uninstall(); err != nil {
		t.Fatalf("Uninstall() = %v", err)
	}
	if got, want := h.calls(), "Query leakguard | Stop leakguard | Query leakguard | Delete leakguard"; got != want {
		t.Fatalf("calls = %s, want %s", got, want)
	}
}

func TestWindowsUninstallReportsAFailedDelete(t *testing.T) {
	h := newWinHarness(t, &ServiceInfo{State: ServiceStopped, Command: wantCommand})
	h.writeBinary(t, "binary")
	h.scm.fail["Delete"] = errors.New("Access is denied.")
	if err := h.w.Uninstall(); err == nil || err.Error() != "could not delete the leakguard service: Access is denied." {
		t.Fatalf("Uninstall() = %v", err)
	}
	if got := h.binary(t); got != "binary" {
		t.Fatalf("binary = %q", got)
	}
}

// The copy can stay locked a moment after the stop: the removal is retried.
func TestWindowsUninstallRetriesALockedBinary(t *testing.T) {
	h := newWinHarness(t, &ServiceInfo{State: ServiceRunning, Command: wantCommand})
	h.writeBinary(t, "binary")
	tries := 0
	h.w.Remove = func(path string) error {
		if tries++; tries < 3 {
			return errors.New("The process cannot access the file")
		}
		return os.Remove(path)
	}
	if err := h.w.Uninstall(); err != nil {
		t.Fatalf("Uninstall() = %v", err)
	}
	if tries != 3 {
		t.Fatalf("tries = %d, want 3", tries)
	}
	h.w.Remove = func(string) error { return errors.New("locked") }
	h.writeBinary(t, "binary")
	h.scm.info = nil
	if err := h.w.Uninstall(); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("Uninstall() = %v, want the removal error", err)
	}
}

func TestWindowsInstalled(t *testing.T) {
	for _, tc := range []struct {
		info *ServiceInfo
		want bool
	}{
		{nil, false},
		{&ServiceInfo{State: ServiceStopped, Command: wantCommand}, true},
		{&ServiceInfo{State: ServiceRunning, Command: strings.ToUpper(wantCommand)}, true},
		{&ServiceInfo{State: ServiceRunning, Command: `"` + winBinary + `"`}, false},
		{&ServiceInfo{State: ServiceRunning, Command: `"C:\Users\x\leakguard.exe" serve`}, false},
	} {
		h := newWinHarness(t, tc.info)
		if got := h.w.Installed(); got != tc.want {
			t.Errorf("Installed() with %+v = %v, want %v", tc.info, got, tc.want)
		}
	}
	h := newWinHarness(t, &ServiceInfo{Command: wantCommand})
	h.scm.fail["Query"] = errors.New("Access is denied.")
	if h.w.Installed() {
		t.Error("Installed() = true when the SCM cannot be asked")
	}
}

func TestWindowsLogAndLegacy(t *testing.T) {
	h := newWinHarness(t, nil)
	if line, ok := h.w.LastLogLine(); ok || line != "" {
		t.Fatalf("LastLogLine() = %q, %v", line, ok)
	}
	if err := os.MkdirAll(filepath.Dir(h.w.Log), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(h.w.Log, []byte("first\r\n2026-11-23T10:00:00Z Protected through WireGuard Tunnel: anthropic\r\n"), 0o644)
	if line, ok := h.w.LastLogLine(); !ok || line != "2026-11-23T10:00:00Z Protected through WireGuard Tunnel: anthropic" {
		t.Fatalf("LastLogLine() = %q, %v", line, ok)
	}
	if h.w.LegacyInstalled() {
		t.Fatal("LegacyInstalled() = true")
	}
	var _ Manager = h.w
}

// The default manager uses the Windows paths and command.
func TestDefaultWindowsService(t *testing.T) {
	scm := &fakeSCM{}
	w := NewWindowsService(scm)
	if w.Binary != WindowsBinaryPath || w.Log != WindowsLogPath || w.Command != ServiceCommand(WindowsBinaryPath) || w.SCM != scm {
		t.Fatalf("NewWindowsService() = %+v", w)
	}
}
