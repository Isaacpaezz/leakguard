package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeSystemctl struct {
	calls []string
	fail  map[string]error
}

func (f *fakeSystemctl) Run(args ...string) (string, error) {
	key := strings.Join(args, " ")
	f.calls = append(f.calls, key)
	return "", f.fail[key]
}

func newTestSystemd(t *testing.T) (Systemd, *fakeSystemctl, *secured) {
	t.Helper()
	f := &fakeSystemctl{fail: map[string]error{}}
	s := &secured{}
	return Systemd{Root: t.TempDir(), Systemctl: f, Secure: s.secure}, f, s
}

func TestUnit(t *testing.T) {
	want := `[Unit]
Description=leakguard: keeps chosen services off the real connection
DefaultDependencies=no
After=local-fs.target
Wants=network-pre.target
Before=network-pre.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=notify
ExecStart=/usr/local/libexec/leakguard/leakguard serve
Restart=always
StandardOutput=append:/var/log/leakguard.log
StandardError=append:/var/log/leakguard.log

[Install]
WantedBy=multi-user.target
`
	if got := Unit(BinaryPath); got != want {
		t.Fatalf("Unit() =\n%s\nwant\n%s", got, want)
	}
}

func TestSystemdInstallCopiesBinaryWritesUnitAndRestarts(t *testing.T) {
	d, f, s := newTestSystemd(t)
	if err := d.Install(writeExecutable(t, "leakguard-binary")); err != nil {
		t.Fatalf("Install() = %v", err)
	}
	bin := filepath.Join(d.Root, BinaryPath)
	unit := filepath.Join(d.Root, UnitPath)
	for path, want := range map[string]struct {
		data string
		mode os.FileMode
	}{bin: {"leakguard-binary", 0o755}, unit: {Unit(BinaryPath), 0o644}} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want.mode {
			t.Errorf("%s mode = %v, want %v", path, info.Mode().Perm(), want.mode)
		}
		if data, _ := os.ReadFile(path); string(data) != want.data {
			t.Errorf("%s = %q, want %q", path, data, want.data)
		}
	}
	if got := strings.Join(s.paths, "|"); got != bin+"|"+unit {
		t.Errorf("secured %q, want the binary then the unit", got)
	}
	if got, want := strings.Join(f.calls, "|"), "daemon-reload|enable "+UnitName+"|restart "+UnitName; got != want {
		t.Errorf("systemctl calls = %q, want %q", got, want)
	}
	if !d.Installed() {
		t.Error("Installed() = false after Install")
	}
}

func TestSystemdInstallStopsWhenSecureFails(t *testing.T) {
	d, f, _ := newTestSystemd(t)
	d.Secure = func(string) error { return errors.New("not owned by root") }
	err := d.Install(writeExecutable(t, "x"))
	if err == nil || !strings.Contains(err.Error(), "refusing to install "+BinaryPath+": not owned by root") {
		t.Fatalf("Install() = %v", err)
	}
	if _, serr := os.Stat(filepath.Join(d.Root, BinaryPath)); !os.IsNotExist(serr) {
		t.Error("the insecure binary was left in place")
	}
	if len(f.calls) != 0 || d.Installed() {
		t.Errorf("systemctl calls = %v, Installed() = %v; want none, false", f.calls, d.Installed())
	}
}

func TestSystemdInstallFailsWhenSystemctlFails(t *testing.T) {
	for _, call := range []string{"daemon-reload", "enable " + UnitName, "restart " + UnitName} {
		d, f, _ := newTestSystemd(t)
		f.fail[call] = errors.New("systemctl " + call + ": exit status 1")
		err := d.Install(writeExecutable(t, "x"))
		if err == nil || !strings.Contains(err.Error(), "systemctl "+call+": exit status 1") {
			t.Errorf("Install() with %q failing = %v", call, err)
		}
		if last := f.calls[len(f.calls)-1]; last != call {
			t.Errorf("with %q failing, systemctl kept going: %v", call, f.calls)
		}
	}
}

func TestSystemdUninstallRemovesEverything(t *testing.T) {
	d, f, _ := newTestSystemd(t)
	if err := d.Install(writeExecutable(t, "x")); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	if err := d.Uninstall(); err != nil {
		t.Fatalf("Uninstall() = %v", err)
	}
	if got, want := strings.Join(f.calls, "|"), "stop "+UnitName+"|disable "+UnitName+"|daemon-reload"; got != want {
		t.Errorf("systemctl calls = %q, want %q", got, want)
	}
	for _, p := range []string{UnitPath, BinaryPath, filepath.Dir(BinaryPath)} {
		if _, err := os.Stat(filepath.Join(d.Root, p)); !os.IsNotExist(err) {
			t.Errorf("%s still exists", p)
		}
	}
	if d.Installed() {
		t.Error("Installed() = true after Uninstall")
	}
}

// Disabling on a computer where the service was never installed succeeds.
func TestSystemdUninstallWhenNothingIsInstalled(t *testing.T) {
	d, f, _ := newTestSystemd(t)
	f.fail["stop "+UnitName] = errors.New("Unit leakguard.service not loaded.")
	f.fail["disable "+UnitName] = errors.New("Unit file leakguard.service does not exist.")
	if err := d.Uninstall(); err != nil {
		t.Fatalf("Uninstall() = %v", err)
	}
}

func TestSystemdInstalledNeedsAUnitThatRunsServe(t *testing.T) {
	d, _, _ := newTestSystemd(t)
	if d.Installed() {
		t.Fatal("Installed() = true without a unit")
	}
	unit := filepath.Join(d.Root, UnitPath)
	os.MkdirAll(filepath.Dir(unit), 0o755)
	os.WriteFile(unit, []byte("[Service]\nExecStart=/usr/local/libexec/leakguard/leakguard version\n"), 0o644)
	if d.Installed() {
		t.Error("Installed() = true for a unit that does not run serve")
	}
	os.WriteFile(unit, []byte(Unit(BinaryPath)), 0o644)
	if !d.Installed() {
		t.Error("Installed() = false for the leakguard unit")
	}
	if d.LegacyInstalled() {
		t.Error("LegacyInstalled() = true on systemd")
	}
}

func TestSystemdLastLogLine(t *testing.T) {
	d, _, _ := newTestSystemd(t)
	if line, ok := d.LastLogLine(); ok || line != "" {
		t.Fatalf("LastLogLine() without a log = %q, %v", line, ok)
	}
	log := filepath.Join(d.Root, SystemdLogPath)
	os.MkdirAll(filepath.Dir(log), 0o755)
	os.WriteFile(log, []byte("2026-11-16T10:00:00Z Protected through wg0: anthropic\n2026-11-16T10:01:00Z leakguard: nft: syntax error\n\n"), 0o644)
	if line, ok := d.LastLogLine(); !ok || line != "2026-11-16T10:01:00Z leakguard: nft: syntax error" {
		t.Fatalf("LastLogLine() = %q, %v", line, ok)
	}
}
