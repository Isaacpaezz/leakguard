package daemon

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type fakeLaunchctl struct {
	calls []string
	fail  map[string]error
}

func (f *fakeLaunchctl) Run(args ...string) (string, error) {
	key := strings.Join(args, " ")
	f.calls = append(f.calls, key)
	return "", f.fail[key]
}

type secured struct{ paths []string }

func (s *secured) secure(path string) error {
	s.paths = append(s.paths, path)
	return nil
}

func newTestDaemon(t *testing.T) (Daemon, *fakeLaunchctl, *secured) {
	t.Helper()
	l := &fakeLaunchctl{}
	s := &secured{}
	return Daemon{Root: t.TempDir(), Launchctl: l, Secure: s.secure}, l, s
}

func writeExecutable(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "leakguard")
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPlist(t *testing.T) {
	got := Plist("/usr/local/libexec/leakguard/leakguard")
	for _, want := range []string{
		"<key>Label</key>\n\t<string>dev.leakguard</string>",
		"<array>\n\t\t<string>/usr/local/libexec/leakguard/leakguard</string>\n\t\t<string>apply</string>\n\t</array>",
		"<key>RunAtLoad</key>\n\t<true/>",
		"<key>StartInterval</key>\n\t<integer>60</integer>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Plist() is missing %q:\n%s", want, got)
		}
	}
}

func TestPlistPassesPlutilLint(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("plutil is only available on macOS")
	}
	path := filepath.Join(t.TempDir(), "dev.leakguard.plist")
	os.WriteFile(path, []byte(Plist(BinaryPath)), 0o644)
	if out, err := exec.Command("/usr/bin/plutil", "-lint", path).CombinedOutput(); err != nil {
		t.Fatalf("plutil -lint rejected the plist: %v\n%s", err, out)
	}
}

func TestInstallCopiesBinaryWritesPlistAndBootstraps(t *testing.T) {
	d, l, s := newTestDaemon(t)
	src := writeExecutable(t, "binary-v1")
	if err := d.Install(src); err != nil {
		t.Fatalf("Install() = %v", err)
	}
	bin := filepath.Join(d.Root, BinaryPath)
	data, err := os.ReadFile(bin)
	if err != nil || string(data) != "binary-v1" {
		t.Fatalf("installed binary = %q, %v", data, err)
	}
	if info, _ := os.Stat(bin); info.Mode().Perm() != 0o755 {
		t.Fatalf("binary mode = %v, want 0755", info.Mode().Perm())
	}
	plist := filepath.Join(d.Root, PlistPath)
	data, err = os.ReadFile(plist)
	if err != nil || string(data) != Plist(BinaryPath) {
		t.Fatalf("plist = %q, %v", data, err)
	}
	if info, _ := os.Stat(plist); info.Mode().Perm() != 0o644 {
		t.Fatalf("plist mode = %v, want 0644", info.Mode().Perm())
	}
	want := "bootout system/" + Label + "|bootstrap system " + plist
	if got := strings.Join(l.calls, "|"); got != want {
		t.Fatalf("launchctl calls = %q, want %q", got, want)
	}
	if got := strings.Join(s.paths, "|"); got != bin+"|"+plist {
		t.Fatalf("secured paths = %q", got)
	}
	if !d.Installed() {
		t.Fatal("Installed() = false after Install")
	}
}

func TestInstallIgnoresBootoutFailure(t *testing.T) {
	d, l, _ := newTestDaemon(t)
	l.fail = map[string]error{"bootout system/" + Label: errors.New("No such process")}
	if err := d.Install(writeExecutable(t, "x")); err != nil {
		t.Fatalf("Install() = %v", err)
	}
}

func TestInstallFailsWhenBootstrapFails(t *testing.T) {
	d, l, _ := newTestDaemon(t)
	l.fail = map[string]error{"bootstrap system " + filepath.Join(d.Root, PlistPath): errors.New("Bootstrap failed: 5")}
	if err := d.Install(writeExecutable(t, "x")); err == nil || !strings.Contains(err.Error(), "Bootstrap failed") {
		t.Fatalf("Install() = %v", err)
	}
}

func TestInstallStopsWhenSecureFails(t *testing.T) {
	d, l, _ := newTestDaemon(t)
	d.Secure = func(string) error { return errors.New("writable by non-root users") }
	if err := d.Install(writeExecutable(t, "x")); err == nil || !strings.Contains(err.Error(), "non-root") {
		t.Fatalf("Install() = %v", err)
	}
	if len(l.calls) != 0 {
		t.Fatalf("launchctl ran %v with an insecure binary", l.calls)
	}
}

func TestInstallReplacesExistingBinary(t *testing.T) {
	d, _, _ := newTestDaemon(t)
	d.Install(writeExecutable(t, "binary-v1"))
	if err := d.Install(writeExecutable(t, "binary-v2")); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(filepath.Join(d.Root, BinaryPath)); string(data) != "binary-v2" {
		t.Fatalf("binary = %q", data)
	}
}

func TestUninstallRemovesEverything(t *testing.T) {
	d, l, _ := newTestDaemon(t)
	d.Install(writeExecutable(t, "x"))
	l.calls = nil
	if err := d.Uninstall(); err != nil {
		t.Fatalf("Uninstall() = %v", err)
	}
	for _, p := range []string{PlistPath, BinaryPath} {
		if _, err := os.Stat(filepath.Join(d.Root, p)); !os.IsNotExist(err) {
			t.Errorf("%s still exists: %v", p, err)
		}
	}
	if got := strings.Join(l.calls, "|"); got != "bootout system/"+Label {
		t.Fatalf("launchctl calls = %q", got)
	}
	if d.Installed() {
		t.Fatal("Installed() = true after Uninstall")
	}
}

func TestUninstallWhenNothingIsInstalled(t *testing.T) {
	d, l, _ := newTestDaemon(t)
	l.fail = map[string]error{"bootout system/" + Label: errors.New("No such process")}
	if err := d.Uninstall(); err != nil {
		t.Fatalf("Uninstall() = %v", err)
	}
}

func TestLegacyInstalled(t *testing.T) {
	d, _, _ := newTestDaemon(t)
	if d.LegacyInstalled() {
		t.Fatal("LegacyInstalled() = true on a clean system")
	}
	legacy := filepath.Join(d.Root, LegacyPlistPath)
	os.MkdirAll(filepath.Dir(legacy), 0o755)
	os.WriteFile(legacy, []byte("<plist/>"), 0o644)
	if !d.LegacyInstalled() {
		t.Fatal("LegacyInstalled() = false with the prototype plist present")
	}
}

func TestCheckRootOwnedRejectsUserDirectories(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	dir := t.TempDir()
	if err := checkRootOwned(dir); err == nil {
		t.Fatalf("checkRootOwned(%s) = nil, want error for a user-owned directory", dir)
	}
}

func TestCheckRootOwnedAcceptsSystemDirectories(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix ownership only")
	}
	if err := checkRootOwned("/usr/bin"); err != nil {
		t.Fatalf("checkRootOwned(/usr/bin) = %v", err)
	}
}
