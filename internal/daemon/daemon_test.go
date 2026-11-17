package daemon

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type fakeLaunchctl struct {
	calls []string
	fail  map[string]error
	// seq answers the first calls of a key in order, before fail applies.
	seq map[string][]error
}

func (f *fakeLaunchctl) Run(args ...string) (string, error) {
	key := strings.Join(args, " ")
	f.calls = append(f.calls, key)
	if q := f.seq[key]; len(q) > 0 {
		f.seq[key] = q[1:]
		return "", q[0]
	}
	return "", f.fail[key]
}

const printJob = "print system/" + Label

var errNoJob = errors.New("Could not find service \"dev.leakguard\" in domain for system")

type secured struct{ paths []string }

func (s *secured) secure(path string) error {
	s.paths = append(s.paths, path)
	return nil
}

func newTestDaemon(t *testing.T) (Daemon, *fakeLaunchctl, *secured) {
	t.Helper()
	l := &fakeLaunchctl{fail: map[string]error{printJob: errNoJob}, seq: map[string][]error{}}
	s := &secured{}
	return Daemon{Root: t.TempDir(), Launchctl: l, Secure: s.secure, Sleep: func(time.Duration) {
		t.Fatal("Install slept although the job was already gone")
	}}, l, s
}

type clock struct{ slept []time.Duration }

func (c *clock) sleep(d time.Duration) { c.slept = append(c.slept, d) }

func (c *clock) total() time.Duration {
	var t time.Duration
	for _, d := range c.slept {
		t += d
	}
	return t
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
		"<array>\n\t\t<string>/usr/local/libexec/leakguard/leakguard</string>\n\t\t<string>serve</string>\n\t</array>",
		"<key>RunAtLoad</key>\n\t<true/>",
		"<key>KeepAlive</key>\n\t<true/>",
		"<key>StandardOutPath</key>\n\t<string>/Library/Logs/leakguard.log</string>",
		"<key>StandardErrorPath</key>\n\t<string>/Library/Logs/leakguard.log</string>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Plist() is missing %q:\n%s", want, got)
		}
	}
	// serve runs for good and re-applies the rules itself.
	for _, gone := range []string{"StartInterval", "<string>apply</string>"} {
		if strings.Contains(got, gone) {
			t.Errorf("Plist() still has %q:\n%s", gone, got)
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
	want := "bootout system/" + Label + "|" + printJob + "|bootstrap system " + plist
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
	l.fail["bootout system/"+Label] = errors.New("No such process")
	if err := d.Install(writeExecutable(t, "x")); err != nil {
		t.Fatalf("Install() = %v", err)
	}
}

// S3: bootout returns before launchd tears the job down.
func TestInstallWaitsForBootoutBeforeBootstrap(t *testing.T) {
	d, l, _ := newTestDaemon(t)
	c := &clock{}
	d.Sleep = c.sleep
	l.seq[printJob] = []error{nil, nil, nil}
	if err := d.Install(writeExecutable(t, "x")); err != nil {
		t.Fatalf("Install() = %v", err)
	}
	want := "bootout system/" + Label + strings.Repeat("|"+printJob, 4) + "|bootstrap system " + filepath.Join(d.Root, PlistPath)
	if got := strings.Join(l.calls, "|"); got != want {
		t.Fatalf("launchctl calls = %q, want %q", got, want)
	}
	if len(c.slept) != 3 {
		t.Fatalf("slept %v, want 3 polls", c.slept)
	}
}

func TestInstallWaitIsBounded(t *testing.T) {
	d, l, _ := newTestDaemon(t)
	c := &clock{}
	d.Sleep = c.sleep
	delete(l.fail, printJob) // the job never goes away
	if err := d.Install(writeExecutable(t, "x")); err != nil {
		t.Fatalf("Install() = %v", err)
	}
	if c.total() > BootoutWait || c.total() < BootoutWait-time.Second {
		t.Fatalf("waited %v in total, want about %v", c.total(), BootoutWait)
	}
	if !strings.Contains(strings.Join(l.calls, "|"), "bootstrap system ") {
		t.Fatalf("launchctl calls = %v, want a bootstrap after the wait", l.calls)
	}
}

func TestInstallRetriesBootstrapOnce(t *testing.T) {
	d, l, _ := newTestDaemon(t)
	c := &clock{}
	d.Sleep = c.sleep
	bootstrap := "bootstrap system " + filepath.Join(d.Root, PlistPath)
	l.seq[bootstrap] = []error{errors.New("Bootstrap failed: 5: Input/output error")}
	if err := d.Install(writeExecutable(t, "x")); err != nil {
		t.Fatalf("Install() = %v", err)
	}
	if n := strings.Count(strings.Join(l.calls, "|"), bootstrap); n != 2 {
		t.Fatalf("bootstrap ran %d times, want 2: %v", n, l.calls)
	}
	if c.total() == 0 || c.total() > 2*BootoutWait {
		t.Fatalf("waited %v before the retry", c.total())
	}
}

func TestInstallFailsWhenBootstrapFails(t *testing.T) {
	d, l, _ := newTestDaemon(t)
	d.Sleep = (&clock{}).sleep
	bootstrap := "bootstrap system " + filepath.Join(d.Root, PlistPath)
	l.fail[bootstrap] = errors.New("Bootstrap failed: 5")
	err := d.Install(writeExecutable(t, "x"))
	if err == nil || !strings.Contains(err.Error(), "Bootstrap failed") || !strings.Contains(err.Error(), "the background service is not loaded") {
		t.Fatalf("Install() = %v", err)
	}
	if n := strings.Count(strings.Join(l.calls, "|"), bootstrap); n != 2 {
		t.Fatalf("bootstrap ran %d times, want 2 (one retry): %v", n, l.calls)
	}
}

func TestLastLogLine(t *testing.T) {
	d, _, _ := newTestDaemon(t)
	if line, ok := d.LastLogLine(); ok || line != "" {
		t.Fatalf("LastLogLine() without a log = %q, %v", line, ok)
	}
	log := filepath.Join(d.Root, LogPath)
	os.MkdirAll(filepath.Dir(log), 0o755)
	old := strings.Repeat("2026-11-16T10:00:00Z Protected through ipsec0: anthropic\n", 2000)
	os.WriteFile(log, []byte(old+"2026-11-16T10:01:00Z leakguard: pfctl: syntax error\n\n"), 0o644)
	if line, ok := d.LastLogLine(); !ok || line != "2026-11-16T10:01:00Z leakguard: pfctl: syntax error" {
		t.Fatalf("LastLogLine() = %q, %v", line, ok)
	}
	os.WriteFile(log, nil, 0o644)
	if line, ok := d.LastLogLine(); ok || line != "" {
		t.Fatalf("LastLogLine() with an empty log = %q, %v", line, ok)
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
	l.fail["bootout system/"+Label] = errors.New("No such process")
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
