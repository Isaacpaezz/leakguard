package menubar

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/daemon"
)

const (
	// The installer puts the tray app and the CLI in %ProgramFiles%\leakguard
	// and the service runs its own copy in the service folder below it.
	winTray      = `C:\Program Files\leakguard\leakguard-tray.exe`
	winNextToApp = `C:\Program Files\leakguard\leakguard.exe`
	winInstalled = `C:\Program Files\leakguard\service\leakguard.exe`
	// A tray app copied to a user's folder, with a non-ASCII name.
	winUserTray = `C:\Users\Ana María\AppData\Local\leakguard\leakguard-tray.exe`
	winUserCLI  = `C:\Users\Ana María\AppData\Local\leakguard\leakguard.exe`
	winReport   = `C:\Users\Ana María\AppData\Local\Temp\leakguard-report-123.txt`
)

// fakeSCM answers Query from services; every other call fails, so a test
// sees any attempt to change the system.
type fakeSCM struct {
	services map[string]daemon.ServiceInfo
	err      error
}

func (f fakeSCM) Query(name string) (daemon.ServiceInfo, error) {
	if f.err != nil {
		return daemon.ServiceInfo{}, f.err
	}
	info, ok := f.services[name]
	if !ok {
		return daemon.ServiceInfo{}, daemon.ErrServiceNotInstalled
	}
	return info, nil
}

var errChange = errors.New("the tray must never change a service")

func (fakeSCM) Create(string, daemon.ServiceConfig) error { return errChange }
func (fakeSCM) Update(string, daemon.ServiceConfig) error { return errChange }
func (fakeSCM) SetRecovery(string, daemon.Recovery) error { return errChange }
func (fakeSCM) Start(string) error                        { return errChange }
func (fakeSCM) Stop(string) error                         { return errChange }
func (fakeSCM) Delete(string) error                       { return errChange }

func serviceRunning(command string) fakeSCM {
	return fakeSCM{services: map[string]daemon.ServiceInfo{
		daemon.ServiceName: {State: daemon.ServiceRunning, Command: command},
	}}
}

// S1: the Windows installed state comes from the Service Control Manager:
// no service is InstallNone, the service running this "serve" is
// InstallCurrent, anything else (another command, an unreadable service)
// is InstallOld, so the installed copy is not reused.
func TestWindowsInstalledState(t *testing.T) {
	current := `"` + winInstalled + `" serve`
	tests := []struct {
		name string
		scm  fakeSCM
		want Install
	}{
		{"no service", fakeSCM{}, InstallNone},
		{"current service", serviceRunning(current), InstallCurrent},
		{"current service, other case", serviceRunning(`"C:\PROGRAM FILES\leakguard\SERVICE\leakguard.exe" serve`), InstallCurrent},
		{"the service running the CLI next to the tray: an older install", serviceRunning(`"` + winNextToApp + `" serve`), InstallOld},
		{"stopped current service", fakeSCM{services: map[string]daemon.ServiceInfo{daemon.ServiceName: {State: daemon.ServiceStopped, Command: current}}}, InstallCurrent},
		{"another command", serviceRunning(`"` + winInstalled + `" apply`), InstallOld},
		{"another binary", serviceRunning(`"C:\Temp\leakguard.exe" serve`), InstallOld},
		{"unreadable", fakeSCM{err: syscall.Errno(5)}, InstallOld},
	}
	for _, tc := range tests {
		if got := WindowsInstalledState(tc.scm, winInstalled); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	if got, want := WindowsInstalledCLI(`C:\Program Files`), winInstalled; got != want {
		t.Errorf("WindowsInstalledCLI = %q, want %q", got, want)
	}
	if got, want := WindowsInstalledCLI(`D:\Programas\`), `D:\Programas\leakguard\service\leakguard.exe`; got != want {
		t.Errorf("WindowsInstalledCLI(D:) = %q, want %q", got, want)
	}
	if got, want := WindowsInstalledCLI(""), winInstalled; got != want {
		t.Errorf("WindowsInstalledCLI(\"\") = %q, want %q", got, want)
	}
}

// S1: the CLI the Windows tray runs elevated is the installed copy only
// while the current service runs it and its folder is admin-only; otherwise
// leakguard.exe next to the tray, like on macOS and Linux.
func TestFindWindowsCLI(t *testing.T) {
	adminOnly := func(string) error { return nil }
	missing := func(p string) error { return &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist} }
	userWritable := func(p string) error { return errors.New(p + ` may be changed by S-1-5-32-545`) }
	next := func(p string) bool { return p == winNextToApp }
	none := func(string) bool { return false }
	tests := []struct {
		name    string
		exe     string
		inst    Install
		isFile  func(string) bool
		check   func(string) error
		want    string
		wantErr error
	}{
		{"current service: the admin-only installed copy wins", winTray, InstallCurrent, next, adminOnly, winInstalled, nil},
		{"current service, copy writable by users: refused, never replaced", winTray, InstallCurrent, next, userWritable, "", ErrCLINotRootOwned},
		{"current service without the copy: the one next to the tray", winTray, InstallCurrent, next, missing, winNextToApp, nil},
		{"no service: the one next to the tray", winTray, InstallNone, next, adminOnly, winNextToApp, nil},
		{"older service: the one next to the tray updates it", winTray, InstallOld, next, adminOnly, winNextToApp, nil},
		{"older service, nothing next to the tray", winTray, InstallOld, none, adminOnly, "", ErrCLIUpdate},
		{"nothing at all", winTray, InstallNone, none, adminOnly, "", ErrNoCLI},
		{"unknown tray path", "", InstallNone, func(string) bool { return true }, adminOnly, "", ErrNoCLI},
		{"relative tray path", `leakguard\leakguard-tray.exe`, InstallNone, func(string) bool { return true }, adminOnly, "", ErrNoCLI},
		{"tray in a user's folder: the one next to it", winUserTray, InstallNone, func(p string) bool { return p == winUserCLI }, adminOnly, winUserCLI, nil},
		{"tray in a user's folder, current service: the installed copy", winUserTray, InstallCurrent, func(p string) bool { return p == winUserCLI }, adminOnly, winInstalled, nil},
	}
	for _, tc := range tests {
		got, err := FindWindowsCLI(tc.exe, tc.inst, winInstalled, tc.isFile, tc.check)
		if got != tc.want || !errors.Is(err, tc.wantErr) || (tc.wantErr == nil) != (err == nil) {
			t.Errorf("%s: %q, %v; want %q, %v", tc.name, got, err, tc.want, tc.wantErr)
		}
	}
	if got, want := Explain(English.ForOS("windows"), ErrCLINotRootOwned), "The installed leakguard is not protected: only administrators should be able to change it. Reinstall it with the leakguard installer."; got != want {
		t.Errorf("Explain = %q, want %q", got, want)
	}
}

// S1: the Windows setup and uninstall run the CLI itself, elevated, with
// its arguments as a list; the path must be an absolute Windows path. The
// report file comes first, so the CLI reads it before any other mistake.
func TestWindowsSetupCommand(t *testing.T) {
	d := Draft{VPNInterface: "ipsec0", Services: []string{"anthropic", "mistral"}}
	got, err := WindowsSetupCommand(winInstalled, d, fullCatalog, winReport)
	want := []string{winInstalled, "enable", "--report-file", winReport, "--vpn", "ipsec0", "anthropic", "mistral"}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("WindowsSetupCommand = %q, %v; want %q", got, err, want)
	}
	// No report file, or one that is not a plain absolute path: no flag,
	// the run still works and only its exit status is known.
	for _, report := range []string{"", "report.txt", `C:\Temp\a"b.txt`, "C:\\Temp\\a\nb.txt", `C:\Temp\..\x.txt`} {
		got, err := WindowsSetupCommand(winInstalled, d, fullCatalog, report)
		want := []string{winInstalled, "enable", "--vpn", "ipsec0", "anthropic", "mistral"}
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("report %q: WindowsSetupCommand = %q, %v; want %q", report, got, err, want)
		}
		got, err = WindowsDisableCommand(winInstalled, report)
		if want := []string{winInstalled, "disable"}; err != nil || !slices.Equal(got, want) {
			t.Errorf("report %q: WindowsDisableCommand = %q, %v; want %q", report, got, err, want)
		}
	}
	for _, bad := range []string{"leakguard.exe", `\leakguard\leakguard.exe`, `\\server\share\leakguard.exe`,
		`\\?\C:\leakguard.exe`, `C:leakguard.exe`, `C:\a"b\leakguard.exe`, "C:\\a\nb\\leakguard.exe",
		"C:\\\xff\\leakguard.exe", `C:\a\..\leakguard.exe`, "/usr/bin/leakguard", ""} {
		if _, err := WindowsSetupCommand(bad, d, fullCatalog, winReport); !errors.Is(err, ErrUnsafeCLIPath) {
			t.Errorf("WindowsSetupCommand(%q) err = %v, want ErrUnsafeCLIPath", bad, err)
		}
		if _, err := WindowsDisableCommand(bad, winReport); !errors.Is(err, ErrUnsafeCLIPath) {
			t.Errorf("WindowsDisableCommand(%q) err = %v, want ErrUnsafeCLIPath", bad, err)
		}
	}
	for _, bad := range []Draft{
		{VPNInterface: "ipsec0", Services: []string{"openai"}},
		{VPNInterface: "ipsec0", Services: []string{"--vpn"}},
		{VPNInterface: "ipsec0"},
		{VPNInterface: "", Services: []string{"anthropic"}},
	} {
		if _, err := WindowsSetupCommand(winInstalled, bad, fullCatalog, winReport); !errors.Is(err, ErrInvalidChoice) {
			t.Errorf("WindowsSetupCommand(%+v) err = %v, want ErrInvalidChoice", bad, err)
		}
	}
	got, err = WindowsDisableCommand(winInstalled, winReport)
	if want := []string{winInstalled, "disable", "--report-file", winReport}; err != nil || !slices.Equal(got, want) {
		t.Errorf("WindowsDisableCommand = %q, %v; want %q", got, err, want)
	}
}

// windowsAliasRules stands in for the Windows adapter rules on other
// systems (config uses the rules of the system it runs on): any alias
// that is valid UTF-8 without control characters, as an adapter that does
// not exist yet is judged. windows_windows_test.go runs the real ones.
func windowsAliasRules(c config.Config, all []catalog.Service) error {
	if c.VPNInterface == "" || !utf8.ValidString(c.VPNInterface) ||
		strings.ContainsFunc(c.VPNInterface, unicode.IsControl) {
		return fmt.Errorf("%q is not a valid interface name", c.VPNInterface)
	}
	return c.ValidateServices(all)
}

// S1: Windows adapter aliases hold spaces and any letter: the setup passes
// them to the elevated CLI as one argument, unchanged.
func TestWindowsSetupCommandAliases(t *testing.T) {
	for _, alias := range []string{"WireGuard Tunnel", "Conexión VPN", "VPN \"oficina\" 2"} {
		d := Draft{VPNInterface: alias, Services: []string{"anthropic"}}
		got, err := windowsSetupCommand(winInstalled, d, fullCatalog, winReport, windowsAliasRules)
		want := []string{winInstalled, "enable", "--report-file", winReport, "--vpn", alias, "anthropic"}
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("alias %q: %q, %v; want %q", alias, got, err, want)
		}
	}
	got, err := windowsSetupCommand(winInstalled, Draft{VPNInterface: "WireGuard Tunnel", Services: []string{"anthropic"}},
		fullCatalog, "", windowsAliasRules)
	if line := WindowsCommandLine(got[1:]); err != nil || line != `enable --vpn "WireGuard Tunnel" anthropic` {
		t.Errorf("command line = %s, %v", line, err)
	}
	_, err = windowsSetupCommand(winInstalled, Draft{VPNInterface: "VPN\x00", Services: []string{"anthropic"}},
		fullCatalog, "", windowsAliasRules)
	if !errors.Is(err, ErrInvalidChoice) {
		t.Errorf("alias with a NUL: err = %v, want ErrInvalidChoice", err)
	}
}

// S1: the elevated arguments follow the Windows command-line rules that
// CommandLineToArgvW and the Go runtime read back (syscall.EscapeArg).
func TestWindowsCommandLine(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"enable", "--vpn", "ipsec0", "anthropic"}, `enable --vpn ipsec0 anthropic`},
		{[]string{"enable", "--vpn", "WireGuard Tunnel"}, `enable --vpn "WireGuard Tunnel"`},
		{[]string{"--vpn", "Conexión VPN ñ"}, `--vpn "Conexión VPN ñ"`},
		{[]string{`a"b`}, `a\"b`},
		{[]string{`a b\`}, `"a b\\"`},
		{[]string{`a\\b c`}, `"a\\b c"`},
		{[]string{`a\"b c`}, `"a\\\"b c"`},
		{[]string{`\\`}, `\\`},
		{[]string{""}, `""`},
		{[]string{"tab\there"}, "\"tab\there\""},
		{nil, ""},
	}
	for _, tc := range tests {
		if got := WindowsCommandLine(tc.args); got != tc.want {
			t.Errorf("WindowsCommandLine(%q) = %s, want %s", tc.args, got, tc.want)
		}
	}
}

// S1: how the elevated run ended: the user declining UAC (ERROR_CANCELLED)
// is a cancel, any other launch failure and any non-zero exit an error.
// A failed run says the message the CLI wrote to the report file, or its
// exit status when it wrote none.
func TestElevationError(t *testing.T) {
	if err := ElevationError(nil, 0, ""); err != nil {
		t.Errorf("exit 0: %v", err)
	}
	if err := ElevationError(nil, 0, "stale text"); err != nil {
		t.Errorf("exit 0 with a report: %v, want nil", err)
	}
	if err := ElevationError(syscall.Errno(1223), 0, ""); !errors.Is(err, ErrCancelled) {
		t.Errorf("ERROR_CANCELLED: err = %v, want ErrCancelled", err)
	}
	if got := WizardMessage(Spanish.ForOS("windows"), ElevationError(syscall.Errno(1223), 0, "")); got != "" {
		t.Errorf("a declined UAC prompt says %q, want nothing", got)
	}
	launch := ElevationError(syscall.Errno(2), 0, "")
	if launch == nil || errors.Is(launch, ErrCancelled) || launch.Error() != "could not start leakguard as administrator: "+syscall.Errno(2).Error() {
		t.Errorf("launch failure: err = %v", launch)
	}
	if err := ElevationError(nil, 1, ""); err == nil || err.Error() != "leakguard exited with status 1" {
		t.Errorf("exit 1: err = %v", err)
	}
	if err := ElevationError(nil, 1, " \n\t"); err == nil || err.Error() != "leakguard exited with status 1" {
		t.Errorf("exit 1 with a blank report: err = %v", err)
	}
	if err := ElevationError(nil, 0xC0000005, ""); err == nil || err.Error() != "leakguard exited with status 3221225477" {
		t.Errorf("crash: err = %v", err)
	}
	msg := `could not apply the firewall rules: "Conexión VPN" is not a VPN interface; it is a real connection`
	err := ElevationError(nil, 1, msg+"\n")
	if err == nil || err.Error() != msg {
		t.Errorf("exit 1 with a report: err = %v, want %q", err, msg)
	}
	if got, want := WizardMessage(English.ForOS("windows"), err), English.ForOS("windows").Text(msgWizardFailed, msg); got != want {
		t.Errorf("the wizard says %q, want %q", got, want)
	}
	if got := Explain(Spanish.ForOS("windows"), err); !strings.Contains(got, msg) {
		t.Errorf("Explain = %q, want it to hold %q", got, msg)
	}
}

// S1: the report file is read capped at maxElevationReport bytes, as
// valid UTF-8 and trimmed; a missing or unreadable one is no report.
func TestReadElevationReport(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tests := []struct {
		path string
		want string
	}{
		{write("ok.txt", "could not install the background service: access denied\n"), "could not install the background service: access denied"},
		{write("empty.txt", ""), ""},
		{write("invalid.txt", "bad \xff byte\r\n"), "bad \uFFFD byte"},
		{filepath.Join(dir, "missing.txt"), ""},
		{dir, ""},
		{"", ""},
	}
	for _, tc := range tests {
		if got := ReadElevationReport(tc.path); got != tc.want {
			t.Errorf("ReadElevationReport(%s) = %q, want %q", filepath.Base(tc.path), got, tc.want)
		}
	}
	long := write("long.txt", strings.Repeat("ñ", maxElevationReport))
	if got := ReadElevationReport(long); len(got) > maxElevationReport || !utf8.ValidString(got) || !strings.HasPrefix(got, "ññ") {
		t.Errorf("long report: %d bytes, valid UTF-8 %v", len(got), utf8.ValidString(got))
	}
}
