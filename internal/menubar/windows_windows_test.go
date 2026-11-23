package menubar

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Isaacpaezz/leakguard/internal/daemon"
)

// These tests run headless on windows-latest: they never show a dialog.

// S1: WindowsCommandLine quotes exactly like syscall.EscapeArg, and
// CommandLineToArgvW reads every argument back unchanged, including VPN
// aliases with spaces, quotes, backslashes and non-ASCII letters.
func TestWindowsCommandLineRoundTrip(t *testing.T) {
	args := []string{"enable", "--vpn", "WireGuard Tunnel", "Conexión VPN ñ", `a"b`, `a b\`, `a\\b c`,
		`a\"b c`, `\\`, "", "tab\there", `C:\Program Files\leakguard\leakguard.exe`, "anthropic"}
	line := WindowsCommandLine(args)
	var want []string
	for _, a := range args {
		want = append(want, syscall.EscapeArg(a))
	}
	if line != strings.Join(want, " ") {
		t.Errorf("WindowsCommandLine = %s\nsyscall.EscapeArg gives %s", line, strings.Join(want, " "))
	}
	cmd, err := windows.UTF16PtrFromString(`C:\leakguard.exe ` + line)
	if err != nil {
		t.Fatal(err)
	}
	var argc int32
	argv, err := windows.CommandLineToArgv(cmd, &argc)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(argv)))
	var got []string
	for _, p := range argv[1:argc] {
		got = append(got, windows.UTF16PtrToString(&p[0]))
	}
	if fmt.Sprintf("%q", got) != fmt.Sprintf("%q", args) {
		t.Errorf("CommandLineToArgvW read back\n%q\nwant\n%q", got, args)
	}
}

// S1: on the real Windows adapter rules, aliases with spaces and non-ASCII
// letters (adapters that do not exist here, judged by name) pass the
// setup's validation and reach the elevated command line unchanged.
func TestWindowsSetupCommandRealAliases(t *testing.T) {
	report := filepath.Join(t.TempDir(), "leakguard-report.txt")
	for _, alias := range []string{"WireGuard Tunnel", "Conexión VPN"} {
		d := Draft{VPNInterface: alias, Services: []string{"anthropic"}}
		argv, err := WindowsSetupCommand(winInstalled, d, fullCatalog, report)
		want := []string{winInstalled, "enable", "--report-file", report, "--vpn", alias, "anthropic"}
		if err != nil || fmt.Sprintf("%q", argv) != fmt.Sprintf("%q", want) {
			t.Fatalf("alias %q: %q, %v; want %q", alias, argv, err, want)
		}
		cmd, err := windows.UTF16PtrFromString(WindowsCommandLine(argv))
		if err != nil {
			t.Fatal(err)
		}
		var argc int32
		parsed, err := windows.CommandLineToArgv(cmd, &argc)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, p := range parsed[:argc] {
			got = append(got, windows.UTF16PtrToString(&p[0]))
		}
		windows.LocalFree(windows.Handle(unsafe.Pointer(parsed)))
		if fmt.Sprintf("%q", got) != fmt.Sprintf("%q", want) {
			t.Errorf("alias %q: CommandLineToArgvW read back %q, want %q", alias, got, want)
		}
	}
}

// S1: the language comes from GetUserDefaultUILanguage.
func TestUserLang(t *testing.T) {
	id := userUILanguage()
	t.Logf("GetUserDefaultUILanguage = %#04x, language %v", id, UserLang())
	if id == 0 {
		t.Fatal("GetUserDefaultUILanguage returned 0")
	}
	if got, want := UserLang().IsSpanish(), id&0x3FF == 0x0A; got != want {
		t.Errorf("Spanish = %v, want %v for %#04x", got, want, id)
	}
	if !strings.HasSuffix(UserLang().String(), "+windows") {
		t.Errorf("UserLang = %v, want the Windows wording", UserLang())
	}
}

// S1: the installed copy's path comes from the Program Files known folder:
// the service's own copy in %ProgramFiles%\leakguard\service.
func TestProgramFiles(t *testing.T) {
	dir := ProgramFiles()
	cli := WindowsInstalledCLI(dir)
	t.Logf("Program Files = %q, installed CLI = %q", dir, cli)
	if checkWindowsPath(dir) != nil || !strings.EqualFold(cli, filepath.Join(dir, "leakguard", "service", "leakguard.exe")) {
		t.Errorf("Program Files = %q, installed CLI = %q", dir, cli)
	}
}

// S1: QuerySCM reads a service with read rights only, and a missing one
// is ErrServiceNotInstalled, so WindowsInstalledState says InstallNone.
func TestQuerySCM(t *testing.T) {
	info, err := QuerySCM{}.Query("EventLog")
	t.Logf("EventLog: %+v, %v", info, err)
	if err != nil || info.State != daemon.ServiceRunning || !strings.Contains(strings.ToLower(info.Command), "svchost.exe") {
		t.Errorf("Query(EventLog) = %+v, %v; want a running svchost service", info, err)
	}
	if _, err := (QuerySCM{}).Query("leakguard-test-missing"); !errors.Is(err, daemon.ErrServiceNotInstalled) {
		t.Errorf("missing service: err = %v, want ErrServiceNotInstalled", err)
	}
	if err := (QuerySCM{}).Stop("EventLog"); err == nil {
		t.Error("QuerySCM stopped a service")
	}
}

// S1: the installed copy is trusted only when it and its folder are
// admin-only and not links: System32's cmd.exe is; a file in the user's
// temporary folder, which the user may change, is not.
func TestCheckInstalledCLIWindows(t *testing.T) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	cmd := filepath.Join(system, "cmd.exe")
	if err := CheckInstalledCLI(cmd); err != nil {
		t.Errorf("CheckInstalledCLI(%s) = %v, want nil", cmd, err)
	}
	dir := t.TempDir()
	user := filepath.Join(dir, "leakguard.exe")
	if err := os.WriteFile(user, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	err = CheckInstalledCLI(user)
	t.Logf("user file: %v", err)
	if err == nil {
		t.Errorf("CheckInstalledCLI(%s) = nil, want a refusal", user)
	}
	if err := CheckInstalledCLI(filepath.Join(dir, "missing.exe")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: err = %v, want fs.ErrNotExist", err)
	}
	link := filepath.Join(dir, "link.exe")
	if err := os.Symlink(cmd, link); err != nil {
		t.Logf("no symlink (%v): the link case needs the right to create symlinks", err)
		return
	}
	if err := CheckInstalledCLI(link); err == nil {
		t.Errorf("CheckInstalledCLI(link to cmd.exe) = nil, want a refusal")
	}
}

// S1: without a manifest asking for comctl32 version 6 (the test binary
// has none, and neither has the tray until the installer adds it),
// TaskDialogIndirect is missing and the dialogs use MessageBoxW.
func TestDialogsWithoutManifest(t *testing.T) {
	err := procTaskDialogIndirect.Find()
	t.Logf("TaskDialogIndirect lookup: %v", err)
	if taskDialogAvailable() {
		t.Error("TaskDialogIndirect found without a manifest: the MessageBoxW fallback is not what runs")
	}
	w := NewWinDialogs(English)
	if w.TaskDialog != nil || w.MessageBox == nil {
		t.Errorf("NewWinDialogs: task dialog %v, message box %v; want only the message box", w.TaskDialog != nil, w.MessageBox != nil)
	}
}

// S1: SHELLEXECUTEINFOW is 112 bytes on 64-bit Windows and 60 on 32-bit.
func TestShellExecuteInfoSize(t *testing.T) {
	want := uintptr(60)
	if unsafe.Sizeof(uintptr(0)) == 8 {
		want = 112
	}
	if got := unsafe.Sizeof(shellExecuteInfo{}); got != want {
		t.Errorf("SHELLEXECUTEINFOW is %d bytes, want %d", got, want)
	}
}

// S1: RunElevated starts the program with "runas", waits for it and maps
// its exit code. An elevated test process gets no UAC prompt, so this runs
// only elevated (as on windows-latest); it would never show the prompt.
func TestRunElevatedExitCode(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated process: otherwise Windows would show the UAC prompt")
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	cmd := filepath.Join(system, "cmd.exe")
	run := func(args ...string) error {
		done := make(chan error, 1)
		go func() { done <- RunElevated(append([]string{cmd}, args...)) }()
		select {
		case err := <-done:
			return err
		case <-time.After(60 * time.Second):
			t.Fatal("no answer in 60 s: a UAC prompt may be waiting")
			return nil
		}
	}
	if err := run("/c", "exit", "0"); err != nil {
		t.Errorf("exit 0: %v", err)
	}
	if err := run("/c", "exit", "7"); err == nil || err.Error() != "leakguard exited with status 7" {
		t.Errorf("exit 7: err = %v, want leakguard exited with status 7", err)
	}
	if err := RunElevated([]string{"cmd.exe", "/c", "exit", "0"}); !errors.Is(err, ErrUnsafeCLIPath) {
		t.Errorf("relative program: err = %v, want ErrUnsafeCLIPath", err)
	}
	if err := RunElevated(nil); err == nil {
		t.Error("RunElevated(nil): no error")
	}
}

// reportHelperArg makes TestHelperElevatedReport act: the elevated copy of
// this test binary writes a message to the report file and exits 3, like
// a failed leakguard enable.
const reportHelperArg = "leakguard-report-helper"

// TestHelperElevatedReport is the elevated program of
// TestRunElevatedWithReport; run on its own it does nothing.
func TestHelperElevatedReport(t *testing.T) {
	args := flag.Args()
	if len(args) != 3 || args[0] != reportHelperArg {
		return
	}
	if args[2] != "" {
		f, err := os.OpenFile(args[1], os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			os.Exit(4)
		}
		f.WriteString(args[2] + "\n")
		f.Close()
	}
	os.Exit(3)
}

// S1: the tray creates a report file in the user's temporary folder,
// passes it to the elevated program, shows the message written there
// instead of the exit status, and removes the file. Like
// TestRunElevatedExitCode, it runs only elevated (as on windows-latest).
func TestRunElevatedWithReport(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated process: otherwise Windows would show the UAC prompt")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	msg := `could not apply the firewall rules: "Conexión VPN" is not a VPN interface`
	for _, tc := range []struct{ write, want string }{
		{msg, msg},
		{"", "leakguard exited with status 3"},
	} {
		var report string
		done := make(chan error, 1)
		go func() {
			done <- RunElevatedWithReport(func(path string) ([]string, error) {
				report = path
				if _, err := os.Stat(path); err != nil {
					return nil, fmt.Errorf("the report file does not exist before the run: %w", err)
				}
				return []string{exe, "-test.run=^TestHelperElevatedReport$", reportHelperArg, path, tc.write}, nil
			})
		}()
		select {
		case err = <-done:
		case <-time.After(60 * time.Second):
			t.Fatal("no answer in 60 s: a UAC prompt may be waiting")
		}
		if err == nil || err.Error() != tc.want {
			t.Errorf("RunElevatedWithReport = %v, want %q", err, tc.want)
		}
		tmp := os.TempDir()
		if report == "" || !strings.EqualFold(filepath.Dir(report), filepath.Clean(tmp)) {
			t.Errorf("report file %q is not in the user's temporary folder %q", report, tmp)
		}
		if _, err := os.Stat(report); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the report file %q was kept: %v", report, err)
		}
	}
	built := errors.New("not a valid choice")
	if err := RunElevatedWithReport(func(string) ([]string, error) { return nil, built }); !errors.Is(err, built) {
		t.Errorf("a command that cannot be built: err = %v", err)
	}
}

// S1: the login item through the real registry, in a temporary key under
// HKCU\Software\leakguard-test that the test removes.
func TestRegistryRunKey(t *testing.T) {
	const parent = `Software\leakguard-test`
	path := fmt.Sprintf(`%s\%d`, parent, os.Getpid())
	t.Cleanup(func() {
		if err := registry.DeleteKey(registry.CURRENT_USER, path); err != nil && !errors.Is(err, registry.ErrNotExist) {
			t.Errorf("cleanup %s: %v", path, err)
		}
		registry.DeleteKey(registry.CURRENT_USER, parent) // only when empty
	})
	key := RegistryRunKey{Path: path}
	if _, err := key.Get(RunValueName); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Get before the key exists: err = %v, want fs.ErrNotExist", err)
	}
	if err := key.Delete(RunValueName); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Delete before the key exists: err = %v, want fs.ErrNotExist", err)
	}

	appData := t.TempDir()
	exe := `C:\Program Files\leakguard\leakguard-tray.exe`
	if on, err := SyncRunValue(key, appData, exe); err != nil || !on {
		t.Fatalf("SyncRunValue = %v, %v", on, err)
	}
	if v, err := key.Get(RunValueName); err != nil || v != `"`+exe+`"` {
		t.Errorf("Run value = %q, %v", v, err)
	}
	if !RunValuePresent(key, appData) {
		t.Error("RunValuePresent = false")
	}

	// A value of another type is replaced, never trusted.
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.SetDWordValue(RunValueName, 1); err != nil {
		t.Fatal(err)
	}
	k.Close()
	if _, err := key.Get(RunValueName); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("DWORD value: err = %v, want a type error", err)
	}
	if _, err := SyncRunValue(key, appData, exe); err != nil {
		t.Fatal(err)
	}
	if v, err := key.Get(RunValueName); err != nil || v != `"`+exe+`"` {
		t.Errorf("after replacing the DWORD: %q, %v", v, err)
	}

	if err := SetRunValue(key, appData, exe, false); err != nil {
		t.Fatal(err)
	}
	if _, err := key.Get(RunValueName); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("turned off: err = %v, want fs.ErrNotExist", err)
	}
	if err := SetRunValue(key, appData, exe, true); err != nil {
		t.Fatal(err)
	}
	if err := RemoveRunValue(key, appData); err != nil {
		t.Fatal(err)
	}
	if RunValuePresent(key, appData) {
		t.Error("uninstall kept the Run value")
	}
}
