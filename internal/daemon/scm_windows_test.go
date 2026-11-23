package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"github.com/Isaacpaezz/leakguard/internal/config"
	"golang.org/x/sys/windows"
)

// needElevated skips without an elevated token, except on CI, which must
// run these tests elevated.
func needElevated(t *testing.T) {
	t.Helper()
	if windows.GetCurrentProcessToken().IsElevated() {
		return
	}
	if os.Getenv("CI") != "" {
		t.Fatal("needs an elevated token, and CI runs elevated")
	}
	t.Skip("needs an elevated token")
}

// asNonAdministrator runs f on this thread impersonating this process's
// token with Administrators deny-only and no privileges: what an
// administrator's unelevated token looks like.
func asNonAdministrator(t *testing.T, f func()) {
	t.Helper()
	var process windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE|windows.TOKEN_ASSIGN_PRIMARY, &process); err != nil {
		t.Fatal(err)
	}
	defer process.Close()
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	disable := windows.SIDAndAttributes{Sid: admins}
	var restricted windows.Token
	const disableMaxPrivilege = 0x1
	r, _, err := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken").Call(
		uintptr(process), disableMaxPrivilege, 1, uintptr(unsafe.Pointer(&disable)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted)))
	if r == 0 {
		t.Fatalf("CreateRestrictedToken: %v", err)
	}
	defer restricted.Close()
	var imp windows.Token
	if err := windows.DuplicateTokenEx(restricted, windows.TOKEN_IMPERSONATE|windows.TOKEN_QUERY, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &imp); err != nil {
		t.Fatal(err)
	}
	defer imp.Close()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.SetThreadToken(nil, imp); err != nil {
		t.Fatalf("SetThreadToken: %v", err)
	}
	defer windows.RevertToSelf()
	f()
}

// S1: status runs unelevated, so SCM.Query must work without
// administrator rights: it opens the manager and the service with read
// access only. Full access (what Query asked before) is refused to such a
// token, so the old Query reported an installed service as missing.
func TestSCMQueryWorksWithoutAdministratorRights(t *testing.T) {
	needElevated(t)
	var scm SCM
	name := fmt.Sprintf("leakguard-test-query-%d", os.Getpid())
	command := `"C:\Windows\System32\cmd.exe" /c exit`
	if err := scm.Create(name, ServiceConfig{DisplayName: name, Command: command, Account: ServiceAccount}); err != nil {
		t.Fatalf("Create() = %v", err)
	}
	t.Cleanup(func() {
		if err := scm.Delete(name); err != nil {
			t.Errorf("Delete() = %v", err)
		}
	})
	// The default service ACL lets interactive users read it; the CI
	// token may not be interactive, so Authenticated Users get the same
	// read access here.
	m, s, err := scm.open(name, windows.WRITE_DAC)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	err = windows.SetSecurityInfo(s.Handle, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	s.Close()
	m.Disconnect()
	if err != nil {
		t.Fatalf("SetSecurityInfo: %v", err)
	}

	var info ServiceInfo
	var queryErr, fullErr error
	asNonAdministrator(t, func() {
		h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
		if err == nil {
			windows.CloseServiceHandle(h)
		}
		fullErr = err
		info, queryErr = scm.Query(name)
	})
	if !errors.Is(fullErr, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("the restricted token opened the SCM with full access (%v): it is not a non-administrator, so the test proves nothing", fullErr)
	}
	if queryErr != nil {
		t.Fatalf("Query() without administrator rights = %v; status would report the service as not installed", queryErr)
	}
	if info.State != ServiceStopped || info.Command != command {
		t.Fatalf("Query() without administrator rights = %+v, want stopped with command %q", info, command)
	}
}

// The service log is read only when nobody but SYSTEM and Administrators
// may write it, so a user cannot forge the line status shows.
func TestWindowsLastLogLineReadsOnlyATrustedLog(t *testing.T) {
	needElevated(t)
	dir := filepath.Join(t.TempDir(), "leakguard")
	if err := config.PrepareDir(dir); err != nil {
		t.Fatalf("PrepareDir() = %v", err)
	}
	log := filepath.Join(dir, "leakguard.log")
	const line = "2026-11-23T10:00:00Z Protected through WireGuard Tunnel: anthropic"
	if err := os.WriteFile(log, []byte(line+"\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	setOwner(t, log, windows.WinBuiltinAdministratorsSid)
	w := WindowsService{Log: log}
	if got, ok := w.LastLogLine(); !ok || got != line {
		t.Fatalf("LastLogLine() of a trusted log = %q, %v; want %q", got, ok, line)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(log, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if got, ok := w.LastLogLine(); ok || got != "" {
		t.Fatalf("LastLogLine() of a log Users may write = %q, %v; want nothing", got, ok)
	}
}

func setOwner(t *testing.T, path string, owner windows.WELL_KNOWN_SID_TYPE) {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(owner)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, sid, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
}

// The real SCM reports a missing service as ErrServiceNotInstalled, which
// Install and Uninstall rely on. Connecting needs an elevated token.
func TestSCMReportsAMissingService(t *testing.T) {
	needElevated(t)
	const name = "leakguard-test-does-not-exist"
	var scm SCM
	if _, err := scm.Query(name); !errors.Is(err, ErrServiceNotInstalled) {
		t.Errorf("Query() = %v, want ErrServiceNotInstalled", err)
	}
	if err := scm.Stop(name); !errors.Is(err, ErrServiceNotInstalled) {
		t.Errorf("Stop() = %v, want ErrServiceNotInstalled", err)
	}
	w := WindowsService{Binary: t.TempDir() + `\leakguard.exe`, SCM: scm}
	if w.Installed() {
		t.Error("Installed() = true")
	}
}

// The default paths follow %ProgramFiles% and %ProgramData%.
func TestWindowsDefaultPaths(t *testing.T) {
	binary, log := WindowsPaths(windowsEnv(t, "ProgramFiles"), windowsEnv(t, "ProgramData"))
	if WindowsBinaryPath != binary || WindowsLogPath != log {
		t.Errorf("paths = %q, %q; want %q, %q", WindowsBinaryPath, WindowsLogPath, binary, log)
	}
}

func windowsEnv(t *testing.T, key string) string {
	v, err := windows.KnownFolderPath(map[string]*windows.KNOWNFOLDERID{
		"ProgramFiles": windows.FOLDERID_ProgramFiles,
		"ProgramData":  windows.FOLDERID_ProgramData,
	}[key], 0)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
