package daemon

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// The real SCM reports a missing service as ErrServiceNotInstalled, which
// Install and Uninstall rely on. Connecting needs an elevated token.
func TestSCMReportsAMissingService(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token")
	}
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
