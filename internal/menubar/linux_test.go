package menubar

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/daemon"
)

func envOf(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

// S1: on Linux the language comes from LANGUAGE, LC_ALL, LC_MESSAGES and
// LANG, in that order.
func TestEnvLang(t *testing.T) {
	tests := []struct {
		env  map[string]string
		want Lang
	}{
		{map[string]string{"LANG": "es_VE.UTF-8"}, Spanish},
		{map[string]string{"LANG": "es_ES@euro"}, Spanish},
		{map[string]string{"LANG": "es"}, Spanish},
		{map[string]string{"LANG": "en_US.UTF-8"}, English},
		{map[string]string{"LANG": "et_EE.UTF-8"}, English},
		{map[string]string{"LANG": "C"}, English},
		{map[string]string{}, English},
		{map[string]string{"LC_MESSAGES": "es_MX.UTF-8", "LANG": "en_US.UTF-8"}, Spanish},
		{map[string]string{"LC_ALL": "en_GB.UTF-8", "LC_MESSAGES": "es_MX.UTF-8"}, English},
		{map[string]string{"LC_ALL": "es_AR.UTF-8", "LANG": "en_US.UTF-8"}, Spanish},
		{map[string]string{"LANGUAGE": "es:en", "LC_ALL": "en_US.UTF-8"}, Spanish},
		{map[string]string{"LANGUAGE": "en_GB:es", "LANG": "es_VE.UTF-8"}, English},
		{map[string]string{"LANGUAGE": ":es_VE", "LANG": "en_US.UTF-8"}, Spanish},
		{map[string]string{"LANGUAGE": "", "LANG": "es_VE.UTF-8"}, Spanish},
	}
	for _, tc := range tests {
		if got := EnvLang(envOf(tc.env)); got != tc.want {
			t.Errorf("EnvLang(%v) = %q, want %q", tc.env, got, tc.want)
		}
	}
}

func writeUnit(t *testing.T, root, content string) {
	t.Helper()
	p := filepath.Join(root, daemon.UnitPath)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// S1: the installed state on Linux comes from the systemd unit.
func TestSystemdInstalledState(t *testing.T) {
	root := t.TempDir()
	if got := SystemdInstalledState(root); got != InstallNone {
		t.Errorf("no unit: %v, want InstallNone", got)
	}
	writeUnit(t, root, daemon.Unit(daemon.BinaryPath))
	if got := SystemdInstalledState(root); got != InstallCurrent {
		t.Errorf("unit running serve: %v, want InstallCurrent", got)
	}
	writeUnit(t, root, strings.ReplaceAll(daemon.Unit(daemon.BinaryPath), daemon.BinaryPath+" serve", "/tmp/leakguard serve"))
	if got := SystemdInstalledState(root); got != InstallOld {
		t.Errorf("unit running another binary: %v, want InstallOld", got)
	}
	writeUnit(t, root, strings.ReplaceAll(daemon.Unit(daemon.BinaryPath), " serve", " apply"))
	if got := SystemdInstalledState(root); got != InstallOld {
		t.Errorf("unit without serve: %v, want InstallOld", got)
	}
}

// S1: the CLI run as root is the installed copy only when the unit runs it
// with serve and it is root-owned; otherwise the one next to the tray.
func TestFindLinuxCLI(t *testing.T) {
	const tray = "/usr/bin/leakguard-menubar"
	const next = "/usr/bin/leakguard"
	exists := func(p string) bool { return p == next }
	rootOwned := func(string) error { return nil }
	missing := func(p string) error { return &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist} }
	notRoot := func(p string) error { return errors.New(p + " is not owned by root") }

	root := t.TempDir()
	if got, err := FindLinuxCLI(root, tray, exists, rootOwned); err != nil || got != next {
		t.Errorf("no unit: %q, %v; want %q", got, err, next)
	}
	writeUnit(t, root, daemon.Unit(daemon.BinaryPath))
	if got, err := FindLinuxCLI(root, tray, exists, rootOwned); err != nil || got != InstalledCLI {
		t.Errorf("current unit: %q, %v; want %q", got, err, InstalledCLI)
	}
	if got, err := FindLinuxCLI(root, tray, exists, missing); err != nil || got != next {
		t.Errorf("current unit, no installed copy: %q, %v; want %q", got, err, next)
	}
	if _, err := FindLinuxCLI(root, tray, exists, notRoot); !errors.Is(err, ErrCLINotRootOwned) {
		t.Errorf("installed copy not owned by root: err = %v, want ErrCLINotRootOwned", err)
	}
	if _, err := FindLinuxCLI(root, tray, func(string) bool { return false }, missing); !errors.Is(err, ErrNoCLI) {
		t.Errorf("nothing to run: err = %v, want ErrNoCLI", err)
	}
}
