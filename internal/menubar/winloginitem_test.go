package menubar

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// fakeRunKey is HKCU\...\Run in memory. failSet and failDelete make the
// next writes fail; broken makes reads fail like a value of another type.
type fakeRunKey struct {
	values              map[string]string
	failSet, failDelete error
	broken              bool
	writes              int
}

func newRunKey() *fakeRunKey { return &fakeRunKey{values: map[string]string{}} }

func (k *fakeRunKey) Get(name string) (string, error) {
	v, ok := k.values[name]
	switch {
	case !ok:
		return "", fmt.Errorf("value %s: %w", name, fs.ErrNotExist)
	case k.broken:
		return "", errors.New("unexpected value type")
	}
	return v, nil
}

func (k *fakeRunKey) Set(name, value string) error {
	if k.failSet != nil {
		return k.failSet
	}
	k.writes++
	k.values[name] = value
	return nil
}

func (k *fakeRunKey) Delete(name string) error {
	if k.failDelete != nil {
		return k.failDelete
	}
	if _, ok := k.values[name]; !ok {
		return fmt.Errorf("value %s: %w", name, fs.ErrNotExist)
	}
	k.writes++
	delete(k.values, name)
	return nil
}

const winTrayExe = `C:\Program Files\leakguard\leakguard-tray.exe`

// S1: the Windows login item is the value "leakguard" of the user's Run
// key: the tray's absolute path, quoted, so Windows never splits it.
func TestRunValue(t *testing.T) {
	got, err := RunValue(winTrayExe)
	if want := `"C:\Program Files\leakguard\leakguard-tray.exe"`; err != nil || got != want {
		t.Errorf("RunValue = %s, %v; want %s", got, err, want)
	}
	if got, err := RunValue(`D:\Programas\Ñandú\leakguard-tray.exe`); err != nil || got != `"D:\Programas\Ñandú\leakguard-tray.exe"` {
		t.Errorf("non-ASCII RunValue = %s, %v", got, err)
	}
	for _, bad := range []string{"leakguard-tray.exe", `\\server\share\leakguard-tray.exe`, `C:\a"b\tray.exe`,
		"C:\\a\nb\\tray.exe", `C:\a\..\tray.exe`, "/usr/bin/leakguard-tray", ""} {
		if _, err := RunValue(bad); err == nil {
			t.Errorf("RunValue(%q): no error", bad)
		}
	}
	if RunKeyPath != `Software\Microsoft\Windows\CurrentVersion\Run` || RunValueName != "leakguard" {
		t.Errorf("Run key = %q, value %q", RunKeyPath, RunValueName)
	}
	if got, want := WindowsPrefsPath(filepath.Join("AppData", "Roaming")), filepath.Join("AppData", "Roaming", "leakguard", "menubar.json"); got != want {
		t.Errorf("WindowsPrefsPath = %q, want %q", got, want)
	}
}

// S1: the menu offers "Open at login" when %APPDATA% and the tray path are
// known; there is no move-to-Applications hint on Windows.
func TestWindowsLoginMenu(t *testing.T) {
	appData := t.TempDir()
	if got := WindowsLoginMenu(appData, winTrayExe); got != LoginItemToggle {
		t.Errorf("known paths: %v, want toggle", got)
	}
	for _, tc := range []struct{ appData, exe string }{{"", winTrayExe}, {"relative", winTrayExe}, {appData, ""}, {appData, "tray.exe"}} {
		if got := WindowsLoginMenu(tc.appData, tc.exe); got != LoginItemHidden {
			t.Errorf("WindowsLoginMenu(%q, %q) = %v, want hidden", tc.appData, tc.exe, got)
		}
	}
}

// S1: the Run value follows the user's choice like the macOS LaunchAgent:
// on unless turned off, rewritten when the tray moved, removed when off,
// all or nothing from the menu, and gone with menubar.json on uninstall.
func TestWindowsRunValue(t *testing.T) {
	appData := t.TempDir()
	key := newRunKey()
	want := `"` + winTrayExe + `"`

	on, err := SyncRunValue(key, appData, winTrayExe)
	if err != nil || !on || key.values[RunValueName] != want {
		t.Fatalf("first sync: %v, %v, value %q; want on and %s", on, err, key.values[RunValueName], want)
	}
	writes := key.writes
	if _, err := SyncRunValue(key, appData, winTrayExe); err != nil || key.writes != writes {
		t.Errorf("second sync wrote again (%d writes, %v)", key.writes-writes, err)
	}
	if !RunValuePresent(key, appData) {
		t.Error("RunValuePresent = false after sync")
	}

	moved := `D:\leakguard\leakguard-tray.exe`
	if _, err := SyncRunValue(key, appData, moved); err != nil || key.values[RunValueName] != `"`+moved+`"` {
		t.Errorf("moved tray: value %q, %v", key.values[RunValueName], err)
	}
	key.values[RunValueName] = "garbage"
	key.broken = true
	if _, err := SyncRunValue(key, appData, winTrayExe); err != nil || key.values[RunValueName] != want {
		t.Errorf("unreadable value: %q, %v; want it replaced", key.values[RunValueName], err)
	}
	key.broken = false

	if err := SetRunValue(key, appData, winTrayExe, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := key.values[RunValueName]; ok || RunValuePresent(key, appData) {
		t.Error("turned off: the Run value is still there")
	}
	if on, err := SyncRunValue(key, appData, winTrayExe); err != nil || on {
		t.Errorf("sync after off: %v, %v; want off", on, err)
	}
	if _, ok := key.values[RunValueName]; ok {
		t.Error("sync after off wrote the Run value")
	}

	// All or nothing: a failed write keeps the choice off.
	key.failSet = errors.New("access denied")
	if err := SetRunValue(key, appData, winTrayExe, true); err == nil {
		t.Error("failed write: no error")
	}
	key.failSet = nil
	if on, _ := SyncRunValue(key, appData, winTrayExe); on {
		t.Error("a failed write saved the choice")
	}

	if err := SetRunValue(key, appData, winTrayExe, true); err != nil || key.values[RunValueName] != want {
		t.Fatalf("turned on: %q, %v", key.values[RunValueName], err)
	}
	if err := RemoveRunValue(key, appData); err != nil {
		t.Fatal(err)
	}
	if _, ok := key.values[RunValueName]; ok {
		t.Error("uninstall kept the Run value")
	}
	if _, err := os.Stat(WindowsPrefsPath(appData)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("uninstall kept menubar.json: %v", err)
	}
	if err := RemoveRunValue(key, appData); err != nil {
		t.Errorf("second uninstall: %v", err)
	}
	key.values[RunValueName] = want
	key.failDelete = errors.New("access denied")
	if err := RemoveRunValue(key, appData); err == nil {
		t.Error("failed delete: no error")
	}

	// Unknown paths never touch the Run key.
	other := newRunKey()
	if _, err := SyncRunValue(other, "", winTrayExe); err == nil || other.writes != 0 {
		t.Errorf("unknown %%APPDATA%%: %v, %d writes", err, other.writes)
	}
	if _, err := SyncRunValue(other, appData, "tray.exe"); err != nil || other.writes != 0 {
		t.Errorf("relative tray: %v, %d writes", err, other.writes)
	}
}
