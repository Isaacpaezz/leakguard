package menubar

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
)

// The Windows login item: the value "leakguard" of the user's Run key,
// which opens the tray app when the user signs in. Like the macOS
// LaunchAgent it is written for the next sign-in only, and the user's
// choice lives in %APPDATA%\leakguard\menubar.json (see loginItem).

// RunKeyPath is the user's Run key under HKEY_CURRENT_USER, and
// RunValueName the value leakguard writes in it.
const (
	RunKeyPath   = `Software\Microsoft\Windows\CurrentVersion\Run`
	RunValueName = "leakguard"
)

// RunKey reads and writes string values of one registry key. Get and
// Delete return an error that wraps fs.ErrNotExist for a missing value.
// RegistryRunKey is the real one on Windows.
type RunKey interface {
	Get(name string) (string, error)
	Set(name, value string) error
	Delete(name string) error
}

// RunValue is the Run value that opens exe, the absolute path of the tray
// app: the path in quotes, so Windows never splits it at a space.
func RunValue(exe string) (string, error) {
	if err := checkWindowsPath(exe); err != nil {
		return "", fmt.Errorf("the app executable %w", err)
	}
	return `"` + exe + `"`, nil
}

// WindowsPrefsPath is where the Windows tray app remembers the user's
// choices, under %APPDATA% (appData).
func WindowsPrefsPath(appData string) string {
	return filepath.Join(appData, "leakguard", "menubar.json")
}

// runStore is the Run value as a login item.
type runStore struct{ key RunKey }

func (s runStore) read() ([]byte, bool) {
	v, err := s.key.Get(RunValueName)
	if err != nil {
		return nil, !errors.Is(err, fs.ErrNotExist)
	}
	return []byte(v), true
}

func (s runStore) write(data []byte) error { return s.key.Set(RunValueName, string(data)) }

func (s runStore) remove() error {
	if err := s.key.Delete(RunValueName); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (s runStore) present() bool {
	_, err := s.key.Get(RunValueName)
	return !errors.Is(err, fs.ErrNotExist)
}

// windowsLoginItem is the Run value in key and the choices in appData.
// Any absolute, clean Windows path may open at sign-in: Windows has no
// read-only DMG or translocated copy to guard against.
func windowsLoginItem(key RunKey, appData string) loginItem {
	managed := func(exe string) bool { return checkWindowsPath(exe) == nil }
	return loginItem{
		base:  appData,
		prefs: WindowsPrefsPath(appData),
		store: runStore{key},
		content: func(exe string) ([]byte, error) {
			v, err := RunValue(exe)
			return []byte(v), err
		},
		manages:   managed,
		canChange: managed,
	}
}

// WindowsLoginMenu says what the Windows menu shows for opening exe at
// sign-in: the toggle, or nothing when %APPDATA% or exe is unknown.
func WindowsLoginMenu(appData, exe string) LoginMenuItem {
	if checkHome(appData) != nil || checkWindowsPath(exe) != nil {
		return LoginItemHidden
	}
	return LoginItemToggle
}

// SyncRunValue makes the Run value in key match the user's choice for exe
// (on unless turned off) and returns that choice, like SyncLoginItem.
func SyncRunValue(key RunKey, appData, exe string) (bool, error) {
	return windowsLoginItem(key, appData).sync(exe)
}

// SetRunValue applies and remembers the user's choice from the menu, all
// or nothing, like SetOpenAtLogin.
func SetRunValue(key RunKey, appData, exe string, on bool) error {
	return windowsLoginItem(key, appData).set(exe, on)
}

// RemoveRunValue removes the Run value and menubar.json, for the
// uninstall, like RemoveLoginItem.
func RemoveRunValue(key RunKey, appData string) error {
	return windowsLoginItem(key, appData).remove()
}

// RunValuePresent reports whether the Run value exists.
func RunValuePresent(key RunKey, appData string) bool {
	return windowsLoginItem(key, appData).present()
}
