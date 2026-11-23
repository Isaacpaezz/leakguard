package menubar

import (
	"path/filepath"
	"strings"
)

// The Linux login item: an XDG autostart entry that opens the tray app when
// the user logs in to the desktop. Like the macOS LaunchAgent it is written
// for the next login only, and the user's choice lives next to it in
// menubar.json (see loginItem).

// AutostartName is the file name of the autostart entry.
const AutostartName = "leakguard.desktop"

// ConfigDir is the user's XDG config folder: $XDG_CONFIG_HOME when it is
// absolute (the XDG spec ignores a relative one), otherwise home/.config.
// It is "" when neither is known, so nothing is ever written relative to
// the current folder.
func ConfigDir(getenv func(string) string, home string) string {
	if dir := getenv("XDG_CONFIG_HOME"); filepath.IsAbs(dir) {
		return dir
	}
	if !filepath.IsAbs(home) {
		return ""
	}
	return filepath.Join(home, ".config")
}

// AutostartPath is the autostart entry in the config folder configDir.
func AutostartPath(configDir string) string {
	return filepath.Join(configDir, "autostart", AutostartName)
}

// LinuxPrefsPath is where the Linux tray app remembers the user's choices.
func LinuxPrefsPath(configDir string) string {
	return filepath.Join(configDir, "leakguard", "menubar.json")
}

// AutostartEntry is the desktop entry that runs exe, the absolute path of
// the tray app, when the user logs in. exe is quoted as one argument of the
// Exec key (Desktop Entry Specification: quoting, then the string escapes).
func AutostartEntry(exe string) ([]byte, error) {
	if err := checkExe(exe); err != nil {
		return nil, err
	}
	return []byte(`[Desktop Entry]
Type=Application
Name=leakguard
Comment=Shows whether your chosen services are protected
Exec=` + desktopExecArg(exe) + `
Terminal=false
X-GNOME-Autostart-enabled=true
`), nil
}

// desktopExecArg quotes s as one argument of a desktop entry's Exec key:
// inside double quotes, ", `, $ and \ get a backslash and % is doubled; then
// every backslash is doubled again, because Exec is a string value.
func desktopExecArg(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '`', '$', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '%':
			b.WriteString("%%")
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return strings.ReplaceAll(b.String(), `\`, `\\`)
}

// linuxLoginItem is the autostart entry and the choices in configDir. Any
// absolute, clean executable may open at login: Linux has no read-only DMG
// or translocated copy to guard against.
func linuxLoginItem(configDir string) loginItem {
	managed := func(exe string) bool { return filepath.IsAbs(exe) && filepath.Clean(exe) == exe }
	return loginItem{
		base:      configDir,
		path:      AutostartPath(configDir),
		prefs:     LinuxPrefsPath(configDir),
		content:   AutostartEntry,
		manages:   managed,
		canChange: managed,
	}
}

// AutostartMenu says what the Linux menu shows for opening exe at login:
// the toggle, or nothing when the config folder or exe is unknown.
func AutostartMenu(configDir, exe string) LoginMenuItem {
	if checkHome(configDir) != nil || !linuxLoginItem(configDir).manages(exe) {
		return LoginItemHidden
	}
	return LoginItemToggle
}

// SyncAutostart makes the autostart entry match the user's choice for exe
// (on unless turned off) and returns that choice, like SyncLoginItem.
func SyncAutostart(configDir, exe string) (bool, error) {
	return linuxLoginItem(configDir).sync(exe)
}

// SetAutostart applies and remembers the user's choice from the menu, all or
// nothing, like SetOpenAtLogin.
func SetAutostart(configDir, exe string, on bool) error {
	return linuxLoginItem(configDir).set(exe, on)
}

// RemoveAutostart removes the autostart entry and menubar.json, for the
// uninstall, like RemoveLoginItem.
func RemoveAutostart(configDir string) error {
	return linuxLoginItem(configDir).remove()
}

// AutostartPresent reports whether the autostart entry exists.
func AutostartPresent(configDir string) bool {
	return linuxLoginItem(configDir).present()
}
