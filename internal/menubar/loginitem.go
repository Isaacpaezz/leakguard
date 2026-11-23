package menubar

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"
)

// The login item: a per-user LaunchAgent that opens the app at login. It
// works without a Developer ID, unlike SMAppService. The app writes it; it
// never loads it with launchctl, so launchd starts the app at the next login
// and no second copy starts now.

// LoginItemLabel is the LaunchAgent's label, the same as the bundle ID.
const LoginItemLabel = "dev.leakguard.menubar"

// LoginItemPath is the LaunchAgent plist in the home folder home.
func LoginItemPath(home string) string {
	return filepath.Join(home, "Library", "LaunchAgents", LoginItemLabel+".plist")
}

// PrefsPath is where the app remembers the user's choices.
func PrefsPath(home string) string {
	return filepath.Join(home, "Library", "Application Support", "leakguard", "menubar.json")
}

// AppBundle returns the .app bundle whose Contents/MacOS holds exe, an
// absolute path. A development build outside a bundle has none.
func AppBundle(exe string) (string, bool) {
	if !filepath.IsAbs(exe) || filepath.Clean(exe) != exe {
		return "", false
	}
	macos := filepath.Dir(exe)
	contents := filepath.Dir(macos)
	bundle := filepath.Dir(contents)
	if filepath.Base(macos) != "MacOS" || filepath.Base(contents) != "Contents" ||
		!strings.HasSuffix(bundle, ".app") || filepath.Base(bundle) == ".app" {
		return "", false
	}
	return bundle, true
}

// LoginItemPlist is the LaunchAgent that runs exe, the absolute path of the
// app executable, when the user logs in to the Mac's desktop.
func LoginItemPlist(exe string) ([]byte, error) {
	if err := checkExe(exe); err != nil {
		return nil, err
	}
	var path bytes.Buffer
	if err := xml.EscapeText(&path, []byte(exe)); err != nil {
		return nil, err
	}
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + LoginItemLabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + path.String() + `</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
</dict>
</plist>
`), nil
}

// checkExe refuses an app executable path that a login item cannot hold
// safely: it must be absolute, valid UTF-8 and without control characters.
func checkExe(exe string) error {
	switch {
	case !filepath.IsAbs(exe):
		return errors.New("the app executable needs an absolute path")
	case !utf8.ValidString(exe):
		return errors.New("the path of the app executable is not valid UTF-8")
	case strings.ContainsFunc(exe, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return errors.New("the path of the app executable contains control characters")
	}
	return nil
}

// loginItem is where one system keeps the login item and the app's
// choices, and how it writes the login item. The macOS LaunchAgent and the
// Linux autostart entry share every rule below.
type loginItem struct {
	// base is the folder both files live under (the home folder, or the XDG
	// config folder); it must be absolute.
	base, path, prefs string
	// content renders the login item that runs exe.
	content func(exe string) ([]byte, error)
	// manages reports whether the login item may be touched for exe at all
	// (DecideLoginItem); canChange whether it may change now (apply).
	manages, canChange func(exe string) bool
}

func macLoginItem(home string, readOnly ReadOnlyFunc) loginItem {
	return loginItem{
		base:    home,
		path:    LoginItemPath(home),
		prefs:   PrefsPath(home),
		content: LoginItemPlist,
		manages: func(exe string) bool {
			_, ok := AppBundle(exe)
			return ok
		},
		canChange: func(exe string) bool { return CanOpenAtLogin(exe, readOnly) },
	}
}

// LoginAction is what to do with the LaunchAgent.
type LoginAction int

const (
	// LoginKeep leaves it as it is.
	LoginKeep LoginAction = iota
	// LoginWrite writes it: it is missing or runs another path.
	LoginWrite
	// LoginRemove removes it: the user turned it off.
	LoginRemove
)

func (a LoginAction) String() string {
	switch a {
	case LoginWrite:
		return "write"
	case LoginRemove:
		return "remove"
	}
	return "keep"
}

// DecideLoginItem says what to do with the LaunchAgent for the app
// executable exe, when the user wants it (wanted) and the current file
// holds data (exists). Outside a .app bundle (a development build) it never
// touches it; otherwise it writes it when it is missing or differs, for
// example because the app moved, and removes it when the user turned it off.
func DecideLoginItem(exe string, wanted bool, data []byte, exists bool) LoginAction {
	return macLoginItem("", nil).decide(exe, wanted, data, exists)
}

func (li loginItem) decide(exe string, wanted bool, data []byte, exists bool) LoginAction {
	if !li.manages(exe) {
		return LoginKeep
	}
	if !wanted {
		if exists {
			return LoginRemove
		}
		return LoginKeep
	}
	want, err := li.content(exe)
	if err != nil {
		return LoginKeep
	}
	if exists && bytes.Equal(data, want) {
		return LoginKeep
	}
	return LoginWrite
}

// Prefs are the menu-bar app's own choices.
type Prefs struct {
	// OpenAtLogin: open the app at login. On unless the user turned it off.
	OpenAtLogin bool
}

type prefsFile struct {
	OpenAtLogin *bool `json:"open_at_login,omitempty"`
}

// maxPrefs bounds how much of menubar.json is read, and maxLoginItem how
// much of the LaunchAgent.
const (
	maxPrefs     = 16 << 10
	maxLoginItem = 16 << 10
)

// LoadPrefs reads the choices in home. A missing or damaged file, or
// anything that is not a regular file, reads as the defaults.
func LoadPrefs(home string) Prefs {
	return macLoginItem(home, nil).loadPrefs()
}

func (li loginItem) loadPrefs() Prefs {
	p := Prefs{OpenAtLogin: true}
	data, err := readRegular(li.prefs, maxPrefs)
	if err != nil {
		return p
	}
	var f prefsFile
	if json.Unmarshal(data, &f) == nil && f.OpenAtLogin != nil {
		p.OpenAtLogin = *f.OpenAtLogin
	}
	return p
}

// SavePrefs writes the choices in home, readable only by the user.
func SavePrefs(home string, p Prefs) error {
	return macLoginItem(home, nil).savePrefs(p)
}

func (li loginItem) savePrefs(p Prefs) error {
	if err := checkHome(li.base); err != nil {
		return err
	}
	data, err := json.Marshal(prefsFile{OpenAtLogin: &p.OpenAtLogin})
	if err != nil {
		return err
	}
	path := li.prefs
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'), 0o600)
}

// SyncLoginItem makes the LaunchAgent in home match the user's choice for
// the app executable exe (see DecideLoginItem) and returns that choice.
// When the app runs from where a login item would not survive a restart
// (see LoginMenu), the LaunchAgent is left as it is: it may open the copy
// in Applications.
func SyncLoginItem(home, exe string, readOnly ReadOnlyFunc) (bool, error) {
	return macLoginItem(home, readOnly).sync(exe)
}

func (li loginItem) sync(exe string) (bool, error) {
	if err := checkHome(li.base); err != nil {
		return true, err
	}
	on := li.loadPrefs().OpenAtLogin
	return on, li.apply(exe, on)
}

// apply makes the LaunchAgent in home match on for the app
// executable exe (see DecideLoginItem), unless the app runs from where a
// login item would not survive a restart (see LoginMenu).
func (li loginItem) apply(exe string, on bool) error {
	if !li.canChange(exe) {
		return nil
	}
	path := li.path
	data, err := readRegular(path, maxLoginItem)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		// Unreadable, too big or not a regular file: replace it when it
		// should be there.
		data, exists = nil, true
	}
	switch li.decide(exe, on, data, exists) {
	case LoginWrite:
		want, err := li.content(exe)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		return writeFileAtomic(path, want, 0o644)
	case LoginRemove:
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// SetOpenAtLogin applies the user's choice from the menu at once (see
// SyncLoginItem) and remembers it. It is all or nothing: the LaunchAgent
// changes first and the choice is saved only when that worked; when saving
// fails, the LaunchAgent goes back to the previous choice. On an error the
// agent and the saved choice stay as they were, so the menu keeps its old
// checkbox. No password is needed: everything is in the user's home folder.
func SetOpenAtLogin(home, exe string, on bool, readOnly ReadOnlyFunc) error {
	return macLoginItem(home, readOnly).set(exe, on)
}

func (li loginItem) set(exe string, on bool) error {
	if err := checkHome(li.base); err != nil {
		return err
	}
	p := li.loadPrefs()
	was := p.OpenAtLogin
	if err := li.apply(exe, on); err != nil {
		return err
	}
	p.OpenAtLogin = on
	if err := li.savePrefs(p); err != nil {
		return errors.Join(err, li.apply(exe, was))
	}
	return nil
}

// RemoveLoginItem removes the LaunchAgent and menubar.json, for the
// uninstall. Files already gone are fine.
func RemoveLoginItem(home string) error {
	return macLoginItem(home, nil).remove()
}

func (li loginItem) remove() error {
	if err := checkHome(li.base); err != nil {
		return err
	}
	var errs []error
	for _, p := range []string{li.path, li.prefs} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	// The leakguard folder goes too when nothing else is in it.
	os.Remove(filepath.Dir(li.prefs))
	return errors.Join(errs...)
}

// checkHome refuses an unknown or relative home folder, so nothing is ever
// written relative to the current folder.
func checkHome(home string) error {
	if !filepath.IsAbs(home) {
		return errors.New("the home folder is unknown")
	}
	return nil
}

// writeFileAtomic replaces path with data: a reader sees the old file or the
// new one, never half of it.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".leakguard-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ReadOnlyFunc reports whether path is on a read-only volume.
// ReadOnlyVolume is the real one.
type ReadOnlyFunc func(path string) (bool, error)

// LoginMenuItem is what the menu shows for opening at login.
type LoginMenuItem int

const (
	// LoginItemHidden: nothing, for a development build outside a bundle.
	LoginItemHidden LoginMenuItem = iota
	// LoginItemToggle: the "Open at login" checkbox.
	LoginItemToggle
	// LoginItemMoveHint: a disabled line asking the user to move the app
	// to Applications, because it runs from somewhere that a restart does
	// not keep (the DMG, or a translocated copy).
	LoginItemMoveHint
)

func (m LoginMenuItem) String() string {
	switch m {
	case LoginItemToggle:
		return "toggle"
	case LoginItemMoveHint:
		return "move hint"
	}
	return "hidden"
}

// LoginMenu says what the menu shows for opening the app executable exe at
// login. A login item only makes sense for a bundle that is still there
// after a restart: never one that macOS translocated (it runs from a random
// read-only copy) or one on a read-only volume such as the mounted DMG.
// When readOnly cannot tell, the answer is the hint: a login item that
// points nowhere would only hide the icon after a restart. Writable
// external disks are fine.
func LoginMenu(exe string, readOnly ReadOnlyFunc) LoginMenuItem {
	bundle, ok := AppBundle(exe)
	if !ok {
		return LoginItemHidden
	}
	if strings.Contains(bundle, "/AppTranslocation/") {
		return LoginItemMoveHint
	}
	if ro, err := readOnly(bundle); err != nil || ro {
		return LoginItemMoveHint
	}
	return LoginItemToggle
}

// CanOpenAtLogin reports whether the LaunchAgent may be written, removed or
// rewritten for the app executable exe (see LoginMenu).
func CanOpenAtLogin(exe string, readOnly ReadOnlyFunc) bool {
	return LoginMenu(exe, readOnly) == LoginItemToggle
}

// readRegular reads path when it is a regular file of at most max bytes.
// The non-blocking open returns at once even for a FIFO without a writer,
// which is then refused, so a launch never hangs on it.
func readRegular(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return data, nil
}

// MustMoveToApplications reports whether the app executable exe runs from
// where it should not be set up or uninstalled: the mounted DMG or a copy
// macOS translocated (see LoginMenu). There the embedded command cannot be
// prepared and the login item would point nowhere after a restart, so the
// user is asked to move the app to Applications first.
func MustMoveToApplications(exe string, readOnly ReadOnlyFunc) bool {
	return LoginMenu(exe, readOnly) == LoginItemMoveHint
}

// GuardMoveToApplications shows, when MustMoveToApplications says so, one
// plain dialog asking the user to move the app to Applications, and returns
// true: the caller then does nothing else. Otherwise it shows nothing and
// returns false.
func GuardMoveToApplications(l Lang, d Dialogs, exe string, readOnly ReadOnlyFunc) bool {
	if !MustMoveToApplications(exe, readOnly) {
		return false
	}
	d.Ask(Dialog{
		Title:   l.Text(msgAppTitle),
		Text:    l.Text(msgMoveToApplicationsFirst),
		Buttons: []string{l.Text(msgButtonUnderstood)},
		Default: 0,
		Cancel:  -1,
	})
	return true
}

// LoginItemPresent reports whether the LaunchAgent exists in home.
func LoginItemPresent(home string) bool {
	return macLoginItem(home, nil).present()
}

func (li loginItem) present() bool {
	if checkHome(li.base) != nil {
		return false
	}
	_, err := os.Lstat(li.path)
	return err == nil
}
