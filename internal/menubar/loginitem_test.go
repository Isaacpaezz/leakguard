package menubar

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const bundledExe = "/Applications/leakguard.app/Contents/MacOS/leakguard-menubar"

const (
	dmgExe         = "/Volumes/leakguard/leakguard.app/Contents/MacOS/leakguard-menubar"
	translocated   = "/private/var/folders/ab/xyz/T/AppTranslocation/1A2B3C4D-0000-1111-2222-333344445555/d/leakguard.app/Contents/MacOS/leakguard-menubar"
	externalExe    = "/Volumes/Extern/Apps/leakguard.app/Contents/MacOS/leakguard-menubar"
	devExe         = "/Users/me/src/leakguard-menubar"
	dmgBundle      = "/Volumes/leakguard/leakguard.app"
	externalBundle = "/Volumes/Extern/Apps/leakguard.app"
)

// writable says every volume is writable.
func writable(string) (bool, error) { return false, nil }

// readOnlyAt says only the volume holding the bundles in ro is read-only.
func readOnlyAt(ro ...string) ReadOnlyFunc {
	return func(path string) (bool, error) {
		for _, p := range ro {
			if path == p {
				return true, nil
			}
		}
		return false, nil
	}
}

func TestAppBundle(t *testing.T) {
	tests := []struct {
		exe, want string
		ok        bool
	}{
		{bundledExe, "/Applications/leakguard.app", true},
		{"/Users/a b/Downloads/leakguard.app/Contents/MacOS/leakguard-menubar", "/Users/a b/Downloads/leakguard.app", true},
		{"/Users/me/src/leakguard/leakguard-menubar", "", false},
		{"/tmp/go-build123/b001/exe/leakguard-menubar", "", false},
		{"/Applications/leakguard/Contents/MacOS/leakguard-menubar", "", false},
		{"/Applications/leakguard.app/Contents/Resources/leakguard-menubar", "", false},
		{"/Applications/leakguard.app/MacOS/leakguard-menubar", "", false},
		{"Applications/leakguard.app/Contents/MacOS/leakguard-menubar", "", false},
		{"", "", false},
	}
	for _, tc := range tests {
		got, ok := AppBundle(tc.exe)
		if got != tc.want || ok != tc.ok {
			t.Errorf("AppBundle(%q) = %q, %v; want %q, %v", tc.exe, got, ok, tc.want, tc.ok)
		}
	}
}

// S3: the agent runs the app executable at login, in the user's GUI
// session only.
func TestLoginItemPlist(t *testing.T) {
	got, err := LoginItemPlist(bundledExe)
	if err != nil {
		t.Fatal(err)
	}
	want := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>dev.leakguard.menubar</string>
	<key>ProgramArguments</key>
	<array>
		<string>/Applications/leakguard.app/Contents/MacOS/leakguard-menubar</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
</dict>
</plist>
`
	if string(got) != want {
		t.Errorf("plist:\n%s\nwant:\n%s", got, want)
	}
	// The path is XML-escaped and reads back exactly.
	tricky := "/Users/a&b/<x>/it's \"q\"/leakguard.app/Contents/MacOS/leakguard-menubar"
	data, err := LoginItemPlist(tricky)
	if err != nil {
		t.Fatal(err)
	}
	args, ok := programArguments(data)
	if !ok || len(args) != 1 || args[0] != tricky {
		t.Errorf("ProgramArguments = %q, %v; want [%q]", args, ok, tricky)
	}
	if runtime.GOOS == "darwin" {
		f := filepath.Join(t.TempDir(), "agent.plist")
		os.WriteFile(f, data, 0o644)
		if out, err := exec.Command("/usr/bin/plutil", "-lint", f).CombinedOutput(); err != nil {
			t.Errorf("plutil -lint: %v\n%s", err, out)
		}
	}
}

func TestLoginItemPlistRejects(t *testing.T) {
	for _, exe := range []string{"", "relative/leakguard-menubar", "/a\nb/leakguard-menubar", "/a\x00b", "/bad\xffutf8"} {
		if data, err := LoginItemPlist(exe); err == nil || data != nil {
			t.Errorf("LoginItemPlist(%q) = %q, %v; want an error", exe, data, err)
		}
	}
}

// S3: write when missing or pointing elsewhere (the app moved), keep when
// current, remove when turned off, and never touch it outside a bundle.
func TestDecideLoginItem(t *testing.T) {
	current, _ := LoginItemPlist(bundledExe)
	moved, _ := LoginItemPlist("/Users/me/Downloads/leakguard.app/Contents/MacOS/leakguard-menubar")
	tests := []struct {
		name   string
		exe    string
		wanted bool
		data   []byte
		exists bool
		want   LoginAction
	}{
		{"first launch", bundledExe, true, nil, false, LoginWrite},
		{"already current", bundledExe, true, current, true, LoginKeep},
		{"app moved", bundledExe, true, moved, true, LoginWrite},
		{"damaged file", bundledExe, true, []byte("garbage"), true, LoginWrite},
		{"turned off, present", bundledExe, false, current, true, LoginRemove},
		{"turned off, absent", bundledExe, false, nil, false, LoginKeep},
		{"development build", "/Users/me/src/leakguard-menubar", true, nil, false, LoginKeep},
		{"development build with an agent", "/Users/me/src/leakguard-menubar", true, moved, true, LoginKeep},
		{"development build turned off", "/Users/me/src/leakguard-menubar", false, current, true, LoginKeep},
		{"unsafe path", "/Apps/a\nb.app/Contents/MacOS/leakguard-menubar", true, nil, false, LoginKeep},
	}
	for _, tc := range tests {
		if got := DecideLoginItem(tc.exe, tc.wanted, tc.data, tc.exists); got != tc.want {
			t.Errorf("%s: DecideLoginItem = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func readOrNil(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return data
}

// S3: on by default, written on launch from a bundle, remembered when
// turned off, rewritten when the app moved; all inside a temp HOME.
func TestSyncLoginItem(t *testing.T) {
	home := t.TempDir()
	agent := LoginItemPath(home)
	if want := filepath.Join(home, "Library", "LaunchAgents", "dev.leakguard.menubar.plist"); agent != want {
		t.Fatalf("LoginItemPath = %q, want %q", agent, want)
	}
	if want := filepath.Join(home, "Library", "Application Support", "leakguard", "menubar.json"); PrefsPath(home) != want {
		t.Fatalf("PrefsPath = %q, want %q", PrefsPath(home), want)
	}

	// A development build writes nothing.
	on, err := SyncLoginItem(home, "/Users/me/src/leakguard-menubar", writable)
	if err != nil || !on {
		t.Fatalf("dev SyncLoginItem = %v, %v; want true, nil", on, err)
	}
	if readOrNil(t, agent) != nil || readOrNil(t, PrefsPath(home)) != nil {
		t.Fatal("a development build wrote the agent or the preferences")
	}

	// First launch from the bundle: on by default, written.
	on, err = SyncLoginItem(home, bundledExe, writable)
	if err != nil || !on {
		t.Fatalf("SyncLoginItem = %v, %v; want true, nil", on, err)
	}
	want, _ := LoginItemPlist(bundledExe)
	if got := readOrNil(t, agent); !bytes.Equal(got, want) {
		t.Fatalf("agent:\n%s\nwant:\n%s", got, want)
	}
	if fi, err := os.Stat(agent); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("agent mode = %v, %v; want 0644", fi.Mode().Perm(), err)
	}

	// The app moved: rewritten with the new path.
	movedExe := "/Users/me/Applications/leakguard.app/Contents/MacOS/leakguard-menubar"
	if on, err = SyncLoginItem(home, movedExe, writable); err != nil || !on {
		t.Fatalf("moved SyncLoginItem = %v, %v", on, err)
	}
	if args, _ := programArguments(readOrNil(t, agent)); len(args) != 1 || args[0] != movedExe {
		t.Errorf("after the move ProgramArguments = %q, want [%q]", args, movedExe)
	}

	// Turned off from the menu: removed and remembered.
	if err := SetOpenAtLogin(home, movedExe, false, writable); err != nil {
		t.Fatal(err)
	}
	if readOrNil(t, agent) != nil {
		t.Error("the agent is still there after turning it off")
	}
	if got := strings.TrimSpace(string(readOrNil(t, PrefsPath(home)))); got != `{"open_at_login":false}` {
		t.Errorf("menubar.json = %s", got)
	}
	if on, err = SyncLoginItem(home, movedExe, writable); err != nil || on {
		t.Fatalf("SyncLoginItem after off = %v, %v; want false, nil", on, err)
	}
	if readOrNil(t, agent) != nil {
		t.Error("the next launch wrote the agent although it was turned off")
	}

	// Turned on again: written at once.
	if err := SetOpenAtLogin(home, movedExe, true, writable); err != nil {
		t.Fatal(err)
	}
	if readOrNil(t, agent) == nil || LoadPrefs(home).OpenAtLogin != true {
		t.Error("turning it on did not write the agent or the preference")
	}

	// Uninstall removes both, and is fine when they are already gone.
	if err := RemoveLoginItem(home); err != nil {
		t.Fatal(err)
	}
	if readOrNil(t, agent) != nil || readOrNil(t, PrefsPath(home)) != nil {
		t.Error("RemoveLoginItem left the agent or menubar.json")
	}
	if err := RemoveLoginItem(home); err != nil {
		t.Errorf("second RemoveLoginItem = %v", err)
	}
}

// A damaged menubar.json reads as the default: open at login.
func TestLoadPrefsDefaults(t *testing.T) {
	home := t.TempDir()
	if !LoadPrefs(home).OpenAtLogin {
		t.Error("missing menubar.json: want open at login")
	}
	os.MkdirAll(filepath.Dir(PrefsPath(home)), 0o700)
	os.WriteFile(PrefsPath(home), []byte("{not json"), 0o600)
	if !LoadPrefs(home).OpenAtLogin {
		t.Error("damaged menubar.json: want open at login")
	}
	os.WriteFile(PrefsPath(home), []byte(`{}`), 0o600)
	if !LoadPrefs(home).OpenAtLogin {
		t.Error("empty menubar.json: want open at login")
	}
}

// Setting the preference outside a bundle saves the choice but writes no
// agent.
func TestSetOpenAtLoginOutsideBundle(t *testing.T) {
	home := t.TempDir()
	if err := SetOpenAtLogin(home, "/Users/me/src/leakguard-menubar", true, writable); err != nil {
		t.Fatal(err)
	}
	if readOrNil(t, LoginItemPath(home)) != nil {
		t.Error("a development build wrote the agent")
	}
}

// Without a known, absolute home folder nothing is written or removed
// relative to the current folder.
func TestLoginItemNeedsAbsoluteHome(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, home := range []string{"", "relative"} {
		if _, err := SyncLoginItem(home, bundledExe, writable); err == nil {
			t.Errorf("SyncLoginItem(%q) = nil error", home)
		}
		if err := SetOpenAtLogin(home, bundledExe, true, writable); err == nil {
			t.Errorf("SetOpenAtLogin(%q) = nil error", home)
		}
		if err := RemoveLoginItem(home); err == nil {
			t.Errorf("RemoveLoginItem(%q) = nil error", home)
		}
	}
	if entries, _ := os.ReadDir("."); len(entries) != 0 {
		t.Errorf("wrote %d entries in the current folder", len(entries))
	}
}

// S3: the login item is offered only where it survives a restart: a .app
// bundle that is neither translocated nor on a read-only volume such as the
// DMG. There the menu shows a hint instead; a development build shows
// nothing.
func TestLoginMenu(t *testing.T) {
	failing := func(string) (bool, error) { return false, errors.New("statfs: no such file or directory") }
	tests := []struct {
		name     string
		exe      string
		readOnly ReadOnlyFunc
		want     LoginMenuItem
	}{
		{"Applications", bundledExe, writable, LoginItemToggle},
		{"writable external disk", externalExe, readOnlyAt(dmgBundle), LoginItemToggle},
		{"read-only DMG", dmgExe, readOnlyAt(dmgBundle), LoginItemMoveHint},
		{"translocated", translocated, writable, LoginItemMoveHint},
		{"volume unknown", bundledExe, failing, LoginItemMoveHint},
		{"development build", devExe, writable, LoginItemHidden},
	}
	for _, tc := range tests {
		if got := LoginMenu(tc.exe, tc.readOnly); got != tc.want {
			t.Errorf("%s: LoginMenu = %v, want %v", tc.name, got, tc.want)
		}
		if got := CanOpenAtLogin(tc.exe, tc.readOnly); got != (tc.want == LoginItemToggle) {
			t.Errorf("%s: CanOpenAtLogin = %v", tc.name, got)
		}
	}
	// The volume checked is the bundle's.
	var asked []string
	LoginMenu(externalExe, func(p string) (bool, error) { asked = append(asked, p); return false, nil })
	if len(asked) != 1 || asked[0] != externalBundle {
		t.Errorf("readOnly asked about %q, want [%q]", asked, externalBundle)
	}
}

// S3: running from the DMG or translocated never writes, rewrites or
// removes the login item, so an agent for the copy in Applications stays.
func TestSyncLoginItemNeverFromDMG(t *testing.T) {
	ro := readOnlyAt(dmgBundle)
	for _, exe := range []string{dmgExe, translocated} {
		home := t.TempDir()
		on, err := SyncLoginItem(home, exe, ro)
		if err != nil || !on {
			t.Fatalf("%s: SyncLoginItem = %v, %v; want true, nil", exe, on, err)
		}
		if readOrNil(t, LoginItemPath(home)) != nil {
			t.Fatalf("%s: wrote the login item", exe)
		}
		if err := SetOpenAtLogin(home, exe, true, ro); err != nil {
			t.Fatal(err)
		}
		if readOrNil(t, LoginItemPath(home)) != nil {
			t.Fatalf("%s: SetOpenAtLogin wrote the login item", exe)
		}

		// The copy in Applications wrote its agent; the DMG copy keeps it.
		if _, err := SyncLoginItem(home, bundledExe, ro); err != nil {
			t.Fatal(err)
		}
		want := readOrNil(t, LoginItemPath(home))
		if _, err := SyncLoginItem(home, exe, ro); err != nil {
			t.Fatal(err)
		}
		if err := SetOpenAtLogin(home, exe, false, ro); err != nil {
			t.Fatal(err)
		}
		if got := readOrNil(t, LoginItemPath(home)); want == nil || !bytes.Equal(got, want) {
			t.Errorf("%s: agent changed to:\n%s\nwant:\n%s", exe, got, want)
		}
	}
	// A writable external disk is fine.
	home := t.TempDir()
	if _, err := SyncLoginItem(home, externalExe, ro); err != nil {
		t.Fatal(err)
	}
	if args, _ := programArguments(readOrNil(t, LoginItemPath(home))); len(args) != 1 || args[0] != externalExe {
		t.Errorf("external disk: ProgramArguments = %q, want [%q]", args, externalExe)
	}
}
