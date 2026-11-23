package menubar

import (
	"os"
	"path/filepath"
	"testing"
)

// S1: the Linux login item lives in the XDG config folder.
func TestConfigDir(t *testing.T) {
	tests := []struct {
		env  map[string]string
		home string
		want string
	}{
		{map[string]string{}, "/home/ana", "/home/ana/.config"},
		{map[string]string{"XDG_CONFIG_HOME": "/home/ana/cfg"}, "/home/ana", "/home/ana/cfg"},
		{map[string]string{"XDG_CONFIG_HOME": "relative/cfg"}, "/home/ana", "/home/ana/.config"},
		{map[string]string{"XDG_CONFIG_HOME": "/srv/cfg"}, "", "/srv/cfg"},
		{map[string]string{}, "", ""},
		{map[string]string{}, "relative", ""},
	}
	for _, tc := range tests {
		if got := ConfigDir(envOf(tc.env), tc.home); got != tc.want {
			t.Errorf("ConfigDir(%v, %q) = %q, want %q", tc.env, tc.home, got, tc.want)
		}
	}
	if got, want := AutostartPath("/home/ana/.config"), "/home/ana/.config/autostart/leakguard.desktop"; got != want {
		t.Errorf("AutostartPath = %q, want %q", got, want)
	}
	if got, want := LinuxPrefsPath("/home/ana/.config"), "/home/ana/.config/leakguard/menubar.json"; got != want {
		t.Errorf("LinuxPrefsPath = %q, want %q", got, want)
	}
}

func TestAutostartEntry(t *testing.T) {
	got, err := AutostartEntry("/usr/bin/leakguard-menubar")
	if err != nil {
		t.Fatal(err)
	}
	want := `[Desktop Entry]
Type=Application
Name=leakguard
Comment=Shows whether your chosen services are protected
Exec="/usr/bin/leakguard-menubar"
Terminal=false
X-GNOME-Autostart-enabled=true
`
	if string(got) != want {
		t.Errorf("entry =\n%s\nwant\n%s", got, want)
	}
	tricky, err := AutostartEntry(`/opt/my "app"/a$b` + "`c`" + `\d%e/leakguard-menubar`)
	if err != nil {
		t.Fatal(err)
	}
	wantExec := `Exec="/opt/my \\"app\\"/a\\$b\\` + "`c" + `\\` + "`" + `\\\\d%%e/leakguard-menubar"`
	if !containsLine(string(tricky), wantExec) {
		t.Errorf("tricky entry =\n%s\nwant line %s", tricky, wantExec)
	}
	for _, bad := range []string{"leakguard-menubar", "/opt/a\nb", "/opt/\xff"} {
		if _, err := AutostartEntry(bad); err == nil {
			t.Errorf("AutostartEntry(%q): no error", bad)
		}
	}
}

func containsLine(s, line string) bool {
	for len(s) > 0 {
		i := 0
		for i < len(s) && s[i] != '\n' {
			i++
		}
		if s[:i] == line {
			return true
		}
		if i == len(s) {
			break
		}
		s = s[i+1:]
	}
	return false
}

// S1: open at login on Linux: on by default, the choice is remembered, and
// the uninstall removes both files.
func TestAutostart(t *testing.T) {
	const exe = "/usr/bin/leakguard-menubar"
	dir := t.TempDir()
	if got := AutostartMenu(dir, exe); got != LoginItemToggle {
		t.Errorf("AutostartMenu = %v, want toggle", got)
	}
	if got := AutostartMenu("", exe); got != LoginItemHidden {
		t.Errorf("AutostartMenu without a config folder = %v, want hidden", got)
	}
	if got := AutostartMenu(dir, "leakguard-menubar"); got != LoginItemHidden {
		t.Errorf("AutostartMenu for a relative executable = %v, want hidden", got)
	}
	if AutostartPresent(dir) {
		t.Fatal("present before any sync")
	}
	on, err := SyncAutostart(dir, exe)
	if err != nil || !on {
		t.Fatalf("SyncAutostart = %v, %v; want true, nil", on, err)
	}
	want, _ := AutostartEntry(exe)
	data, err := os.ReadFile(AutostartPath(dir))
	if err != nil || string(data) != string(want) {
		t.Fatalf("autostart file = %q, %v; want %q", data, err, want)
	}
	if !AutostartPresent(dir) {
		t.Error("not present after sync")
	}

	if err := SetAutostart(dir, exe, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(AutostartPath(dir)); !os.IsNotExist(err) {
		t.Errorf("autostart file after turning it off: %v", err)
	}
	if on, err := SyncAutostart(dir, exe); err != nil || on {
		t.Errorf("SyncAutostart after turning it off = %v, %v; want false, nil", on, err)
	}
	if _, err := os.Stat(AutostartPath(dir)); !os.IsNotExist(err) {
		t.Errorf("sync brought the autostart file back: %v", err)
	}
	if info, err := os.Stat(LinuxPrefsPath(dir)); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("choice file: %v, %v; want mode 0600", info, err)
	}

	if err := SetAutostart(dir, exe, true); err != nil {
		t.Fatal(err)
	}
	if err := RemoveAutostart(dir); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{AutostartPath(dir), LinuxPrefsPath(dir), filepath.Dir(LinuxPrefsPath(dir))} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s after RemoveAutostart: %v", p, err)
		}
	}
	if AutostartPresent(dir) {
		t.Error("present after RemoveAutostart")
	}
	if _, err := SyncAutostart("", exe); err == nil {
		t.Error("SyncAutostart without a config folder: no error")
	}
	if err := RemoveAutostart("relative"); err == nil {
		t.Error("RemoveAutostart with a relative folder: no error")
	}
}
