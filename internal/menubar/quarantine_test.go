package menubar

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const bundledCLI = "/Applications/leakguard.app/Contents/MacOS/leakguard"

// S6: only the CLI inside the running app's own bundle, and only when it is
// quarantined.
func TestShouldClearQuarantine(t *testing.T) {
	tests := []struct {
		name        string
		exe, cli    string
		quarantined bool
		want        bool
	}{
		{"bundled CLI, quarantined", bundledExe, bundledCLI, true, true},
		{"bundled CLI, not quarantined", bundledExe, bundledCLI, false, false},
		{"installed root copy", bundledExe, InstalledCLI, true, false},
		{"CLI of another bundle", bundledExe, "/Users/me/Downloads/leakguard.app/Contents/MacOS/leakguard", true, false},
		{"other file in the bundle", bundledExe, "/Applications/leakguard.app/Contents/Resources/leakguard", true, false},
		{"development build", "/Users/me/src/leakguard-menubar", "/Users/me/src/leakguard", true, false},
		{"unknown executable", "", bundledCLI, true, false},
		{"relative CLI", bundledExe, "leakguard", true, false},
		{"path with dot-dot", bundledExe, "/Applications/leakguard.app/Contents/MacOS/../MacOS/leakguard", true, false},
	}
	for _, tc := range tests {
		if got := ShouldClearQuarantine(tc.exe, tc.cli, tc.quarantined); got != tc.want {
			t.Errorf("%s: ShouldClearQuarantine = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestClearQuarantineArgs(t *testing.T) {
	got := ClearQuarantineArgs("/Users/a b/leakguard.app/Contents/MacOS/leakguard")
	want := []string{"-s", "-d", "com.apple.quarantine", "/Users/a b/leakguard.app/Contents/MacOS/leakguard"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("args = %q, want %q", got, want)
	}
}

// Reading the mark never follows a symlink either.
func TestReadQuarantineArgs(t *testing.T) {
	got := ReadQuarantineArgs("/Users/a b/leakguard.app/Contents/MacOS/leakguard")
	want := []string{"-s", "-p", "com.apple.quarantine", "/Users/a b/leakguard.app/Contents/MacOS/leakguard"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("args = %q, want %q", got, want)
	}
}

// S6: xattr's answer: the mark is there, it is not ("No such xattr"), or
// it could not be read, which is ErrQuarantined, explained in plain words.
func TestQuarantineCheck(t *testing.T) {
	exit1 := errors.New("exit status 1")
	tests := []struct {
		name    string
		stderr  string
		err     error
		want    bool
		wantErr bool
	}{
		{"marked", "", nil, true, false},
		{"not marked", "xattr: /Applications/leakguard.app/Contents/MacOS/leakguard: No such xattr: com.apple.quarantine\n", exit1, false, false},
		{"permission denied", "xattr: [Errno 1] Operation not permitted: '/Applications/leakguard.app/Contents/MacOS/leakguard'\n", exit1, false, true},
		{"no such file", "xattr: No such file: /Applications/leakguard.app/Contents/MacOS/leakguard\n", exit1, false, true},
		{"xattr missing", "", errors.New("exec: \"/usr/bin/xattr\": stat /usr/bin/xattr: no such file or directory"), false, true},
		{"other attribute missing", "xattr: /x: No such xattr: com.apple.provenance\n", exit1, false, true},
	}
	for _, tc := range tests {
		got, err := QuarantineCheck(tc.stderr, tc.err)
		if got != tc.want {
			t.Errorf("%s: quarantined = %v, want %v", tc.name, got, tc.want)
		}
		if tc.wantErr != (err != nil) || err != nil && !errors.Is(err, ErrQuarantined) {
			t.Errorf("%s: err = %v, want ErrQuarantined: %v", tc.name, err, tc.wantErr)
		}
		if err != nil && !strings.HasPrefix(Explain(Spanish, err), "macOS no deja usar el comando leakguard") {
			t.Errorf("%s: Explain = %q", tc.name, Explain(Spanish, err))
		}
	}
}

// tempBundle makes leakguard.app/Contents/MacOS in a temp folder and
// returns the menu-bar executable and CLI paths in it; the CLI is not
// created.
func tempBundle(t *testing.T) (exe, cli string) {
	t.Helper()
	macos := filepath.Join(t.TempDir(), "leakguard.app", "Contents", "MacOS")
	if err := os.MkdirAll(macos, 0o755); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(macos, "leakguard-menubar"), filepath.Join(macos, "leakguard")
}

// S6 (verifier): a symlink in place of the bundled CLI is never cleared,
// whatever it points to.
func TestPrepareCLIRefusesSymlink(t *testing.T) {
	d := t.TempDir()
	macos := filepath.Join(d, "leakguard.app", "Contents", "MacOS")
	if err := os.MkdirAll(macos, 0o755); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(d, "other")
	if err := os.WriteFile(other, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(macos, "leakguard")
	if err := os.Symlink(other, cli); err != nil {
		t.Fatal(err)
	}
	cleared := false
	err := PrepareCLI(filepath.Join(macos, "leakguard-menubar"), cli,
		func(string) (bool, error) { return true, nil },
		func(string) error { cleared = true; return nil })
	if cleared {
		t.Fatal("cleared the quarantine mark through a symlink")
	}
	if !errors.Is(err, ErrQuarantined) {
		t.Errorf("err = %v, want ErrQuarantined", err)
	}
}

// S6: anything but a regular file at the bundled CLI's place is refused
// too, and nothing is cleared.
func TestPrepareCLIRefusesNonRegular(t *testing.T) {
	for _, kind := range []string{"directory", "missing", "dangling symlink"} {
		exe, cli := tempBundle(t)
		switch kind {
		case "directory":
			os.Mkdir(cli, 0o755)
		case "dangling symlink":
			os.Symlink(filepath.Join(filepath.Dir(cli), "gone"), cli)
		}
		cleared := false
		err := PrepareCLI(exe, cli,
			func(string) (bool, error) { return true, nil },
			func(string) error { cleared = true; return nil })
		if cleared || !errors.Is(err, ErrQuarantined) {
			t.Errorf("%s: cleared = %v, err = %v; want nothing cleared and ErrQuarantined", kind, cleared, err)
		}
	}
}

// S6: PrepareCLI clears the attribute only when it should, and a failure
// is explained in plain words, never silent.
func TestPrepareCLI(t *testing.T) {
	type call struct{ checked, cleared []string }
	exe, cli := tempBundle(t)
	if err := os.WriteFile(cli, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		exe, cli    string
		quarantined bool
		checkErr    error
		clearErr    error
		wantCleared bool
		wantErr     error
	}{
		{"quarantined bundled CLI", exe, cli, true, nil, nil, true, nil},
		{"clean bundled CLI", exe, cli, false, nil, nil, false, nil},
		{"installed copy", exe, InstalledCLI, true, nil, nil, false, nil},
		{"check fails", exe, cli, false, errors.New("xattr missing"), nil, false, ErrQuarantined},
		{"clear fails", exe, cli, true, nil, errors.New("Operation not permitted"), true, ErrQuarantined},
	}
	for _, tc := range tests {
		var c call
		err := PrepareCLI(tc.exe, tc.cli,
			func(p string) (bool, error) { c.checked = append(c.checked, p); return tc.quarantined, tc.checkErr },
			func(p string) error { c.cleared = append(c.cleared, p); return tc.clearErr })
		if (len(c.cleared) == 1) != tc.wantCleared || (tc.wantCleared && c.cleared[0] != tc.cli) {
			t.Errorf("%s: cleared %q, want cleared=%v", tc.name, c.cleared, tc.wantCleared)
		}
		if tc.wantErr == nil && err != nil || tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestExplainQuarantine(t *testing.T) {
	err := QuarantineError(errors.New("xattr: [Errno 1] Operation not permitted"))
	if err.Error() != "xattr: [Errno 1] Operation not permitted" {
		t.Errorf("Error() = %q, want the original text", err.Error())
	}
	es := "macOS no deja usar el comando leakguard que viene dentro de la app. Sigue la guía «Cómo abrir leakguard» del disco de instalación o https://github.com/Isaacpaezz/leakguard/blob/main/docs/install-macos.md"
	en := "macOS does not let the app use the leakguard command inside it. Follow the guide «Cómo abrir leakguard» on the install disk or https://github.com/Isaacpaezz/leakguard/blob/main/docs/install-macos.md"
	if got := Explain(Spanish, err); got != es {
		t.Errorf("Spanish = %q\nwant       %q", got, es)
	}
	if got := Explain(English, err); got != en {
		t.Errorf("English = %q\nwant       %q", got, en)
	}
	if got := WizardMessage(Spanish, stepError{msgActivateFailed, err}); !strings.HasPrefix(got, "No se pudo activar la protección: "+es) {
		t.Errorf("wizard message = %q", got)
	}
}

// A failure to clear the mark that is itself a permission error still
// points to the guide, not to "only administrators".
func TestExplainQuarantineWinsOverPermission(t *testing.T) {
	err := QuarantineError(fs.ErrPermission)
	if got := Explain(English, err); !strings.HasPrefix(got, "macOS does not let the app use") {
		t.Errorf("Explain = %q", got)
	}
}
