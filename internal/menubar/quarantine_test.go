package menubar

import (
	"errors"
	"io/fs"
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
	want := []string{"-d", "com.apple.quarantine", "/Users/a b/leakguard.app/Contents/MacOS/leakguard"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("args = %q, want %q", got, want)
	}
}

// S6: PrepareCLI clears the attribute only when it should, and a failure
// is explained in plain words, never silent.
func TestPrepareCLI(t *testing.T) {
	type call struct{ checked, cleared []string }
	tests := []struct {
		name        string
		exe, cli    string
		quarantined bool
		checkErr    error
		clearErr    error
		wantCleared bool
		wantErr     error
	}{
		{"quarantined bundled CLI", bundledExe, bundledCLI, true, nil, nil, true, nil},
		{"clean bundled CLI", bundledExe, bundledCLI, false, nil, nil, false, nil},
		{"installed copy", bundledExe, InstalledCLI, true, nil, nil, false, nil},
		{"check fails", bundledExe, bundledCLI, false, errors.New("xattr missing"), nil, false, nil},
		{"clear fails", bundledExe, bundledCLI, true, nil, errors.New("Operation not permitted"), true, ErrQuarantined},
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
