package menubar

import (
	"errors"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// Strings that would break out of a naively quoted AppleScript literal.
var trickyTexts = []string{
	`plain`,
	`it's "quoted"`,
	`back\slash`,
	`\"`,
	`end with a backslash\`,
	`" & (do shell script "id") & "`,
	"\" & (do shell script \"touch /tmp/leakguard-pwned\") & \"",
	"line one\nline two\n\nparagraph",
	"tab\there",
	"carriage\rreturn",
	`\n is not a newline here`,
	"¬ continuation ¬\n«data utxt0041» ñandú ¡Listo! ¿Sí?",
	"",
}

func TestAppleScriptString(t *testing.T) {
	tests := map[string]string{
		`a"b`:      `a\"b`,
		`a\b`:      `a\\b`,
		"a\nb":     `a\nb`,
		"a\rb\tc":  `a\rb\tc`,
		"a\x00b":   `a b`,
		"a\x7fb":   `a b`,
		"a\xffb":   "a�b",
		"ñ «» ¬ ¡": "ñ «» ¬ ¡",
	}
	for in, want := range tests {
		if got := appleScriptString(in); got != want {
			t.Errorf("appleScriptString(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDialogScript(t *testing.T) {
	d := Dialog{Title: "Paso 2 de 3", Text: "Desconecta tu VPN\ny toca \"Siguiente\".", Buttons: []string{"Cancelar", "Siguiente"}, Default: 1, Cancel: 0}
	want := "activate\n" +
		`return button returned of (display dialog "Desconecta tu VPN\ny toca \"Siguiente\"." with title "Paso 2 de 3" buttons {"Cancelar", "Siguiente"} default button "Siguiente" cancel button "Cancelar" with icon note)`
	if got := DialogScript(d); got != want {
		t.Errorf("DialogScript =\n%s\nwant\n%s", got, want)
	}
	d = Dialog{Title: "leakguard", Text: "Listo", Buttons: []string{"Aceptar"}, Default: 0, Cancel: -1}
	want = "activate\n" +
		`return button returned of (display dialog "Listo" with title "leakguard" buttons {"Aceptar"} default button "Aceptar" with icon note)`
	if got := DialogScript(d); got != want {
		t.Errorf("DialogScript without cancel =\n%s\nwant\n%s", got, want)
	}
}

func TestListScript(t *testing.T) {
	l := List{Title: "Paso 1 de 3", Text: "Elige", Items: []string{"Anthropic (Claude)", `Say "hi"`}, OK: "Siguiente", Cancel: "Cancelar", Multiple: true}
	want := `set L to {"Anthropic (Claude)", "Say \"hi\""}
activate
set picked to choose from list L with title "Paso 1 de 3" with prompt "Elige" OK button name "Siguiente" cancel button name "Cancelar" with multiple selections allowed
if picked is false then error number -128
set out to {}
considering case
	repeat with p in picked
		repeat with i from 1 to count of L
			if item i of L is (contents of p) then set end of out to i
		end repeat
	end repeat
end considering
set AppleScript's text item delimiters to ","
return out as text`
	if got := ListScript(l); got != want {
		t.Errorf("ListScript =\n%s\nwant\n%s", got, want)
	}
	l.Multiple = false
	if got := ListScript(l); strings.Contains(got, "multiple") {
		t.Errorf("single-choice ListScript allows several: %s", got)
	}
}

func TestParseButton(t *testing.T) {
	d := Dialog{Buttons: []string{"Cancelar", "Elegir de una lista", "Reintentar"}}
	if i, err := ParseButton("Elegir de una lista\n", d); err != nil || i != 1 {
		t.Errorf("ParseButton = %d, %v; want 1", i, err)
	}
	if i, err := ParseButton("Otro\n", d); err == nil {
		t.Errorf("ParseButton(unknown) = %d, nil; want an error", i)
	}
}

func TestParseChoice(t *testing.T) {
	many := List{Items: []string{"a", "b", "c"}, Multiple: true}
	one := List{Items: []string{"a", "b"}}
	tests := []struct {
		out     string
		l       List
		want    []int
		wantErr bool
	}{
		{"1,3\n", many, []int{0, 2}, false},
		{"2\n", one, []int{1}, false},
		{"1,2\n", one, nil, true},
		{"0\n", many, nil, true},
		{"4\n", many, nil, true},
		{"1,1\n", many, nil, true},
		{"x\n", many, nil, true},
		{"\n", many, nil, true},
	}
	for _, tc := range tests {
		got, err := ParseChoice(tc.out, tc.l)
		if (err != nil) != tc.wantErr || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ParseChoice(%q) = %v, %v; want %v (error %v)", tc.out, got, err, tc.want, tc.wantErr)
		}
	}
}

// Cancelling a dialog or the administrator prompt is never an error to show.
func TestScriptError(t *testing.T) {
	exit1 := errors.New("exit status 1")
	tests := []struct {
		out  string
		err  error
		want string
	}{
		{"0:95: execution error: User canceled. (-128)\n", exit1, ErrCancelled.Error()},
		{"0:17: execution error: Cancelado por el usuario. (-128)\n", exit1, ErrCancelled.Error()},
		{"0:120: execution error: leakguard: name at least one service (see leakguard services) (1)\n", exit1, "leakguard: name at least one service (see leakguard services)"},
		{"something odd\n", exit1, "something odd"},
		{"a\nb\nlast line\n\n", exit1, "last line"},
		{"", errors.New(`exec: "/usr/bin/osascript": no such file`), `exec: "/usr/bin/osascript": no such file`},
		{" \n", nil, "osascript failed"},
	}
	for _, tc := range tests {
		got := ScriptError(tc.out, tc.err)
		if got == nil || got.Error() != tc.want {
			t.Errorf("ScriptError(%q) = %v, want %q", tc.out, got, tc.want)
		}
		if cancelled := errors.Is(got, ErrCancelled); cancelled != (tc.want == ErrCancelled.Error()) {
			t.Errorf("ScriptError(%q) cancelled = %v", tc.out, cancelled)
		}
	}
}

func needOsascript(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("needs macOS osascript")
	}
}

// Every escaped string comes back from AppleScript exactly as it went in. It
// only runs "return", never a dialog or administrator rights.
func TestAppleScriptStringRoundTrip(t *testing.T) {
	needOsascript(t)
	for _, s := range trickyTexts {
		out, err := exec.Command("/usr/bin/osascript", "-e", `return "`+appleScriptString(s)+`"`).CombinedOutput()
		if err != nil {
			t.Fatalf("osascript with %q: %v: %s", s, err, out)
		}
		if got := strings.TrimSuffix(string(out), "\n"); got != s {
			t.Errorf("AppleScript returned %q, want %q", got, s)
		}
	}
}

// The scripts built from tricky strings compile; nothing is run.
func TestScriptsCompile(t *testing.T) {
	needOsascript(t)
	dir := t.TempDir()
	draft := Draft{VPNInterface: "utun3", Services: []string{"anthropic"}}
	for i, s := range trickyTexts {
		setup, err := SetupScript("/tmp/"+strings.ReplaceAll(s, "\n", " ")+"/leakguard", draft, fullCatalog, s)
		if err != nil && !strings.Contains(err.Error(), "control characters") {
			t.Fatalf("SetupScript(%q): %v", s, err)
		}
		scripts := []string{
			DialogScript(Dialog{Title: s, Text: s, Buttons: []string{s + "1", s + "2"}, Default: 1, Cancel: 0}),
			ListScript(List{Title: s, Text: s, Items: []string{s + "a", s + "b"}, OK: s + "ok", Cancel: s + "no", Multiple: i%2 == 0}),
		}
		if err == nil {
			scripts = append(scripts, setup)
		}
		for j, script := range scripts {
			out, err := exec.Command("/usr/bin/osacompile", "-o", filepath.Join(dir, "s.scpt"), "-e", script).CombinedOutput()
			if err != nil {
				t.Errorf("script %d for %q does not compile: %v: %s\n%s", j, s, err, out, script)
			}
		}
	}
}
