package menubar

import (
	"errors"
	"io/fs"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"
)

var trickyPaths = []string{
	"/Applications/leakguard/leakguard",
	"/Users/a b/My Apps/leakguard",
	"/tmp/it's/leakguard",
	`/tmp/"quoted"/leakguard`,
	"/tmp/$HOME/$(id)/leakguard",
	"/tmp/`id`/leakguard",
	`/tmp/back\slash/leakguard`,
	"/tmp/semi;rm -rf ~;/leakguard",
	"/tmp/'; id; '/leakguard",
}

func TestShellQuote(t *testing.T) {
	tests := map[string]string{
		"/usr/local/bin/leakguard": `'/usr/local/bin/leakguard'`,
		"/a b/c":                   `'/a b/c'`,
		"/it's":                    `'/it'\''s'`,
		"$x`y`":                    "'$x`y`'",
		"":                         `''`,
	}
	for in, want := range tests {
		if got := ShellQuote(in); got != want {
			t.Errorf("ShellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

// The shell must see each quoted path as exactly one literal word.
func TestShellQuoteRoundTripsThroughSh(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	for _, p := range trickyPaths {
		out, err := exec.Command("/bin/sh", "-c", "printf '%s|' "+ShellQuote(p)).Output()
		if err != nil {
			t.Fatalf("sh with %q: %v", p, err)
		}
		if got := string(out); got != p+"|" {
			t.Errorf("sh saw %q, want %q", got, p+"|")
		}
	}
}

// unAppleScript decodes the body of an AppleScript string literal.
func unAppleScript(t *testing.T, lit string) string {
	t.Helper()
	var b strings.Builder
	for i := 0; i < len(lit); i++ {
		switch c := lit[i]; c {
		case '"':
			t.Fatalf("unescaped quote in %q", lit)
		case '\\':
			i++
			if i == len(lit) {
				t.Fatalf("dangling backslash in %q", lit)
			}
			b.WriteByte(lit[i])
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

var oneService = Draft{VPNInterface: "ipsec0", Services: []string{"anthropic"}}

func TestSetupScript(t *testing.T) {
	tests := []struct {
		cli   string
		draft Draft
		want  string
	}{
		{
			cli:   "/usr/local/libexec/leakguard/leakguard",
			draft: oneService,
			want:  `do shell script "'/usr/local/libexec/leakguard/leakguard' enable '--vpn' 'ipsec0' 'anthropic'" with administrator privileges`,
		},
		{
			cli:   "/Users/me/bin/leakguard",
			draft: Draft{VPNInterface: "utun3", Services: []string{"anthropic", "mistral"}},
			want:  `do shell script "'/Users/me/bin/leakguard' enable '--vpn' 'utun3' 'anthropic' 'mistral'" with administrator privileges`,
		},
		{
			cli:   `/tmp/"it's"\x/leakguard`,
			draft: oneService,
			want:  `do shell script "'/tmp/\"it'\\''s\"\\x/leakguard' enable '--vpn' 'ipsec0' 'anthropic'" with administrator privileges`,
		},
	}
	for _, tc := range tests {
		got, err := SetupScript(tc.cli, tc.draft, fullCatalog)
		if err != nil {
			t.Fatalf("SetupScript(%q): %v", tc.cli, err)
		}
		if got != tc.want {
			t.Errorf("script = %s\nwant      %s", got, tc.want)
		}
	}
}

// Every tricky path survives both layers: the AppleScript string, then the shell.
func TestSetupScriptAgainstInjection(t *testing.T) {
	const prefix, suffix = `do shell script "`, `" with administrator privileges`
	draft := Draft{VPNInterface: "utun3", Services: []string{"anthropic", "mistral"}}
	for _, p := range trickyPaths {
		script, err := SetupScript(p, draft, fullCatalog)
		if err != nil {
			t.Fatalf("SetupScript(%q): %v", p, err)
		}
		if !strings.HasPrefix(script, prefix) || !strings.HasSuffix(script, suffix) {
			t.Fatalf("unexpected script shape: %s", script)
		}
		cmd := unAppleScript(t, strings.TrimSuffix(strings.TrimPrefix(script, prefix), suffix))
		if want := ShellQuote(p) + " enable '--vpn' 'utun3' 'anthropic' 'mistral'"; cmd != want {
			t.Errorf("shell command = %s, want %s", cmd, want)
		}
		if runtime.GOOS == "windows" {
			continue
		}
		// Run the decoded command with printf in place of the binary.
		out, err := exec.Command("/bin/sh", "-c", "printf '%s|' "+cmd).Output()
		if err != nil {
			t.Fatalf("sh: %v", err)
		}
		if got, want := string(out), p+"|enable|--vpn|utun3|anthropic|mistral|"; got != want {
			t.Errorf("sh saw %q, want %q", got, want)
		}
	}
}

func TestSetupScriptRejects(t *testing.T) {
	tests := []struct {
		name    string
		cli     string
		draft   Draft
		wantErr string
	}{
		{"empty path", "", oneService, "the leakguard command needs an absolute path"},
		{"relative path", "relative/leakguard", oneService, "the leakguard command needs an absolute path"},
		{"newline in path", "/tmp/a\nb/leakguard", oneService, "the path of the leakguard command contains control characters"},
		{"carriage return in path", "/tmp/a\rb", oneService, "the path of the leakguard command contains control characters"},
		{"NUL in path", "/tmp/\x00", oneService, "the path of the leakguard command contains control characters"},
		{"no VPN", "/x/leakguard", Draft{Services: []string{"anthropic"}}, "VPN interface is not set"},
		{"real connection", "/x/leakguard", Draft{VPNInterface: "en0", Services: []string{"anthropic"}}, `"en0" is not a VPN interface; it carries your real connection`},
		{"injected VPN", "/x/leakguard", Draft{VPNInterface: "utun0'; id; '", Services: []string{"anthropic"}}, `"utun0'; id; '" is not a valid interface name`},
		{"option as VPN", "/x/leakguard", Draft{VPNInterface: "-h", Services: []string{"anthropic"}}, `"-h" is not a valid interface name`},
		{"no services", "/x/leakguard", Draft{VPNInterface: "ipsec0"}, "no services selected"},
		{"unknown service", "/x/leakguard", Draft{VPNInterface: "ipsec0", Services: []string{"$(id)"}}, `unknown service "$(id)"`},
		{"option as service", "/x/leakguard", Draft{VPNInterface: "ipsec0", Services: []string{"--vpn"}}, `unknown service "--vpn"`},
		{"planned service", "/x/leakguard", Draft{VPNInterface: "ipsec0", Services: []string{"openai"}}, `service "openai" is not supported yet`},
		{"duplicate service", "/x/leakguard", Draft{VPNInterface: "ipsec0", Services: []string{"anthropic", "anthropic"}}, `service "anthropic" is listed twice`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := SetupScript(tc.cli, tc.draft, fullCatalog)
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("SetupScript = %q, %v; want error %q", s, err, tc.wantErr)
			}
			if s != "" {
				t.Errorf("script with an error = %q, want none", s)
			}
		})
	}
}

const (
	nextToApp = "/Users/me/bin/leakguard"
	appExe    = "/Users/me/bin/leakguard-menubar"
)

func TestFindCLI(t *testing.T) {
	rootOwned := func(string) error { return nil }
	missing := func(p string) error { return &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist} }
	notRoot := func(p string) error { return errors.New(p + " is not owned by root") }
	tests := []struct {
		name    string
		exe     string
		inst    Install
		exists  []string
		check   func(string) error
		want    string
		wantErr string
	}{
		{
			name:   "current install: the root-owned installed copy wins",
			exe:    appExe,
			inst:   InstallCurrent,
			exists: []string{nextToApp, InstalledCLI},
			check:  rootOwned,
			want:   InstalledCLI,
		},
		{
			name:    "current install not owned by root is refused, never replaced",
			exe:     appExe,
			inst:    InstallCurrent,
			exists:  []string{nextToApp, InstalledCLI},
			check:   notRoot,
			wantErr: "the installed leakguard is not owned by root; reinstall with sudo leakguard enable",
		},
		{
			name:   "current plist without the installed binary uses the one next to the app",
			exe:    appExe,
			inst:   InstallCurrent,
			exists: []string{nextToApp},
			check:  missing,
			want:   nextToApp,
		},
		{
			name:   "older install: the one next to the app updates it",
			exe:    appExe,
			inst:   InstallOld,
			exists: []string{nextToApp, InstalledCLI},
			check:  rootOwned,
			want:   nextToApp,
		},
		{
			name:    "older install and nothing next to the app",
			exe:     appExe,
			inst:    InstallOld,
			exists:  []string{InstalledCLI},
			check:   rootOwned,
			wantErr: "Update leakguard: put the new leakguard next to this app, or run: sudo leakguard enable",
		},
		{
			name:   "first run uses the one next to the app",
			exe:    appExe,
			inst:   InstallNone,
			exists: []string{nextToApp},
			check:  missing,
			want:   nextToApp,
		},
		{
			name:    "first run with nothing next to the app",
			exe:     appExe,
			inst:    InstallNone,
			check:   missing,
			wantErr: "Put the leakguard command next to this app, then try again",
		},
		{
			name:    "unknown executable on the first run",
			inst:    InstallNone,
			check:   missing,
			wantErr: "Put the leakguard command next to this app, then try again",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isExe := func(p string) bool { return slices.Contains(tc.exists, p) }
			got, err := FindCLI(tc.exe, tc.inst, isExe, tc.check)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("FindCLI = %q, %v; want error %q", got, err, tc.wantErr)
				}
				if got != "" {
					t.Errorf("path with an error = %q", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Errorf("FindCLI = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestSetupScriptRejectsInvalidUTF8(t *testing.T) {
	s, err := SetupScript("/tmp/\xff\xfe/leakguard", oneService, fullCatalog)
	if err == nil || err.Error() != "the path of the leakguard command is not valid UTF-8" {
		t.Errorf("SetupScript = %q, %v; want the UTF-8 error", s, err)
	}
	if s != "" {
		t.Errorf("script with an error = %q", s)
	}
}

func TestSetupFailure(t *testing.T) {
	tests := map[string]string{
		"0:95: execution error: User canceled. (-128)\n": "Set up canceled",
		"0:120: execution error: leakguard: name at least one service, for example: sudo leakguard enable anthropic (see leakguard services) (1)\n": "Set up failed: leakguard: name at least one service, for example: sudo leakguard enable anthropic (see leakguard services)",
		"something odd\n":     "Set up failed: something odd",
		"a\nb\nlast line\n\n": "Set up failed: last line",
	}
	for out, want := range tests {
		if got := SetupFailure(out, errors.New("exit status 1")); got != want {
			t.Errorf("SetupFailure(%q) = %q, want %q", out, got, want)
		}
	}
	// Without any output, the error from running osascript is the only clue.
	if got := SetupFailure("", errors.New(`exec: "/usr/bin/osascript": no such file`)); got != `Set up failed: exec: "/usr/bin/osascript": no such file` {
		t.Errorf("SetupFailure with empty output = %q", got)
	}
	if got := SetupFailure(" \n", nil); got != "Set up failed" {
		t.Errorf("SetupFailure without output or error = %q", got)
	}
}

func TestShort(t *testing.T) {
	tests := []struct {
		in   string
		max  int
		want string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"one two three four", 10, "one two t…"},
		{"ñandú ñandú", 6, "ñandú…"},
		{"first\nsecond", 20, "first"},
	}
	for _, tc := range tests {
		if got := Short(tc.in, tc.max); got != tc.want {
			t.Errorf("Short(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
		}
	}
}
