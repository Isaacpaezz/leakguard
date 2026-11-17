package menubar

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/config"
)

// InstalledCLI is the root-owned copy of the CLI that the daemon runs.
const InstalledCLI = "/usr/local/libexec/leakguard/leakguard"

// Messages FindCLI returns when it finds nothing safe to run.
const (
	errNotRootOwned = "the installed leakguard is not owned by root; reinstall with sudo leakguard enable"
	errUpdate       = "Update leakguard: put the new leakguard next to this app, or run: sudo leakguard enable"
	errNoCLI        = "Put the leakguard command next to this app, then try again"
)

// FindCLI returns the leakguard CLI to run as root for "Set up leakguard…".
//
// The installed copy (InstalledCLI) is used only when the installed
// LaunchDaemon runs "serve" (inst is InstallCurrent): an older copy would
// re-install the periodic apply, the socket would never appear, and the app
// would stay "not set up". Before it is trusted, checkInstalled must confirm
// that it, and every directory above it, is owned by root and not writable
// by anyone else, without following symlinks. If that check fails for any
// reason other than a missing file, FindCLI refuses instead of running
// another binary.
//
// The leakguard next to the app executable exe may be writable by the user,
// so it is used only when no current installed copy exists: on the first run
// or to update an older install.
func FindCLI(exe string, inst Install, isExecutable func(path string) bool, checkInstalled func(path string) error) (string, error) {
	if inst == InstallCurrent {
		err := checkInstalled(InstalledCLI)
		switch {
		case err == nil:
			return InstalledCLI, nil
		case !errors.Is(err, fs.ErrNotExist):
			return "", errors.New(errNotRootOwned)
		}
	}
	if exe != "" {
		if next := filepath.Join(filepath.Dir(exe), "leakguard"); isExecutable(next) {
			return next, nil
		}
	}
	if inst == InstallOld {
		return "", errors.New(errUpdate)
	}
	return "", errors.New(errNoCLI)
}

// ShellQuote quotes s as one POSIX shell word: inside single quotes nothing
// is special, so each single quote closes the quoting, adds an escaped quote
// and reopens it.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// appleScriptString escapes s for the inside of an AppleScript string literal.
func appleScriptString(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

// SetupScript is the AppleScript that runs "cli enable --vpn IFACE
// SERVICE..." once with administrator rights. cli must be an absolute path
// without control characters, and the draft must pass config.Validate
// against the catalog all; anything else is refused before quoting. Every
// argument is quoted for the shell, then the command for AppleScript.
func SetupScript(cli string, d Draft, all []catalog.Service) (string, error) {
	if !filepath.IsAbs(cli) {
		return "", errors.New("the leakguard command needs an absolute path")
	}
	if !utf8.ValidString(cli) {
		return "", errors.New("the path of the leakguard command is not valid UTF-8")
	}
	if strings.ContainsFunc(cli, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", errors.New("the path of the leakguard command contains control characters")
	}
	if err := (config.Config{VPNInterface: d.VPNInterface, Services: d.Services}).Validate(all); err != nil {
		return "", err
	}
	words := []string{ShellQuote(cli), "enable", ShellQuote("--vpn"), ShellQuote(d.VPNInterface)}
	for _, id := range d.Services {
		words = append(words, ShellQuote(id))
	}
	cmd := strings.Join(words, " ")
	return `do shell script "` + appleScriptString(cmd) + `" with administrator privileges`, nil
}

// SetupFailure explains the output of a failed osascript run of SetupScript,
// such as "0:95: execution error: User canceled. (-128)".
func SetupFailure(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	if _, msg, ok := strings.Cut(last, "execution error: "); ok {
		last = msg
	}
	if strings.HasSuffix(last, "(-128)") {
		return "Set up canceled"
	}
	if i := strings.LastIndex(last, " ("); i > 0 && strings.HasSuffix(last, ")") {
		if _, err := strconv.Atoi(last[i+2 : len(last)-1]); err == nil {
			last = last[:i]
		}
	}
	if last == "" {
		return "Set up failed"
	}
	return "Set up failed: " + last
}

// Short keeps the first line of s and cuts it to at most max characters,
// ending with "…" when it was longer.
func Short(s string, max int) string {
	s = firstLine(s)
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}
