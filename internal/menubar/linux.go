package menubar

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Isaacpaezz/leakguard/internal/daemon"
)

// EnvLang is the language of a Linux desktop session, chosen like gettext
// does: the message locale is the first set of LC_ALL, LC_MESSAGES and LANG
// ("C" when none is); LANGUAGE (its first entry) overrides it unless that
// locale is "C" or "POSIX". Spanish when the result is Spanish ("es",
// "es_VE.UTF-8", "es_ES@euro"), English otherwise, including "C".
func EnvLang(getenv func(string) string) Lang {
	locale := "C"
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := getenv(key); v != "" {
			locale = v
			break
		}
	}
	if locale != "C" && locale != "POSIX" {
		if v := firstEntry(getenv("LANGUAGE")); v != "" {
			locale = v
		}
	}
	// Drop the codeset and the modifier: es_VE.UTF-8, es_ES@euro.
	if i := strings.IndexAny(locale, ".@"); i >= 0 {
		locale = locale[:i]
	}
	return ParseLang(locale)
}

// firstEntry is the first non-empty entry of a colon-separated list.
func firstEntry(list string) string {
	for _, e := range strings.Split(list, ":") {
		if e != "" {
			return e
		}
	}
	return ""
}

// SystemdInstalledState reads the systemd unit under root ("" or "/" for the
// real system), the Linux counterpart of InstalledState: no unit is
// InstallNone, a unit that runs the installed copy with "serve" is
// InstallCurrent, and anything else that exists is InstallOld, so the
// installed copy is not reused.
func SystemdInstalledState(root string) Install {
	if _, err := os.Lstat(filepath.Join(root, daemon.UnitPath)); errors.Is(err, fs.ErrNotExist) {
		return InstallNone
	}
	if (daemon.Systemd{Root: root}).Installed() {
		return InstallCurrent
	}
	return InstallOld
}

// FindLinuxCLI is FindCLI for the Linux tray app exe, with the installed
// state read from the systemd unit under root.
func FindLinuxCLI(root, exe string, isExecutable func(path string) bool, checkInstalled func(path string) error) (string, error) {
	return FindCLI(exe, SystemdInstalledState(root), isExecutable, checkInstalled)
}
