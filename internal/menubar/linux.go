package menubar

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Isaacpaezz/leakguard/internal/daemon"
)

// EnvLang is the language of a Linux desktop session: the first locale set
// in LANGUAGE (its first entry), LC_ALL, LC_MESSAGES or LANG decides.
// Spanish when it is Spanish ("es", "es_VE.UTF-8", "es_ES@euro"), English
// otherwise, including "C" and nothing set.
func EnvLang(getenv func(string) string) Lang {
	for _, key := range []string{"LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"} {
		v := getenv(key)
		if key == "LANGUAGE" {
			v = firstEntry(v)
		}
		if v == "" {
			continue
		}
		// Drop the codeset and the modifier: es_VE.UTF-8, es_ES@euro.
		if i := strings.IndexAny(v, ".@"); i >= 0 {
			v = v[:i]
		}
		return ParseLang(v)
	}
	return English
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
