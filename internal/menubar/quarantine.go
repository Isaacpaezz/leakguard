package menubar

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// A DMG downloaded with a browser marks every file in it with the
// com.apple.quarantine attribute. Opening the app approves the app, but the
// leakguard command inside it may keep the mark, and macOS may refuse to run
// it from the administrator prompt. Once the user opened the app (it is
// running), the app clears the mark on its own embedded command, and only on
// that one, before running it.

// QuarantineAttr is the extended attribute macOS sets on downloads.
const QuarantineAttr = "com.apple.quarantine"

// ErrQuarantined: macOS refused the leakguard command inside the app and
// the app could not clear the mark; Explain points to the install guide.
var ErrQuarantined = errors.New("macOS blocked the leakguard command inside the app")

// QuarantineError marks err, a failure to clear the quarantine mark, as
// ErrQuarantined, keeping its text.
func QuarantineError(err error) error {
	return kindError{ErrQuarantined, err}
}

// ShouldClearQuarantine reports whether the app, running from exe, should
// clear the quarantine mark on cli before running it as administrator: only
// when cli is the leakguard command inside the app's own bundle and it is
// quarantined. The installed root-owned copy, another bundle's command and
// development builds are never touched.
func ShouldClearQuarantine(exe, cli string, quarantined bool) bool {
	return quarantined && isBundledCLI(exe, cli)
}

// isBundledCLI reports whether cli is the leakguard command inside the
// bundle of the app executable exe, by its path alone.
func isBundledCLI(exe, cli string) bool {
	if !filepath.IsAbs(cli) || filepath.Clean(cli) != cli {
		return false
	}
	bundle, ok := AppBundle(exe)
	return ok && cli == filepath.Join(bundle, "Contents", "MacOS", "leakguard")
}

// ClearQuarantineArgs are the arguments to /usr/bin/xattr that clear the
// mark on exactly path: no -r, no shell, and -s so a symlink is never
// followed.
func ClearQuarantineArgs(path string) []string {
	return []string{"-s", "-d", QuarantineAttr, path}
}

// ReadQuarantineArgs are the arguments to /usr/bin/xattr that print the
// mark on exactly path, without following a symlink.
func ReadQuarantineArgs(path string) []string {
	return []string{"-s", "-p", QuarantineAttr, path}
}

// QuarantineCheck reads the answer of xattr run with ReadQuarantineArgs:
// its standard error and the error it ended with. The mark is there when it
// succeeded and missing when xattr said the attribute does not exist; any
// other failure is ErrQuarantined, since the app cannot tell whether macOS
// will refuse the command.
func QuarantineCheck(stderr string, err error) (bool, error) {
	if err == nil {
		return true, nil
	}
	if strings.Contains(stderr, "No such xattr: "+QuarantineAttr) {
		return false, nil
	}
	if msg := strings.TrimSpace(stderr); msg != "" {
		return false, QuarantineError(fmt.Errorf("%s: %w", firstLine(msg), err))
	}
	return false, QuarantineError(err)
}

// PrepareCLI clears the quarantine mark on cli when it is the leakguard
// command inside the bundle of the app executable exe and carries the mark;
// any other command is left alone. The bundled command must be a regular
// file, never a symlink or anything else, or the mark is not touched and
// the answer is ErrQuarantined. quarantined reads the mark and clear removes
// it; a failure of either is ErrQuarantined, never silent.
func PrepareCLI(exe, cli string, quarantined func(string) (bool, error), clear func(string) error) error {
	if !isBundledCLI(exe, cli) {
		return nil
	}
	info, err := os.Lstat(cli)
	if err != nil {
		return QuarantineError(err)
	}
	if !info.Mode().IsRegular() {
		return QuarantineError(fmt.Errorf("%s is not a regular file", cli))
	}
	q, err := quarantined(cli)
	if err != nil {
		if errors.Is(err, ErrQuarantined) {
			return err
		}
		return QuarantineError(err)
	}
	if !q {
		return nil
	}
	if err := clear(cli); err != nil {
		return QuarantineError(err)
	}
	return nil
}
