package menubar

import (
	"errors"
	"path/filepath"
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
	if !quarantined || !filepath.IsAbs(cli) || filepath.Clean(cli) != cli {
		return false
	}
	bundle, ok := AppBundle(exe)
	return ok && cli == filepath.Join(bundle, "Contents", "MacOS", "leakguard")
}

// ClearQuarantineArgs are the arguments to /usr/bin/xattr that clear the
// mark on exactly path: no -r, no shell.
func ClearQuarantineArgs(path string) []string {
	return []string{"-d", QuarantineAttr, path}
}

// PrepareCLI clears the quarantine mark on cli when ShouldClearQuarantine
// says so. quarantined reads the mark; when it cannot, cli runs as it is and
// any refusal shows when it runs. A failure to clear it is ErrQuarantined,
// never silent.
func PrepareCLI(exe, cli string, quarantined func(string) (bool, error), clear func(string) error) error {
	q, err := quarantined(cli)
	if err != nil || !ShouldClearQuarantine(exe, cli, q) {
		return nil
	}
	if err := clear(cli); err != nil {
		return QuarantineError(err)
	}
	return nil
}
