//go:build !unix

package menubar

import "errors"

// CheckInstalledCLI always fails: root ownership is a Unix check.
func CheckInstalledCLI(string) error {
	return errors.New("root ownership checks are only supported on Unix")
}
