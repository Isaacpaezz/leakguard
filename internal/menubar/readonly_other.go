//go:build !darwin

package menubar

import "errors"

// ReadOnlyVolume cannot tell on this system, so no login item is ever
// written (see LoginMenu); the login item is a macOS feature.
func ReadOnlyVolume(string) (bool, error) {
	return false, errors.New("volume checks are only supported on macOS")
}
