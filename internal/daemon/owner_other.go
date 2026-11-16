//go:build !unix

package daemon

import "errors"

func checkRootOwned(string) error {
	return errors.New("root ownership checks are only supported on Unix")
}
