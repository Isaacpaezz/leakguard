//go:build !windows

package config

import "os"

// renameBusy is false: a rename never waits for a reader here.
func renameBusy(error) bool { return false }

// replaceFile is os.Rename, which replaces path atomically.
func replaceFile(tmp, path string) error { return os.Rename(tmp, path) }
