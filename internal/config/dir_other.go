//go:build !windows

package config

import "os"

// prepareDir creates dir, readable by everyone, when it is missing.
func prepareDir(dir string) error { return os.MkdirAll(dir, 0o755) }

// OpenTrusted opens the file at path for reading. Only Windows checks who
// may write it: elsewhere the files live in root-owned directories.
func OpenTrusted(path string) (*os.File, error) { return os.Open(path) }

// ownFile does nothing: the owner is already root.
func ownFile(string) error { return nil }
