//go:build !windows

package config

import "os"

// PrepareDir creates dir, readable by everyone, when it is missing.
func PrepareDir(dir string) error { return os.MkdirAll(dir, 0o755) }
