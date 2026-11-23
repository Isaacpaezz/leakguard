//go:build !linux && !windows

package config

// macOS (and any other system) judges VPN interfaces by name.
var host = rules{goos: "darwin"}
