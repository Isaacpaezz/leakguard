//go:build !linux && !windows

package ipc

// DefaultPath is where the daemon listens.
const DefaultPath = "/var/run/leakguard.sock"
