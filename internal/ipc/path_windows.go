//go:build windows

package ipc

// DefaultPath is the named pipe where the daemon listens.
const DefaultPath = `\\.\pipe\leakguard`
