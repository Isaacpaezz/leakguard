//go:build !unix

package ipc

// restrictUmask is a no-op where umask does not exist.
func restrictUmask() func() { return func() {} }
