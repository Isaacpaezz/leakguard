//go:build unix

package ipc

import "syscall"

// restrictUmask makes new files inaccessible to group and others until the
// returned function restores the previous umask.
func restrictUmask() func() {
	old := syscall.Umask(0o077)
	return func() { syscall.Umask(old) }
}
