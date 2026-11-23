package config

import (
	"errors"
	"syscall"
	"time"
)

// ReplaceFile moves the file at tmp over path, in the same directory: the
// last step of an atomic save, used by Save and the stats. On Windows the
// rename replaces path even while a reader that shares deleting holds it
// (POSIX semantics, through os.Root), and is tried again for about 2 s
// while another handle still keeps it out (ERROR_ACCESS_DENIED or
// ERROR_SHARING_VIOLATION), since readers hold the file for milliseconds.
// Elsewhere it is os.Rename. On failure tmp is left for the caller to
// remove.
func ReplaceFile(tmp, path string) error {
	return retryWhile(renameBusy, time.Sleep, func() error { return replaceFile(tmp, path) })
}

// Windows error numbers of a replace kept out by another handle of the
// file: ERROR_ACCESS_DENIED and ERROR_SHARING_VIOLATION.
const (
	errorAccessDenied     = syscall.Errno(5)
	errorSharingViolation = syscall.Errno(32)
)

// renameBusyOnWindows reports whether err is a Windows error that a rename
// returns while another handle has the file open. It is portable so the
// decision is tested on every OS; only Windows uses it (renameBusy).
func renameBusyOnWindows(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && (errno == errorAccessDenied || errno == errorSharingViolation)
}
