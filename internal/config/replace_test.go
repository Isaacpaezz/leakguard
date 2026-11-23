package config

import (
	"errors"
	"io/fs"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// T14e: Windows refuses to replace a file by a rename while another
// handle has it open (ERROR_ACCESS_DENIED, or ERROR_SHARING_VIOLATION when
// that handle does not share deleting). Readers hold the file for
// milliseconds, so ReplaceFile tries again for about 2 s before failing.

// What a busy replace returns on Windows: ERROR_ACCESS_DENIED (5) and
// ERROR_SHARING_VIOLATION (32), wrapped as os.Rename and os.Root do.
var (
	errRenameDenied  = &os.LinkError{Op: "rename", Old: ".config-1.json", New: "config.json", Err: syscall.Errno(5)}
	errRenameSharing = &os.LinkError{Op: "renameat", Old: ".config-1.json", New: "config.json", Err: syscall.Errno(32)}
)

func TestRenameBusyOnWindows(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"access denied", errRenameDenied, true},
		{"sharing violation", errRenameSharing, true},
		{"sharing violation in a path error", &fs.PathError{Op: "open", Path: "config.json", Err: syscall.Errno(32)}, true},
		{"file not found", &os.LinkError{Op: "rename", Err: syscall.Errno(2)}, false},
		{"lock violation", &os.LinkError{Op: "rename", Err: syscall.Errno(33)}, false},
		{"not an errno", errors.New("Access is denied."), false},
		{"nil", nil, false},
	} {
		if got := renameBusyOnWindows(tc.err); got != tc.want {
			t.Errorf("%s: renameBusyOnWindows(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}

// Only Windows retries a replace: elsewhere a rename never waits for a
// reader, so a failed rename fails at once, as before.
func TestReplaceRetriesOnlyOnWindows(t *testing.T) {
	if got, want := renameBusy(errRenameDenied), runtime.GOOS == "windows"; got != want {
		t.Errorf("renameBusy(%v) on %s = %v, want %v", errRenameDenied, runtime.GOOS, got, want)
	}
}

func TestRetryWhileRetriesABusyReplaceUntilItSucceeds(t *testing.T) {
	calls := 0
	var slept time.Duration
	err := retryWhile(renameBusyOnWindows, func(d time.Duration) { slept += d }, func() error {
		calls++
		if calls < 3 {
			return errRenameDenied
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("retryWhile() = %v after %d calls, want nil after 3", err, calls)
	}
	if want := inUseDelays[0] + inUseDelays[1]; slept != want {
		t.Errorf("slept %v between the attempts, want %v", slept, want)
	}
}

func TestRetryWhileGivesUpAfterAboutTwoSeconds(t *testing.T) {
	calls := 0
	var slept time.Duration
	err := retryWhile(renameBusyOnWindows, func(d time.Duration) { slept += d }, func() error {
		calls++
		return errRenameSharing
	})
	if err != errRenameSharing {
		t.Fatalf("retryWhile() = %v, want the last error %v", err, errRenameSharing)
	}
	if want := len(inUseDelays) + 1; calls != want {
		t.Errorf("%d calls, want %d", calls, want)
	}
	if slept < time.Second || slept > 2*time.Second {
		t.Errorf("waited %v in all, want between 1 s and 2 s", slept)
	}
}

func TestRetryWhileNeverRetriesAnotherError(t *testing.T) {
	notFound := &os.LinkError{Op: "rename", Err: syscall.Errno(2)}
	calls := 0
	var slept time.Duration
	err := retryWhile(renameBusyOnWindows, func(d time.Duration) { slept += d }, func() error {
		calls++
		return notFound
	})
	if err != notFound || calls != 1 || slept != 0 {
		t.Errorf("retryWhile() = %v after %d calls and %v of waits, want %v after 1 call and no wait", err, calls, slept, notFound)
	}
}
