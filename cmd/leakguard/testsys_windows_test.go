package main

import (
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// The test harness's view of Windows: the daemon listens on a named pipe,
// and a directory held open for adding files makes saves fail. See
// testsys_other_test.go for macOS and Linux.

var pipeCount atomic.Int32

// testSocket returns a pipe name no other test or daemon uses.
func testSocket(*testing.T) string {
	return fmt.Sprintf(`\\.\pipe\leakguard-cmd-test-%d-%d`, os.Getpid(), pipeCount.Add(1))
}

// dialTestSocket connects to the test daemon's pipe.
func dialTestSocket(path string) (net.Conn, error) {
	timeout := time.Second
	return winio.DialPipe(path, &timeout)
}

// occupySocket creates the pipe at path first, as a running daemon would,
// and returns the error serve reports: it never shares its pipe.
func occupySocket(t *testing.T, path string) string {
	t.Helper()
	ln, err := winio.ListenPipe(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return "leakguard: could not create " + path + " (is another leakguard daemon running?): "
}

// simulateMacOS makes the harness a Mac for one test: its fake interfaces
// (en0, ipsec0, utun0) are judged by the macOS rules, because the Windows
// rules ask the real adapters, and its messages say sudo, unless the test
// chose the wording itself (withAdminHint, withWindowsWords). The Windows
// rules and wording have their own tests.
func simulateMacOS(t *testing.T) {
	t.Helper()
	t.Cleanup(config.SimulateMacOS())
	if wordsChosen {
		return
	}
	oldHint, oldWords := needAdmin, windowsWords
	needAdmin, windowsWords = needAdminFor("darwin"), false
	t.Cleanup(func() { needAdmin, windowsWords = oldHint, oldWords })
}

// skipUnlessSavesCanFail does nothing: blockConfigSaves works for
// administrators too.
func skipUnlessSavesCanFail(*testing.T) {}

// holdForAdding opens dir for adding files, so config.Save's PrepareDir,
// which refuses a directory someone holds open for writing, fails until
// the handle is closed.
func holdForAdding(t *testing.T, dir string) (release func()) {
	t.Helper()
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.FILE_WRITE_DATA /* FILE_ADD_FILE */, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatalf("CreateFile(%s) = %v", dir, err)
	}
	closed := false
	release = func() {
		if !closed {
			closed = true
			windows.CloseHandle(h)
		}
	}
	t.Cleanup(release)
	return release
}

// blockConfigSaves makes saving the configuration in dir fail until the
// returned function runs.
func blockConfigSaves(t *testing.T, dir string) (unblock func()) {
	t.Helper()
	return holdForAdding(t, dir)
}

// breakConfigDir makes saving the configuration in dir fail until the
// test ends.
func breakConfigDir(t *testing.T, dir string) error {
	holdForAdding(t, dir)
	return nil
}
