//go:build !windows

package main

import (
	"net"
	"os"
	"testing"
)

// The test harness's view of the system on macOS and Linux: a Unix socket
// for the daemon, and Unix permissions to make saves fail. See
// testsys_windows_test.go for Windows.

// testSocket returns a daemon socket path no other test uses.
func testSocket(t *testing.T) string { return shortSocket(t) }

// dialTestSocket connects to the test daemon's socket.
func dialTestSocket(path string) (net.Conn, error) { return net.Dial("unix", path) }

// occupySocket puts something at path that serve cannot replace and
// returns the error serve reports.
func occupySocket(t *testing.T, path string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte("not a socket"), 0o644); err != nil {
		t.Fatal(err)
	}
	return "leakguard: refusing to replace " + path + ": it is not a socket"
}

// simulateMacOS does nothing: macOS and Linux keep their own interface
// rules and wording in the harness.
func simulateMacOS(*testing.T) {}

// skipUnlessSavesCanFail skips as root, which ignores directory
// permissions, so blockConfigSaves cannot make a save fail.
func skipUnlessSavesCanFail(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions, so the save cannot be made to fail")
	}
}

// blockConfigSaves makes saving the configuration in dir fail until the
// returned function runs.
func blockConfigSaves(t *testing.T, dir string) (unblock func()) {
	t.Helper()
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// breakConfigDir puts a file where the configuration's directory dir was,
// so saving the configuration fails, also as root.
func breakConfigDir(_ *testing.T, dir string) error {
	if err := os.Rename(dir, dir+".moved"); err != nil {
		return err
	}
	return os.WriteFile(dir, nil, 0o644)
}
