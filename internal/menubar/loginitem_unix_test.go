//go:build unix

package menubar

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// within fails the test when f does not return in time: a read that blocks
// on a FIFO would hang the app at launch.
func within(t *testing.T, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("%s blocked", what)
	}
}

// A FIFO at menubar.json or at the LaunchAgent never blocks the app:
// menubar.json reads as the defaults, and the agent is written over it.
func TestLoginItemRefusesFIFO(t *testing.T) {
	home := t.TempDir()
	for _, p := range []string{PrefsPath(home), LoginItemPath(home)} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	within(t, "LoadPrefs", func() {
		if !LoadPrefs(home).OpenAtLogin {
			t.Error("a FIFO at menubar.json: want the default, open at login")
		}
	})
	within(t, "SyncLoginItem", func() {
		if on, err := SyncLoginItem(home, bundledExe, writable); err != nil || !on {
			t.Errorf("SyncLoginItem = %v, %v; want true, nil", on, err)
		}
	})
	want, _ := LoginItemPlist(bundledExe)
	if fi, err := os.Lstat(LoginItemPath(home)); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("agent = %v, %v; want a regular file", fi, err)
	}
	if got := readOrNil(t, LoginItemPath(home)); string(got) != string(want) {
		t.Errorf("agent:\n%s\nwant:\n%s", got, want)
	}
}
