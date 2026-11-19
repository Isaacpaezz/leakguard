//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/stats"
)

// S4, rule 4: a stats file that would block on read (a FIFO) never keeps the
// rules from loading at start, nor the socket from answering.
func TestServeLoadsTheRulesWhenTheStatsFileBlocks(t *testing.T) {
	h, p := statefulHarness(t)
	path := h.path(stats.DefaultPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Fatal(err)
	}
	// Frees a reader stuck on the FIFO, so a failing run still ends.
	t.Cleanup(func() {
		if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			f.Close()
		}
	})
	s := startServe(t, h)
	if n := p.count(loadAnchor); n != 1 {
		t.Fatalf("the anchor was loaded %d times at start, want once", n)
	}
	st, err := s.client.Status()
	if err != nil || !st.Protected {
		t.Fatalf("Status() = %+v, %v; want protected", st, err)
	}
	if code := s.stop(t); code != 0 {
		t.Fatalf("serve exit code = %d: %s", code, s.stderr.String())
	}
	if want := "leakguard: could not read the session stats: " + path + ": not a regular file\n"; !strings.Contains(s.stderr.String(), want) {
		t.Fatalf("stderr = %q, want %q", s.stderr.String(), want)
	}
}
