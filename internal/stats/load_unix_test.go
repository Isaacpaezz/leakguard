//go:build unix

package stats

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Load never blocks on a file that is not a regular file, such as a FIFO
// without a writer: it starts fresh and says why.
func TestLoadRefusesAFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Fatal(err)
	}
	// Frees a reader stuck on the FIFO, so a failing run still ends.
	t.Cleanup(func() {
		if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			f.Close()
		}
	})
	type result struct {
		t   *Tracker
		err error
	}
	done := make(chan result, 1)
	go func() {
		tr, err := Load(path, time.UTC)
		done <- result{tr, err}
	}()
	select {
	case r := <-done:
		if r.err == nil || r.err.Error() != path+": not a regular file" {
			t.Fatalf("Load() error = %v, want %q", r.err, path+": not a regular file")
		}
		if r.t == nil || r.t.State() != (State{}) {
			t.Fatalf("Load() tracker = %+v, want a fresh one", r.t)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Load blocked on a FIFO")
	}
}
