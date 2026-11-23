package stats

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// T14e: "leakguard status" reads stats.json while the daemon saves it
// every sample. The reader shares deleting and Save replaces the file
// anyway; the reader sees the old or the new stats, never a mix.
func TestSaveWhileAReaderHoldsTheStats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")
	tr := New(time.UTC)
	now := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	tr.ObserveVPN(now, true)
	if err := Save(path, tr.State()); err != nil {
		t.Fatalf("Save() = %v", err)
	}
	oldData, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := openRead(path)
	if err != nil {
		t.Fatalf("openRead() = %v", err)
	}
	const hold = 300 * time.Millisecond
	type read struct {
		data []byte
		err  error
	}
	got := make(chan read, 1)
	go func() {
		time.Sleep(hold)
		data, err := io.ReadAll(f)
		f.Close()
		got <- read{data, err}
	}()
	tr.ObserveVPN(now.Add(5*time.Second), false)
	start := time.Now()
	err = Save(path, tr.State())
	elapsed := time.Since(start)
	r := <-got
	if err != nil {
		t.Fatalf("Save() while a reader held the stats for %v = %v", hold, err)
	}
	t.Logf("Save() returned after %v with a reader holding the stats for %v", elapsed, hold)
	newData, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if r.err != nil || (!bytes.Equal(r.data, oldData) && !bytes.Equal(r.data, newData)) {
		t.Errorf("the reader read %q, %v; want the old %q or the new %q", r.data, r.err, oldData, newData)
	}
	loaded, err := Load(path, time.UTC)
	if err != nil || loaded.State().Drops != 1 {
		t.Errorf("Load() after the Save = %+v, %v; want the new stats with 1 drop", loaded.State(), err)
	}
	if left, err := filepath.Glob(filepath.Join(dir, ".stats-*")); err != nil || len(left) != 0 {
		t.Errorf("temporary files left = %v, %v; want none", left, err)
	}
}
