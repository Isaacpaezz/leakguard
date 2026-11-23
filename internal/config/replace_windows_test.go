package config

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// T14e: the daemon reads config.json on every sample and every status, so
// a reader can hold it while a set or a pause saves it. Save must still
// replace it, and the reader sees the old or the new configuration, never
// a mix. Before T14e the replace failed with "Access is denied.".
func TestSaveWhileAReaderHoldsTheConfig(t *testing.T) {
	needElevated(t)
	dir := filepath.Join(t.TempDir(), "leakguard")
	path := filepath.Join(dir, "config.json")
	old := Config{VPNInterface: "WireGuard Tunnel", Services: []string{"anthropic"}}
	next := Config{VPNInterface: "WireGuard Tunnel", Services: []string{"anthropic"}, Paused: true}
	if err := Save(path, old); err != nil {
		t.Fatalf("Save() = %v", err)
	}
	oldData, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := OpenTrusted(path)
	if err != nil {
		t.Fatalf("OpenTrusted() = %v", err)
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
	start := time.Now()
	err = Save(path, next)
	elapsed := time.Since(start)
	r := <-got
	if err != nil {
		t.Fatalf("Save() while a reader held the config for %v = %v", hold, err)
	}
	t.Logf("Save() returned after %v with a reader holding the config for %v", elapsed, hold)
	newData, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if r.err != nil || (!bytes.Equal(r.data, oldData) && !bytes.Equal(r.data, newData)) {
		t.Errorf("the reader read %q, %v; want the old %q or the new %q", r.data, r.err, oldData, newData)
	}
	if c, err := Load(path); err != nil || !c.Paused {
		t.Errorf("Load() after the Save = %+v, %v; want the paused config", c, err)
	}
	if left, err := filepath.Glob(filepath.Join(dir, ".config-*")); err != nil || len(left) != 0 {
		t.Errorf("temporary files left = %v, %v; want none", left, err)
	}
}
