//go:build unix

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// T14e: a Save whose final rename fails leaves no temporary file behind
// and the old entry in place.
func TestSaveLeavesNoTemporaryFileWhenTheRenameFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	// A non-empty directory where the file goes: the rename fails.
	if err := os.MkdirAll(filepath.Join(path, "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, Config{VPNInterface: "utun4", Services: []string{"anthropic"}}); err == nil {
		t.Fatal("Save() over a directory = nil, want an error")
	}
	left, err := filepath.Glob(filepath.Join(dir, ".config-*"))
	if err != nil || len(left) != 0 {
		t.Errorf("temporary files left = %v, %v; want none", left, err)
	}
	if fi, err := os.Stat(filepath.Join(path, "keep")); err != nil || !fi.IsDir() {
		t.Errorf("the entry at the config path changed: %v", err)
	}
}
