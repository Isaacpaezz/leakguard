//go:build unix

package menubar

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckInstalledCLI(t *testing.T) {
	dir := t.TempDir()
	userFile := filepath.Join(dir, "leakguard")
	if err := os.WriteFile(userFile, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink("/usr/bin/env", link); err != nil {
		t.Fatal(err)
	}

	if err := CheckInstalledCLI(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: %v, want ErrNotExist", err)
	}
	if os.Getuid() != 0 {
		if err := CheckInstalledCLI(userFile); err == nil || !strings.Contains(err.Error(), "is not owned by root") {
			t.Errorf("user-owned file: %v, want not owned by root", err)
		}
	}
	if err := CheckInstalledCLI(link); err == nil || !strings.Contains(err.Error(), "is a symlink") {
		t.Errorf("symlink to a root-owned file: %v, want a symlink error", err)
	}
	if err := CheckInstalledCLI("relative/leakguard"); err == nil {
		t.Error("relative path accepted")
	}
	// /usr/bin/env is a root-owned regular file below root-owned directories
	// on macOS and on Linux CI runners.
	if info, err := os.Lstat("/usr/bin/env"); err == nil && info.Mode().IsRegular() {
		if err := CheckInstalledCLI("/usr/bin/env"); err != nil {
			t.Errorf("/usr/bin/env: %v, want nil", err)
		}
	}
}
