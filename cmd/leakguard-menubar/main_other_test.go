//go:build !darwin && !linux && !windows

package main

import (
	"bytes"
	"testing"
)

func TestRunIsNotSupportedYet(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(&stderr); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if got, want := stderr.String(), "leakguard-menubar: not supported yet on this system; it runs on macOS, Linux and Windows\n"; got != want {
		t.Errorf("stderr = %q, want %q", got, want)
	}
}
