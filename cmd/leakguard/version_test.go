package main

import (
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/version"
)

// S1: "leakguard version" prints the injected version, without root.
func TestVersionCommand(t *testing.T) {
	defer func(v string) { version.Version = v }(version.Version)
	h := newHarness(t, false)
	code, out, errOut := h.run("version")
	expect(t, code, out, errOut, 0, nil, nil)
	if out != "leakguard dev\n" {
		t.Errorf("stdout = %q, want %q", out, "leakguard dev\n")
	}
	version.Version = "0.1.0"
	code, out, errOut = h.run("version")
	expect(t, code, out, errOut, 0, nil, nil)
	if out != "leakguard 0.1.0\n" {
		t.Errorf("stdout = %q, want %q", out, "leakguard 0.1.0\n")
	}
	code, out, errOut = h.run("version", "extra")
	expect(t, code, out, errOut, 2, nil, []string{"version takes no arguments"})
	if out != "" {
		t.Errorf("stdout with a usage error = %q, want empty", out)
	}
	code, out, errOut = h.run("help")
	expect(t, code, out, errOut, 0, []string{"leakguard version\n      Show the version of leakguard."}, nil)
}
