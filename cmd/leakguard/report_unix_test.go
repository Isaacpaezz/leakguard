//go:build !windows

package main

import "testing"

// S2 (SF7): --report-file exists only on Windows: on macOS and Linux
// enable and disable refuse it as before, with a usage error and exit 2.
func TestReportFileFlagIsWindowsOnly(t *testing.T) {
	if reportFileFlag {
		t.Fatal("--report-file is defined on this system")
	}
	for _, args := range [][]string{
		{"enable", "--report-file", "r.txt", "--vpn", "utun4", "anthropic"},
		{"disable", "--report-file", "r.txt"},
	} {
		code, out, errOut := runReport(reportEnv(t, true, nil), args...)
		want := "leakguard: flag provided but not defined: -report-file\nRun \"leakguard help\" for usage.\n"
		if code != 2 || out != "" || errOut != want {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want exit 2 and the undefined flag", args[0], code, out, errOut)
		}
	}
}
