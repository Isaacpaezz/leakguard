//go:build windows

package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// S1 (SF7): --report-file is defined on Windows, where the tray app passes
// it to the elevated enable and disable.
func TestReportFileFlagIsDefinedOnWindows(t *testing.T) {
	if !reportFileFlag {
		t.Fatal("--report-file is not defined on Windows")
	}
	report := reportFile(t)
	code, _, errOut := runReport(reportEnv(t, false, nil), "disable", "--report-file", report)
	if code != 1 || readReport(t, report) != needAdmin("disable")+"\n" {
		t.Errorf("disable --report-file: exit %d, stderr %q, report %q", code, errOut, readReport(t, report))
	}
}

// S1 (SF4): the report file this process created is owned by its token's
// user or default owner, so writing it passes the owner check; the
// invoker's SIDs are known.
func TestReportOwnerOfAFileThisUserCreated(t *testing.T) {
	report := reportFile(t)
	f, err := os.OpenFile(report, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := checkReportOwner(report, f); err != nil {
		t.Fatalf("checkReportOwner() = %v", err)
	}
	if err := writeReport(report, errors.New("busy")); err != nil || readReport(t, report) != "busy\n" {
		t.Fatalf("writeReport() = %v, report %q", err, readReport(t, report))
	}
	ids, err := invokerSIDs()
	if err != nil || len(ids) == 0 || strings.Join(ids, "") == "" {
		t.Fatalf("invokerSIDs() = %q, %v", ids, err)
	}
}
