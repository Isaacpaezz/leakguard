package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/daemon"
	"github.com/Isaacpaezz/leakguard/internal/firewall"
)

// These tests run on every system: the tray app on Windows passes
// --report-file to the elevated enable and disable, whose console it
// cannot read, and shows the error they write there.

// reportFirewall is a firewall that loads and flushes nothing, or fails
// with flushErr.
type reportFirewall struct{ flushErr error }

func (reportFirewall) Name() string                           { return "test firewall" }
func (reportFirewall) Apply(string, []catalog.Service) error  { return nil }
func (f reportFirewall) Flush() error                         { return f.flushErr }
func (reportFirewall) Enabled() (bool, error)                 { return true, nil }
func (reportFirewall) Verify(string, []catalog.Service) error { return nil }
func (reportFirewall) BlockCount() (uint64, error)            { return 0, firewall.ErrUnsupported }

// reportServices is a service manager that installs and removes nothing.
type reportServices struct{}

func (reportServices) Install(string) error        { return nil }
func (reportServices) Uninstall() error            { return nil }
func (reportServices) Installed() bool             { return false }
func (reportServices) LegacyInstalled() bool       { return false }
func (reportServices) LastLogLine() (string, bool) { return "", false }

var _ daemon.Manager = reportServices{}

// reportEnv is an administrator (or not) on a system whose firewall
// fails to flush with flushErr.
func reportEnv(t *testing.T, admin bool, flushErr error) Env {
	t.Helper()
	return Env{
		IsRoot:     func() bool { return admin },
		Root:       t.TempDir(),
		Firewall:   func(Env) firewall.Firewall { return reportFirewall{flushErr} },
		Services:   func(Env) daemon.Manager { return reportServices{} },
		Interfaces: func() ([]Interface, error) { return nil, nil },
	}
}

// reportFile is an empty report file, as the tray app creates it.
func reportFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "leakguard-report.txt")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runReport(env Env, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr, env)
	return code, stdout.String(), stderr.String()
}

func readReport(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// S1: enable and disable write their final error message to the report
// file, the same text stderr shows after "leakguard: ", and exit as
// without the flag.
func TestReportFileGetsTheFinalError(t *testing.T) {
	flushFailed := errors.New("the filter engine is busy")
	tests := []struct {
		name     string
		admin    bool
		flushErr error
		args     []string
		code     int
		want     string
	}{
		{"enable without administrator rights", false, nil,
			[]string{"enable", "--vpn", "WireGuard Tunnel", "anthropic"}, 1, needAdmin("enable")},
		{"disable without administrator rights", false, nil,
			[]string{"disable"}, 1, needAdmin("disable")},
		{"disable whose firewall fails", true, flushFailed,
			[]string{"disable"}, 1, "could not remove the firewall rules: the filter engine is busy"},
		{"enable of an unknown service", true, nil,
			[]string{"enable", "--vpn", "wg0", "nope"}, 1, `unknown service "nope"`},
		{"enable without services: a usage error", true, nil,
			[]string{"enable", "--vpn", "wg0"}, 2, "name at least one service, for example: "},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := reportFile(t)
			args := append([]string{tc.args[0], "--report-file", report}, tc.args[1:]...)
			code, out, errOut := runReport(reportEnv(t, tc.admin, tc.flushErr), args...)
			plainCode, plainOut, plainErr := runReport(reportEnv(t, tc.admin, tc.flushErr), tc.args...)
			if code != tc.code || code != plainCode || out != plainOut || errOut != plainErr {
				t.Errorf("with the report file: %d, %q, %q; without: %d, %q, %q; want exit %d and the same output",
					code, out, errOut, plainCode, plainOut, plainErr, tc.code)
			}
			got := readReport(t, report)
			if !strings.HasPrefix(got, tc.want) || !strings.HasSuffix(got, "\n") || strings.Count(got, "\n") != 1 {
				t.Errorf("report = %q, want %q and one newline", got, tc.want)
			}
			if !strings.Contains(errOut, "leakguard: "+strings.TrimSuffix(got, "\n")+"\n") {
				t.Errorf("stderr %q does not hold the reported message %q", errOut, got)
			}
		})
	}
}

// S1: a successful run writes nothing to the report file.
func TestReportFileStaysEmptyOnSuccess(t *testing.T) {
	report := reportFile(t)
	code, out, errOut := runReport(reportEnv(t, true, nil), "disable", "--report-file", report)
	expect(t, code, out, errOut, 0, []string{"Protection disabled."}, nil)
	if got := readReport(t, report); got != "" {
		t.Errorf("report = %q, want empty", got)
	}
}

// S1: the report file must already exist (the tray app creates it): the
// elevated command never creates a file, never follows a link, and a
// report it cannot write is a warning that keeps the exit status.
func TestReportFileIsNeverCreatedOrFollowed(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.txt")
	code, _, errOut := runReport(reportEnv(t, false, nil), "disable", "--report-file", missing)
	if code != 1 || !strings.Contains(errOut, "leakguard: "+needAdmin("disable")+"\n") ||
		!strings.Contains(errOut, "leakguard: warning: could not write the report file: ") {
		t.Errorf("missing report file: exit %d, stderr %q", code, errOut)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the missing report file was created: %v", err)
	}

	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v (Windows needs an elevated test or developer mode)", err)
	}
	code, _, errOut = runReport(reportEnv(t, false, nil), "disable", "--report-file", link)
	if code != 1 || !strings.Contains(errOut, "leakguard: warning: could not write the report file: ") {
		t.Errorf("linked report file: exit %d, stderr %q", code, errOut)
	}
	if got := readReport(t, target); got != "keep" {
		t.Errorf("the link's target became %q", got)
	}
	if err := os.Mkdir(filepath.Join(dir, "folder"), 0o700); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = runReport(reportEnv(t, false, nil), "disable", "--report-file", filepath.Join(dir, "folder"))
	if code != 1 || !strings.Contains(errOut, "leakguard: warning: could not write the report file: ") {
		t.Errorf("folder as the report file: exit %d, stderr %q", code, errOut)
	}
}

// S1: a long message is cut to maxReport bytes, never inside a character.
func TestReportFileIsCapped(t *testing.T) {
	report := reportFile(t)
	long := strings.Repeat("ñ", maxReport) // 2 bytes each
	if err := writeReport(report, errors.New(long)); err != nil {
		t.Fatal(err)
	}
	got := readReport(t, report)
	if len(got) > maxReport || !utf8.ValidString(got) || !strings.HasSuffix(got, "\n") || !strings.HasPrefix(got, "ññ") {
		t.Errorf("capped report: %d bytes, valid UTF-8 %v", len(got), utf8.ValidString(got))
	}
	// A shorter message replaces a longer one entirely.
	if err := writeReport(report, errors.New("short")); err != nil {
		t.Fatal(err)
	}
	if got := readReport(t, report); got != "short\n" {
		t.Errorf("rewritten report = %q, want %q", got, "short\n")
	}
}

// S1: the flag is internal: no help text names it, and the commands that
// do not take it still refuse it.
func TestReportFileIsHidden(t *testing.T) {
	for _, goos := range []string{"darwin", "linux", "windows"} {
		if strings.Contains(usageFor(goos), "report") {
			t.Errorf("the %s help names the report file", goos)
		}
	}
	code, _, errOut := runReport(reportEnv(t, true, nil), "apply", "--report-file", reportFile(t))
	if code != 2 || !strings.Contains(errOut, "flag provided but not defined: -report-file") {
		t.Errorf("apply --report-file: exit %d, stderr %q", code, errOut)
	}
}
