package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func repo(t *testing.T, changelog string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "CHANGELOG.md"), []byte(changelog), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

const released = "# Changelog\n\n## [Unreleased]\n\n## [0.1.0] - 2026-11-20\n\n### Added\n- The macOS app.\n\n## [0.0.1] - 2026-11-01\n\n- Old.\n"

// S1: the release notes are the newest CHANGELOG section.
func TestNotes(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"-root", repo(t, released), "-version", "0.1.0"}, &out, &errb)
	if code != 0 || errb.String() != "" {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	if want := "**v0.1.0** · 2026-11-20\n\n**Added**\n- The macOS app.\n"; out.String() != want {
		t.Errorf("notes = %q, want %q", out.String(), want)
	}
}

// A tag without its own CHANGELOG section stops the release.
func TestNotesRequireTheTagSection(t *testing.T) {
	for _, tc := range []struct{ changelog, version string }{
		{released, "0.2.0"},
		{released, "0.1"},
		{"# Changelog\n\n## [Unreleased]\n\n- Pending.\n", "0.1.0"},
	} {
		var out, errb bytes.Buffer
		code := run([]string{"-root", repo(t, tc.changelog), "-version", tc.version}, &out, &errb)
		want := "releasenotes: the newest section of CHANGELOG.md is not ## [" + tc.version + "]; add it before pushing the tag\n"
		if code != 1 || out.String() != "" || errb.String() != want {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want 1, nothing, %q", tc.version, code, out.String(), errb.String(), want)
		}
	}
}

func TestNotesWithoutVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"-root", repo(t, released)}, &out, &errb); code != 2 {
		t.Errorf("exit %d, want 2 (the version is required)", code)
	}
	var out2, errb2 bytes.Buffer
	if code := run([]string{"-root", t.TempDir(), "-version", "0.1.0"}, &out2, &errb2); code != 1 || errb2.Len() == 0 {
		t.Errorf("missing CHANGELOG: exit %d, stderr %q", code, errb2.String())
	}
}
