package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "catalog", "services"), 0o755))
	must(os.WriteFile(filepath.Join(root, "catalog", "services", "openai.json"),
		[]byte(`{"id":"openai","name":"OpenAI","status":"planned"}`), 0o644))
	must(os.WriteFile(filepath.Join(root, "CHANGELOG.md"),
		[]byte("# Changelog\n\n## [Unreleased]\n\n- Pending.\n"), 0o644))
	must(os.WriteFile(filepath.Join(root, "README.md"), []byte(
		"# x\n<!-- BEGIN GENERATED: services -->\n<!-- END GENERATED: services -->\n"+
			"<!-- BEGIN GENERATED: whats-new -->\n<!-- END GENERATED: whats-new -->\n"), 0o644))
	return root
}

func TestRunCheckFailsWhenReadmeIsStale(t *testing.T) {
	root := setupRepo(t)
	before, _ := os.ReadFile(filepath.Join(root, "README.md"))
	var out, errb bytes.Buffer
	code := run([]string{"-root", root, "-check"}, &out, &errb)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if want := "README.md is out of date; run: go run ./tools/readmegen\n"; errb.String() != want {
		t.Fatalf("stderr = %q, want %q", errb.String(), want)
	}
	after, _ := os.ReadFile(filepath.Join(root, "README.md"))
	if !bytes.Equal(before, after) {
		t.Fatal("-check modified README.md")
	}
}

func TestRunWritesThenCheckPasses(t *testing.T) {
	root := setupRepo(t)
	var out, errb bytes.Buffer
	if code := run([]string{"-root", root}, &out, &errb); code != 0 {
		t.Fatalf("write exit = %d, stderr = %q", code, errb.String())
	}
	if out.String() != "README.md updated\n" {
		t.Fatalf("stdout = %q", out.String())
	}
	got, _ := os.ReadFile(filepath.Join(root, "README.md"))
	if !strings.Contains(string(got), "| OpenAI | `openai` |") || !strings.Contains(string(got), "- Pending.") {
		t.Fatalf("README not regenerated:\n%s", got)
	}
	out.Reset()
	errb.Reset()
	if code := run([]string{"-root", root, "-check"}, &out, &errb); code != 0 {
		t.Fatalf("check exit = %d, stderr = %q", code, errb.String())
	}
	if out.String() != "README.md is up to date\n" {
		t.Fatalf("stdout = %q", out.String())
	}
}

func TestRunReportsInvalidCatalog(t *testing.T) {
	root := setupRepo(t)
	os.WriteFile(filepath.Join(root, "catalog", "services", "openai.json"), []byte(`{"id":"openai"}`), 0o644)
	var out, errb bytes.Buffer
	if code := run([]string{"-root", root}, &out, &errb); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.HasPrefix(errb.String(), "readmegen: ") || !strings.Contains(errb.String(), "openai.json") {
		t.Fatalf("stderr = %q", errb.String())
	}
}

func TestRunIsStableOnCRLFFiles(t *testing.T) {
	root := setupRepo(t)
	var out, errb bytes.Buffer
	if code := run([]string{"-root", root}, &out, &errb); code != 0 {
		t.Fatalf("write exit = %d, stderr = %q", code, errb.String())
	}
	path := filepath.Join(root, "README.md")
	lf, _ := os.ReadFile(path)
	os.WriteFile(path, bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n")), 0o644)
	out.Reset()
	if code := run([]string{"-root", root, "-check"}, &out, &errb); code != 0 {
		t.Fatalf("check on CRLF copy exit = %d, stderr = %q", code, errb.String())
	}
}
