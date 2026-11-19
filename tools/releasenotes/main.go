// Command releasenotes prints the GitHub Release notes for a version: the
// newest released section of CHANGELOG.md, the same text as "What's new" in
// the README. It fails when that section is not the version being released,
// so a tag never ships with the wrong notes.
//
//	go run ./tools/releasenotes -version 0.1.0 > notes.md
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Isaacpaezz/leakguard/internal/readme"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("releasenotes", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", ".", "repository root")
	version := fs.String("version", "", "the version being released, without the leading v")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *version == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: go run ./tools/releasenotes [-root DIR] -version VERSION")
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "releasenotes: "+format+"\n", a...)
		return 1
	}
	changelog, err := os.ReadFile(filepath.Join(*root, "CHANGELOG.md"))
	if err != nil {
		return fail("%v", err)
	}
	changelog = bytes.ReplaceAll(changelog, []byte("\r\n"), []byte("\n"))
	notes, err := readme.LatestChanges(string(changelog))
	if err != nil {
		return fail("%v", err)
	}
	if !strings.HasPrefix(notes, "**v"+*version+"**") {
		return fail("the newest section of CHANGELOG.md is not ## [%s]; add it before pushing the tag", *version)
	}
	fmt.Fprintln(stdout, notes)
	return 0
}
