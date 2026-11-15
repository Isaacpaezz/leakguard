// Command readmegen regenerates the generated sections of README.md from the
// service catalog and CHANGELOG.md. With -check it only reports drift.
//
//	go run ./tools/readmegen          # rewrite README.md
//	go run ./tools/readmegen -check   # exit 1 when README.md is stale
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/readme"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("readmegen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", ".", "repository root")
	check := fs.Bool("check", false, "fail instead of writing when README.md is out of date")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	fail := func(err error) int {
		fmt.Fprintf(stderr, "readmegen: %v\n", err)
		return 1
	}
	services, err := catalog.Load(filepath.Join(*root, "catalog", "services"))
	if err != nil {
		return fail(err)
	}
	changelog, err := os.ReadFile(filepath.Join(*root, "CHANGELOG.md"))
	if err != nil {
		return fail(err)
	}
	readmePath := filepath.Join(*root, "README.md")
	current, err := os.ReadFile(readmePath)
	if err != nil {
		return fail(err)
	}
	// Windows checkouts may use CRLF; generate and compare with LF only.
	current = bytes.ReplaceAll(current, []byte("\r\n"), []byte("\n"))
	changelog = bytes.ReplaceAll(changelog, []byte("\r\n"), []byte("\n"))
	next, err := readme.Render(string(current), string(changelog), services)
	if err != nil {
		return fail(err)
	}

	upToDate := bytes.Equal(current, []byte(next))
	switch {
	case *check && upToDate:
		fmt.Fprintln(stdout, "README.md is up to date")
	case *check:
		fmt.Fprintln(stderr, "README.md is out of date; run: go run ./tools/readmegen")
		return 1
	case upToDate:
		fmt.Fprintln(stdout, "README.md is up to date")
	default:
		if err := os.WriteFile(readmePath, []byte(next), 0o644); err != nil {
			return fail(err)
		}
		fmt.Fprintln(stdout, "README.md updated")
	}
	return 0
}
