// Command debversion prints the Debian package version for VERSION, a
// release version such as 0.2.0 or 0.2.0-beta.1 (without the leading v of
// the tag). scripts/build-linux.sh uses it for the .deb's control file:
//
//	go run ./tools/debversion 0.2.0-beta.1   # prints 0.2.0~beta.1
package main

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// versionPattern is the release version rule of tools/infoplist and
// scripts/build-macos.sh: numbers without leading zeros, then an optional
// pre-release of letters, digits, dots and hyphens. Nothing else can reach
// the control file.
var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z-]+)*)?$`)

const usage = "usage: go run ./tools/debversion VERSION\n"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	v := args[0]
	if !versionPattern.MatchString(v) {
		fmt.Fprintf(stderr, "debversion: %q is not a version like 1.2.3 or 1.2.3-rc.1\n%s", v, usage)
		return 2
	}
	fmt.Fprintln(stdout, Debian(v))
	return 0
}

// Debian is the Debian version of v, already validated. dpkg sorts "~"
// before anything, even the end of the version, so 0.2.0~beta.1 comes
// before 0.2.0, like the pre-release 0.2.0-beta.1 does in semantic
// versioning. A Debian version without a revision may not contain a
// hyphen, so every hyphen of the pre-release becomes a tilde.
func Debian(v string) string { return strings.ReplaceAll(v, "-", "~") }
