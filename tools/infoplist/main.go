// Command infoplist prints the Info.plist of leakguard.app for VERSION, a
// release version such as 0.1.0 or 0.1.0-rc.1 (without the leading v of
// the tag). scripts/build-macos.sh uses it:
//
//	go run ./tools/infoplist 0.1.0 > leakguard.app/Contents/Info.plist
package main

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// versionPattern is a semantic version without build metadata: numbers
// without leading zeros, then an optional pre-release of letters, digits,
// dots and hyphens. Nothing else can reach the plist.
var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z-]+)*)?$`)

const usage = "usage: go run ./tools/infoplist VERSION\n"

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
		fmt.Fprintf(stderr, "infoplist: %q is not a version like 1.2.3 or 1.2.3-rc.1\n%s", v, usage)
		return 2
	}
	fmt.Fprint(stdout, InfoPlist(v))
	return 0
}

// InfoPlist is the bundle's Info.plist for version v, already validated.
// macOS reads CFBundleShortVersionString and CFBundleVersion as plain
// numbers, so a pre-release keeps only 1.2.3 there; "leakguard version" and
// the menu's tooltip show the full version.
func InfoPlist(v string) string {
	core, _, _ := strings.Cut(v, "-")
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>es</string>
	<key>CFBundleDisplayName</key>
	<string>leakguard</string>
	<key>CFBundleExecutable</key>
	<string>leakguard-menubar</string>
	<key>CFBundleIconFile</key>
	<string>AppIcon</string>
	<key>CFBundleIdentifier</key>
	<string>dev.leakguard.menubar</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>leakguard</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>` + core + `</string>
	<key>CFBundleVersion</key>
	<string>` + core + `</string>
	<key>LSMinimumSystemVersion</key>
	<string>13.0</string>
	<key>LSUIElement</key>
	<true/>
	<key>NSHumanReadableCopyright</key>
	<string>MIT License</string>
</dict>
</plist>
`
}
