// Package version holds the leakguard version. Release builds set it with
//
//	go build -ldflags "-X github.com/Isaacpaezz/leakguard/internal/version.Version=0.1.0"
//
// (see scripts/build-macos.sh); any other build reports "dev".
package version

import "strings"

// Version is set at link time; it is "dev" for development builds.
var Version = "dev"

// String is Version, or "dev" when it was set to nothing.
func String() string {
	if v := strings.TrimSpace(Version); v != "" {
		return v
	}
	return "dev"
}
