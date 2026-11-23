//go:build !windows

package config

import "testing"

// hostNames returns interface names the host's rules refuse. macOS and
// Linux judge these by name (Linux finds no such interface in sysfs).
func hostNames(*testing.T) testNames {
	return testNames{invalid: "ipsec0 all", loopback: "lo0", physical: "en0"}
}
