package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/probe"
)

// Route flags of the Linux kernel (linux/route.h).
const (
	rtfUp     = 0x0001
	rtfReject = 0x0200
)

// routeDefaultInterface asks macOS's route command for the default route.
func routeDefaultInterface() (string, error) {
	out, err := exec.Command("/sbin/route", "-n", "get", "default").Output()
	if err != nil {
		return "", err
	}
	return probe.ParseDefaultRoute(string(out))
}

// procDefaultInterface returns the interface of the Linux default route
// with the lowest metric, from root/proc/net/route, or from
// root/proc/net/ipv6_route when there is no IPv4 one. Empty root is "/".
func procDefaultInterface(root string) (string, error) {
	v4, err := os.ReadFile(filepath.Join(root, "/proc/net/route"))
	if err != nil {
		return "", err
	}
	name := bestRoute(string(v4), parseIPv4Route)
	if name == "" {
		// Missing when IPv6 is disabled.
		v6, _ := os.ReadFile(filepath.Join(root, "/proc/net/ipv6_route"))
		name = bestRoute(string(v6), parseIPv6Route)
	}
	if name == "" {
		return "", errors.New("no default route found")
	}
	if !config.ValidInterfaceName(name) {
		return "", fmt.Errorf("default route has an invalid interface name %q", name)
	}
	return name, nil
}

// bestRoute returns the interface of the usable default route with the
// lowest metric, or "".
func bestRoute(table string, parse func([]string) (string, uint64, bool)) string {
	best, bestMetric := "", uint64(0)
	for _, line := range strings.Split(table, "\n") {
		name, metric, ok := parse(strings.Fields(line))
		if ok && (best == "" || metric < bestMetric) {
			best, bestMetric = name, metric
		}
	}
	return best
}

func usableRoute(flags string) bool {
	f, err := strconv.ParseUint(flags, 16, 32)
	return err == nil && f&rtfUp != 0 && f&rtfReject == 0
}

// parseIPv4Route reads one /proc/net/route line: Iface Destination Gateway
// Flags RefCnt Use Metric Mask ..., numbers in hex except Metric.
func parseIPv4Route(f []string) (string, uint64, bool) {
	if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" || !usableRoute(f[3]) {
		return "", 0, false
	}
	metric, err := strconv.ParseUint(f[6], 10, 32)
	return f[0], metric, err == nil
}

// parseIPv6Route reads one /proc/net/ipv6_route line: Destination PrefixLen
// Source SourcePrefixLen NextHop Metric RefCnt Use Flags Iface, in hex.
func parseIPv6Route(f []string) (string, uint64, bool) {
	if len(f) < 10 || f[0] != strings.Repeat("0", 32) || f[1] != "00" || f[9] == "lo" || !usableRoute(f[8]) {
		return "", 0, false
	}
	metric, err := strconv.ParseUint(f[5], 16, 32)
	return f[9], metric, err == nil
}
