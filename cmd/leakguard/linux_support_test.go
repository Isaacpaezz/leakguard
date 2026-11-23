package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/daemon"
	"github.com/Isaacpaezz/leakguard/internal/stats"
)

// withUsage makes the help that of goos for one test.
func withUsage(t *testing.T, goos string) {
	t.Helper()
	old := usage
	usage = usageFor(goos)
	t.Cleanup(func() { usage = old })
}

// S2: the macOS help is byte-identical to the one shipped in 0.1.0.
func TestUsageOnMacOSIsUnchanged(t *testing.T) {
	const want = "978865cdec190dbba50c5a6d9fc7cc8132f1eab9d39401e8acc3631a85049255"
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(usageFor("darwin")))); got != want {
		t.Fatalf("macOS usage changed: sha256 %s, want %s\n%s", got, want, usageFor("darwin"))
	}
	if runtime.GOOS == "darwin" && usage != usageFor("darwin") {
		t.Fatal("usage on macOS is not the macOS text")
	}
}

// S1: the Linux help names the Linux firewall, paths and tray app.
func TestUsageOnLinux(t *testing.T) {
	got := usageFor("linux")
	for _, want := range []string{
		"verifies as root that the nftables firewall rules are\n      loaded;",
		"run to /var/log/leakguard.log, keeps the session stats in\n      /var/lib/leakguard/stats.json, and answers the tray app on\n      /run/leakguard.sock. Only administrators can talk to it.\n",
		"It also ends a pause from the tray app.",
		"sudo leakguard enable --vpn wg0 anthropic",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Linux usage lacks %q", want)
		}
	}
	for _, bad := range []string{"pf ", "/Library", "/var/run", "launchd", "LaunchDaemon", "menu-bar", "ipsec0"} {
		if strings.Contains(got, bad) {
			t.Errorf("Linux usage names %q", bad)
		}
	}
	if runtime.GOOS == "linux" {
		if usage != got {
			t.Error("usage on Linux is not the Linux text")
		}
		for _, p := range []string{stats.DefaultPath, daemon.SystemdLogPath} {
			if !strings.Contains(got, p) {
				t.Errorf("Linux usage lacks the real path %s", p)
			}
		}
	}
}

func TestViaExamplePerOS(t *testing.T) {
	if got := viaExampleFor("darwin"); got != "en0" {
		t.Errorf("viaExampleFor(darwin) = %q, want en0", got)
	}
	if got := viaExampleFor("linux"); got != "eth0" {
		t.Errorf("viaExampleFor(linux) = %q, want eth0", got)
	}
}

const procRoute = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT                                                       \n" +
	"eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0                                                                               \n" +
	"eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0                                                                               \n" +
	"docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0                                                                               \n"

// A VPN that takes the default route with a lower metric, plus a rejected
// default route that must never be picked.
const procRouteVPN = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
	"wlp2s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
	"wg0\t00000000\t00000000\t0001\t0\t0\t50\t00000000\t0\t0\t0\n" +
	"lo\t00000000\t00000000\t0201\t0\t0\t0\t00000000\t0\t0\t0\n" +
	"wlp2s0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n"

// OpenVPN's def1 routes (0.0.0.0/1 and 128.0.0.0/1) are not the default route.
const procRouteDef1 = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
	"tun0\t00000000\t0100080A\t0003\t0\t0\t0\t00000080\t0\t0\t0\n" +
	"tun0\t00000080\t0100080A\t0003\t0\t0\t0\t00000080\t0\t0\t0\n" +
	"enp3s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"

const procIPv6Route = "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001   enp3s0\n" +
	"00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n" +
	"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00450003   enp3s0\n"

const procIPv6RouteNoDefault = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n"

func writeProc(t *testing.T, v4, v6 string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "proc", "net")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if v4 != "-" {
		os.WriteFile(filepath.Join(dir, "route"), []byte(v4), 0o444)
	}
	if v6 != "-" {
		os.WriteFile(filepath.Join(dir, "ipv6_route"), []byte(v6), 0o444)
	}
	return root
}

// S1: "leakguard test" finds the real connection on Linux from /proc.
func TestProcDefaultInterface(t *testing.T) {
	for _, tc := range []struct {
		name, v4, v6, want, err string
	}{
		{"ethernet", procRoute, procIPv6RouteNoDefault, "eth0", ""},
		{"VPN default route has the lowest metric", procRouteVPN, "", "wg0", ""},
		{"OpenVPN def1 routes are not the default", procRouteDef1, "", "enp3s0", ""},
		{"IPv6 only", "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n", procIPv6Route, "enp3s0", ""},
		{"IPv6 disabled", procRoute, "-", "eth0", ""},
		{"no default route", "Iface\tDestination\n", procIPv6RouteNoDefault, "", "no default route found"},
		{"unreadable", "-", "-", "", "route: no such file or directory"},
		{"invalid name", "Iface\tDestination\nbad/name\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n", "", "", `default route has an invalid interface name "bad/name"`},
	} {
		got, err := procDefaultInterface(writeProc(t, tc.v4, tc.v6))
		if got != tc.want || (tc.err == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("%s: procDefaultInterface() = %q, %v; want %q, %q", tc.name, got, err, tc.want, tc.err)
		}
	}
}

type fakeSystemctl struct{ calls []string }

func (f *fakeSystemctl) Run(args ...string) (string, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	return "", nil
}

// S1: enable, status and disable drive systemd through Env.Systemctl.
func TestSystemdServicesThroughTheCLI(t *testing.T) {
	h := newHarness(t, true)
	sc := &fakeSystemctl{}
	h.env.Systemctl = sc
	h.env.Services = systemdServices
	code, out, errOut := h.run("enable", "--vpn", "ipsec0", "anthropic")
	expect(t, code, out, errOut, 0, []string{"Protected through ipsec0"}, nil)
	if data, err := os.ReadFile(h.path(daemon.UnitPath)); err != nil || string(data) != daemon.Unit(daemon.BinaryPath) {
		t.Fatalf("unit = %q, %v", data, err)
	}
	code, out, errOut = h.run("status")
	expect(t, code, out, errOut, 0, []string{"Background service: installed"}, nil)
	code, out, errOut = h.run("disable")
	expect(t, code, out, errOut, 0, []string{"Protection disabled."}, nil)
	want := "daemon-reload|enable leakguard.service|restart leakguard.service|stop leakguard.service|disable leakguard.service|daemon-reload"
	if got := strings.Join(sc.calls, "|"); got != want {
		t.Errorf("systemctl calls = %q, want %q", got, want)
	}
	if len(h.launchctl.calls) != 0 || exists(h.path(daemon.PlistPath)) {
		t.Errorf("launchd was used: %v", h.launchctl.calls)
	}
	if _, err := h.loadConfig(t); err != nil {
		t.Errorf("disable lost the configuration: %v", err)
	}
}
