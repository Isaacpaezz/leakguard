package config

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// fakeIface adds an interface to a fake /sys/class/net tree: its link type,
// its flags and the entries (files or links) the kernel would show.
func fakeIface(t *testing.T, root, name string, linkType int, flags string, entries ...string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"type": strconv.Itoa(linkType) + "\n", "flags": flags + "\n"}
	for _, e := range entries {
		files[e] = ""
	}
	for f, data := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// A fake sysfs with one of each kind of Linux interface.
func linuxRules(t *testing.T) rules {
	root := t.TempDir()
	// Refused: physical, wireless, bridges, veth pairs, dummy, loopback.
	fakeIface(t, root, "eth0", 1, "0x1003", "device")
	fakeIface(t, root, "enp3s0", 1, "0x1003", "device")
	fakeIface(t, root, "wlan0", 1, "0x1003", "device", "wireless")
	fakeIface(t, root, "wlp2s0", 1, "0x1003", "device", "phy80211")
	fakeIface(t, root, "docker0", 1, "0x1003", "bridge")
	fakeIface(t, root, "br-1a2b3c", 1, "0x1003", "bridge")
	fakeIface(t, root, "virbr0", 1, "0x1003", "bridge")
	fakeIface(t, root, "veth1a2b", 1, "0x1003")
	fakeIface(t, root, "vethport", 1, "0x1003", "brport")
	fakeIface(t, root, "dummy0", 1, "0x83")
	fakeIface(t, root, "lo", 772, "0x9")
	// A tunnel-like link type on real hardware is still the real connection.
	fakeIface(t, root, "wwan0", 65534, "0x1091", "device")
	// Accepted: tun/tap, wireguard, PPP, IPv4 and IPv6 tunnels.
	fakeIface(t, root, "tun0", 65534, "0x1091", "tun_flags")
	fakeIface(t, root, "tap0", 1, "0x1003", "tun_flags")
	fakeIface(t, root, "wg-mullvad", 65534, "0x91")
	fakeIface(t, root, "proton0", 65534, "0x91")
	fakeIface(t, root, "ppp0", 512, "0x1091")
	fakeIface(t, root, "vti0", 768, "0x91")
	fakeIface(t, root, "ip6tnl0", 769, "0x91")
	return rules{goos: "linux", sysfs: root}
}

func TestLinuxRefusesNonVPNInterfaces(t *testing.T) {
	r := linuxRules(t)
	cases := map[string]string{
		"eth0":      "it carries your real connection",
		"enp3s0":    "it carries your real connection",
		"wlan0":     "it carries your real connection",
		"wlp2s0":    "it carries your real connection",
		"wwan0":     "it carries your real connection",
		"docker0":   "it is a bridge",
		"br-1a2b3c": "it is a bridge",
		"virbr0":    "it is a bridge",
		"vethport":  "it is a bridge",
		"veth1a2b":  "it is not a tunnel",
		"dummy0":    "it is not a tunnel",
		"lo":        "it is the loopback",
	}
	var names []string
	for name, want := range cases {
		names = append(names, name)
		err := r.check(name)
		if err == nil || !strings.Contains(err.Error(), strconv.Quote(name)+" is not a VPN interface; "+want) {
			t.Errorf("check(%q) = %v, want %q", name, err, want)
		}
	}
	if got := r.candidates(names); len(got) != 0 {
		t.Errorf("candidates() = %v, want none", got)
	}
}

func TestLinuxAcceptsTunnels(t *testing.T) {
	r := linuxRules(t)
	want := []string{"tun0", "tap0", "wg-mullvad", "proton0", "ppp0", "vti0", "ip6tnl0"}
	for _, name := range want {
		if err := r.check(name); err != nil {
			t.Errorf("check(%q) = %v", name, err)
		}
	}
	in := append([]string{"lo", "eth0", "wlan0", "docker0", "veth1a2b"}, want...)
	if got := r.candidates(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates() = %v, want %v", got, want)
	}
}

// A VPN that is down has no interface: rules naming it block everything, so
// it is judged by its name, and real-connection names are still refused.
func TestLinuxJudgesAMissingInterfaceByName(t *testing.T) {
	r := rules{goos: "linux", sysfs: t.TempDir()}
	for _, ok := range []string{"wg0", "tun1", "mullvad"} {
		if err := r.check(ok); err != nil {
			t.Errorf("check(%q) = %v", ok, err)
		}
	}
	for _, name := range []string{"lo", "eth1", "enp0s31f6", "wlan1", "wlp3s0", "docker0", "br-x", "virbr1", "veth9", "dummy1",
		"bond0", "usb0", "rndis0", "rmnet_data0", "ib0", "vlan10", "macvlan0", "macvtap0", "ipvlan0", "team0", "vxlan0"} {
		err := r.check(name)
		if err == nil || !strings.Contains(err.Error(), strconv.Quote(name)+" is not a VPN interface") {
			t.Errorf("check(%q) = %v, want a refusal naming it", name, err)
		}
	}
	if got, want := r.candidates([]string{"wg0", "eth1", "mullvad", "tun1"}), []string{"wg0", "tun1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("candidates() = %v, want %v", got, want)
	}
}

// An interface whose kernel facts cannot be read is refused, never assumed.
func TestLinuxRefusesUnreadableFacts(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "wg0"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := rules{goos: "linux", sysfs: root}
	if err := r.check("wg0"); err == nil || !strings.Contains(err.Error(), `cannot tell whether "wg0" is a VPN interface`) {
		t.Fatalf("check() = %v, want a refusal", err)
	}
	if got := r.candidates([]string{"wg0"}); len(got) != 0 {
		t.Fatalf("candidates() = %v, want none", got)
	}
}

func TestLinuxInterfaceNames(t *testing.T) {
	r := rules{goos: "linux", sysfs: t.TempDir()}
	for name, want := range map[string]bool{
		"wg-mullvad":       true,
		"tun.vpn":          true,
		"Proton_0":         true,
		"0vpn":             true,
		"a":                true,
		"abcdefghijklmno":  true,  // 15 characters, the kernel's limit
		"abcdefghijklmnop": false, // 16
		"":                 false,
		"-wg":              false,
		".tun":             false,
		"_wg":              false,
		"wg 0":             false,
		"wg/0":             false,
		"wg0;":             false,
		"wg\"0":            false,
	} {
		if got := r.validName(name); got != want {
			t.Errorf("validName(%q) = %v, want %v", name, got, want)
		}
	}
	if err := r.check("wg/../../x"); err == nil || !strings.Contains(err.Error(), "not a valid interface name") {
		t.Errorf("check() = %v, want an invalid name", err)
	}
}

// Until Windows gets its own rules, no interface is ever accepted there.
func TestWindowsRefusesEveryVPNInterface(t *testing.T) {
	r := rules{goos: "windows"}
	for _, name := range []string{"utun4", "wg0", "Mullvad", "Ethernet 2"} {
		err := r.check(name)
		if err == nil || err.Error() != "choosing a VPN interface is not supported on Windows yet" {
			t.Errorf("check(%q) = %v", name, err)
		}
	}
	if err := r.check(""); err == nil || err.Error() != "VPN interface is not set" {
		t.Errorf("check(\"\") = %v", err)
	}
	if got := r.candidates([]string{"utun4", "wg0", "tun1"}); len(got) != 0 {
		t.Errorf("candidates() = %v, want none", got)
	}
}

// macOS keeps exactly the classification it had before Linux and Windows.
func TestDarwinRulesUnchanged(t *testing.T) {
	r := rules{goos: "darwin"}
	in := []string{"lo0", "en0", "utun4", "ipsec0", "awdl0", "ppp0", "wg0", "tun1", "bridge0", "tap2", "llw0", "anpi0", "gif0", "stf0", "ap1"}
	if got, want := r.candidates(in), []string{"utun4", "ipsec0", "ppp0", "wg0", "tun1", "tap2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates() = %v, want %v", got, want)
	}
	for _, ok := range []string{"ipsec0", "utun4", "wg0", "ppp0", "tun1", "tap2"} {
		if err := r.check(ok); err != nil {
			t.Errorf("check(%q) = %v", ok, err)
		}
	}
	cases := map[string]string{
		"":                 "VPN interface is not set",
		"ipsec0 all":       "not a valid interface name",
		"Ipsec0":           "not a valid interface name",
		"wg-mullvad":       "not a valid interface name",
		"abcdefghijklmnop": "not a valid interface name",
		"en0":              `"en0" is not a VPN interface; it carries your real connection`,
		"lo0":              `"lo0" is not a VPN interface; it carries your real connection`,
		"bridge0":          `"bridge0" is not a VPN interface; it carries your real connection`,
		"awdl0":            `"awdl0" is not a VPN interface; it carries your real connection`,
	}
	for name, want := range cases {
		if err := r.check(name); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("check(%q) = %v, want %q", name, err, want)
		}
	}
	if !r.validName("abcdefghijklmno") || r.validName("tun.vpn") {
		t.Error("validName() changed on macOS")
	}
}

// The exported functions use the rules of the system they run on.
func TestHostRulesFollowTheOS(t *testing.T) {
	want := map[string]string{"linux": "linux", "windows": "windows"}[runtime.GOOS]
	if want == "" {
		want = "darwin"
	}
	if host.goos != want {
		t.Fatalf("host.goos = %q, want %q", host.goos, want)
	}
	if want == "linux" && host.sysfs != "/sys/class/net" {
		t.Fatalf("host.sysfs = %q", host.sysfs)
	}
}

func TestPathPerOS(t *testing.T) {
	cases := []struct{ goos, programData, want string }{
		{"darwin", "", "/Library/Application Support/leakguard/config.json"},
		{"linux", "", "/etc/leakguard/config.json"},
		{"windows", `D:\Data`, `D:\Data\leakguard\config.json`},
		{"windows", `D:\Data\`, `D:\Data\leakguard\config.json`},
		{"windows", "", `C:\ProgramData\leakguard\config.json`},
	}
	for _, tc := range cases {
		if got := pathFor(tc.goos, tc.programData); got != tc.want {
			t.Errorf("pathFor(%q, %q) = %q, want %q", tc.goos, tc.programData, got, tc.want)
		}
	}
	if runtime.GOOS != "windows" && DefaultPath != pathFor(runtime.GOOS, "") {
		t.Errorf("DefaultPath = %q, want %q", DefaultPath, pathFor(runtime.GOOS, ""))
	}
}
