package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// rules tell, for one operating system, which interface names are plain and
// which interfaces are VPN tunnels. The package uses host, the rules of the
// system it runs on; tests build the rules of every system.
type rules struct {
	goos  string // "darwin", "linux" or "windows"
	sysfs string // Linux only: the /sys/class/net directory to read
}

// The name is pasted into firewall rules, so only plain interface names pass.
// Linux names may also hold "_", "." and "-" (wg-mullvad, tun.vpn); both
// systems allow 15 characters.
var (
	macName   = regexp.MustCompile(`^[a-z][a-z0-9]{0,14}$`)
	linuxName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)
)

// Prefixes of interfaces that carry the real connection, never a VPN.
var (
	nonVPNPrefixes      = []string{"lo", "en", "bridge", "awdl", "llw", "ap", "anpi", "gif", "stf"}
	linuxNonVPNPrefixes = []string{"lo", "eth", "en", "wl", "ww", "docker", "br", "virbr", "veth", "dummy", "bond"}
)

// Prefixes of interfaces that VPN clients create.
var vpnPrefixes = []string{"utun", "ipsec", "ppp", "tun", "tap", "wg"}

// Linux kernel facts: the IFF_LOOPBACK flag and ARPHRD_* link types.
const (
	iffLoopback    = 0x8
	arphrdLoopback = 772
)

// Link types of tunnels: ARPHRD_NONE (wireguard, xfrm, tun), ARPHRD_PPP,
// ARPHRD_TUNNEL (IPIP, VTI) and ARPHRD_TUNNEL6.
var linuxTunnelTypes = map[int]bool{65534: true, 512: true, 768: true, 769: true}

func (r rules) validName(name string) bool {
	if r.goos == "linux" {
		return linuxName.MatchString(name)
	}
	return macName.MatchString(name)
}

func (r rules) check(name string) error {
	switch {
	case name == "":
		return errors.New("VPN interface is not set")
	case r.goos == "windows":
		return errors.New("choosing a VPN interface is not supported on Windows yet")
	case !r.validName(name):
		return fmt.Errorf("%q is not a valid interface name", name)
	case r.goos == "linux":
		return r.checkLinux(name)
	case hasPrefix(name, nonVPNPrefixes):
		return realConnection(name)
	}
	return nil
}

func (r rules) candidates(names []string) []string {
	var out []string
	for _, n := range names {
		if r.candidate(n) {
			out = append(out, n)
		}
	}
	return out
}

func (r rules) candidate(name string) bool {
	switch r.goos {
	case "windows":
		return false
	case "linux":
		if !r.validName(name) {
			return false
		}
		if _, err := os.Stat(filepath.Join(r.sysfs, name)); errors.Is(err, fs.ErrNotExist) {
			return hasPrefix(name, vpnPrefixes) && r.checkLinux(name) == nil
		}
		return r.checkLinux(name) == nil
	}
	return hasPrefix(name, vpnPrefixes)
}

// checkLinux decides by what the kernel says about the interface, not by its
// name. An interface that does not exist (the VPN is down) is judged by its
// name: rules naming it block everything until it comes back.
func (r rules) checkLinux(name string) error {
	f, err := readLinuxFacts(filepath.Join(r.sysfs, name))
	if errors.Is(err, fs.ErrNotExist) {
		if hasPrefix(name, linuxNonVPNPrefixes) {
			return realConnection(name)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot tell whether %q is a VPN interface: %w", name, err)
	}
	return classifyLinux(name, f)
}

// linuxFacts is what /sys/class/net/<name> shows about an interface.
type linuxFacts struct {
	loopback bool // IFF_LOOPBACK, or the loopback link type
	device   bool // "device": backed by hardware
	wireless bool // "wireless" or "phy80211"
	bridge   bool // "bridge" or "brport": a bridge or one of its ports
	tun      bool // "tun_flags": a tun or tap device
	linkType int  // "type"
}

// classifyLinux accepts only tunnels: tun/tap devices and tunnel link types
// that are not hardware, wireless, bridges or the loopback.
func classifyLinux(name string, f linuxFacts) error {
	switch {
	case f.loopback:
		return fmt.Errorf("%q is not a VPN interface; it is the loopback", name)
	case f.device || f.wireless:
		return realConnection(name)
	case f.bridge:
		return fmt.Errorf("%q is not a VPN interface; it is a bridge", name)
	case f.tun || linuxTunnelTypes[f.linkType]:
		return nil
	}
	return fmt.Errorf("%q is not a VPN interface; it is not a tunnel", name)
}

// readLinuxFacts reads one interface directory. It returns fs.ErrNotExist only
// when the interface does not exist. An entry that cannot be checked counts
// as present, and an unreadable type or flags is an error, so a doubt
// refuses the interface.
func readLinuxFacts(dir string) (linuxFacts, error) {
	if _, err := os.Stat(dir); err != nil {
		return linuxFacts{}, err
	}
	linkType, err := readNumber(filepath.Join(dir, "type"))
	if err != nil {
		return linuxFacts{}, fmt.Errorf("link type: %v", err)
	}
	flags, err := readNumber(filepath.Join(dir, "flags"))
	if err != nil {
		return linuxFacts{}, fmt.Errorf("flags: %v", err)
	}
	has := func(entry string) bool {
		_, err := os.Lstat(filepath.Join(dir, entry))
		return !errors.Is(err, fs.ErrNotExist)
	}
	return linuxFacts{
		loopback: flags&iffLoopback != 0 || linkType == arphrdLoopback,
		device:   has("device"),
		wireless: has("wireless") || has("phy80211"),
		bridge:   has("bridge") || has("brport"),
		tun:      has("tun_flags"),
		linkType: int(linkType),
	}, nil
}

// readNumber reads a sysfs number such as "1" or "0x1003".
func readNumber(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 0, 32)
}

func realConnection(name string) error {
	return fmt.Errorf("%q is not a VPN interface; it carries your real connection", name)
}

func hasPrefix(name string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// pathFor is where the configuration lives on goos. programData is
// %ProgramData% on Windows.
func pathFor(goos, programData string) string {
	switch goos {
	case "linux":
		return "/etc/leakguard/config.json"
	case "windows":
		return windowsDir(programData) + `\config.json`
	}
	return "/Library/Application Support/leakguard/config.json"
}

func windowsDir(programData string) string {
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return strings.TrimRight(programData, `\/`) + `\leakguard`
}
