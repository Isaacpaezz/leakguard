package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// windowsAdapter is what GetAdaptersAddresses says about one network
// adapter. The config stores its alias (the friendly name).
type windowsAdapter struct {
	alias       string // FriendlyName, e.g. "WireGuard Tunnel"
	description string // e.g. "Intel(R) Wi-Fi 6 AX201 160MHz"
	ifType      uint32 // IfType (ipifcons.h)
	up          bool   // OperStatus is IfOperStatusUp
	hasMAC      bool   // PhysicalAddressLength > 0
}

// Interface types of Windows adapters (ipifcons.h).
const (
	winEthernet = 6
	winPPP      = 23
	winLoopback = 24
	winVirtual  = 53 // IF_TYPE_PROP_VIRTUAL: Wintun, WireGuard
	winWiFi     = 71
	winTunnel   = 131
)

// maxAliasBytes bounds an adapter alias (IF_MAX_STRING_SIZE is 256 UTF-16
// characters; 256 bytes is stricter for non-ASCII names).
const maxAliasBytes = 256

// Adapter descriptions, matched ignoring case. Only the allow-lists accept;
// anything else is refused (fail closed).
var (
	// VPN adapters accepted with a tunnel, PPP or virtual interface type.
	winVPNDescriptions = []string{"TAP-Windows", "Wintun", "WireGuard", "OpenVPN", "AnyConnect", "Fortinet", "FortiClient"}
	// VPN adapters that present themselves as Ethernet.
	winEthernetVPNDescriptions = []string{"TAP-Windows", "Wintun", "WireGuard"}
	winVMDescriptions          = []string{"Hyper-V", "vEthernet", "VirtualBox", "VMware"}
	// IPv6 transition tunnels and Bluetooth ride on the real connection.
	winRealDescriptions = []string{"Bluetooth", "Teredo", "ISATAP", "6to4", "IP-HTTPS"}
	// Names of real connections, for an adapter that does not exist.
	winRealNames = []string{"Ethernet", "Wi-Fi", "WLAN", "Local Area Connection", "Conexión de área local", "Bluetooth", "vEthernet"}
)

// validWindowsAlias reports whether name can be an adapter alias.
func validWindowsAlias(name string) bool {
	if name == "" || len(name) > maxAliasBytes || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// checkWindows decides by what Windows says about the adapter. An adapter
// that does not exist (the VPN is down) is judged by its name: rules
// naming it block everything until it comes back. Aliases are matched
// ignoring case, like Windows resolves them.
func (r rules) checkWindows(name string) error {
	adapters, err := r.listAdapters()
	if err != nil {
		return fmt.Errorf("cannot tell whether %q is a VPN interface: %w", name, err)
	}
	found := false
	for _, a := range adapters {
		if strings.EqualFold(a.alias, name) {
			found = true
			if err := classifyWindows(name, a); err != nil {
				return err
			}
		}
	}
	if !found && hasPrefixFold(name, winRealNames) {
		return realConnection(name)
	}
	return nil
}

func (r rules) listAdapters() ([]windowsAdapter, error) {
	if r.adapters == nil {
		return nil, errors.New("the network adapters cannot be listed")
	}
	return r.adapters()
}

// same compares interface names like the system resolves them: Windows
// adapter aliases ignoring case, other names exactly.
func (r rules) same(a, b string) bool {
	if r.goos == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// canonical returns the name of names that is name, ignoring case on
// Windows (an exact match first), or name when none is.
func (r rules) canonical(name string, names []string) string {
	if r.goos != "windows" || slices.Contains(names, name) {
		return name
	}
	for _, n := range names {
		if strings.EqualFold(n, name) {
			return n
		}
	}
	return name
}

// windowsCandidates keeps the names of connected VPN adapters.
func (r rules) windowsCandidates(names []string) []string {
	adapters, err := r.listAdapters()
	if err != nil {
		return nil
	}
	var out []string
	for _, n := range names {
		if !validWindowsAlias(n) {
			continue
		}
		up := false
		for _, a := range adapters {
			if strings.EqualFold(a.alias, n) && a.up {
				up = true
			}
		}
		if up && r.checkWindows(n) == nil {
			out = append(out, n)
		}
	}
	return out
}

// classifyWindows accepts tunnels, PPP and RAS connections (the built-in
// IKEv2, SSTP and L2TP VPNs) and the adapters of known VPN clients.
func classifyWindows(name string, a windowsAdapter) error {
	desc := a.description
	switch {
	case a.ifType == winLoopback || containsFold(desc, []string{"Loopback"}):
		return fmt.Errorf("%q is not a VPN interface; it is the loopback", name)
	case containsFold(desc, winVMDescriptions) || hasPrefixFold(a.alias, []string{"vEthernet"}):
		return fmt.Errorf("%q is not a VPN interface; it is a virtual machine adapter", name)
	case a.ifType == winWiFi || containsFold(desc, winRealDescriptions):
		return realConnection(name)
	}
	switch a.ifType {
	case winPPP, winTunnel, winVirtual:
		if containsFold(desc, winVPNDescriptions) {
			return nil
		}
		// RAS connections have no hardware address. A PPPoE WAN Miniport
		// (PPP without a MAC) is accepted here too, like Linux ppp0: it
		// is the real connection of some DSL users, but Windows cannot
		// tell it from a PPP VPN, and the setup wizard picks the adapter
		// that appears when the VPN connects.
		if a.ifType != winVirtual && !a.hasMAC {
			return nil
		}
	case winEthernet:
		// AnyConnect and Fortinet adapters that report Ethernet are
		// refused (fail closed): only these descriptions are trusted on
		// an Ethernet type; the others need a tunnel, PPP or virtual one.
		if containsFold(desc, winEthernetVPNDescriptions) {
			return nil
		}
		return realConnection(name)
	}
	return fmt.Errorf("%q is not a VPN interface; it is not a known VPN adapter", name)
}

func containsFold(s string, subs []string) bool {
	s = strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(s, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

func hasPrefixFold(s string, prefixes []string) bool {
	s = strings.ToLower(s)
	for _, p := range prefixes {
		if strings.HasPrefix(s, strings.ToLower(p)) {
			return true
		}
	}
	return false
}
