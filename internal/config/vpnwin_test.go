package config

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Interface types of the Windows adapters in the tests (ipifcons.h).
const (
	tEthernet = 6
	tPPP      = 23
	tLoopback = 24
	tVirtual  = 53
	tWiFi     = 71
	tTunnel   = 131
)

// windowsAdaptersFixture is one of each kind of Windows adapter, connected.
var windowsAdaptersFixture = []windowsAdapter{
	// Accepted.
	{alias: "WireGuard Tunnel", description: "WireGuard Tunnel", ifType: tVirtual, up: true},
	{alias: "Conexión VPN", description: "Conexión VPN", ifType: tPPP, up: true},
	{alias: "Work IKEv2", description: "Work IKEv2", ifType: tTunnel, up: true},
	{alias: "OpenVPN Wintun", description: "Wintun Userspace Tunnel", ifType: tVirtual, up: true},
	{alias: "OpenVPN Data Channel Offload", description: "OpenVPN Data Channel Offload", ifType: tVirtual, up: true},
	{alias: "Ethernet 3", description: "TAP-Windows Adapter V9", ifType: tEthernet, up: true, hasMAC: true},
	{alias: "Mullvad", description: "WireGuard Tunnel #2", ifType: tEthernet, up: true, hasMAC: true},
	{alias: "Cisco", description: "Cisco AnyConnect Secure Mobility Client Virtual Miniport Adapter", ifType: tVirtual, up: true},
	{alias: "Forti", description: "Fortinet Virtual Ethernet Adapter (NDIS 6.30)", ifType: tPPP, up: true},
	{alias: "FortiSSL", description: "FortiClient SSL VPN Adapter", ifType: tTunnel, up: true, hasMAC: true},
	// PPPoE is accepted like Linux ppp0 (documented in classifyWindows).
	{alias: "Broadband", description: "WAN Miniport (PPPOE)", ifType: tPPP, up: true},
	// Refused.
	{alias: "Ethernet", description: "Intel(R) Ethernet Connection I219-V", ifType: tEthernet, up: true, hasMAC: true},
	{alias: "Wi-Fi", description: "Intel(R) Wi-Fi 6 AX201 160MHz", ifType: tWiFi, up: true, hasMAC: true},
	{alias: "Loopback Pseudo-Interface 1", description: "Software Loopback Interface 1", ifType: tLoopback, up: true},
	{alias: "vEthernet (Default Switch)", description: "Hyper-V Virtual Ethernet Adapter", ifType: tEthernet, up: true, hasMAC: true},
	{alias: "VirtualBox Host-Only Network", description: "VirtualBox Host-Only Ethernet Adapter", ifType: tEthernet, up: true, hasMAC: true},
	{alias: "VMware Network Adapter VMnet8", description: "VMware Virtual Ethernet Adapter for VMnet8", ifType: tEthernet, up: true, hasMAC: true},
	{alias: "Bluetooth Network Connection", description: "Bluetooth Device (Personal Area Network)", ifType: tEthernet, up: true, hasMAC: true},
	{alias: "Teredo", description: "Teredo Tunneling Pseudo-Interface", ifType: tTunnel, up: true, hasMAC: true},
	{alias: "isatap.lan", description: "Microsoft ISATAP Adapter", ifType: tTunnel, up: true},
	{alias: "Home", description: "Realtek PCIe GbE Family Controller", ifType: tEthernet, up: true, hasMAC: true},
	{alias: "Hyper Tunnel", description: "Hyper-V Virtual Tunnel", ifType: tTunnel, up: true},
	{alias: "Unknown Virtual", description: "Some Virtual Adapter", ifType: tVirtual, up: true},
	{alias: "Tunnel With MAC", description: "Some Tunnel", ifType: tTunnel, up: true, hasMAC: true},
	{alias: "AnyConnect Ethernet", description: "Cisco AnyConnect Virtual Miniport Adapter", ifType: tEthernet, up: true, hasMAC: true},
	{alias: "Cellular", description: "Generic Mobile Broadband Adapter", ifType: 243, up: true},
	// Accepted but disconnected: never a candidate.
	{alias: "WireGuard Down", description: "WireGuard Tunnel", ifType: tVirtual},
}

func windowsRules(adapters []windowsAdapter, err error) rules {
	return rules{goos: "windows", adapters: func() ([]windowsAdapter, error) { return adapters, err }}
}

var windowsAccepted = []string{
	"WireGuard Tunnel", "Conexión VPN", "Work IKEv2", "OpenVPN Wintun", "OpenVPN Data Channel Offload",
	"Ethernet 3", "Mullvad", "Cisco", "Forti", "FortiSSL", "Broadband",
}

// S1, S7: tunnels, PPP and RAS connections and known VPN adapters are accepted.
func TestWindowsAcceptsVPNAdapters(t *testing.T) {
	r := windowsRules(windowsAdaptersFixture, nil)
	for _, name := range windowsAccepted {
		if err := r.check(name); err != nil {
			t.Errorf("check(%q) = %v", name, err)
		}
	}
	// The alias is matched like Windows does, ignoring case.
	if err := r.check("wireguard tunnel"); err != nil {
		t.Errorf("check(wireguard tunnel) = %v", err)
	}
}

// S7: every other adapter is refused, with the reason, wrapping ErrVPNRefused.
func TestWindowsRefusesNonVPNAdapters(t *testing.T) {
	r := windowsRules(windowsAdaptersFixture, nil)
	cases := map[string]string{
		"Ethernet":                      "it carries your real connection",
		"Wi-Fi":                         "it carries your real connection",
		"Home":                          "it carries your real connection",
		"home":                          "it carries your real connection",
		"Bluetooth Network Connection":  "it carries your real connection",
		"Teredo":                        "it carries your real connection",
		"isatap.lan":                    "it carries your real connection",
		"Loopback Pseudo-Interface 1":   "it is the loopback",
		"vEthernet (Default Switch)":    "it is a virtual machine adapter",
		"VirtualBox Host-Only Network":  "it is a virtual machine adapter",
		"VMware Network Adapter VMnet8": "it is a virtual machine adapter",
		"Hyper Tunnel":                  "it is a virtual machine adapter",
		"AnyConnect Ethernet":           "it carries your real connection",
		"Unknown Virtual":               "it is not a known VPN adapter",
		"Tunnel With MAC":               "it is not a known VPN adapter",
		"Cellular":                      "it is not a known VPN adapter",
	}
	for name, want := range cases {
		err := r.check(name)
		if err == nil || err.Error() != strconv.Quote(name)+" is not a VPN interface; "+want || !errors.Is(err, ErrVPNRefused) {
			t.Errorf("check(%q) = %v, want %q wrapping ErrVPNRefused", name, err, want)
		}
	}
}

// S1: candidates are only the connected VPN adapters, in the given order.
func TestWindowsCandidatesAreConnectedVPNAdapters(t *testing.T) {
	r := windowsRules(windowsAdaptersFixture, nil)
	var all []string
	for _, a := range windowsAdaptersFixture {
		all = append(all, a.alias)
	}
	all = append(all, "Not There")
	if got := r.candidates(all); !reflect.DeepEqual(got, windowsAccepted) {
		t.Fatalf("candidates() = %v, want %v", got, windowsAccepted)
	}
}

// S7: a VPN that is down has no adapter; it is judged by name, and the
// names of real connections are refused.
func TestWindowsJudgesAMissingAdapterByName(t *testing.T) {
	r := windowsRules(nil, nil)
	for _, ok := range []string{"WireGuard Tunnel", "Conexión VPN", "Mullvad", "Proton VPN"} {
		if err := r.check(ok); err != nil {
			t.Errorf("check(%q) = %v", ok, err)
		}
	}
	for _, name := range []string{"Ethernet", "Ethernet 2", "ethernet", "Wi-Fi", "Wi-Fi 2", "WLAN", "wlan 3",
		"Local Area Connection", "Local Area Connection* 1", "Conexión de área local", "CONEXIÓN DE ÁREA LOCAL 2",
		"Bluetooth Network Connection", "vEthernet (WSL)"} {
		err := r.check(name)
		if err == nil || err.Error() != strconv.Quote(name)+" is not a VPN interface; it carries your real connection" || !errors.Is(err, ErrVPNRefused) {
			t.Errorf("check(%q) = %v, want a refusal naming it", name, err)
		}
	}
	if got := r.candidates([]string{"WireGuard Tunnel"}); len(got) != 0 {
		t.Errorf("candidates() = %v, want none: a missing adapter is not connected", got)
	}
}

// S7: when the adapters cannot be listed, nothing is accepted.
func TestWindowsRefusesWhenAdaptersCannotBeListed(t *testing.T) {
	r := windowsRules(nil, errors.New("GetAdaptersAddresses: access denied"))
	err := r.check("WireGuard Tunnel")
	if err == nil || err.Error() != `cannot tell whether "WireGuard Tunnel" is a VPN interface: GetAdaptersAddresses: access denied` || !errors.Is(err, ErrVPNRefused) {
		t.Fatalf("check() = %v", err)
	}
	if got := r.candidates([]string{"WireGuard Tunnel"}); len(got) != 0 {
		t.Fatalf("candidates() = %v, want none", got)
	}
}

// An alias is a friendly name: valid UTF-8, 1 to 256 bytes, no control
// characters; spaces and non-ASCII letters are fine.
func TestWindowsAdapterAliases(t *testing.T) {
	r := windowsRules(nil, nil)
	for name, want := range map[string]bool{
		"WireGuard Tunnel":       true,
		"Conexión VPN":           true,
		"VPN (trabajo) #2":       true,
		"a":                      true,
		strings.Repeat("a", 256): true,
		strings.Repeat("a", 257): false,
		strings.Repeat("é", 128): true,  // 256 bytes
		strings.Repeat("é", 129): false, // 258 bytes
		"":                       false,
		"wg\x00":                 false,
		"wg\n0":                  false,
		"wg\t0":                  false,
		"wg\x7f":                 false,
		"wg\u0085":               false,
		"wg\xff":                 false,
	} {
		if got := r.validName(name); got != want {
			t.Errorf("validName(%q) = %v, want %v", name, got, want)
		}
	}
	err := r.check("wg\n0")
	if err == nil || err.Error() != `"wg\n0" is not a valid interface name` || !errors.Is(err, ErrVPNRefused) {
		t.Errorf("check() = %v, want an invalid name", err)
	}
	if err := r.check(""); err == nil || err.Error() != "VPN interface is not set" {
		t.Errorf("check(\"\") = %v", err)
	}
	if got := r.candidates([]string{"wg\n0"}); len(got) != 0 {
		t.Errorf("candidates() = %v, want none", got)
	}
}

// Without an adapter source, nothing is accepted (fail closed).
func TestWindowsWithoutAdapterSourceRefuses(t *testing.T) {
	r := rules{goos: "windows"}
	if err := r.check("WireGuard Tunnel"); !errors.Is(err, ErrVPNRefused) {
		t.Fatalf("check() = %v, want a refusal", err)
	}
}
