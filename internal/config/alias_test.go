package config

import "testing"

// S7 (B1): Windows resolves adapter aliases ignoring case, but the firewall
// and the daemon look the saved alias up exactly, so a VPN chosen as
// "wireguard tunnel" for the adapter "WireGuard Tunnel" must be stored as
// the adapter's real alias. Other systems keep the name as typed.
func TestCanonicalInterfaceName(t *testing.T) {
	adapters := []string{"Ethernet", "WireGuard Tunnel", "Conexión VPN"}
	cases := []struct {
		goos, name string
		names      []string
		want       string
	}{
		{"windows", "wireguard tunnel", adapters, "WireGuard Tunnel"},
		{"windows", "WIREGUARD TUNNEL", adapters, "WireGuard Tunnel"},
		{"windows", "WireGuard Tunnel", adapters, "WireGuard Tunnel"},
		{"windows", "CONEXIÓN VPN", adapters, "Conexión VPN"},
		// An exact match wins over one that differs only in case.
		{"windows", "vpn", []string{"VPN", "vpn"}, "vpn"},
		// An adapter that does not exist (the VPN is down) keeps the name.
		{"windows", "Work IKEv2", adapters, "Work IKEv2"},
		{"windows", "wireguard tunnel", nil, "wireguard tunnel"},
		{"windows", "", adapters, ""},
		// macOS and Linux names are case-sensitive: never changed.
		{"darwin", "UTUN4", []string{"utun4"}, "UTUN4"},
		{"linux", "WG0", []string{"wg0"}, "WG0"},
		{"linux", "wg0", []string{"wg0"}, "wg0"},
	}
	for _, tc := range cases {
		if got := (rules{goos: tc.goos}).canonical(tc.name, tc.names); got != tc.want {
			t.Errorf("%s: canonical(%q, %q) = %q, want %q", tc.goos, tc.name, tc.names, got, tc.want)
		}
	}
}

// S7 (B1): Windows compares adapter aliases ignoring case, like it resolves
// them; macOS and Linux compare interface names exactly.
func TestSameInterface(t *testing.T) {
	cases := []struct {
		goos, a, b string
		want       bool
	}{
		{"windows", "WireGuard Tunnel", "wireguard tunnel", true},
		{"windows", "Conexión VPN", "CONEXIÓN VPN", true},
		{"windows", "WireGuard Tunnel", "WireGuard Tunnel 2", false},
		{"windows", "", "", true},
		{"darwin", "utun4", "utun4", true},
		{"darwin", "utun4", "UTUN4", false},
		{"linux", "wg0", "WG0", false},
		{"linux", "wg0", "wg0", true},
	}
	for _, tc := range cases {
		if got := (rules{goos: tc.goos}).same(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: same(%q, %q) = %v, want %v", tc.goos, tc.a, tc.b, got, tc.want)
		}
	}
	// The exported helpers use this system's rules.
	if !SameInterface("utun4", "utun4") || CanonicalInterfaceName("utun4", nil) != "utun4" {
		t.Error("the exported helpers changed a name with no adapter to match")
	}
}
