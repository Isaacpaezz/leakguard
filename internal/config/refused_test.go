package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// S7: every reason to refuse the VPN interface wraps ErrVPNRefused, on every
// system, and keeps its message; accepted interfaces return nil.
func TestEveryVPNRefusalWrapsErrVPNRefused(t *testing.T) {
	linux := linuxRules(t)
	unreadable := linuxRules(t)
	if err := os.Remove(filepath.Join(unreadable.sysfs, "tun0", "type")); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		r       rules
		refused []string
		ok      []string
	}{
		{rules{goos: "darwin"}, []string{"", "ipsec0 all", "en0", "lo0", "bridge0"}, []string{"ipsec0", "utun4"}},
		{linux, []string{"", "wg/x", "eth0", "wlan0", "docker0", "lo", "usb0", "veth1a2b"}, []string{"tun0", "wg-mullvad", "wg9"}},
		{unreadable, []string{"tun0"}, nil},
		{rules{goos: "windows"}, []string{"", "utun4", "Ethernet 2"}, nil},
	}
	for _, tc := range cases {
		for _, name := range tc.refused {
			msg := tc.r.reason(name)
			err := tc.r.check(name)
			if !errors.Is(err, ErrVPNRefused) || msg == nil || err.Error() != msg.Error() {
				t.Errorf("%s: check(%q) = %v, want ErrVPNRefused with message %v", tc.r.goos, name, err, msg)
			}
		}
		for _, name := range tc.ok {
			if err := tc.r.check(name); err != nil {
				t.Errorf("%s: check(%q) = %v", tc.r.goos, name, err)
			}
		}
	}
}

// Validate wraps ErrVPNRefused only for the VPN interface; ValidateServices
// checks the rest without it.
func TestValidateTellsAVPNRefusalApart(t *testing.T) {
	vpn := Config{VPNInterface: "en0", Services: []string{"anthropic"}}
	if err := vpn.Validate(testCatalog); !errors.Is(err, ErrVPNRefused) {
		t.Fatalf("Validate(en0) = %v, want ErrVPNRefused", err)
	}
	if err := vpn.ValidateServices(testCatalog); err != nil {
		t.Fatalf("ValidateServices(en0) = %v", err)
	}
	if err := CheckVPNInterface("en0"); !errors.Is(err, ErrVPNRefused) {
		t.Fatalf("CheckVPNInterface(en0) = %v, want ErrVPNRefused", err)
	}
	for _, c := range []Config{
		{VPNInterface: "utun4", Services: []string{"gemini"}},
		{VPNInterface: "utun4"},
		{VPNInterface: "en0", Services: []string{"openai"}},
	} {
		err := c.ValidateServices(testCatalog)
		if err == nil || errors.Is(err, ErrVPNRefused) {
			t.Errorf("ValidateServices(%+v) = %v, want a service error", c, err)
		}
		if c.VPNInterface == "utun4" {
			if err := c.Validate(testCatalog); err == nil || errors.Is(err, ErrVPNRefused) {
				t.Errorf("Validate(%+v) = %v, want a service error", c, err)
			}
		}
	}
}
