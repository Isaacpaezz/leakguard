package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
)

var testCatalog = []catalog.Service{
	{ID: "anthropic", Status: catalog.StatusSupported},
	{ID: "example", Status: catalog.StatusSupported},
	{ID: "openai", Status: catalog.StatusPlanned},
}

func TestValidateAccepts(t *testing.T) {
	c := Config{VPNInterface: "ipsec0", Services: []string{"anthropic", "example"}}
	if err := c.Validate(testCatalog); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"no interface", Config{Services: []string{"anthropic"}}, "VPN interface is not set"},
		{"rule injection", Config{VPNInterface: "ipsec0 all", Services: []string{"anthropic"}}, "not a valid interface name"},
		{"loopback", Config{VPNInterface: "lo0", Services: []string{"anthropic"}}, "not a VPN interface"},
		{"physical", Config{VPNInterface: "en0", Services: []string{"anthropic"}}, "not a VPN interface"},
		{"no services", Config{VPNInterface: "utun4"}, "no services selected"},
		{"unknown service", Config{VPNInterface: "utun4", Services: []string{"gemini"}}, `unknown service "gemini"`},
		{"planned service", Config{VPNInterface: "utun4", Services: []string{"openai"}}, `service "openai" is not supported yet`},
		{"duplicate", Config{VPNInterface: "utun4", Services: []string{"anthropic", "anthropic"}}, `service "anthropic" is listed twice`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate(testCatalog)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSaveThenLoadRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "config.json")
	want := Config{VPNInterface: "utun4", Services: []string{"anthropic"}}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load() = %+v, want %+v", got, want)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, want 0644", info.Mode().Perm())
	}
}

func TestLoadMissingFileIsNotConfigured(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "config.json"))
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Load() error = %v, want ErrNotConfigured", err)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(path, []byte(`{"vpn_interface":"utun4","services":["anthropic"],"allow_leaks":true}`), 0o644)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "allow_leaks") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestVPNCandidates(t *testing.T) {
	in := []string{"lo0", "en0", "utun4", "ipsec0", "awdl0", "ppp0", "wg0", "tun1", "bridge0"}
	want := []string{"utun4", "ipsec0", "ppp0", "wg0", "tun1"}
	if got := VPNCandidates(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("VPNCandidates() = %v, want %v", got, want)
	}
}
