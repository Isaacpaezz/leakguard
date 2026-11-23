package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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

// testNames are interface names the host's rules refuse (see hostNames).
type testNames struct{ invalid, loopback, physical string }

// writeRaw writes a configuration file as given, bypassing Save, the way
// Save leaves it: in a prepared directory and, on Windows, owned by
// Administrators, so Load trusts it and reads what it holds.
func writeRaw(t *testing.T, path, data string) {
	t.Helper()
	if err := PrepareDir(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ownFile(path); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejects(t *testing.T) {
	names := hostNames(t)
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"no interface", Config{Services: []string{"anthropic"}}, "VPN interface is not set"},
		{"rule injection", Config{VPNInterface: names.invalid, Services: []string{"anthropic"}}, "not a valid interface name"},
		{"loopback", Config{VPNInterface: names.loopback, Services: []string{"anthropic"}}, "not a VPN interface"},
		{"physical", Config{VPNInterface: names.physical, Services: []string{"anthropic"}}, "not a VPN interface"},
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
	// Windows has no Unix modes; who may write the file there is checked
	// by Load (TestLoadRefusesAConfigSomeoneElseMayWrite).
	info, _ := os.Stat(path)
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
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
	writeRaw(t, path, `{"vpn_interface":"utun4","services":["anthropic"],"allow_leaks":true}`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "allow_leaks") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestVPNCandidates(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows keeps only connected VPN adapters: never the loopback
		// (connected), a real-connection name, nor a name no adapter has.
		in := []string{hostNames(t).loopback, "Ethernet 99", "utun4", "ipsec0", "wg0"}
		if got := VPNCandidates(in); len(got) != 0 {
			t.Fatalf("VPNCandidates(%q) = %v, want none", in, got)
		}
		return
	}
	in := []string{"lo0", "en0", "utun4", "ipsec0", "awdl0", "ppp0", "wg0", "tun1", "bridge0"}
	want := []string{"utun4", "ipsec0", "ppp0", "wg0", "tun1"}
	if got := VPNCandidates(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("VPNCandidates() = %v, want %v", got, want)
	}
}

func TestLoadRejectsTrailingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeRaw(t, path, `{"vpn_interface":"utun4","services":["anthropic"]} {"vpn_interface":"en0"}`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unexpected data after the configuration") {
		t.Fatalf("Load() error = %v, want trailing data error", err)
	}
}

func TestLoadAcceptsTrailingWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeRaw(t, path, "{\"vpn_interface\":\"utun4\",\"services\":[\"anthropic\"]}\n\n")
	if _, err := Load(path); err != nil {
		t.Fatalf("Load() = %v", err)
	}
}

func TestCheckVPNInterface(t *testing.T) {
	for _, ok := range []string{"ipsec0", "utun4", "wg0", "ppp0"} {
		if err := CheckVPNInterface(ok); err != nil {
			t.Errorf("CheckVPNInterface(%q) = %v", ok, err)
		}
	}
	names := hostNames(t)
	cases := map[string]string{
		"":             "VPN interface is not set",
		names.invalid:  "not a valid interface name",
		names.physical: "not a VPN interface",
		names.loopback: "not a VPN interface",
	}
	for name, want := range cases {
		if err := CheckVPNInterface(name); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("CheckVPNInterface(%q) = %v, want %q", name, err, want)
		}
	}
}

func TestValidInterfaceName(t *testing.T) {
	cases := map[string]bool{"en0": true, "ipsec0": true, "en0;": false, "": false, "a b": false}
	if runtime.GOOS == "windows" {
		// An adapter alias: 1 to 256 bytes of UTF-8 without control characters.
		cases = map[string]bool{"en0": true, "WireGuard Tunnel": true, "en0;": true, "": false, "a\tb": false, strings.Repeat("a", 257): false}
	}
	for name, want := range cases {
		if got := ValidInterfaceName(name); got != want {
			t.Errorf("ValidInterfaceName(%q) = %v, want %v", name, got, want)
		}
	}
}

// The menu-bar app's pause is saved, so the daemon does not re-apply the rules.
func TestPausedRoundTripsAndIsOmittedWhenFalse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	want := Config{VPNInterface: "utun4", Services: []string{"anthropic"}, Paused: true}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Load() = %+v, %v; want %+v", got, err, want)
	}
	want.Paused = false
	Save(path, want)
	if data, _ := os.ReadFile(path); strings.Contains(string(data), "paused") {
		t.Fatalf("an unpaused config mentions paused:\n%s", data)
	}
	if err := want.Validate(testCatalog); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	want.Paused = true
	if err := want.Validate(testCatalog); err != nil {
		t.Fatalf("Validate() of a paused config = %v", err)
	}
}
