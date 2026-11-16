// Package config stores which services leakguard protects and which network
// interface is the VPN.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
)

// ErrNotConfigured means no configuration file exists yet.
var ErrNotConfigured = errors.New("leakguard is not configured yet")

// Config is the user's choice of VPN interface and protected services.
type Config struct {
	VPNInterface string   `json:"vpn_interface"`
	Services     []string `json:"services"`
}

// The name is pasted into firewall rules, so only plain interface names pass.
var interfaceName = regexp.MustCompile(`^[a-z][a-z0-9]{0,14}$`)

// Prefixes of interfaces that carry the real connection, never a VPN.
var nonVPNPrefixes = []string{"lo", "en", "bridge", "awdl", "llw", "ap", "anpi", "gif", "stf"}

// Prefixes of interfaces that VPN clients create.
var vpnPrefixes = []string{"utun", "ipsec", "ppp", "tun", "tap", "wg"}

// Validate checks the configuration against the service catalog.
func (c Config) Validate(services []catalog.Service) error {
	switch {
	case c.VPNInterface == "":
		return errors.New("VPN interface is not set")
	case !interfaceName.MatchString(c.VPNInterface):
		return fmt.Errorf("%q is not a valid interface name", c.VPNInterface)
	case hasPrefix(c.VPNInterface, nonVPNPrefixes):
		return fmt.Errorf("%q is not a VPN interface; it carries your real connection", c.VPNInterface)
	case len(c.Services) == 0:
		return errors.New("no services selected")
	}
	seen := map[string]bool{}
	for _, id := range c.Services {
		s, ok := catalog.Find(services, id)
		switch {
		case !ok:
			return fmt.Errorf("unknown service %q", id)
		case s.Status != catalog.StatusSupported:
			return fmt.Errorf("service %q is not supported yet", id)
		case seen[id]:
			return fmt.Errorf("service %q is listed twice", id)
		}
		seen[id] = true
	}
	return nil
}

// VPNCandidates keeps the interface names that look like VPN tunnels.
func VPNCandidates(names []string) []string {
	var out []string
	for _, n := range names {
		if hasPrefix(n, vpnPrefixes) {
			out = append(out, n)
		}
	}
	return out
}

func hasPrefix(name string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Load reads the configuration at path. A missing file returns ErrNotConfigured.
func Load(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, ErrNotConfigured
	}
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Save writes the configuration atomically, readable by everyone and writable
// only by its owner.
func Save(path string, c Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
