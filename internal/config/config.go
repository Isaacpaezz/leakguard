// Package config stores which services leakguard protects and which network
// interface is the VPN.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
)

// DefaultPath is where the configuration lives. It is owned by root and
// readable by everyone, so status and test work without sudo.
// macOS: /Library/Application Support/leakguard/config.json; Linux:
// /etc/leakguard/config.json; Windows: %ProgramData%\leakguard\config.json.
var DefaultPath = pathFor(runtime.GOOS, os.Getenv("ProgramData"))

// ErrNotConfigured means no configuration file exists yet.
var ErrNotConfigured = errors.New("leakguard is not configured yet")

// Config is the user's choice of VPN interface and protected services.
type Config struct {
	VPNInterface string   `json:"vpn_interface"`
	Services     []string `json:"services"`
	// Paused is set when the menu-bar app pauses the protection: the daemon
	// keeps running but does not load the rules until the next change.
	Paused bool `json:"paused,omitempty"`
}

// ValidInterfaceName reports whether name is a plain interface name, safe to
// paste into firewall rules.
func ValidInterfaceName(name string) bool {
	return host.validName(name)
}

// CheckVPNInterface reports why name cannot be used as the VPN interface.
// The firewall backends call it too, so a bad name never reaches the rules.
// macOS judges by name; Linux by what the kernel says about the interface;
// Windows refuses every interface for now. Every refusal wraps ErrVPNRefused.
func CheckVPNInterface(name string) error {
	return host.check(name)
}

// Validate checks the configuration against the service catalog. A refused
// VPN interface wraps ErrVPNRefused.
func (c Config) Validate(services []catalog.Service) error {
	if err := CheckVPNInterface(c.VPNInterface); err != nil {
		return err
	}
	return c.ValidateServices(services)
}

// ValidateServices checks everything but the VPN interface: the chosen
// services against the catalog.
func (c Config) ValidateServices(services []catalog.Service) error {
	if len(c.Services) == 0 {
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
	return host.candidates(names)
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
	if _, err := dec.Token(); err != io.EOF {
		return Config{}, fmt.Errorf("%s: unexpected data after the configuration", path)
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
	// Flush to disk before the rename, so a crash never leaves an empty file.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
