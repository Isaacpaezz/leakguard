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
// paste into firewall rules. On Windows it is an adapter alias: valid UTF-8,
// 1 to 256 bytes, no control characters.
func ValidInterfaceName(name string) bool {
	return host.validName(name)
}

// CheckVPNInterface reports why name cannot be used as the VPN interface.
// The firewall backends call it too, so a bad name never reaches the rules.
// macOS judges by name; Linux by what the kernel says about the interface;
// Windows by what GetAdaptersAddresses says about the adapter. Linux and
// Windows judge a missing interface by name. Every refusal wraps
// ErrVPNRefused.
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

// CanonicalInterfaceName returns the interface name to store for name,
// given the names of the interfaces that exist now. Windows resolves adapter
// aliases ignoring case, but the firewall and the daemon look the saved
// alias up exactly, so on Windows it returns the existing adapter's real
// alias (an exact match first); a name no adapter matches is kept. macOS
// and Linux names are case-sensitive: name is returned unchanged.
func CanonicalInterfaceName(name string, names []string) string {
	return host.canonical(name, names)
}

// SameInterface reports whether a and b name the same interface: ignoring
// case on Windows, exactly elsewhere.
func SameInterface(a, b string) bool {
	return host.same(a, b)
}

// VPNCandidates keeps the interface names that look like VPN tunnels. On
// Windows only connected VPN adapters are kept.
func VPNCandidates(names []string) []string {
	return host.candidates(names)
}

// Load reads the configuration at path. A missing file returns
// ErrNotConfigured. On Windows a file someone other than SYSTEM and
// Administrators may write, or a link, is refused with ErrUnsafePath, so
// the SYSTEM daemon never runs a configuration a user planted.
func Load(path string) (Config, error) {
	var c Config
	data, err := readTrusted(path)
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

// readTrusted reads the file OpenTrusted opens.
func readTrusted(path string) ([]byte, error) {
	f, err := OpenTrusted(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// Save writes the configuration atomically, readable by everyone and writable
// only by its owner. The directory is made by PrepareDir: on Windows only
// SYSTEM and Administrators can write it, and the new file replaces
// whatever had the name (a file a user planted included) by a rename.
func Save(path string, c Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := PrepareDir(filepath.Dir(path)); err != nil {
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
	if err := ownFile(tmp.Name()); err != nil {
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
