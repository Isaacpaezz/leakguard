// Package firewall is what leakguard needs from an operating system's packet
// filter: load the rules that keep protected services on the VPN, remove
// them, verify them and read their block counter. Each OS has its own
// backend; only package main picks one.
package firewall

import (
	"errors"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
)

// Firewall loads and inspects the leakguard rules.
type Firewall interface {
	// Name is how users know the packet filter, for example "pf".
	Name() string
	// Apply loads rules that let traffic to services leave only on vpn,
	// and verifies them. On failure the previously loaded rules stay.
	Apply(vpn string, services []catalog.Service) error
	// Flush removes every leakguard rule.
	Flush() error
	// Enabled reports whether the packet filter is filtering at all.
	Enabled() (bool, error)
	// Verify checks that the loaded rules protect every range of services
	// on vpn. No rules at all is ErrNotLoaded.
	Verify(vpn string, services []catalog.Service) error
	// BlockCount returns how many packets the rules rejected since they
	// were last loaded. No rules at all is ErrNotLoaded.
	BlockCount() (uint64, error)
}

var (
	// ErrNotLoaded means no leakguard rules are loaded.
	ErrNotLoaded = errors.New("leakguard rules are not loaded")
	// ErrUnsupported means this operating system has no backend yet.
	ErrUnsupported = errors.New("this operating system is not supported yet")
)
