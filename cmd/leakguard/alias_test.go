package main

import (
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/daemon"
	"github.com/Isaacpaezz/leakguard/internal/firewall"
)

// aliasFirewall records the VPN interface of every Apply.
type aliasFirewall struct {
	mu      *sync.Mutex
	applied *[]string
}

func (aliasFirewall) Name() string { return "test firewall" }
func (f aliasFirewall) Apply(vpn string, _ []catalog.Service) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	*f.applied = append(*f.applied, vpn)
	return nil
}
func (aliasFirewall) Flush() error                           { return nil }
func (aliasFirewall) Enabled() (bool, error)                 { return true, nil }
func (aliasFirewall) Verify(string, []catalog.Service) error { return nil }
func (aliasFirewall) BlockCount() (uint64, error)            { return 0, firewall.ErrUnsupported }

// aliasEnv is an administrator on a system with the interfaces ifs; the
// VPN interface of every Apply is appended to applied.
func aliasEnv(t *testing.T, applied *[]string, ifs ...Interface) Env {
	t.Helper()
	fw := aliasFirewall{mu: new(sync.Mutex), applied: applied}
	return Env{
		IsRoot:     func() bool { return true },
		Root:       t.TempDir(),
		Firewall:   func(Env) firewall.Firewall { return fw },
		Services:   func(Env) daemon.Manager { return reportServices{} },
		Interfaces: func() ([]Interface, error) { return ifs, nil },
		Executable: func() (string, error) { return "leakguard", nil },
		Now:        func() time.Time { return fixedNow },
	}
}

// savedVPN reads the VPN interface of the saved configuration file as
// written, without the checks of config.Load.
func savedVPN(t *testing.T, env Env) string {
	t.Helper()
	b, err := os.ReadFile(rooted(env.Root, config.DefaultPath))
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg.VPNInterface
}
