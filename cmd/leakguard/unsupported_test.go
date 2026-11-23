package main

import (
	"errors"
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/daemon"
	"github.com/Isaacpaezz/leakguard/internal/firewall"
)

const unsupportedMsg = "this operating system is not supported yet"

// unsupportedHarness is a system without a firewall or service backend,
// which is what main builds on every OS that has none yet.
func unsupportedHarness(t *testing.T, root bool) *harness {
	t.Helper()
	h := newHarness(t, root)
	h.env.Firewall = nil
	h.env.Services = nil
	return h
}

// S1, S7: without a backend, every change fails closed and touches nothing.
func TestUnsupportedSystemRefusesChanges(t *testing.T) {
	paused := config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}, Paused: true}
	for _, args := range [][]string{
		{"enable", "--vpn", "ipsec0", "anthropic"},
		{"apply"},
		{"serve"},
	} {
		for _, root := range []bool{true, false} {
			h := unsupportedHarness(t, root)
			if args[0] != "enable" {
				h.saveConfig(t, paused)
			}
			code, out, errOut := h.run(args...)
			expect(t, code, out, errOut, 1, nil, []string{"leakguard: cannot protect services on this computer: " + unsupportedMsg})
			if out != "" {
				t.Errorf("%v: stdout = %q, want empty", args, out)
			}
			if len(h.pfctl.calls) != 0 || len(h.launchctl.calls) != 0 || exists(h.path(daemon.PlistPath)) {
				t.Errorf("%v changed the system: pfctl %v, launchctl %v", args, h.pfctl.calls, h.launchctl.calls)
			}
			cfg, err := h.loadConfig(t)
			switch {
			case args[0] == "enable" && !errors.Is(err, config.ErrNotConfigured):
				t.Errorf("enable wrote a configuration: %+v, %v", cfg, err)
			case args[0] != "enable" && (err != nil || !cfg.Paused):
				t.Errorf("%v changed the configuration: %+v, %v", args, cfg, err)
			}
		}
	}
}

func TestUnsupportedSystemStatusIsNotProtected(t *testing.T) {
	h := unsupportedHarness(t, true)
	h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}})
	code, out, errOut := h.run("status")
	expect(t, code, out, errOut, 1, []string{"Background service: not installed", "NOT PROTECTED: cannot read the firewall: " + unsupportedMsg}, nil)
}

func TestUnsupportedSystemDisableFails(t *testing.T) {
	h := unsupportedHarness(t, true)
	code, out, errOut := h.run("disable")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: could not remove the background service: cannot remove the background service: " + unsupportedMsg})
}

func TestUnsupportedBackendsFailClosed(t *testing.T) {
	var fw firewall.Firewall = unsupportedFirewall{}
	if err := fw.Apply("ipsec0", nil); !errors.Is(err, firewall.ErrUnsupported) {
		t.Errorf("Apply() = %v", err)
	}
	if err := fw.Verify("ipsec0", nil); !errors.Is(err, firewall.ErrUnsupported) {
		t.Errorf("Verify() = %v", err)
	}
	if err := fw.Flush(); !errors.Is(err, firewall.ErrUnsupported) {
		t.Errorf("Flush() = %v", err)
	}
	if on, err := fw.Enabled(); on || !errors.Is(err, firewall.ErrUnsupported) {
		t.Errorf("Enabled() = %v, %v", on, err)
	}
	if n, err := fw.BlockCount(); n != 0 || !errors.Is(err, firewall.ErrUnsupported) || errors.Is(err, firewall.ErrNotLoaded) {
		t.Errorf("BlockCount() = %d, %v", n, err)
	}
	var m daemon.Manager = unsupportedServices{}
	if err := m.Install("/bin/leakguard"); !errors.Is(err, firewall.ErrUnsupported) {
		t.Errorf("Install() = %v", err)
	}
	if err := m.Uninstall(); !errors.Is(err, firewall.ErrUnsupported) {
		t.Errorf("Uninstall() = %v", err)
	}
	if m.Installed() || m.LegacyInstalled() {
		t.Error("an unsupported service manager reports an installed service")
	}
	if line, ok := m.LastLogLine(); ok || line != "" {
		t.Errorf("LastLogLine() = %q, %v", line, ok)
	}
}
