package main

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/firewall"
	"github.com/Isaacpaezz/leakguard/internal/wfp"
)

// S1: the Windows firewall is the Windows Filtering Platform, and it checks
// the VPN adapter itself, so a refused one is never permitted (S7).
func TestWFPFirewall(t *testing.T) {
	fw, ok := wfpFirewall(Env{}).(wfp.Firewall)
	if !ok {
		t.Fatalf("wfpFirewall() = %T, want wfp.Firewall", wfpFirewall(Env{}))
	}
	if fw.Check == nil || fw.Name() != "Windows Filtering Platform" {
		t.Fatalf("wfpFirewall() = %+v: Check must be config.CheckVPNInterface", fw)
	}
	for _, name := range []string{"Ethernet", "Wi-Fi", "lo", "en0"} {
		if got, want := fw.Check(name), config.CheckVPNInterface(name); (got == nil) != (want == nil) {
			t.Errorf("Check(%q) = %v, want %v", name, got, want)
		}
	}
}

// adapterFirewall is a firewall like WFP: its rules name the VPN adapter
// that exists when they load, so they verify only while the VPN is in the
// state it was in then (connected: permits for its LUID; down: blocks only).
// With static set, they always verify, like pf and nftables.
type adapterFirewall struct {
	mu       sync.Mutex
	vpn      *interfacesSwitch
	static   bool
	loaded   []bool // the VPN state at each Apply
	verifies int
}

func (f *adapterFirewall) up() bool {
	ifs, _ := f.vpn.list()
	return ifs[1].Connected()
}

func (f *adapterFirewall) Name() string { return "adapter firewall" }

func (f *adapterFirewall) Apply(string, []catalog.Service) error {
	up := f.up()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loaded = append(f.loaded, up)
	return nil
}

func (f *adapterFirewall) Flush() error           { return nil }
func (f *adapterFirewall) Enabled() (bool, error) { return true, nil }

func (f *adapterFirewall) Verify(string, []catalog.Service) error {
	up := f.up()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifies++
	if !f.static && len(f.loaded) > 0 && f.loaded[len(f.loaded)-1] != up {
		return errors.New("1 missing (first: permit)")
	}
	return nil
}

func (f *adapterFirewall) BlockCount() (uint64, error) {
	return 0, firewall.ErrUnsupported
}

func (f *adapterFirewall) state() ([]bool, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]bool(nil), f.loaded...), f.verifies
}

// T10b: when the VPN connects or drops, serve checks the rules at the next
// VPN sample, not at the next 30 s check: they verify, and load again only
// when that fails. On Windows the permits appear within a sample of the VPN
// connecting; on macOS and Linux the verify passes and nothing loads.
func TestServeChecksWhenTheVPNConnectsOrDrops(t *testing.T) {
	for _, static := range []bool{false, true} {
		h := newHarness(t, true)
		h.saveConfig(t, anthropicConfig)
		vpn := &interfacesSwitch{}
		fw := &adapterFirewall{vpn: vpn, static: static}
		h.env.Interfaces = vpn.list
		h.env.Firewall = func(Env) firewall.Firewall { return fw }
		h.env.SampleEvery = time.Millisecond // the check stays at an hour
		s := startServe(t, h)
		want := []bool{false}
		for _, up := range []bool{true, false} {
			_, before := fw.state()
			vpn.set(up)
			if !static {
				want = append(want, up)
			}
			eventually(t, "a check after the VPN changed", func() bool {
				loaded, verifies := fw.state()
				return verifies > before && len(loaded) == len(want) && loaded[len(loaded)-1] == want[len(want)-1]
			})
		}
		if code := s.stop(t); code != 0 {
			t.Fatalf("serve exit code = %d: %s", code, s.stderr.String())
		}
		if loaded, _ := fw.state(); len(loaded) != len(want) {
			t.Errorf("static %v: loads with the VPN up = %v, want %v", static, loaded, want)
		}
		if static && strings.Contains(s.stderr.String(), "rules not verified") {
			t.Errorf("static rules were reloaded:\n%s", s.stderr.String())
		}
	}
}

// withWindowsWords makes the messages those of Windows for one test.
func withWindowsWords(t *testing.T) {
	t.Helper()
	withAdminHint(t, "windows")
	old := windowsWords
	windowsWords = true
	t.Cleanup(func() { windowsWords = old })
}

// S1: on Windows no message says sudo: it names an administrator terminal.
func TestWindowsMessagesNameAnAdministratorTerminal(t *testing.T) {
	withWindowsWords(t)
	h := newHarness(t, true)
	code, out, errOut := h.run("status")
	expect(t, code, out, errOut, 0, []string{"leakguard is not configured yet.\nStart with: leakguard enable --vpn ADAPTER SERVICE... (in an administrator terminal)\nSee your VPN interfaces with: leakguard interfaces\n"}, nil)
	code, out, errOut = h.run("test")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: not configured yet; run: leakguard enable --vpn ADAPTER SERVICE... (in an administrator terminal)\n"})
	code, out, errOut = h.run("interfaces")
	expect(t, code, out, errOut, 0, []string{"Use it with: leakguard enable --vpn NAME SERVICE... (in an administrator terminal)\n"}, nil)
	code, out, errOut = h.run("enable", "--vpn", "ipsec0")
	expect(t, code, out, errOut, 2, nil, []string{"leakguard: name at least one service, for example: leakguard enable anthropic (in an administrator terminal; see leakguard services)\n"})

	h.saveConfig(t, anthropicConfig)
	h.pfctl.outputs["-s info"] = "Status: Disabled for 0 days\n"
	code, out, errOut = h.run("status")
	expect(t, code, out, errOut, 1, []string{"NOT PROTECTED: pf is disabled; turn it back on with: leakguard apply (in an administrator terminal)\n"}, nil)

	blocked, _ := statefulHarness(t)
	blocked.saveConfig(t, config.Config{VPNInterface: refusedVPN, Services: []string{"anthropic"}})
	blocked.run("apply")
	code, out, errOut = blocked.run("status")
	expect(t, code, out, errOut, 1, []string{`protected services are blocked: the saved VPN "en9" is not a VPN interface; choose yours with: leakguard enable --vpn ADAPTER (in an administrator terminal)` + "\n"}, nil)

	user := newHarness(t, false)
	user.saveConfig(t, anthropicConfig)
	code, out, errOut = user.run("status")
	expect(t, code, out, errOut, 0, []string{
		"Background service: not installed (run \"leakguard enable\" in an administrator terminal)\n",
		"Firewall:           run \"leakguard status\" in an administrator terminal to verify the rules\n",
	}, nil)
	for _, text := range []string{notConfiguredHelp(), errNotConfigured.Error()} {
		if strings.Contains(text, "sudo") {
			t.Errorf("Windows message says sudo: %q", text)
		}
	}
}

// S2: macOS and Linux keep their messages byte for byte.
func TestUnixMessagesStillSaySudo(t *testing.T) {
	h := newHarness(t, true)
	code, out, errOut := h.run("status")
	expect(t, code, out, errOut, 0, []string{"leakguard is not configured yet.\nStart with: sudo leakguard enable --vpn IFACE SERVICE...\nSee your VPN interfaces with: leakguard interfaces\n"}, nil)
	code, out, errOut = h.run("test")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: not configured yet; run: sudo leakguard enable --vpn IFACE SERVICE...\n"})
	code, out, errOut = h.run("interfaces")
	expect(t, code, out, errOut, 0, []string{"Use it with: sudo leakguard enable --vpn NAME SERVICE...\n"}, nil)
	code, out, errOut = h.run("enable", "--vpn", "ipsec0")
	expect(t, code, out, errOut, 2, nil, []string{"leakguard: name at least one service, for example: sudo leakguard enable anthropic (see leakguard services)\n"})
	h.saveConfig(t, anthropicConfig)
	h.pfctl.outputs["-s info"] = "Status: Disabled for 0 days\n"
	code, out, errOut = h.run("status")
	expect(t, code, out, errOut, 1, []string{"NOT PROTECTED: pf is disabled; turn it back on with: sudo leakguard apply\n"}, nil)
	blocked, _ := statefulHarness(t)
	blocked.saveConfig(t, config.Config{VPNInterface: refusedVPN, Services: []string{"anthropic"}})
	blocked.run("apply")
	code, out, errOut = blocked.run("status")
	expect(t, code, out, errOut, 1, []string{blockedReason + "\n"}, nil)
	user := newHarness(t, false)
	user.saveConfig(t, anthropicConfig)
	code, out, errOut = user.run("status")
	expect(t, code, out, errOut, 0, []string{
		"Background service: not installed (run: sudo leakguard enable)\n",
		"Firewall:           run \"sudo leakguard status\" to verify the rules\n",
	}, nil)
}
