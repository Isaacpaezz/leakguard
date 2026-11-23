package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/daemon"
	"github.com/Isaacpaezz/leakguard/internal/pf"
)

// fakePfctl answers like a pf that loads whatever it is given.
type fakePfctl struct {
	calls   []string
	outputs map[string]string
	fail    map[string]error
}

func (f *fakePfctl) Run(stdin string, args ...string) (string, error) {
	key := strings.Join(args, " ")
	f.calls = append(f.calls, key)
	return f.outputs[key], f.fail[key]
}

type fakeLaunchctl struct{ calls []string }

// Run answers like a launchd that unloads jobs at once: "print" fails
// because the job is already gone.
func (f *fakeLaunchctl) Run(args ...string) (string, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	if args[0] == "print" {
		return "", errors.New("Could not find service")
	}
	return "", nil
}

var fixedNow = time.Date(2026, 11, 16, 15, 0, 0, 0, time.UTC)

type fakeResolver map[string][]string

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	raw, ok := f[host]
	if !ok {
		return nil, fmt.Errorf("lookup %s: no such host", host)
	}
	var out []netip.Addr
	for _, r := range raw {
		out = append(out, netip.MustParseAddr(r))
	}
	return out, nil
}

// anthropicResolver resolves every catalog domain of anthropic inside its ranges.
func anthropicResolver() fakeResolver {
	return fakeResolver{
		"anthropic.com":     {"160.79.104.10", "2607:6bc0::10"},
		"api.anthropic.com": {"160.79.104.10", "2607:6bc0::10"},
		"claude.ai":         {"160.79.104.10"},
		"claude.com":        {"160.79.104.10"},
	}
}

type harness struct {
	env       Env
	pfctl     *fakePfctl
	launchctl *fakeLaunchctl
	mu        sync.Mutex
	dialed    []string
	dialIface string
}

// loadedPfctl returns pfctl outputs for the anthropic rules loaded on iface.
func loadedPfctl(t *testing.T, iface string) map[string]string {
	t.Helper()
	svcs, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	s, _ := catalog.Find(svcs, "anthropic")
	table := strings.Join(append(append([]string{}, s.IPv4...), s.IPv6...), "\n")
	return map[string]string{
		"-s info": "Status: Enabled for 1 days\n",
		"-a " + pf.Anchor + " -s rules": "pass out quick on " + iface + " from any to <leakguard> flags S/SA keep state\n" +
			"block return out quick from any to <leakguard>\n",
		"-a " + pf.Anchor + " -t leakguard -T show": table,
	}
}

func newHarness(t *testing.T, root bool) *harness {
	t.Helper()
	h := &harness{
		pfctl:     &fakePfctl{outputs: loadedPfctl(t, "ipsec0")},
		launchctl: &fakeLaunchctl{},
	}
	exe := filepath.Join(t.TempDir(), "leakguard")
	os.WriteFile(exe, []byte("leakguard-binary"), 0o755)
	h.env = Env{
		IsRoot:    func() bool { return root },
		Root:      t.TempDir(),
		Pfctl:     h.pfctl,
		Launchctl: h.launchctl,
		Secure:    func(string) error { return nil },
		Firewall:  pfFirewall,
		Services:  launchdServices,
		Interfaces: func() ([]Interface, error) {
			return []Interface{
				{Name: "en0", Up: true, HasAddress: true},
				{Name: "en1", Up: true, HasAddress: true},
				{Name: "utun0", Up: true},
				{Name: "ipsec0", Up: true, HasAddress: true},
			}, nil
		},
		Executable: func() (string, error) { return exe, nil },
		Resolver:   anthropicResolver(),
		Dial: func(_ context.Context, iface string, addr netip.AddrPort) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.dialIface = iface
			h.dialed = append(h.dialed, addr.String())
			return syscall.ECONNREFUSED
		},
		DefaultInterface: func() (string, error) { return "en0", nil },
		Now:              func() time.Time { return fixedNow },
		Location:         time.UTC,
	}
	return h
}

func (h *harness) run(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr, h.env)
	return code, stdout.String(), stderr.String()
}

func (h *harness) path(p string) string { return filepath.Join(h.env.Root, p) }

func (h *harness) saveConfig(t *testing.T, c config.Config) {
	t.Helper()
	if err := config.Save(h.path(config.DefaultPath), c); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) loadConfig(t *testing.T) (config.Config, error) {
	t.Helper()
	return config.Load(h.path(config.DefaultPath))
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func expect(t *testing.T, code int, stdout, stderr string, wantCode int, wantOut, wantErr []string) {
	t.Helper()
	if code != wantCode {
		t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s", code, wantCode, stdout, stderr)
	}
	for _, w := range wantOut {
		if !strings.Contains(stdout, w) {
			t.Errorf("stdout is missing %q:\n%s", w, stdout)
		}
	}
	for _, w := range wantErr {
		if !strings.Contains(stderr, w) {
			t.Errorf("stderr is missing %q:\n%s", w, stderr)
		}
	}
	if wantErr == nil && stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
}

func TestHelpListsEveryCommand(t *testing.T) {
	h := newHarness(t, false)
	for _, args := range [][]string{{"help"}, {"-h"}, {"--help"}} {
		code, out, errOut := h.run(args...)
		expect(t, code, out, errOut, 0, []string{
			"leakguard services", "leakguard interfaces", "sudo leakguard enable [--vpn IFACE] SERVICE...",
			"sudo leakguard disable", "leakguard status", "leakguard test [--via IFACE]", "sudo leakguard apply",
			"sudo leakguard serve", "asks the background service",
			"the only\n      other connected interface",
			"sudo leakguard enable --vpn ipsec0 anthropic",
			"It also ends a pause from the menu-bar app.",
			"Once they are loaded, a pause from the menu-bar app ends.",
			"the VPN session and\n      today's blocks",
			"checks them every 30 seconds, and loads them again\n      only when the check fails or the saved choice changed",
			"/Library/Application Support/leakguard/stats.json",
		}, nil)
	}
}

func TestUsageErrors(t *testing.T) {
	h := newHarness(t, false)
	code, out, errOut := h.run()
	expect(t, code, out, errOut, 2, nil, []string{"Usage:"})
	code, out, errOut = h.run("frobnicate")
	expect(t, code, out, errOut, 2, nil, []string{`leakguard: unknown command "frobnicate"`, "Usage:"})
	code, out, errOut = h.run("status", "extra")
	expect(t, code, out, errOut, 2, nil, []string{"leakguard: status takes no arguments"})
}

func TestServicesMarksSelectedOnes(t *testing.T) {
	h := newHarness(t, false)
	code, out, errOut := h.run("services")
	expect(t, code, out, errOut, 0, []string{"anthropic", "Anthropic (Claude)", "supported", "openai", "planned"}, nil)
	if strings.Contains(out, "* anthropic") {
		t.Fatalf("anthropic marked without a config:\n%s", out)
	}
	h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}})
	code, out, errOut = h.run("services")
	expect(t, code, out, errOut, 0, []string{"* anthropic", "* = protected"}, nil)
	if strings.Contains(out, "* openai") {
		t.Fatalf("openai marked as protected:\n%s", out)
	}
}

func TestInterfacesListsVPNCandidates(t *testing.T) {
	h := newHarness(t, false)
	code, out, errOut := h.run("interfaces")
	expect(t, code, out, errOut, 0, []string{"utun0", "up, no address", "ipsec0", "connected"}, nil)
	if strings.Contains(out, "en0") {
		t.Fatalf("en0 listed as a VPN candidate:\n%s", out)
	}
}

func TestEnableRequiresRoot(t *testing.T) {
	h := newHarness(t, false)
	code, out, errOut := h.run("enable", "--vpn", "ipsec0", "anthropic")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: run with sudo: sudo leakguard enable"})
	if exists(h.path(config.DefaultPath)) || len(h.pfctl.calls) != 0 || len(h.launchctl.calls) != 0 {
		t.Fatal("enable changed the system without root")
	}
}

func TestEnableProtectsAndInstallsTheDaemon(t *testing.T) {
	h := newHarness(t, true)
	code, out, errOut := h.run("enable", "--vpn", "ipsec0", "anthropic")
	expect(t, code, out, errOut, 0, []string{"Protected through ipsec0: Anthropic (Claude)"}, nil)
	got, err := h.loadConfig(t)
	if err != nil || got.VPNInterface != "ipsec0" || strings.Join(got.Services, ",") != "anthropic" {
		t.Fatalf("saved config = %+v, %v", got, err)
	}
	if data, _ := os.ReadFile(h.path(daemon.BinaryPath)); string(data) != "leakguard-binary" {
		t.Fatalf("installed binary = %q", data)
	}
	if data, _ := os.ReadFile(h.path(daemon.PlistPath)); string(data) != daemon.Plist(daemon.BinaryPath) {
		t.Fatalf("plist = %q", data)
	}
	if !strings.Contains(strings.Join(h.launchctl.calls, "|"), "bootstrap system "+h.path(daemon.PlistPath)) {
		t.Fatalf("launchctl calls = %v", h.launchctl.calls)
	}
	if !strings.Contains(strings.Join(h.pfctl.calls, "|"), "-a "+pf.Anchor+" -f -") {
		t.Fatalf("pfctl calls = %v, want the anchor loaded", h.pfctl.calls)
	}
}

func TestEnableReusesTheSavedConfig(t *testing.T) {
	h := newHarness(t, true)
	h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}})
	code, out, errOut := h.run("enable")
	expect(t, code, out, errOut, 0, []string{"Protected through ipsec0"}, nil)
}

func TestEnableDetectsTheOnlyConnectedVPN(t *testing.T) {
	h := newHarness(t, true)
	code, out, errOut := h.run("enable", "anthropic")
	expect(t, code, out, errOut, 0, []string{"Detected VPN interface: ipsec0", "Protected through ipsec0"}, nil)
}

func TestEnableRefusesToGuessTheVPN(t *testing.T) {
	h := newHarness(t, true)
	h.env.Interfaces = func() ([]Interface, error) {
		return []Interface{{Name: "ipsec0", Up: true, HasAddress: true}, {Name: "utun4", Up: true, HasAddress: true}}, nil
	}
	code, out, errOut := h.run("enable", "anthropic")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: cannot tell which interface is your VPN", "ipsec0", "utun4", "--vpn"})
	if exists(h.path(config.DefaultPath)) || len(h.pfctl.calls) != 0 {
		t.Fatal("enable guessed a VPN interface")
	}
	h.env.Interfaces = func() ([]Interface, error) { return nil, nil }
	code, out, errOut = h.run("enable", "anthropic")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: no VPN interface found", "--vpn"})
}

func TestEnableRejectsInvalidChoices(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"enable", "--vpn", "ipsec0", "openai"}, `leakguard: service "openai" is not supported yet`},
		{[]string{"enable", "--vpn", "ipsec0", "gemini"}, `leakguard: unknown service "gemini"`},
		{[]string{"enable", "--vpn", "en0", "anthropic"}, `leakguard: "en0" is not a VPN interface`},
	}
	for _, tc := range cases {
		h := newHarness(t, true)
		code, out, errOut := h.run(tc.args...)
		expect(t, code, out, errOut, 1, nil, []string{tc.want})
		if exists(h.path(config.DefaultPath)) || len(h.pfctl.calls) != 0 || exists(h.path(daemon.PlistPath)) {
			t.Fatalf("%v changed the system", tc.args)
		}
	}
}

func TestEnableUsageErrors(t *testing.T) {
	h := newHarness(t, true)
	code, out, errOut := h.run("enable", "--vpn", "ipsec0")
	expect(t, code, out, errOut, 2, nil, []string{"leakguard: name at least one service"})
	code, out, errOut = h.run("enable", "anthropic", "--vpn", "ipsec0")
	expect(t, code, out, errOut, 2, nil, []string{"leakguard: put flags before the services"})
	code, out, errOut = h.run("enable", "--bogus")
	expect(t, code, out, errOut, 2, nil, []string{"flag provided but not defined: -bogus"})
}

func TestEnableFailsWithoutInstallingWhenPfFails(t *testing.T) {
	h := newHarness(t, true)
	h.pfctl.fail = map[string]error{"-a " + pf.Anchor + " -f -": errors.New("pfctl: syntax error")}
	code, out, errOut := h.run("enable", "--vpn", "ipsec0", "anthropic")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: could not apply the firewall rules", "syntax error"})
	if exists(h.path(daemon.PlistPath)) {
		t.Fatal("daemon installed although the rules failed")
	}
}

func TestEnableWarnsAboutThePrototype(t *testing.T) {
	h := newHarness(t, true)
	legacy := h.path(daemon.LegacyPlistPath)
	os.MkdirAll(filepath.Dir(legacy), 0o755)
	os.WriteFile(legacy, []byte("<plist/>"), 0o644)
	code, out, errOut := h.run("enable", "--vpn", "ipsec0", "anthropic")
	expect(t, code, out, errOut, 0, []string{"Protected through ipsec0"}, []string{"leakguard: warning: the macOS prototype is still installed", "sudo prototypes/macos-pf/uninstall.sh"})
	if !exists(legacy) {
		t.Fatal("enable removed the prototype plist")
	}
}

func TestEnableNotesADisconnectedVPN(t *testing.T) {
	h := newHarness(t, true)
	h.pfctl.outputs = loadedPfctl(t, "utun7")
	code, out, errOut := h.run("enable", "--vpn", "utun7", "anthropic")
	expect(t, code, out, errOut, 0, []string{"utun7 is not connected right now"}, nil)
}

func TestDisable(t *testing.T) {
	h := newHarness(t, false)
	code, out, errOut := h.run("disable")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: run with sudo: sudo leakguard disable"})

	h = newHarness(t, true)
	h.run("enable", "--vpn", "ipsec0", "anthropic")
	h.pfctl.calls, h.launchctl.calls = nil, nil
	code, out, errOut = h.run("disable")
	expect(t, code, out, errOut, 0, []string{"Protection disabled. Protected services now use your normal connection.\n"}, nil)
	if exists(h.path(daemon.PlistPath)) || exists(h.path(daemon.BinaryPath)) {
		t.Fatal("disable left the daemon installed")
	}
	if strings.Join(h.pfctl.calls, "|") != "-a "+pf.Anchor+" -F all" {
		t.Fatalf("pfctl calls = %v, want a flush", h.pfctl.calls)
	}
	if strings.Join(h.launchctl.calls, "|") != "bootout system/"+daemon.Label {
		t.Fatalf("launchctl calls = %v", h.launchctl.calls)
	}
	if _, err := h.loadConfig(t); err != nil {
		t.Fatalf("disable removed the config: %v", err)
	}
}

func TestApply(t *testing.T) {
	h := newHarness(t, false)
	code, out, errOut := h.run("apply")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: run with sudo"})

	h = newHarness(t, true)
	h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}})
	code, out, errOut = h.run("apply")
	expect(t, code, out, errOut, 0, []string{"Protected through ipsec0: anthropic"}, nil)
	// S4: the daemon log needs a timestamp on every run.
	if out != "2026-11-16T15:00:00Z Protected through ipsec0: anthropic\n" {
		t.Fatalf("stdout = %q, want one timestamped line", out)
	}
}

// A pause from the menu-bar app must not survive the root CLI: once apply or
// enable loads the rules, the saved config is unpaused, so the daemon loads
// them again after a reboot.
func TestApplyAndEnableEndAPause(t *testing.T) {
	for _, args := range [][]string{{"apply"}, {"enable"}, {"enable", "--vpn", "ipsec0", "anthropic"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			h := newHarness(t, true)
			h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}, Paused: true})
			code, out, errOut := h.run(args...)
			expect(t, code, out, errOut, 0, []string{"Protected through ipsec0"}, nil)
			got, err := h.loadConfig(t)
			if err != nil || got.Paused || got.VPNInterface != "ipsec0" || strings.Join(got.Services, ",") != "anthropic" {
				t.Fatalf("saved config = %+v, %v; want ipsec0, anthropic, unpaused", got, err)
			}
			if !strings.Contains(strings.Join(h.pfctl.calls, "|"), "-a "+pf.Anchor+" -f -") {
				t.Fatalf("pfctl calls = %v, want the anchor loaded", h.pfctl.calls)
			}
		})
	}
}

// If apply cannot load the rules, the pause stays saved: it ends only when
// the rules are really loaded.
func TestApplyKeepsThePauseWhenTheRulesFail(t *testing.T) {
	h := newHarness(t, true)
	h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}, Paused: true})
	h.pfctl.fail = map[string]error{"-a " + pf.Anchor + " -f -": errors.New("pfctl: syntax error")}
	code, out, errOut := h.run("apply")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: pfctl: syntax error"})
	if got, err := h.loadConfig(t); err != nil || !got.Paused {
		t.Fatalf("saved config = %+v, %v; want still paused", got, err)
	}
}

func TestApplyTimestampsFailures(t *testing.T) {
	h := newHarness(t, true)
	h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}})
	h.pfctl.fail = map[string]error{"-a " + pf.Anchor + " -f -": errors.New("pfctl: syntax error")}
	code, out, errOut := h.run("apply")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: pfctl: syntax error"})
	if out != "" || errOut != "2026-11-16T15:00:00Z leakguard: pfctl: syntax error\n" {
		t.Fatalf("stdout = %q, stderr = %q, want one timestamped error line", out, errOut)
	}
}

func TestApplyFailsClosedWithoutAValidConfig(t *testing.T) {
	h := newHarness(t, true)
	code, out, errOut := h.run("apply")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: not configured yet; run: sudo leakguard enable --vpn IFACE SERVICE..."})
	if len(h.pfctl.calls) != 0 {
		t.Fatalf("apply touched pf without a config: %v", h.pfctl.calls)
	}
	os.MkdirAll(filepath.Dir(h.path(config.DefaultPath)), 0o755)
	os.WriteFile(h.path(config.DefaultPath), []byte(`{"vpn_interface":"en0","services":["anthropic"]}`), 0o644)
	code, out, errOut = h.run("apply")
	expect(t, code, out, errOut, 1, nil, []string{`leakguard: invalid configuration: "en0" is not a VPN interface`})
	if len(h.pfctl.calls) != 0 {
		t.Fatalf("apply touched pf with an invalid config (it must never flush): %v", h.pfctl.calls)
	}
}

func TestStatus(t *testing.T) {
	h := newHarness(t, false)
	code, out, errOut := h.run("status")
	expect(t, code, out, errOut, 0, []string{"leakguard is not configured yet", "sudo leakguard enable --vpn IFACE SERVICE..."}, nil)

	h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}})
	code, out, errOut = h.run("status")
	expect(t, code, out, errOut, 0, []string{"VPN interface:", "ipsec0 (connected)", "Services:", "anthropic", "Background service:", "not installed", `run "sudo leakguard status" to verify`}, nil)
	if len(h.pfctl.calls) != 0 {
		t.Fatalf("status ran pfctl without root: %v", h.pfctl.calls)
	}
}

func TestStatusShowsTheLastLogLine(t *testing.T) {
	h := newHarness(t, false)
	h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}})
	code, out, errOut := h.run("status")
	expect(t, code, out, errOut, 0, []string{"Services:"}, nil)
	if strings.Contains(out, "Last background run") {
		t.Fatalf("status shows a log line without a log:\n%s", out)
	}
	log := h.path(daemon.LogPath)
	os.MkdirAll(filepath.Dir(log), 0o755)
	os.WriteFile(log, []byte("2026-11-16T14:59:00Z Protected through ipsec0: anthropic\n2026-11-16T15:00:00Z leakguard: pfctl: syntax error\n"), 0o644)
	code, out, errOut = h.run("status")
	expect(t, code, out, errOut, 0, []string{"Last background run: 2026-11-16T15:00:00Z leakguard: pfctl: syntax error\n"}, nil)
}

func TestStatusVerifiesWithRoot(t *testing.T) {
	h := newHarness(t, true)
	h.run("enable", "--vpn", "ipsec0", "anthropic")
	code, out, errOut := h.run("status")
	expect(t, code, out, errOut, 0, []string{"Background service: installed", "Firewall:", "PROTECTED"}, nil)

	h.pfctl.outputs["-a "+pf.Anchor+" -s rules"] = ""
	code, out, errOut = h.run("status")
	expect(t, code, out, errOut, 1, []string{"NOT PROTECTED: leakguard rules are not loaded"}, nil)
}

// S2: rules in the anchor filter nothing while pf itself is disabled.
func TestStatusFailsWhenPfIsDisabled(t *testing.T) {
	h := newHarness(t, true)
	h.run("enable", "--vpn", "ipsec0", "anthropic")
	h.pfctl.outputs["-s info"] = "Status: Disabled for 0 days\n"
	code, out, errOut := h.run("status")
	expect(t, code, out, errOut, 1, []string{"Firewall:", "NOT PROTECTED: pf is disabled"}, nil)
	if strings.Contains(out, "Firewall:           PROTECTED") || strings.Contains(out, " PROTECTED\n") {
		t.Fatalf("status says PROTECTED with pf disabled:\n%s", out)
	}
	h.pfctl.fail = map[string]error{"-s info": errors.New("pfctl: /dev/pf: Permission denied")}
	code, out, errOut = h.run("status")
	expect(t, code, out, errOut, 1, []string{"NOT PROTECTED: pfctl: /dev/pf: Permission denied"}, nil)
}

func TestTestCommand(t *testing.T) {
	h := newHarness(t, false)
	code, out, errOut := h.run("test")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: not configured yet; run: sudo leakguard enable --vpn IFACE SERVICE..."})

	h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}})
	code, out, errOut = h.run("test")
	expect(t, code, out, errOut, 0, []string{"through en0", "OK blocked", "160.79.104.10", "2607:6bc0::10", "All protected services are blocked outside the VPN."}, nil)
	if h.dialIface != "en0" {
		t.Fatalf("dialed through %q, want en0", h.dialIface)
	}

	code, out, errOut = h.run("test", "--via", "en1")
	expect(t, code, out, errOut, 0, []string{"through en1"}, nil)
	if h.dialIface != "en1" {
		t.Fatalf("--via ignored: dialed through %q", h.dialIface)
	}
}

func TestTestReportsLeaks(t *testing.T) {
	h := newHarness(t, false)
	h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}})
	h.env.Dial = func(context.Context, string, netip.AddrPort) error { return nil }
	code, out, errOut := h.run("test")
	expect(t, code, out, errOut, 1, []string{"LEAK"}, []string{"leakguard: anthropic is reachable outside the VPN"})
}

func TestTestNeverPassesUntested(t *testing.T) {
	h := newHarness(t, false)
	h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}})
	h.env.Resolver = fakeResolver{}
	code, out, errOut := h.run("test")
	expect(t, code, out, errOut, 1, []string{"untested"}, []string{"leakguard: anthropic could not be tested; this is not a pass"})
	if len(h.dialed) != 0 {
		t.Fatalf("dialed %v without resolved addresses", h.dialed)
	}
}

func TestTestFailsWhenAnAddressIsNotCovered(t *testing.T) {
	h := newHarness(t, false)
	h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}})
	res := anthropicResolver()
	res["claude.ai"] = []string{"160.79.104.10", "104.18.0.2"}
	h.env.Resolver = res
	code, out, errOut := h.run("test")
	expect(t, code, out, errOut, 1,
		[]string{"NOT COVERED", "claude.ai 104.18.0.2", "outside the catalog ranges; pf does not protect it"},
		[]string{"leakguard: anthropic: claude.ai resolves to 104.18.0.2, outside the catalog ranges; pf does not protect it"})
	if strings.Contains(out, "All protected services are blocked") {
		t.Fatalf("test passed with an address outside the catalog:\n%s", out)
	}
	for _, d := range h.dialed {
		if strings.HasPrefix(d, "104.18.0.2") {
			t.Fatalf("dialed %s outside the catalog ranges", d)
		}
	}
}

func TestTestFailsWhenOneDomainIsUntested(t *testing.T) {
	h := newHarness(t, false)
	h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}})
	res := anthropicResolver()
	delete(res, "claude.com")
	h.env.Resolver = res
	code, out, errOut := h.run("test")
	expect(t, code, out, errOut, 1, []string{"untested", "claude.com", "no such host"},
		[]string{"leakguard: anthropic: claude.com could not be tested; this is not a pass"})
}

// L2: IPv6 has no route on an IPv4-only Wi-Fi; that address stays untested
// but does not fail a domain whose IPv4 address is blocked.
func TestTestPassesWithAnUntestedAddressInABlockedDomain(t *testing.T) {
	h := newHarness(t, false)
	h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}})
	h.env.Dial = func(_ context.Context, _ string, addr netip.AddrPort) error {
		if addr.Addr().Is6() {
			return syscall.EHOSTUNREACH
		}
		return syscall.ECONNREFUSED
	}
	code, out, errOut := h.run("test")
	expect(t, code, out, errOut, 0, []string{"untested", "2607:6bc0::10", "no refusal", "All protected services are blocked outside the VPN."}, nil)
}

func TestTestRefusesTheVPNInterface(t *testing.T) {
	h := newHarness(t, false)
	h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}})
	code, out, errOut := h.run("test", "--via", "ipsec0")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: ipsec0 is a VPN interface", "--via"})
	code, out, errOut = h.run("test", "--via", "en0;rm")
	expect(t, code, out, errOut, 2, nil, []string{`leakguard: "en0;rm" is not a valid interface name`})
	if len(h.dialed) != 0 {
		t.Fatalf("dialed %v through the wrong interface", h.dialed)
	}
}

// L2: en0 is an unplugged Ethernet port, en1 the Wi-Fi, the default route the VPN.
func liveInterfaces() ([]Interface, error) {
	return []Interface{
		{Name: "lo0", Up: true},
		{Name: "en0", Up: true},
		{Name: "en1", Up: true, HasAddress: true},
		{Name: "ipsec0", Up: true, HasAddress: true},
		{Name: "utun3", Up: true, HasAddress: true},
	}, nil
}

func TestTestPicksTheRealInterfaceWhenTheDefaultRouteIsTheVPN(t *testing.T) {
	for _, tc := range []struct {
		name   string
		route  func() (string, error)
		reason string
	}{
		{"vpn route", func() (string, error) { return "ipsec0", nil }, "The default route uses ipsec0, a VPN interface"},
		{"no route", func() (string, error) { return "", errors.New("no default route found") }, "Cannot read the default route (no default route found)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, false)
			h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}})
			h.env.DefaultInterface = tc.route
			h.env.Interfaces = liveInterfaces
			code, out, errOut := h.run("test")
			expect(t, code, out, errOut, 0, []string{
				tc.reason + "; testing through en1, the only connected interface outside the VPN.\n",
				"through en1, outside the VPN", "All protected services are blocked outside the VPN."}, nil)
			if h.dialIface != "en1" {
				t.Fatalf("dialed through %q, want en1", h.dialIface)
			}
		})
	}
}

func TestTestNeverGuessesTheRealInterface(t *testing.T) {
	h := newHarness(t, false)
	h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}})
	h.env.DefaultInterface = func() (string, error) { return "ipsec0", nil }
	code, out, errOut := h.run("test")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: the default route uses ipsec0, a VPN interface, and more than one other interface is connected (en0, en1); name your real connection with --via IFACE\n"})
	if out != "" {
		t.Fatalf("stdout = %q, want empty", out)
	}

	h.env.Interfaces = func() ([]Interface, error) {
		return []Interface{{Name: "en0", Up: true}, {Name: "ipsec0", Up: true, HasAddress: true}}, nil
	}
	code, out, errOut = h.run("test")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: the default route uses ipsec0, a VPN interface, and no other interface is connected; connect Wi-Fi or Ethernet, or name your real connection with --via IFACE\n"})

	h.env.DefaultInterface = func() (string, error) { return "", errors.New("no default route found") }
	h.env.Interfaces = func() ([]Interface, error) { return nil, errors.New("permission denied") }
	code, out, errOut = h.run("test")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: cannot read the default route (no default route found), and the interfaces cannot be listed (permission denied); name your real connection with --via IFACE\n"})
	if len(h.dialed) != 0 {
		t.Fatalf("dialed %v without knowing the real interface", h.dialed)
	}
}

func TestTestRejectsAnInactiveVia(t *testing.T) {
	h := newHarness(t, false)
	h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}})
	h.env.Interfaces = liveInterfaces
	code, out, errOut := h.run("test", "--via", "en0")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: en0 is not connected; pick the interface of your real connection with --via (connected: en1)\n"})
	code, out, errOut = h.run("test", "--via", "en9")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: en9 does not exist; pick the interface of your real connection with --via (connected: en1)\n"})
	h.env.Interfaces = func() ([]Interface, error) { return []Interface{{Name: "en0"}}, nil }
	code, out, errOut = h.run("test", "--via", "en0")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: en0 is not connected; pick the interface of your real connection with --via (connected: none)\n"})
	if out != "" || len(h.dialed) != 0 {
		t.Fatalf("probed through an inactive interface: stdout %q, dialed %v", out, h.dialed)
	}
}
