package main

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/daemon"
	"github.com/Isaacpaezz/leakguard/internal/nft"
	"github.com/Isaacpaezz/leakguard/internal/pf"
)

// fakeNft is an nftables that keeps the leakguard table it was given and
// lists it as "nft -j" does.
type fakeNft struct {
	mu     sync.Mutex
	calls  []string
	loaded bool
	oif    string
	sets   [2][]string
}

var (
	nftOif   = regexp.MustCompile(`oifname != "([^"]*)"`)
	nftElems = regexp.MustCompile(`elements = \{ ([^}]*) \}`)
)

func (f *fakeNft) Run(stdin string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.Join(args, " ")
	f.calls = append(f.calls, key)
	switch key {
	case "-f -":
		f.loaded = strings.Contains(stdin, "chain "+nft.Chain)
		f.oif, f.sets = "", [2][]string{}
		if m := nftOif.FindStringSubmatch(stdin); m != nil {
			f.oif = m[1]
		}
		for i, set := range strings.Split(stdin, "set protected")[1:] {
			if m := nftElems.FindStringSubmatch(set); m != nil && i < 2 {
				f.sets[i] = strings.Split(m[1], ", ")
			}
		}
	case "-j list table inet leakguard":
		if !f.loaded {
			return "", errors.New("nft -j list table inet leakguard: exit status 1: Error: No such file or directory")
		}
		return f.listing(), nil
	}
	return "", nil
}

func (f *fakeNft) listing() string {
	objs := []string{`{"chain": {"family": "inet", "table": "leakguard", "name": "output", "hook": "output"}}`}
	for i, name := range []string{"protected4", "protected6"} {
		var elems []string
		for _, e := range f.sets[i] {
			switch lo, hi, isRange := strings.Cut(e, "-"); {
			case isRange:
				elems = append(elems, fmt.Sprintf(`{"range": [%q, %q]}`, lo, hi))
			case strings.Contains(e, "/"):
				addr, bits, _ := strings.Cut(e, "/")
				elems = append(elems, fmt.Sprintf(`{"prefix": {"addr": %q, "len": %s}}`, addr, bits))
			default:
				elems = append(elems, fmt.Sprintf("%q", e))
			}
		}
		objs = append(objs, fmt.Sprintf(`{"set": {"name": %q, "elem": [%s]}}`, name, strings.Join(elems, ", ")))
	}
	for _, fam := range [][2]string{{"ip", "protected4"}, {"ip6", "protected6"}} {
		for _, tcp := range []bool{true, false} {
			var e []string
			if f.oif != "" {
				e = append(e, fmt.Sprintf(`{"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": %q}}`, f.oif))
			}
			e = append(e, fmt.Sprintf(`{"match": {"op": "==", "left": {"payload": {"protocol": %q, "field": "daddr"}}, "right": "@%s"}}`, fam[0], fam[1]))
			reject := `{"reject": {"type": "icmpx", "expr": "port-unreachable"}}`
			if tcp {
				e = append(e, `{"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}}`)
				reject = `{"reject": {"type": "tcp reset"}}`
			}
			e = append(e, `{"counter": {"packets": 0, "bytes": 0}}`, reject)
			objs = append(objs, fmt.Sprintf(`{"rule": {"chain": "output", "expr": [%s]}}`, strings.Join(e, ", ")))
		}
	}
	return `{"nftables": [` + strings.Join(objs, ", ") + "]}"
}

// linuxHarness picks the Linux backends, nftables and systemd, through fakes.
func linuxHarness(t *testing.T) (*harness, *fakeNft, *fakeSystemctl) {
	t.Helper()
	h := newHarness(t, true)
	n, sc := &fakeNft{}, &fakeSystemctl{}
	h.env.Nft, h.env.Systemctl = n, sc
	h.env.Firewall, h.env.Services = nftFirewall, systemdServices
	return h, n, sc
}

// S1: enable, status and disable work on Linux through nftables and systemd.
func TestLinuxBackendsThroughTheCLI(t *testing.T) {
	h, n, sc := linuxHarness(t)
	code, out, errOut := h.run("enable", "--vpn", "wg0", "anthropic")
	expect(t, code, out, errOut, 0, []string{"Protected through wg0: Anthropic"}, nil)
	if !n.loaded || n.oif != "wg0" || len(n.sets[0]) == 0 || len(n.sets[1]) == 0 {
		t.Fatalf("nft table = loaded %v, oif %q, sets %v", n.loaded, n.oif, n.sets)
	}
	code, out, errOut = h.run("status")
	expect(t, code, out, errOut, 0, []string{"VPN interface:      wg0", "Background service: installed", "Firewall:           PROTECTED"}, nil)
	code, out, errOut = h.run("disable")
	expect(t, code, out, errOut, 0, []string{"Protection disabled."}, nil)
	if n.loaded {
		t.Fatal("disable left the nft table loaded")
	}
	code, out, errOut = h.run("status")
	expect(t, code, out, errOut, 1, []string{"Background service: not installed", "Firewall:           NOT PROTECTED: leakguard rules are not loaded"}, nil)
	if !strings.HasPrefix(strings.Join(sc.calls, "|"), "daemon-reload|enable leakguard.service|restart leakguard.service") {
		t.Errorf("systemctl calls = %v", sc.calls)
	}
	if len(h.pfctl.calls) != 0 || len(h.launchctl.calls) != 0 || exists(h.path(daemon.PlistPath)) {
		t.Errorf("macOS backends used: pfctl %v, launchctl %v", h.pfctl.calls, h.launchctl.calls)
	}
}

// S1: on Linux, main picks nftables, run by the real nft.
func TestLinuxPicksNftables(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	if reflect.ValueOf(systemFirewall).Pointer() != reflect.ValueOf(nftFirewall).Pointer() {
		t.Fatal("systemFirewall is not nftFirewall")
	}
	if _, ok := systemEnv().Nft.(nft.ExecRunner); !ok {
		t.Fatal("systemEnv().Nft is not nft.ExecRunner")
	}
	if fw := nftFirewall(Env{}); fw.Name() != "nftables" {
		t.Fatalf("nftFirewall() = %s", fw.Name())
	}
}

// refusedVPN is refused on every system: by name on macOS and, as a missing
// interface, by name on Linux too.
const refusedVPN = "en9"

const (
	blockedLog    = `invalid configuration: "en9" is not a VPN interface; it carries your real connection; protected services are blocked on every interface`
	blockedReason = `protected services are blocked: the saved VPN "en9" is not a VPN interface; choose yours with: sudo leakguard enable --vpn IFACE`
)

func blockOnly(p *statefulPfctl) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.rules) == 1 && strings.HasPrefix(p.rules[0], "block return out quick to <leakguard>") && len(p.table) > 0
}

// S7: when the saved VPN becomes refused, the daemon loads the block-all
// rules and logs why once, then only verifies them (the counter keeps
// counting); when the VPN is accepted again, it loads the normal rules.
func TestServeBlocksEverythingWhenTheSavedVPNIsRefused(t *testing.T) {
	h, p := statefulHarness(t)
	h.env.ApplyEvery = 5 * time.Millisecond
	s := startServe(t, h)
	s.waitFor(t, "Protected through ipsec0: anthropic\n", 1)
	h.saveConfig(t, config.Config{VPNInterface: refusedVPN, Services: []string{"anthropic"}})
	eventually(t, "the block-all rules", func() bool { return blockOnly(p) && p.count(loadAnchor) == 2 })
	reads := p.count("-a " + pf.Anchor + " -s rules")
	eventually(t, "3 more verifies", func() bool { return p.count("-a "+pf.Anchor+" -s rules") >= reads+3 })
	p.block(4)
	eventually(t, "4 blocks", func() bool { return todayBlocks(s) == 4 })
	st, err := s.client.Status()
	if err != nil || st.Protected || st.Reason != blockedReason || st.VPNInterface != refusedVPN {
		t.Fatalf("socket status = %+v, %v; want not protected: %s", st, err, blockedReason)
	}
	if n := p.count(loadAnchor); n != 2 || !blockOnly(p) {
		t.Fatalf("loads = %d, want 2: the block-all rules must be verified, not reloaded", n)
	}
	h.saveConfig(t, config.Config{VPNInterface: "utun9", Services: []string{"anthropic"}})
	s.waitFor(t, "Protected through utun9: anthropic\n", 1)
	h.saveConfig(t, config.Config{VPNInterface: refusedVPN, Services: []string{"anthropic"}})
	eventually(t, "the block-all rules again", func() bool { return blockOnly(p) && p.count(loadAnchor) == 4 })
	s.stop(t)
	want := strings.Repeat("2026-11-16T15:00:00Z leakguard: "+blockedLog+"\n", 2)
	if got := s.stderr.String(); got != want {
		t.Fatalf("stderr = %q, want the reason once per change:\n%q", got, want)
	}
}

// Paused still means no rules, even with a refused VPN.
func TestServeLoadsNothingWhilePausedWithARefusedVPN(t *testing.T) {
	h, p := statefulHarness(t)
	h.env.ApplyEvery = 5 * time.Millisecond
	h.saveConfig(t, config.Config{VPNInterface: refusedVPN, Services: []string{"anthropic"}, Paused: true})
	s := startServe(t, h)
	time.Sleep(30 * time.Millisecond) // several ticks
	s.stop(t)
	if n := p.count(loadAnchor); n != 0 || p.loadedRules() {
		t.Fatalf("loads = %d while paused", n)
	}
}

// S7: "sudo leakguard apply" with a refused saved VPN loads the block-all
// rules, ends a pause and fails with the reason.
func TestApplyBlocksEverythingWhenTheSavedVPNIsRefused(t *testing.T) {
	h, p := statefulHarness(t)
	h.saveConfig(t, config.Config{VPNInterface: refusedVPN, Services: []string{"anthropic"}, Paused: true})
	code, out, errOut := h.run("apply")
	if code != 1 || out != "" || errOut != "2026-11-16T15:00:00Z leakguard: "+blockedLog+"\n" {
		t.Fatalf("apply = %d, stdout %q, stderr %q", code, out, errOut)
	}
	if !blockOnly(p) || p.count(loadAnchor) != 1 {
		t.Fatalf("apply did not load the block-all rules: %v", p.calls)
	}
	if cfg, err := h.loadConfig(t); err != nil || cfg.Paused || cfg.VPNInterface != refusedVPN {
		t.Fatalf("config = %+v, %v; want the pause cleared and the rest kept", cfg, err)
	}
}

// S7: an invalid choice of services still leaves the rules alone.
func TestApplyWithInvalidServicesAndARefusedVPNTouchesNothing(t *testing.T) {
	h, p := statefulHarness(t)
	os.WriteFile(h.path(config.DefaultPath), []byte(`{"vpn_interface":"en9","services":["gemini"]}`), 0o644)
	code, out, errOut := h.run("apply")
	expect(t, code, out, errOut, 1, nil, []string{`leakguard: invalid configuration: "en9" is not a VPN interface`})
	if len(p.calls) != 0 {
		t.Fatalf("apply touched pf: %v", p.calls)
	}
}

// S7: status says plainly that protected services are blocked, naming the
// saved VPN, and whether the block-all rules are really loaded.
func TestStatusSaysBlockedWhenTheSavedVPNIsRefused(t *testing.T) {
	h, p := statefulHarness(t)
	h.saveConfig(t, config.Config{VPNInterface: refusedVPN, Services: []string{"anthropic"}})
	if code, _, _ := h.run("apply"); code != 1 || !blockOnly(p) {
		t.Fatal("apply did not load the block-all rules")
	}
	code, out, errOut := h.run("status")
	expect(t, code, out, errOut, 1, []string{"VPN interface:      en9 (not connected)", "Services:           anthropic", "Firewall:           NOT PROTECTED: " + blockedReason + "\n"}, nil)

	p.unload()
	code, out, errOut = h.run("status")
	expect(t, code, out, errOut, 1, []string{`Firewall:           NOT PROTECTED: the saved VPN "en9" is not a VPN interface, and protected services are not blocked: leakguard rules are not loaded` + "\n"}, nil)
}

// S2: the normal serve path loads the same rules once, then verifies them,
// and logs exactly what it logged before.
func TestServeNormalPathIsUnchanged(t *testing.T) {
	h, p := statefulHarness(t)
	h.env.ApplyEvery = 5 * time.Millisecond
	s := startServe(t, h)
	s.waitFor(t, "Protected through ipsec0: anthropic\n", 3)
	s.stop(t)
	if s.stderr.String() != "" {
		t.Fatalf("stderr = %q", s.stderr.String())
	}
	if got := strings.ReplaceAll(s.stdout.String(), "2026-11-16T15:00:00Z Protected through ipsec0: anthropic\n", ""); got != "" {
		t.Fatalf("stdout has other lines: %q", got)
	}
	want := []string{"pass out quick on ipsec0 to <leakguard> keep state", "block return out quick to <leakguard>"}
	if p.count(loadAnchor) != 1 || !reflect.DeepEqual(p.rules, want) {
		t.Fatalf("loads = %d, rules = %q", p.count(loadAnchor), p.rules)
	}
}

// S7 on Linux: a refused saved VPN loads nftables rules that allow no
// interface, and status says so.
func TestLinuxApplyBlocksEverythingWhenTheSavedVPNIsRefused(t *testing.T) {
	h, n, _ := linuxHarness(t)
	h.saveConfig(t, config.Config{VPNInterface: refusedVPN, Services: []string{"anthropic"}})
	code, out, errOut := h.run("apply")
	if code != 1 || out != "" || errOut != "2026-11-16T15:00:00Z leakguard: "+blockedLog+"\n" {
		t.Fatalf("apply = %d, stdout %q, stderr %q", code, out, errOut)
	}
	if !n.loaded || n.oif != "" || len(n.sets[0]) == 0 || len(n.sets[1]) == 0 {
		t.Fatalf("nft table = loaded %v, oif %q, sets %v; want block-all rules", n.loaded, n.oif, n.sets)
	}
	code, out, errOut = h.run("status")
	expect(t, code, out, errOut, 1, []string{"Firewall:           NOT PROTECTED: " + blockedReason + "\n"}, nil)
}
