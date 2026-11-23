package wfp

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/firewall"
)

// A nested range stays its own filter; a range listed twice is one filter.
var services = []catalog.Service{
	{ID: "claude", IPv4: []string{"160.79.104.0/23", "160.79.104.0/24"}, IPv6: []string{"2607:6bc0::/48"}},
	{ID: "openai", IPv4: []string{"160.79.104.0/23"}, IPv6: []string{"2607:6bc0:1::/48"}},
}

var ranges = []string{"160.79.104.0/23", "160.79.104.0/24", "2607:6bc0::/48", "2607:6bc0:1::/48"}

const (
	vpn     = "WireGuard Tunnel" // aliases may contain spaces
	vpnLUID = 0x0047000000000005
)

// fakeEngine keeps filters in memory and checks after every change that
// each protected range is still blocked once it was blocked.
type fakeEngine struct {
	t          *testing.T
	installed  bool
	provider   bool
	filters    []Filter
	ops        []string
	failAdd    int // fail the n-th Add (1-based) of this engine; 0 never
	adds       int
	failList   error
	failDelete func(GUID) error // fails Delete of this key when it returns an error
	opens      int
	closes     int
	mustBlock  []netip.Prefix // ranges that must stay blocked
	gapChecked int
}

func (e *fakeEngine) Install() error {
	e.ops = append(e.ops, "install")
	e.installed, e.provider = true, true
	return nil
}

func (e *fakeEngine) Installed() (bool, error) { return e.installed, nil }

func (e *fakeEngine) Filters() ([]Filter, error) {
	if e.failList != nil {
		return nil, e.failList
	}
	return slices.Clone(e.filters), nil
}

func (e *fakeEngine) Add(f Filter) error {
	e.adds++
	if e.adds == e.failAdd {
		return errors.New("FWP_E_OUT_OF_BOUNDS")
	}
	for _, x := range e.filters {
		if x.Key == f.Key {
			return fmt.Errorf("filter %s already exists", f.Key)
		}
	}
	if !e.installed {
		return errors.New("FWP_E_SUBLAYER_NOT_FOUND")
	}
	e.ops = append(e.ops, "add "+f.Rule.Action.String())
	e.filters = append(e.filters, f)
	e.checkGap()
	return nil
}

func (e *fakeEngine) Delete(k GUID) error {
	if e.failDelete != nil {
		if err := e.failDelete(k); err != nil {
			return err
		}
	}
	e.ops = append(e.ops, "delete")
	e.filters = slices.DeleteFunc(e.filters, func(f Filter) bool { return f.Key == k })
	e.checkGap()
	return nil
}

func (e *fakeEngine) Uninstall() error {
	if len(e.filters) > 0 {
		return errors.New("FWP_E_IN_USE")
	}
	e.ops = append(e.ops, "uninstall")
	e.installed, e.provider = false, false
	return nil
}

func (e *fakeEngine) Close() error { e.closes++; return nil }

// checkGap fails when a range in mustBlock has no hard block filter.
func (e *fakeEngine) checkGap() {
	e.gapChecked++
	for _, p := range e.mustBlock {
		blocked := false
		for _, f := range e.filters {
			r := f.Rule
			if r.Action == ActionBlock && r.Hard && r.Remote == p && r.LUID == 0 && r.Sublayer == SublayerKey {
				blocked = true
			}
		}
		if !blocked {
			e.t.Errorf("after %q, %s is not blocked", e.ops[len(e.ops)-1], p)
		}
	}
}

func (e *fakeEngine) rules() []Rule {
	var out []Rule
	for _, f := range e.filters {
		out = append(out, f.Rule)
	}
	return out
}

func newFake(t *testing.T) *fakeEngine { return &fakeEngine{t: t} }

// fw is a Firewall over e whose resolver knows only vpn, and whose checker
// accepts every alias but "Ethernet".
func fw(e *fakeEngine) Firewall {
	return Firewall{
		Open: func() (Engine, error) { e.opens++; return e, nil },
		Resolve: func(alias string) (uint64, error) {
			if alias == vpn {
				return vpnLUID, nil
			}
			return 0, fmt.Errorf("%w %q", ErrNoAdapter, alias)
		},
		Check: func(alias string) error {
			if alias == "Ethernet" {
				return fmt.Errorf("%q is a physical network adapter: %w", alias, config.ErrVPNRefused)
			}
			return nil
		},
	}
}

func prefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

// want is the expected rule set: blocks for every range, permits for luid.
func want(t *testing.T, luid uint64) []Rule {
	t.Helper()
	var out []Rule
	for _, p := range prefixes(t, ranges...) {
		layer := LayerConnectV4
		if p.Addr().Is6() {
			layer = LayerConnectV6
		}
		out = append(out, Rule{Layer: layer, Sublayer: SublayerKey, Action: ActionBlock, Remote: p, Weight: BlockWeight, Hard: true, Persistent: true})
	}
	if luid != 0 {
		for _, r := range slices.Clone(out) {
			r.Action, r.LUID, r.Weight, r.Hard = ActionPermit, luid, PermitWeight, false
			out = append(out, r)
		}
	}
	return out
}

func sameRules(t *testing.T, got, wantRules []Rule) {
	t.Helper()
	key := func(r Rule) string { return r.String() }
	g := slices.Sorted(slices.Values(mapRules(got, key)))
	w := slices.Sorted(slices.Values(mapRules(wantRules, key)))
	if !slices.Equal(g, w) {
		t.Errorf("rules:\n got %q\nwant %q", g, w)
	}
}

func mapRules(rs []Rule, f func(Rule) string) []string {
	var out []string
	for _, r := range rs {
		out = append(out, f(r))
	}
	return out
}

func TestName(t *testing.T) {
	if got := (Firewall{}).Name(); got != "Windows Filtering Platform" {
		t.Errorf("Name() = %q", got)
	}
}

func TestBlockCountIsUnsupported(t *testing.T) {
	n, err := (Firewall{}).BlockCount()
	if !errors.Is(err, firewall.ErrUnsupported) || n != 0 {
		t.Errorf("BlockCount() = %d, %v; want 0 and ErrUnsupported", n, err)
	}
}

// The permit outweighs the block, and neither is 0: a weight that cannot be
// read back reads as 0 and must never match an expected filter.
func TestBlockAndPermitWeights(t *testing.T) {
	if BlockWeight == 0 || PermitWeight <= BlockWeight {
		t.Errorf("block weight %d, permit weight %d: the permit must outweigh the block, and neither may be 0", BlockWeight, PermitWeight)
	}
	rules, err := Rules(vpnLUID, services)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if (r.Action == ActionBlock && r.Weight != BlockWeight) || (r.Action == ActionPermit && r.Weight != PermitWeight) {
			t.Errorf("rule %s has the wrong weight", r)
		}
	}
}

func TestApplyLoadsBlocksAndPermitsForTheVPN(t *testing.T) {
	e := newFake(t)
	if err := fw(e).Apply(vpn, services); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !e.installed {
		t.Error("provider and sublayer not installed")
	}
	sameRules(t, e.rules(), want(t, vpnLUID))
	if e.opens != e.closes {
		t.Errorf("opened %d sessions, closed %d", e.opens, e.closes)
	}
}

func TestApplyAddsBlocksBeforePermits(t *testing.T) {
	e := newFake(t)
	if err := fw(e).Apply(vpn, services); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	firstPermit := slices.Index(e.ops, "add permit")
	lastBlock := -1
	for i, op := range e.ops {
		if op == "add block" {
			lastBlock = i
		}
	}
	if firstPermit < 0 || lastBlock > firstPermit {
		t.Errorf("ops %q: every block must come before the first permit", e.ops)
	}
}

func TestApplyWithEmptyVPNLoadsBlocksOnly(t *testing.T) {
	e := newFake(t)
	if err := fw(e).Apply("", services); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	sameRules(t, e.rules(), want(t, 0))
}

func TestApplyWithRefusedVPNLoadsBlocksOnly(t *testing.T) {
	e := newFake(t)
	err := fw(e).Apply("Ethernet", services)
	if err == nil || !errors.Is(err, config.ErrVPNRefused) {
		t.Fatalf("Apply = %v, want a refusal", err)
	}
	if !strings.Contains(err.Error(), `cannot use "Ethernet" as the VPN interface, protected services are blocked on every interface: "Ethernet" is a physical network adapter`) {
		t.Errorf("error %q does not name the reason", err)
	}
	sameRules(t, e.rules(), want(t, 0))
}

// S7: a VPN adapter that does not exist (the VPN is down, the normal state
// on Windows) loads the blocks only, and that is a success.
func TestApplyWithAbsentAdapterLoadsBlocksOnly(t *testing.T) {
	e := newFake(t)
	f := fw(e)
	if err := f.Apply(vpn, services); err != nil {
		t.Fatalf("Apply(%q): %v", vpn, err)
	}
	if err := f.Apply("OpenVPN Data Channel Offload", services); err != nil {
		t.Fatalf("Apply with the VPN adapter absent = %v, want nil", err)
	}
	sameRules(t, e.rules(), want(t, 0))
}

// S7: when the adapters cannot be listed, the blocks load and Apply fails.
func TestApplyWhenTheAdaptersCannotBeListedLoadsBlocksAndFails(t *testing.T) {
	e := newFake(t)
	f := fw(e)
	f.Resolve = func(string) (uint64, error) {
		return 0, errors.New("cannot list the network adapters: ERROR_NOT_ENOUGH_MEMORY")
	}
	err := f.Apply(vpn, services)
	if err == nil || !strings.Contains(err.Error(), "protected services are blocked on every interface: cannot list the network adapters: ERROR_NOT_ENOUGH_MEMORY") {
		t.Fatalf("Apply = %v, want the listing failure", err)
	}
	sameRules(t, e.rules(), want(t, 0))
	if err := f.Verify(vpn, services); err == nil || !strings.Contains(err.Error(), "ERROR_NOT_ENOUGH_MEMORY") {
		t.Errorf("Verify = %v, want the listing failure", err)
	}
}

func TestApplyWithDefaultCheckRefusesWhatConfigRefuses(t *testing.T) {
	const name = "Ethernet 2"
	refusal := config.CheckVPNInterface(name)
	if refusal == nil {
		t.Fatalf("config accepts %q; pick a name it refuses", name)
	}
	e := newFake(t)
	f := fw(e)
	f.Check = nil
	f.Resolve = func(string) (uint64, error) { return vpnLUID, nil }
	err := f.Apply(name, services)
	if err == nil || !strings.Contains(err.Error(), refusal.Error()) {
		t.Fatalf("Apply = %v, want %v", err, refusal)
	}
	sameRules(t, e.rules(), want(t, 0))
}

func TestApplyReplacesWithoutAGap(t *testing.T) {
	e := newFake(t)
	f := fw(e)
	if err := f.Apply("", services); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	e.mustBlock = prefixes(t, ranges...)
	e.ops = nil
	if err := f.Apply(vpn, services); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if e.gapChecked == 0 {
		t.Fatal("no change was checked")
	}
	firstDelete := slices.Index(e.ops, "delete")
	lastAdd := -1
	for i, op := range e.ops {
		if strings.HasPrefix(op, "add ") {
			lastAdd = i
		}
	}
	if firstDelete < 0 || lastAdd > firstDelete {
		t.Errorf("ops %q: every new filter must be added before the first old one is deleted", e.ops)
	}
	sameRules(t, e.rules(), want(t, vpnLUID))
	// Back to blocks only: permits go, blocks never do.
	if err := f.Apply("", services); err != nil {
		t.Fatalf("third Apply: %v", err)
	}
	sameRules(t, e.rules(), want(t, 0))
}

func TestApplyFailureKeepsTheOldFilters(t *testing.T) {
	e := newFake(t)
	f := fw(e)
	if err := f.Apply(vpn, services); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	old := slices.Clone(e.filters)
	e.mustBlock = prefixes(t, ranges...)
	e.adds, e.failAdd = 0, 3
	err := f.Apply("", services)
	if err == nil || !strings.Contains(err.Error(), "FWP_E_OUT_OF_BOUNDS") {
		t.Fatalf("Apply = %v, want the add failure", err)
	}
	if !slices.Equal(e.filters, old) {
		t.Errorf("filters after a failed Apply:\n got %v\nwant %v", e.filters, old)
	}
	if e.opens != e.closes {
		t.Errorf("opened %d sessions, closed %d", e.opens, e.closes)
	}
}

func TestApplyListFailureChangesNothing(t *testing.T) {
	e := newFake(t)
	e.failList = errors.New("FWP_E_TIMEOUT")
	if err := fw(e).Apply(vpn, services); err == nil || !strings.Contains(err.Error(), "FWP_E_TIMEOUT") {
		t.Fatalf("Apply = %v, want the list failure", err)
	}
	if len(e.filters) != 0 {
		t.Errorf("filters added after a failed listing: %v", e.filters)
	}
}

func TestApplyRejectsBadRangesBeforeTouchingTheEngine(t *testing.T) {
	e := newFake(t)
	bad := []catalog.Service{{ID: "bad", IPv4: []string{"160.79.104.0/33"}}}
	if err := fw(e).Apply(vpn, bad); err == nil || !strings.Contains(err.Error(), "service bad") {
		t.Fatalf("Apply = %v, want a range error", err)
	}
	if e.opens != 0 || len(e.ops) != 0 {
		t.Errorf("engine touched: %d opens, ops %q", e.opens, e.ops)
	}
}

func TestApplyRemovesLeftoversOfEveryOldGeneration(t *testing.T) {
	e := newFake(t)
	e.installed = true
	stray := Rule{Layer: LayerConnectV4, Sublayer: SublayerKey, Action: ActionPermit, Remote: netip.MustParsePrefix("160.79.104.0/23"), LUID: 7, Weight: PermitWeight, Persistent: true}
	e.filters = []Filter{
		{Key: filterKey(4, 0), Rule: stray},
		{Key: filterKey(9, 0), Rule: stray},
		{Key: GUID{Data1: 1}, Rule: stray}, // a key leakguard never makes
	}
	if err := fw(e).Apply(vpn, services); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	sameRules(t, e.rules(), want(t, vpnLUID))
	for _, x := range e.filters {
		if g, ok := generation(x.Key); !ok || g != 10 {
			t.Errorf("filter key %s: generation %d, %v; want 10", x.Key, g, ok)
		}
	}
}

func TestFilterKeysAreUniqueAndCarryTheirGeneration(t *testing.T) {
	seen := map[GUID]bool{}
	for _, gen := range []uint32{1, 2, math.MaxUint32} {
		for _, i := range []uint32{0, 1, 255, 256, math.MaxUint32} {
			k := filterKey(gen, i)
			if seen[k] {
				t.Errorf("key %s repeats", k)
			}
			seen[k] = true
			if g, ok := generation(k); !ok || g != gen {
				t.Errorf("generation(%s) = %d, %v; want %d", k, g, ok, gen)
			}
		}
	}
	if _, ok := generation(ProviderKey); ok {
		t.Error("the provider key parses as a filter key")
	}
}

func TestNextGeneration(t *testing.T) {
	keys := func(gens ...uint32) []Filter {
		var out []Filter
		for _, g := range gens {
			out = append(out, Filter{Key: filterKey(g, 0)})
		}
		return out
	}
	for _, tc := range []struct {
		name string
		used []uint32
		want uint32
	}{
		{"none", nil, 1},
		{"after the newest", []uint32{3, 1}, 4},
		{"wraps and skips 0", []uint32{math.MaxUint32}, 1},
		{"wraps and skips used", []uint32{math.MaxUint32, 1, 2}, 3},
	} {
		if got := nextGeneration(keys(tc.used...)); got != tc.want {
			t.Errorf("%s: nextGeneration(%v) = %d, want %d", tc.name, tc.used, got, tc.want)
		}
	}
}

func TestVerifyPassesAfterApply(t *testing.T) {
	e := newFake(t)
	f := fw(e)
	for _, v := range []string{vpn, ""} {
		if err := f.Apply(v, services); err != nil {
			t.Fatalf("Apply(%q): %v", v, err)
		}
		if err := f.Verify(v, services); err != nil {
			t.Errorf("Verify(%q): %v", v, err)
		}
	}
}

func TestVerifyWithoutSublayerIsNotLoaded(t *testing.T) {
	e := newFake(t)
	if err := fw(e).Verify(vpn, services); !errors.Is(err, firewall.ErrNotLoaded) {
		t.Errorf("Verify = %v, want ErrNotLoaded", err)
	}
}

func TestVerifyFailsOnMissingExtraOrChangedFilters(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(e *fakeEngine)
		want   string
	}{
		{"missing block", func(e *fakeEngine) { e.filters = e.filters[1:] }, "1 missing (first: block 160.79.104.0/23 at ALE_AUTH_CONNECT_V4, weight 1)"},
		{"missing permit", func(e *fakeEngine) { e.filters = e.filters[:len(e.filters)-1] }, "1 missing (first: permit 2607:6bc0:1::/48 at ALE_AUTH_CONNECT_V6 on interface LUID 0x47000000000005, weight 2)"},
		{"duplicate", func(e *fakeEngine) {
			e.filters = append(e.filters, Filter{Key: filterKey(99, 0), Rule: e.filters[0].Rule})
		}, "1 unexpected (first: block 160.79.104.0/23"},
		{"extra range", func(e *fakeEngine) {
			r := e.filters[0].Rule
			r.Remote = netip.MustParsePrefix("10.0.0.0/8")
			e.filters = append(e.filters, Filter{Key: filterKey(99, 0), Rule: r})
		}, "1 unexpected (first: block 10.0.0.0/8"},
		{"block turned permit", func(e *fakeEngine) { e.filters[0].Rule.Action = ActionPermit }, "1 unexpected (first: permit 160.79.104.0/23 at ALE_AUTH_CONNECT_V4, weight 1"},
		{"other LUID", func(e *fakeEngine) { e.filters[len(e.filters)-1].Rule.LUID = 9 }, "on interface LUID 0x9"},
		{"permit for any interface", func(e *fakeEngine) { e.filters[len(e.filters)-1].Rule.LUID = 0 }, "1 unexpected (first: permit 2607:6bc0:1::/48 at ALE_AUTH_CONNECT_V6, weight 2"},
		{"other layer", func(e *fakeEngine) { e.filters[0].Rule.Layer = LayerOther }, "at another layer"},
		{"other sublayer", func(e *fakeEngine) { e.filters[0].Rule.Sublayer = GUID{Data1: 1} }, "sublayer {00000001-"},
		{"heavier block", func(e *fakeEngine) { e.filters[0].Rule.Weight = 3 }, "weight 3"},
		{"weight read back as 0", func(e *fakeEngine) { e.filters[0].Rule.Weight = 0 }, "1 unexpected (first: block 160.79.104.0/23 at ALE_AUTH_CONNECT_V4, weight 0)"},
		{"soft block", func(e *fakeEngine) { e.filters[0].Rule.Hard = false }, ", soft"},
		{"not persistent", func(e *fakeEngine) { e.filters[0].Rule.Persistent = false }, "not persistent"},
		{"extra condition", func(e *fakeEngine) { e.filters[0].Rule.Other = "condition ALE_APP_ID" }, "condition ALE_APP_ID"},
		{"all gone", func(e *fakeEngine) { e.filters = nil }, "8 missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newFake(t)
			f := fw(e)
			if err := f.Apply(vpn, services); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			tc.change(e)
			err := f.Verify(vpn, services)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Verify = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifyEmptyVPNFailsWhenAnInterfaceIsPermitted(t *testing.T) {
	e := newFake(t)
	f := fw(e)
	if err := f.Apply(vpn, services); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := f.Verify("", services); err == nil || !strings.Contains(err.Error(), "4 unexpected (first: permit") {
		t.Errorf("Verify(\"\") = %v, want the permits reported", err)
	}
}

func TestVerifyVPNFailsWhenOnlyBlocksAreLoaded(t *testing.T) {
	e := newFake(t)
	f := fw(e)
	if err := f.Apply("", services); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := f.Verify(vpn, services); err == nil || !strings.Contains(err.Error(), "4 missing (first: permit") {
		t.Errorf("Verify = %v, want the missing permits", err)
	}
}

func TestVerifyFailsWhenTheVPNLUIDChanged(t *testing.T) {
	e := newFake(t)
	f := fw(e)
	if err := f.Apply(vpn, services); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	f.Resolve = func(string) (uint64, error) { return vpnLUID + 1, nil } // RAS reconnect
	if err := f.Verify(vpn, services); err == nil || !strings.Contains(err.Error(), "missing (first: permit") {
		t.Errorf("Verify = %v, want the new LUID missing", err)
	}
}

func TestVerifyRefusedVPNFailsEvenWithTheBlocksLoaded(t *testing.T) {
	e := newFake(t)
	f := fw(e)
	_ = f.Apply("Ethernet", services)
	err := f.Verify("Ethernet", services)
	if !errors.Is(err, config.ErrVPNRefused) || !strings.HasPrefix(err.Error(), "protected services are blocked on every interface: ") {
		t.Errorf("Verify = %v, want the refusal with the blocks loaded", err)
	}
	// A refused VPN with permits loaded reports both.
	if err := f.Apply(vpn, services); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	err = f.Verify("Ethernet", services)
	if !errors.Is(err, config.ErrVPNRefused) || !strings.Contains(err.Error(), "4 unexpected (first: permit") {
		t.Errorf("Verify = %v, want the permits and the refusal", err)
	}
}

// S7: with the VPN adapter absent, the blocks alone verify; permits left
// for it do not.
func TestVerifyAbsentAdapterExpectsTheBlocksOnly(t *testing.T) {
	e := newFake(t)
	f := fw(e)
	if err := f.Apply("Gone", services); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := f.Verify("Gone", services); err != nil {
		t.Errorf("Verify with the blocks loaded = %v, want nil", err)
	}
	if err := f.Apply(vpn, services); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := f.Verify("Gone", services); err == nil || !strings.Contains(err.Error(), "4 unexpected (first: permit") {
		t.Errorf("Verify with permits loaded = %v, want them reported", err)
	}
}

// When a rollback Delete fails after a failed Add, the error names the
// filter left behind and a later Verify reports it as unexpected.
func TestApplyReportsAFailedRollback(t *testing.T) {
	e := newFake(t)
	f := fw(e)
	if err := f.Apply(vpn, services); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	e.mustBlock = prefixes(t, ranges...)
	e.adds, e.failAdd = 0, 3 // adds blocks 0 and 1 of the new generation, then fails
	stuck := filterKey(2, 1)
	e.failDelete = func(k GUID) error {
		if k == stuck {
			return errors.New("FWP_E_IN_USE")
		}
		return nil
	}
	err := f.Apply("", services)
	if err == nil || !strings.Contains(err.Error(), "FWP_E_OUT_OF_BOUNDS") ||
		!strings.Contains(err.Error(), "cannot remove the new filter block 160.79.104.0/24 at ALE_AUTH_CONNECT_V4") ||
		!strings.Contains(err.Error(), "FWP_E_IN_USE") {
		t.Fatalf("Apply = %v, want the add failure and the filter that could not be removed", err)
	}
	e.failDelete = nil
	if err := f.Verify(vpn, services); err == nil || !strings.Contains(err.Error(), "1 unexpected (first: block 160.79.104.0/24 at ALE_AUTH_CONNECT_V4") {
		t.Errorf("Verify = %v, want the leftover reported", err)
	}
}

// When deleting an old filter fails after the new generation was added,
// the error names it, the other old filters are still deleted, and a later
// Verify reports the leftover as unexpected.
func TestApplyReportsAnOldFilterThatCannotBeDeleted(t *testing.T) {
	e := newFake(t)
	f := fw(e)
	if err := f.Apply(vpn, services); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	stuck := e.filters[0] // the first block; the 7 old filters after it still go
	e.failDelete = func(k GUID) error {
		if k == stuck.Key {
			return errors.New("FWP_E_IN_USE")
		}
		return nil
	}
	err := f.Apply("", services)
	if err == nil || !strings.Contains(err.Error(), "cannot delete the old filter "+stuck.Rule.String()+": FWP_E_IN_USE") {
		t.Fatalf("Apply = %v, want the old filter named", err)
	}
	e.failDelete = nil
	if n := len(e.filters); n != 5 {
		t.Errorf("%d filters left, want the 4 new blocks and the stuck old block: %v", n, e.rules())
	}
	if err := f.Verify("", services); err == nil || err.Error() != "leakguard filters do not match the protected services: 1 unexpected (first: "+stuck.Rule.String()+")" {
		t.Errorf("Verify = %v, want the leftover block reported", err)
	}
}

func TestFlushRemovesEverything(t *testing.T) {
	e := newFake(t)
	f := fw(e)
	if err := f.Apply(vpn, services); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := f.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(e.filters) != 0 || e.installed || e.provider {
		t.Errorf("after Flush: filters %v, sublayer %v, provider %v", e.filters, e.installed, e.provider)
	}
	if err := f.Verify(vpn, services); !errors.Is(err, firewall.ErrNotLoaded) {
		t.Errorf("Verify after Flush = %v, want ErrNotLoaded", err)
	}
	if err := f.Flush(); err != nil {
		t.Errorf("second Flush: %v", err)
	}
	if e.opens != e.closes {
		t.Errorf("opened %d sessions, closed %d", e.opens, e.closes)
	}
}

func TestEnabled(t *testing.T) {
	e := newFake(t)
	if ok, err := fw(e).Enabled(); !ok || err != nil {
		t.Errorf("Enabled() = %v, %v; want true", ok, err)
	}
	down := Firewall{Open: func() (Engine, error) { return nil, errors.New("the BFE service is not running") }}
	if ok, err := down.Enabled(); ok || err == nil {
		t.Errorf("Enabled() = %v, %v; want false and the error", ok, err)
	}
}

func TestDefaultEngineOutsideWindowsIsUnsupported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the real engine is tested by the Windows integration test")
	}
	ok, err := (Firewall{}).Enabled()
	if ok || !errors.Is(err, firewall.ErrUnsupported) {
		t.Errorf("Enabled() = %v, %v; want ErrUnsupported", ok, err)
	}
	if _, err := resolveLUID(vpn); !errors.Is(err, firewall.ErrUnsupported) {
		t.Errorf("resolveLUID = %v, want ErrUnsupported", err)
	}
}

func TestLookupMatchesTheExactAlias(t *testing.T) {
	adapters := []Adapter{{Alias: "Ethernet", LUID: 1}, {Alias: "WireGuard Tunnel", LUID: vpnLUID}, {Alias: "wireguard tunnel", LUID: 3}}
	if luid, err := lookup(adapters, vpn); err != nil || luid != vpnLUID {
		t.Errorf("lookup(%q) = %#x, %v; want %#x", vpn, luid, err, vpnLUID)
	}
	if _, err := lookup(adapters, "WireGuard"); !errors.Is(err, ErrNoAdapter) || err.Error() != `no network adapter is named "WireGuard"` {
		t.Errorf("lookup of a missing alias = %v", err)
	}
}

func TestRulesOrderAndShape(t *testing.T) {
	rules, err := Rules(vpnLUID, services)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 8 {
		t.Fatalf("%d rules, want 8: %v", len(rules), rules)
	}
	for i, r := range rules {
		block := i < 4
		if (r.Action == ActionBlock) != block {
			t.Errorf("rule %d is %s; blocks come first", i, r.Action)
		}
	}
	if got := rules[0].Remote.String(); got != "160.79.104.0/23" {
		t.Errorf("first range %s, want IPv4 first, sorted", got)
	}
}
