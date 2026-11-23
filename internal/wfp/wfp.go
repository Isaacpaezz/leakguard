// Package wfp drives the Windows Filtering Platform. leakguard owns one
// persistent provider and one sublayer with fixed GUIDs and adds its filters
// there, for IPv4 and IPv6: at ALE_AUTH_CONNECT (this computer's
// connections) and at IPFORWARD (packets it routes for others), one block
// per protected range and, above it, one permit per range for traffic that
// leaves on the VPN adapter. Other providers' filters are never read or
// touched.
//
// What CI proved on windows-latest (Server 2025, runs 45125443458 and
// 45127817057, TestIntegrationForwardedTraffic):
//
//   - Process-isolated Windows containers on Docker's nat network share
//     this kernel, so their connects are authorized at this computer's
//     ALE_AUTH_CONNECT and never pass IPFORWARD. With the VPN down they
//     are blocked at once (WSAEACCES); with the VPN up they stay blocked,
//     because their ALE local interface is the container's own vNIC, never
//     the VPN's: over-blocking that fails closed.
//   - Hyper-V guests are NOT filtered: a KNOWN GAP. A Hyper-V isolated
//     container reached the protected address with nothing loaded, with
//     the VPN down, with the real adapter as the VPN and after Flush. Its
//     traffic is NAT-translated inside the Hyper-V virtual switch
//     (HNS/VFP) and never reaches this computer's ALE or IPFORWARD layers.
//     The same holds for WSL2 in NAT mode and Hyper-V virtual machines.
//     Closing it needs filters at the WFP vSwitch layers and a decision
//     on over-blocking WSL2 while the VPN is up.
//   - With every filter loaded and the adapter the route leaves on as the
//     VPN, this computer's own connect to the protected address succeeds.
//
// The IPFORWARD filters stay for traffic this computer routes itself, such
// as Internet Connection Sharing clients; that they block it is unproven.
// WSL2 in mirrored mode and virtual machines bridged on an external switch
// are not covered either.
//
// The filter set, the diff against what is loaded and the swap from the old
// set to the new one are portable and run against an Engine; only the
// Engine that talks to the real filtering engine is Windows code.
package wfp

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/firewall"
)

// GUID has the memory layout of a Windows GUID.
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func (g GUID) String() string {
	return fmt.Sprintf("{%08X-%04X-%04X-%02X-%X}", g.Data1, g.Data2, g.Data3, g.Data4[:2], g.Data4[2:])
}

var (
	// ProviderKey identifies the leakguard provider. It is persistent and
	// never tied to a Windows service, so the filters stay active while the
	// leakguard service is stopped or being upgraded.
	ProviderKey = GUID{0x1511AB70, 0xFF32, 0x4B5E, [8]byte{0xB8, 0xF5, 0x2A, 0x0C, 0xA9, 0x49, 0xC9, 0xE2}}
	// SublayerKey identifies the sublayer that holds every leakguard filter.
	SublayerKey = GUID{0xA6050E5E, 0x8200, 0x4873, [8]byte{0x89, 0x54, 0xB1, 0xC4, 0x33, 0xCD, 0x2E, 0xB8}}
	// filterSpace is the fixed part of every filter key; Data1 holds the
	// generation and the last four bytes of Data4 the filter's index.
	filterSpace = GUID{0, 0xB9F4, 0x4C8A, [8]byte{0xB8, 0x45, 0xD6, 0x8C}}
)

const (
	// SublayerWeight puts the leakguard sublayer ahead of the others.
	SublayerWeight uint16 = 0xFFFF
	// BlockWeight and PermitWeight order the filters inside the sublayer:
	// the permit for the VPN adapter wins over the block of the same range.
	// Both are written as explicit FWP_UINT64 weights, which the engine
	// keeps as given, and neither is 0, so a weight that cannot be read
	// back never matches an expected filter.
	BlockWeight  uint64 = 1
	PermitWeight uint64 = 2
)

// ErrNoAdapter means no network adapter has the VPN's alias: the VPN is
// down, its adapter removed until it connects again.
var ErrNoAdapter = errors.New("no network adapter is named")

// Layer is where a filter runs.
type Layer int

const (
	// LayerOther is any layer leakguard never uses.
	LayerOther Layer = iota
	// LayerConnectV4 is ALE_AUTH_CONNECT_V4.
	LayerConnectV4
	// LayerConnectV6 is ALE_AUTH_CONNECT_V6.
	LayerConnectV6
	// LayerForwardV4 is IPFORWARD_V4: packets this computer's own IP stack
	// routes for others, such as Internet Connection Sharing clients
	// (unproven). Process-isolated containers are filtered at
	// ALE_AUTH_CONNECT instead, and Hyper-V guests (WSL2 in NAT mode,
	// Hyper-V virtual machines and isolated containers) reach neither
	// layer: a known gap (see the package documentation).
	LayerForwardV4
	// LayerForwardV6 is IPFORWARD_V6.
	LayerForwardV6
)

func (l Layer) String() string {
	switch l {
	case LayerConnectV4:
		return "ALE_AUTH_CONNECT_V4"
	case LayerConnectV6:
		return "ALE_AUTH_CONNECT_V6"
	case LayerForwardV4:
		return "IPFORWARD_V4"
	case LayerForwardV6:
		return "IPFORWARD_V6"
	}
	return "another layer"
}

// Forward reports whether l filters forwarded traffic. There a rule's
// Remote is the packet's destination and its LUID the interface the packet
// is forwarded to.
func (l Layer) Forward() bool { return l == LayerForwardV4 || l == LayerForwardV6 }

// Action is what a filter does with matching connections.
type Action int

const (
	// ActionOther is any action leakguard never uses (callouts).
	ActionOther Action = iota
	// ActionBlock blocks the connection.
	ActionBlock
	// ActionPermit permits it.
	ActionPermit
)

func (a Action) String() string {
	switch a {
	case ActionBlock:
		return "block"
	case ActionPermit:
		return "permit"
	}
	return "another action"
}

// Rule is what a filter does, without its key. Two filters with equal rules
// are interchangeable.
type Rule struct {
	Layer    Layer
	Sublayer GUID
	Action   Action
	// Remote is the protected destination range: a connection's remote
	// address, or a forwarded packet's destination.
	Remote netip.Prefix
	// LUID is the interface a connection must leave on, or a forwarded
	// packet must be forwarded to; 0 is any.
	LUID   uint64
	Weight uint64
	// Hard means lower sublayers cannot override the action.
	Hard bool
	// Persistent filters survive a restart of the filtering engine.
	Persistent bool
	// Other describes conditions leakguard never writes. A rule with Other
	// set never matches an expected one.
	Other string
}

func (r Rule) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s at %s", r.Action, r.Remote, r.Layer)
	if r.LUID != 0 {
		fmt.Fprintf(&b, " on interface LUID %#x", r.LUID)
	}
	fmt.Fprintf(&b, ", weight %d", r.Weight)
	if r.Sublayer != SublayerKey {
		fmt.Fprintf(&b, ", sublayer %s", r.Sublayer)
	}
	if r.Action == ActionBlock && !r.Hard {
		b.WriteString(", soft")
	}
	if !r.Persistent {
		b.WriteString(", not persistent")
	}
	if r.Other != "" {
		fmt.Fprintf(&b, ", %s", r.Other)
	}
	return b.String()
}

// Filter is a filter of the leakguard provider.
type Filter struct {
	Key  GUID
	Rule Rule
}

// Engine is the part of the filtering engine leakguard uses. Every method
// works on the leakguard provider only.
type Engine interface {
	// Install adds the provider and the sublayer when they are missing.
	Install() error
	// Installed reports whether the sublayer exists.
	Installed() (bool, error)
	// Filters returns every filter of the provider.
	Filters() ([]Filter, error)
	// Add adds a filter.
	Add(Filter) error
	// Delete deletes the filter with this key; a missing one is not an
	// error.
	Delete(key GUID) error
	// Uninstall deletes the sublayer and the provider; missing ones are
	// not an error.
	Uninstall() error
	// Close ends the session.
	Close() error
}

// Firewall applies and inspects the leakguard filters.
type Firewall struct {
	// Open connects to the filtering engine; nil means the Windows
	// Filtering Platform (an error wrapping firewall.ErrUnsupported on
	// other systems).
	Open func() (Engine, error)
	// Resolve returns the LUID of the network adapter with this alias
	// (its friendly name), or an error wrapping ErrNoAdapter when there
	// is none; nil means GetAdaptersAddresses.
	Resolve func(alias string) (uint64, error)
	// Check reports why an alias cannot be the VPN; nil means
	// config.CheckVPNInterface.
	Check func(string) error
}

var _ firewall.Firewall = Firewall{}

// Name implements firewall.Firewall.
func (Firewall) Name() string { return "Windows Filtering Platform" }

// BlockCount implements firewall.Firewall. Filters have no counters; WFP
// only reports drops through its event log, which is off by default.
func (Firewall) BlockCount() (uint64, error) {
	return 0, fmt.Errorf("the Windows Filtering Platform does not count blocked connections: %w", firewall.ErrUnsupported)
}

func (f Firewall) open() (Engine, error) {
	if f.Open == nil {
		return openEngine()
	}
	return f.Open()
}

// Enabled reports whether the Base Filtering Engine answers.
func (f Firewall) Enabled() (bool, error) {
	e, err := f.open()
	if err != nil {
		return false, err
	}
	return true, e.Close()
}

// allowed returns the LUID of the adapter vpn names, 0 when no adapter has
// that name (the VPN is down), or why it cannot be allowed.
func (f Firewall) allowed(vpn string) (uint64, error) {
	check := f.Check
	if check == nil {
		check = config.CheckVPNInterface
	}
	if err := check(vpn); err != nil {
		return 0, err
	}
	resolve := f.Resolve
	if resolve == nil {
		resolve = resolveLUID
	}
	luid, err := resolve(vpn)
	if errors.Is(err, ErrNoAdapter) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if luid == 0 {
		return 0, fmt.Errorf("network adapter %q has no LUID", vpn)
	}
	return luid, nil
}

// Adapter is a network adapter as GetAdaptersAddresses reports it.
type Adapter struct {
	// Alias is the friendly name users see, for example "Ethernet 2".
	Alias string
	LUID  uint64
	// Type is the IANA interface type, for example 24 for loopback.
	Type uint32
	// Index is the interface index (IfIndex).
	Index uint32
}

// lookup returns the LUID of the adapter whose alias is alias, ignoring
// case like Windows and config.CheckVPNInterface. When more than one
// adapter matches, it refuses rather than guess which one is the VPN.
func lookup(adapters []Adapter, alias string) (uint64, error) {
	var found []Adapter
	for _, a := range adapters {
		if strings.EqualFold(a.Alias, alias) {
			found = append(found, a)
		}
	}
	switch len(found) {
	case 0:
		return 0, fmt.Errorf("%w %q", ErrNoAdapter, alias)
	case 1:
		return found[0].LUID, nil
	}
	names := make([]string, len(found))
	for i, a := range found {
		names[i] = strconv.Quote(a.Alias)
	}
	return 0, fmt.Errorf("%d network adapters are named %q ignoring case (%s): cannot tell which one is the VPN", len(found), alias, strings.Join(names, ", "))
}

// Rules returns the filters that keep services on the adapter with this
// LUID, for this computer's connections (ALE_AUTH_CONNECT) and for the
// traffic its IP stack forwards (IPFORWARD; Hyper-V guests never reach it,
// see the package documentation), in the order Apply adds them: blocks
// first. luid 0 returns blocks only,
// so no interface may carry protected traffic.
func Rules(luid uint64, services []catalog.Service) ([]Rule, error) {
	prefixes, err := protected(services)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	for _, action := range []Action{ActionBlock, ActionPermit} {
		if action == ActionPermit && luid == 0 {
			break
		}
		for _, forward := range []bool{false, true} {
			for _, p := range prefixes {
				r := Rule{Layer: LayerConnectV4, Sublayer: SublayerKey, Action: action, Remote: p, Weight: BlockWeight, Hard: true, Persistent: true}
				switch {
				case forward && p.Addr().Is6():
					r.Layer = LayerForwardV6
				case forward:
					r.Layer = LayerForwardV4
				case p.Addr().Is6():
					r.Layer = LayerConnectV6
				}
				if action == ActionPermit {
					r.LUID, r.Weight, r.Hard = luid, PermitWeight, false
				}
				rules = append(rules, r)
			}
		}
	}
	return rules, nil
}

// protected returns the services' ranges, masked, sorted, without
// duplicates, IPv4 first.
func protected(services []catalog.Service) ([]netip.Prefix, error) {
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, s := range services {
		for _, c := range slices.Concat(s.IPv4, s.IPv6) {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				return nil, fmt.Errorf("service %s: %w", s.ID, err)
			}
			p = p.Masked()
			if p.Addr().Is4In6() || p.Addr().Zone() != "" {
				return nil, fmt.Errorf("service %s: %s is not a plain IPv4 or IPv6 range", s.ID, c)
			}
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return out, nil
}

// filterKey is the key of the index-th filter of a generation.
func filterKey(gen, index uint32) GUID {
	k := filterSpace
	k.Data1 = gen
	k.Data4[4], k.Data4[5], k.Data4[6], k.Data4[7] = byte(index>>24), byte(index>>16), byte(index>>8), byte(index)
	return k
}

// generation returns the generation in a leakguard filter key.
func generation(k GUID) (uint32, bool) {
	if k.Data2 != filterSpace.Data2 || k.Data3 != filterSpace.Data3 || [4]byte(k.Data4[:4]) != [4]byte(filterSpace.Data4[:4]) {
		return 0, false
	}
	return k.Data1, true
}

// nextGeneration returns the generation after the newest one in use, never
// 0 and never one in use, so new filter keys never collide with old ones.
func nextGeneration(filters []Filter) uint32 {
	used := map[uint32]bool{}
	var newest uint32
	for _, f := range filters {
		if g, ok := generation(f.Key); ok {
			used[g] = true
			newest = max(newest, g)
		}
	}
	g := newest
	for {
		if g == math.MaxUint32 {
			g = 0
		}
		g++
		if !used[g] {
			return g
		}
	}
}

// Apply loads the filters and verifies them. An empty vpn loads blocks
// only, so no interface may carry protected traffic. So does a vpn that
// names no adapter: the VPN is down, which is the normal state on Windows
// (RAS and WireGuard adapters exist only while connected), so that is a
// success. When vpn is refused, or the adapters cannot be read, it loads
// those same blocks and returns the reason.
//
// The new filters are added before the old ones are deleted, so protected
// traffic is never unblocked mid-way; when an add fails, the new filters
// added so far are deleted and the old ones stay. A filter that cannot be
// deleted is named in the error, and Verify reports it as unexpected.
func (f Firewall) Apply(vpn string, services []catalog.Service) error {
	var luid uint64
	var refused error
	if vpn != "" {
		luid, refused = f.allowed(vpn)
	}
	rules, err := Rules(luid, services)
	if err != nil {
		return err
	}
	err = f.load(rules)
	if refused != nil {
		if err != nil {
			return fmt.Errorf("cannot use %q as the VPN interface (%v), and cannot block protected services: %w", vpn, refused, err)
		}
		return fmt.Errorf("cannot use %q as the VPN interface, protected services are blocked on every interface: %w", vpn, refused)
	}
	if err != nil {
		return err
	}
	return f.Verify(vpn, services)
}

// load replaces the leakguard filters with rules: add all, then delete the
// old ones.
func (f Firewall) load(rules []Rule) (err error) {
	e, err := f.open()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, e.Close()) }()
	if err := e.Install(); err != nil {
		return fmt.Errorf("cannot add the leakguard provider and sublayer: %w", err)
	}
	old, err := e.Filters()
	if err != nil {
		return fmt.Errorf("cannot list the leakguard filters: %w", err)
	}
	gen := nextGeneration(old)
	for i, r := range rules {
		k := filterKey(gen, uint32(i))
		if err := e.Add(Filter{Key: k, Rule: r}); err != nil {
			err = fmt.Errorf("cannot add filter %s: %w", r, err)
			for j := i - 1; j >= 0; j-- {
				if derr := e.Delete(filterKey(gen, uint32(j))); derr != nil {
					err = errors.Join(err, fmt.Errorf("cannot remove the new filter %s again: %w", rules[j], derr))
				}
			}
			return err
		}
	}
	// Every old filter is tried, so one that cannot go leaves no others.
	var errs []error
	for _, o := range old {
		if g, ok := generation(o.Key); ok && g == gen {
			continue
		}
		if err := e.Delete(o.Key); err != nil {
			errs = append(errs, fmt.Errorf("cannot delete the old filter %s: %w", o.Rule, err))
		}
	}
	return errors.Join(errs...)
}

// Flush deletes every leakguard filter, then the sublayer and the
// provider. Nothing loaded is not an error.
func (f Firewall) Flush() (err error) {
	e, err := f.open()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, e.Close()) }()
	filters, err := e.Filters()
	if err != nil {
		return fmt.Errorf("cannot list the leakguard filters: %w", err)
	}
	for _, x := range filters {
		if err := e.Delete(x.Key); err != nil {
			return fmt.Errorf("cannot delete filter %s: %w", x.Rule, err)
		}
	}
	return e.Uninstall()
}

// ErrNotLoaded means the leakguard sublayer does not exist.
var ErrNotLoaded = firewall.ErrNotLoaded

// Verify checks that the loaded filters are exactly what a successful
// Apply(vpn, services) loads: one block per range and one permit per range
// for the adapter vpn names now, nothing missing, extra or changed. An empty
// vpn, or one that names no adapter (the VPN is down), checks that no
// interface is permitted. A refused vpn, or adapters that cannot be read,
// fail even when the blocks are loaded.
func (f Firewall) Verify(vpn string, services []catalog.Service) (err error) {
	loaded, err := f.loaded()
	if err != nil {
		return err
	}
	var luid uint64
	var refused error
	if vpn != "" {
		luid, refused = f.allowed(vpn)
	}
	want, err := Rules(luid, services)
	if err != nil {
		return err
	}
	diff := compare(want, loaded)
	switch {
	case refused != nil && diff == nil:
		return fmt.Errorf("protected services are blocked on every interface: %w", refused)
	case refused != nil:
		return fmt.Errorf("%v; and %q cannot be the VPN interface: %w", diff, vpn, refused)
	}
	return diff
}

// loaded returns the rules of the leakguard filters.
func (f Firewall) loaded() (rules []Rule, err error) {
	e, err := f.open()
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, e.Close()) }()
	ok, err := e.Installed()
	if err != nil {
		return nil, fmt.Errorf("cannot read the leakguard sublayer: %w", err)
	}
	if !ok {
		return nil, ErrNotLoaded
	}
	filters, err := e.Filters()
	if err != nil {
		return nil, fmt.Errorf("cannot list the leakguard filters: %w", err)
	}
	for _, x := range filters {
		rules = append(rules, x.Rule)
	}
	return rules, nil
}

// compare reports the filters missing from loaded and those loaded but not
// wanted, counting duplicates. A changed filter is both.
func compare(want, loaded []Rule) error {
	count := map[Rule]int{}
	for _, r := range want {
		count[r]++
	}
	var extra []Rule
	for _, r := range loaded {
		if count[r] > 0 {
			count[r]--
		} else {
			extra = append(extra, r)
		}
	}
	var missing []Rule
	for _, r := range want {
		if count[r] > 0 {
			count[r]--
			missing = append(missing, r)
		}
	}
	if len(missing) == 0 && len(extra) == 0 {
		return nil
	}
	var parts []string
	if len(missing) > 0 {
		parts = append(parts, fmt.Sprintf("%d missing (first: %s)", len(missing), missing[0]))
	}
	if len(extra) > 0 {
		parts = append(parts, fmt.Sprintf("%d unexpected (first: %s)", len(extra), extra[0]))
	}
	return fmt.Errorf("leakguard filters do not match the protected services: %s", strings.Join(parts, ", "))
}
