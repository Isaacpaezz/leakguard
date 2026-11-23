//go:build windows

package wfp

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"syscall"
	"unsafe"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// session is an Engine over a real, non-dynamic WFP session: what it adds
// outlives the session and the process. h is a second session handle that
// reads what tailscale/wf reads wrong: the filters' weights.
type session struct {
	s *wf.Session
	h windows.Handle
}

var (
	fwpuclnt                = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0     = fwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0    = fwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmFilterGetByKey0 = fwpuclnt.NewProc("FwpmFilterGetByKey0")
	procFwpmFreeMemory0     = fwpuclnt.NewProc("FwpmFreeMemory0")
)

// rpcAuthnWinNT is RPC_C_AUTHN_WINNT, the authentication of a local
// session.
const rpcAuthnWinNT = 10

// openEngine connects to the Base Filtering Engine.
func openEngine() (Engine, error) {
	const hint = "cannot open the Windows Filtering Platform (is the Base Filtering Engine service running?): %w"
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return nil, errors.New("leakguard reads Windows Filtering Platform filters on 64-bit Windows only")
	}
	s, err := wf.New(&wf.Options{Name: "leakguard", Description: "leakguard kill switch"})
	if err != nil {
		return nil, fmt.Errorf(hint, err)
	}
	var h windows.Handle
	if r, _, _ := procFwpmEngineOpen0.Call(0, rpcAuthnWinNT, 0, 0, uintptr(unsafe.Pointer(&h))); r != 0 {
		s.Close()
		return nil, fmt.Errorf(hint, syscall.Errno(r))
	}
	return session{s, h}, nil
}

// filter0 reads the filter with this key as the engine stores it and
// passes it to read before the engine frees it.
func (e session) filter0(key GUID, read func(*fwpmFilter0)) error {
	var p *fwpmFilter0
	if r, _, _ := procFwpmFilterGetByKey0.Call(uintptr(e.h), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&p))); r != 0 {
		return syscall.Errno(r)
	}
	defer procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&p)))
	read(p)
	return nil
}

// is reports whether err is the WFP error code.
func is(err error, code windows.Handle) bool {
	var e syscall.Errno
	return errors.As(err, &e) && uintptr(e) == uintptr(code)
}

func (e session) Install() error {
	err := e.s.AddProvider(&wf.Provider{
		ID:          wf.ProviderID(ProviderKey),
		Name:        "leakguard",
		Description: "Keeps protected services on the VPN",
		Persistent:  true,
	})
	if err != nil && !is(err, windows.FWP_E_ALREADY_EXISTS) {
		return err
	}
	err = e.s.AddSublayer(&wf.Sublayer{
		ID:          wf.SublayerID(SublayerKey),
		Name:        "leakguard",
		Description: "Blocks protected services outside the VPN",
		Persistent:  true,
		Provider:    wf.ProviderID(ProviderKey),
		Weight:      SublayerWeight,
	})
	if err != nil && !is(err, windows.FWP_E_ALREADY_EXISTS) {
		return err
	}
	return nil
}

func (e session) Installed() (bool, error) {
	sls, err := e.s.Sublayers(wf.ProviderID(ProviderKey))
	if err != nil {
		return false, err
	}
	for _, sl := range sls {
		if GUID(sl.ID) == SublayerKey {
			return true, nil
		}
	}
	return false, nil
}

func (e session) Filters() ([]Filter, error) {
	rules, err := e.s.Rules()
	if err != nil {
		return nil, err
	}
	var out []Filter
	for _, r := range rules {
		if GUID(r.Provider) != ProviderKey {
			continue
		}
		rule := fromWF(r)
		// tailscale/wf's weight is never right (see fwpmFilter0).
		var other string
		err := e.filter0(GUID(r.ID), func(f *fwpmFilter0) { rule.Weight, other = weightOf(&f.Weight) })
		if is(err, windows.FWP_E_FILTER_NOT_FOUND) {
			continue // deleted since the listing
		}
		if err != nil {
			return nil, fmt.Errorf("cannot read the weight of filter %s: %w", GUID(r.ID), err)
		}
		if other != "" {
			rule.Other = strings.Join(slices.DeleteFunc([]string{rule.Other, other}, func(s string) bool { return s == "" }), ", ")
		}
		out = append(out, Filter{Key: GUID(r.ID), Rule: rule})
	}
	return out, nil
}

// dump describes every filter at ALE_AUTH_CONNECT as the engine stores it,
// leakguard's or not: provider, sublayer, layer, action, weight, effective
// weight and conditions. It is for diagnostics.
func (e session) dump() ([]string, error) {
	rules, err := e.s.Rules()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rules {
		if r.Layer != wf.LayerALEAuthConnectV4 && r.Layer != wf.LayerALEAuthConnectV6 {
			continue
		}
		weight, effective := "unreadable", "unreadable"
		if err := e.filter0(GUID(r.ID), func(f *fwpmFilter0) {
			weight, effective = describeWeight(&f.Weight), describeWeight(&f.EffectiveWeight)
		}); err != nil {
			weight = err.Error()
		}
		var conds []string
		for _, m := range r.Conditions {
			conds = append(conds, m.String())
		}
		out = append(out, fmt.Sprintf("filter %s %q: provider %s, sublayer %s, layer %s, action %s, hard %v, weight %s, effective weight %s, conditions [%s]",
			GUID(r.ID), r.Name, GUID(r.Provider), GUID(r.Sublayer), r.Layer, r.Action, r.HardAction, weight, effective, strings.Join(conds, "; ")))
	}
	return out, nil
}

func (e session) Add(f Filter) error {
	r, err := toWF(f)
	if err != nil {
		return err
	}
	return e.s.AddRule(r)
}

func (e session) Delete(k GUID) error {
	if err := e.s.DeleteRule(wf.RuleID(k)); err != nil && !is(err, windows.FWP_E_FILTER_NOT_FOUND) {
		return err
	}
	return nil
}

func (e session) Uninstall() error {
	if err := e.s.DeleteSublayer(wf.SublayerID(SublayerKey)); err != nil && !is(err, windows.FWP_E_SUBLAYER_NOT_FOUND) {
		return fmt.Errorf("cannot delete the leakguard sublayer: %w", err)
	}
	if err := e.s.DeleteProvider(wf.ProviderID(ProviderKey)); err != nil && !is(err, windows.FWP_E_PROVIDER_NOT_FOUND) {
		return fmt.Errorf("cannot delete the leakguard provider: %w", err)
	}
	return nil
}

func (e session) Close() error {
	if r, _, _ := procFwpmEngineClose0.Call(uintptr(e.h)); r != 0 {
		return errors.Join(syscall.Errno(r), e.s.Close())
	}
	return e.s.Close()
}

// toWF is the WFP filter for f: the remote address must be in the range
// and, for a permit, the connection must leave on the adapter's LUID.
func toWF(f Filter) (*wf.Rule, error) {
	r := f.Rule
	if r.Other != "" || !r.Remote.IsValid() {
		return nil, fmt.Errorf("leakguard never adds filter %s", r)
	}
	var layer wf.LayerID
	switch r.Layer {
	case LayerConnectV4:
		layer = wf.LayerALEAuthConnectV4
	case LayerConnectV6:
		layer = wf.LayerALEAuthConnectV6
	default:
		return nil, fmt.Errorf("leakguard never adds filter %s", r)
	}
	var action wf.Action
	switch r.Action {
	case ActionBlock:
		action = wf.ActionBlock
	case ActionPermit:
		action = wf.ActionPermit
	default:
		return nil, fmt.Errorf("leakguard never adds filter %s", r)
	}
	conds := []*wf.Match{{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: r.Remote}}
	if r.LUID != 0 {
		conds = append(conds, &wf.Match{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: r.LUID})
	}
	return &wf.Rule{
		ID:          wf.RuleID(f.Key),
		Name:        fmt.Sprintf("leakguard %s %s", r.Action, r.Remote),
		Description: "Protected service outside the VPN",
		Layer:       layer,
		Sublayer:    wf.SublayerID(r.Sublayer),
		Weight:      r.Weight,
		Conditions:  conds,
		Action:      action,
		HardAction:  r.Hard,
		Persistent:  r.Persistent,
		Provider:    wf.ProviderID(ProviderKey),
	}, nil
}

// fromWF is the Rule of a loaded filter. Anything toWF never writes ends up
// in Other, so the filter never matches an expected one.
func fromWF(r *wf.Rule) Rule {
	out := Rule{Sublayer: GUID(r.Sublayer), Weight: r.Weight, Hard: r.HardAction, Persistent: r.Persistent}
	switch r.Layer {
	case wf.LayerALEAuthConnectV4:
		out.Layer = LayerConnectV4
	case wf.LayerALEAuthConnectV6:
		out.Layer = LayerConnectV6
	}
	switch r.Action {
	case wf.ActionBlock:
		out.Action = ActionBlock
	case wf.ActionPermit:
		out.Action = ActionPermit
	}
	var other []string
	if r.BootTime {
		other = append(other, "boot-time")
	}
	if r.Disabled {
		other = append(other, "disabled")
	}
	var remote, local bool
	for _, m := range r.Conditions {
		switch {
		case m.Field == wf.FieldIPRemoteAddress && m.Op == wf.MatchTypeEqual && !remote:
			switch v := m.Value.(type) {
			case netip.Prefix:
				out.Remote, remote = v, true
			case netip.Addr:
				out.Remote, remote = netip.PrefixFrom(v, v.BitLen()), true
			default:
				other = append(other, "condition "+m.String())
			}
		case m.Field == wf.FieldIPLocalInterface && m.Op == wf.MatchTypeEqual && !local:
			if v, ok := m.Value.(uint64); ok && v != 0 {
				out.LUID, local = v, true
			} else {
				other = append(other, "condition "+m.String())
			}
		default:
			other = append(other, "condition "+m.String())
		}
	}
	if !remote {
		other = append(other, "no remote address condition")
	}
	out.Other = strings.Join(other, ", ")
	return out
}

// resolveLUID returns the LUID of the adapter whose alias is alias.
func resolveLUID(alias string) (uint64, error) {
	as, err := adapters()
	if err != nil {
		return 0, err
	}
	return lookup(as, alias)
}

// adapters lists the network adapters with GetAdaptersAddresses.
func adapters() ([]Adapter, error) {
	const flags = windows.GAA_FLAG_SKIP_UNICAST | windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER
	size := uint32(16 << 10)
	for {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size)
		if err == nil {
			var out []Adapter
			for a := first; a != nil; a = a.Next {
				out = append(out, Adapter{Alias: windows.UTF16PtrToString(a.FriendlyName), LUID: a.Luid, Type: a.IfType})
			}
			return out, nil
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) || size <= uint32(len(buf)) {
			return nil, fmt.Errorf("cannot list the network adapters: %w", err)
		}
	}
}
