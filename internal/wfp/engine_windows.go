//go:build windows

package wfp

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"syscall"
	"unsafe"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// session is an Engine over a real, non-dynamic WFP session: what it adds
// outlives the session and the process.
type session struct{ s *wf.Session }

// openEngine connects to the Base Filtering Engine.
func openEngine() (Engine, error) {
	s, err := wf.New(&wf.Options{Name: "leakguard", Description: "leakguard kill switch"})
	if err != nil {
		return nil, fmt.Errorf("cannot open the Windows Filtering Platform (is the Base Filtering Engine service running?): %w", err)
	}
	return session{s}, nil
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
		if GUID(r.Provider) == ProviderKey {
			out = append(out, Filter{Key: GUID(r.ID), Rule: fromWF(r)})
		}
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

func (e session) Close() error { return e.s.Close() }

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
