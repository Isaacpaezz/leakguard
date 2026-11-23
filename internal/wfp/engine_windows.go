//go:build windows

package wfp

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// session is an Engine over a real, non-dynamic WFP session: what it adds
// outlives the session and the process. tailscale/wf adds and deletes; h is
// a second session handle that lists the leakguard filters with
// leakguard's own bindings, because tailscale/wf lists every filter on the
// system, fails on any it cannot parse and reads every field after the
// action 8 bytes off (see fwpmFilter0).
type session struct {
	s *wf.Session
	h windows.Handle
}

var (
	fwpuclnt                         = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0              = fwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0             = fwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmFilterCreateEnumHandle0  = fwpuclnt.NewProc("FwpmFilterCreateEnumHandle0")
	procFwpmFilterEnum0              = fwpuclnt.NewProc("FwpmFilterEnum0")
	procFwpmFilterDestroyEnumHandle0 = fwpuclnt.NewProc("FwpmFilterDestroyEnumHandle0")
	procFwpmFreeMemory0              = fwpuclnt.NewProc("FwpmFreeMemory0")
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

// enum passes every filter of provider at layer l (every provider's when
// provider is nil) to visit, before the engine frees it. The engine selects
// them (see enumTemplate); nothing else is listed.
func (e session) enum(provider *GUID, l Layer, visit func(*fwpmFilter0)) error {
	tm := enumTemplate(provider, l)
	var h windows.Handle
	r, _, _ := procFwpmFilterCreateEnumHandle0.Call(uintptr(e.h), uintptr(unsafe.Pointer(&tm)), uintptr(unsafe.Pointer(&h)))
	runtime.KeepAlive(provider)
	if r != 0 {
		return fmt.Errorf("at %s: %w", l, syscall.Errno(r))
	}
	defer procFwpmFilterDestroyEnumHandle0.Call(uintptr(e.h), uintptr(h))
	for {
		var entries **fwpmFilter0
		var n uint32
		if r, _, _ := procFwpmFilterEnum0.Call(uintptr(e.h), uintptr(h), 100, uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&n))); r != 0 {
			return fmt.Errorf("at %s: %w", l, syscall.Errno(r))
		}
		if entries == nil {
			return nil
		}
		for _, f := range unsafe.Slice(entries, n) {
			visit(f)
		}
		procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&entries)))
		if n == 0 {
			return nil
		}
	}
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

// Filters lists the leakguard provider's filters at the layers leakguard
// uses, and only those: the engine never hands over another provider's.
func (e session) Filters() ([]Filter, error) {
	key := ProviderKey
	var out []Filter
	for _, l := range filterLayers {
		err := e.enum(&key, l, func(f *fwpmFilter0) {
			if f.ProviderKey != nil && *f.ProviderKey == ProviderKey {
				out = append(out, filterOf(f))
			}
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// dump describes every filter at the layers leakguard uses as the engine
// stores it, leakguard's or not: provider, the rule as leakguard reads it
// and the effective weight. It is for diagnostics, and reads nothing
// leakguard does not know how to read.
func (e session) dump() ([]string, error) {
	var out []string
	for _, l := range filterLayers {
		err := e.enum(nil, l, func(f *fwpmFilter0) {
			provider := "none"
			if f.ProviderKey != nil {
				provider = f.ProviderKey.String()
			}
			x := filterOf(f)
			out = append(out, fmt.Sprintf("filter %s %q: provider %s, %s, effective weight %s",
				x.Key, windows.UTF16PtrToString(f.Name), provider, x.Rule, describeWeight(&f.EffectiveWeight)))
		})
		if err != nil {
			return out, err
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

func (e session) Close() error {
	if r, _, _ := procFwpmEngineClose0.Call(uintptr(e.h)); r != 0 {
		return errors.Join(syscall.Errno(r), e.s.Close())
	}
	return e.s.Close()
}

// toWF is the WFP filter for f: the remote address (the destination of a
// forwarded packet) must be in the range and, for a permit, the traffic
// must leave on the adapter's LUID (be forwarded to it).
func toWF(f Filter) (*wf.Rule, error) {
	r := f.Rule
	if r.Other != "" || !r.Remote.IsValid() || r.Layer == LayerOther {
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
	conds := []*wf.Match{{Field: wf.FieldID(remoteField(r.Layer)), Op: wf.MatchTypeEqual, Value: r.Remote}}
	if r.LUID != 0 {
		conds = append(conds, &wf.Match{Field: wf.FieldID(interfaceField(r.Layer)), Op: wf.MatchTypeEqual, Value: r.LUID})
	}
	name := fmt.Sprintf("leakguard %s %s", r.Action, r.Remote)
	if r.Layer.Forward() {
		name += " (forwarded)"
	}
	return &wf.Rule{
		ID:          wf.RuleID(f.Key),
		Name:        name,
		Description: "Protected service outside the VPN",
		Layer:       wf.LayerID(layerKey(r.Layer)),
		Sublayer:    wf.SublayerID(r.Sublayer),
		Weight:      r.Weight,
		Conditions:  conds,
		Action:      action,
		HardAction:  r.Hard,
		Persistent:  r.Persistent,
		Provider:    wf.ProviderID(ProviderKey),
	}, nil
}

// resolveLUID returns the LUID of the adapter whose alias is alias,
// ignoring case.
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
				out = append(out, Adapter{Alias: windows.UTF16PtrToString(a.FriendlyName), LUID: a.Luid, Type: a.IfType, Index: a.IfIndex})
			}
			return out, nil
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) || size <= uint32(len(buf)) {
			return nil, fmt.Errorf("cannot list the network adapters: %w", err)
		}
	}
}
