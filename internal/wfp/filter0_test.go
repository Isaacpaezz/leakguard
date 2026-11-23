package wfp

import (
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unsafe"
)

// fwpmFilter0 matches FWPM_FILTER0 of fwpmtypes.h on 64-bit Windows: the
// weights sit at the header's offsets (tailscale/wf reads effectiveWeight
// 8 bytes off, so its weights always read back as 0).
func TestFilter0Layout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("leakguard reads WFP filters on 64-bit Windows only")
	}
	var f fwpmFilter0
	for _, tc := range []struct {
		field     string
		got, want uintptr
	}{
		{"layerKey", unsafe.Offsetof(f.LayerKey), 64},
		{"subLayerKey", unsafe.Offsetof(f.SublayerKey), 80},
		{"weight", unsafe.Offsetof(f.Weight), 96},
		{"numFilterConditions", unsafe.Offsetof(f.NumFilterConditions), 112},
		{"action", unsafe.Offsetof(f.ActionType), 128},
		{"rawContext/providerContextKey", unsafe.Offsetof(f.Context), 152},
		{"reserved", unsafe.Offsetof(f.Reserved), 168},
		{"filterId", unsafe.Offsetof(f.FilterID), 176},
		{"effectiveWeight", unsafe.Offsetof(f.EffectiveWeight), 184},
		{"sizeof(FWPM_FILTER0)", unsafe.Sizeof(f), 200},
	} {
		if tc.got != tc.want {
			t.Errorf("%s at %d, want %d", tc.field, tc.got, tc.want)
		}
	}
}

// The stored weight leakguard writes is an FWP_UINT64; anything else never
// matches an expected filter.
func TestWeightOf(t *testing.T) {
	x := uint64(PermitWeight)
	v := fwpValue0{Type: fwpUint64}
	*(**uint64)(unsafe.Pointer(&v.Value)) = &x
	if w, other := weightOf(&v); w != PermitWeight || other != "" {
		t.Errorf("weightOf(FWP_UINT64 %d) = %d, %q", x, w, other)
	}
	runtime.KeepAlive(&x)
	for _, tc := range []struct {
		v    fwpValue0
		want string
	}{
		{fwpValue0{Type: fwpEmpty}, "automatic weight (FWP_EMPTY)"},
		{fwpValue0{Type: fwpUint8, Value: 15}, "weight range 15 (FWP_UINT8)"},
		{fwpValue0{Type: fwpUint64}, "weight FWP_UINT64 without a value"},
		{fwpValue0{Type: 3, Value: 7}, "weight of data type 3"},
	} {
		w, other := weightOf(&tc.v)
		if w != 0 || other != tc.want {
			t.Errorf("weightOf(%+v) = %d, %q; want 0, %q", tc.v, w, other, tc.want)
		}
	}
}

// The effective weight is printed, never compared.
func TestDescribeWeight(t *testing.T) {
	x := uint64(1) << 60
	v := fwpValue0{Type: fwpUint64}
	*(**uint64)(unsafe.Pointer(&v.Value)) = &x
	if got := describeWeight(&v); got != "1152921504606846976 (FWP_UINT64)" {
		t.Errorf("describeWeight() = %q", got)
	}
	runtime.KeepAlive(&x)
	if got := describeWeight(&fwpValue0{Type: fwpUint8, Value: 2}); !strings.Contains(got, "weight range 2") {
		t.Errorf("describeWeight() = %q", got)
	}
}

// FWPM_FILTER_CONDITION0, FWPM_FILTER_ENUM_TEMPLATE0 and the address
// masks match fwpmtypes.h and fwptypes.h on 64-bit Windows.
func TestConditionAndEnumTemplateLayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("leakguard reads WFP filters on 64-bit Windows only")
	}
	var c fwpmFilterCondition0
	var e fwpmFilterEnumTemplate0
	var v6 fwpV6AddrAndMask
	var f fwpmFilter0
	for _, tc := range []struct {
		field     string
		got, want uintptr
	}{
		{"condition fieldKey", unsafe.Offsetof(c.FieldKey), 0},
		{"condition matchType", unsafe.Offsetof(c.MatchType), 16},
		{"condition conditionValue", unsafe.Offsetof(c.Value), 24},
		{"sizeof(FWPM_FILTER_CONDITION0)", unsafe.Sizeof(c), 40},
		{"template providerKey", unsafe.Offsetof(e.ProviderKey), 0},
		{"template layerKey", unsafe.Offsetof(e.LayerKey), 8},
		{"template enumType", unsafe.Offsetof(e.EnumType), 24},
		{"template flags", unsafe.Offsetof(e.Flags), 28},
		{"template providerContextTemplate", unsafe.Offsetof(e.ProviderContextTemplate), 32},
		{"template numFilterConditions", unsafe.Offsetof(e.NumFilterConditions), 40},
		{"template filterCondition", unsafe.Offsetof(e.FilterCondition), 48},
		{"template actionMask", unsafe.Offsetof(e.ActionMask), 56},
		{"template calloutKey", unsafe.Offsetof(e.CalloutKey), 64},
		{"sizeof(FWPM_FILTER_ENUM_TEMPLATE0)", unsafe.Sizeof(e), 72},
		{"sizeof(FWP_V4_ADDR_AND_MASK)", unsafe.Sizeof(fwpV4AddrAndMask{}), 8},
		{"FWP_V6_ADDR_AND_MASK prefixLength", unsafe.Offsetof(v6.PrefixLength), 16},
		{"sizeof(FWP_V6_ADDR_AND_MASK)", unsafe.Sizeof(v6), 17},
		{"FWPM_FILTER0 flags", unsafe.Offsetof(f.Flags), 32},
		{"FWPM_FILTER0 providerKey", unsafe.Offsetof(f.ProviderKey), 40},
		{"FWPM_FILTER0 filterCondition", unsafe.Offsetof(f.FilterCondition), 120},
	} {
		if tc.got != tc.want {
			t.Errorf("%s at %d, want %d", tc.field, tc.got, tc.want)
		}
	}
}

// The layer and condition GUIDs are the ones fwpmu.h documents.
func TestLayerAndFieldKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  GUID
		want string
	}{
		{"FWPM_LAYER_ALE_AUTH_CONNECT_V4", layerKey(LayerConnectV4), "{C38D57D1-05A7-4C33-904F-7FBCEEE60E82}"},
		{"FWPM_LAYER_ALE_AUTH_CONNECT_V6", layerKey(LayerConnectV6), "{4A72393B-319F-44BC-84C3-BA54DCB3B6B4}"},
		{"FWPM_LAYER_IPFORWARD_V4", layerKey(LayerForwardV4), "{A82ACC24-4EE1-4EE1-B465-FD1D25CB10A4}"},
		{"FWPM_LAYER_IPFORWARD_V6", layerKey(LayerForwardV6), "{7B964818-19C7-493A-B71F-832C3684D28C}"},
		{"FWPM_CONDITION_IP_REMOTE_ADDRESS", remoteField(LayerConnectV4), "{B235AE9A-1D64-49B8-A44C-5FF3D9095045}"},
		{"FWPM_CONDITION_IP_LOCAL_INTERFACE", interfaceField(LayerConnectV6), "{4CD62A49-59C3-4969-B7F3-BDA5D32890A4}"},
		{"FWPM_CONDITION_IP_DESTINATION_ADDRESS", remoteField(LayerForwardV4), "{2D79133B-B390-45C6-8699-ACACEAAFED33}"},
		{"FWPM_CONDITION_IP_FORWARD_INTERFACE", interfaceField(LayerForwardV6), "{1076B8A5-6323-4C5E-9810-E8D3FC9E6136}"},
	} {
		if tc.got.String() != tc.want {
			t.Errorf("%s = %s, want %s", tc.name, tc.got, tc.want)
		}
	}
	for _, l := range filterLayers {
		if layerOf(layerKey(l)) != l {
			t.Errorf("layerOf(layerKey(%s)) = %s", l, layerOf(layerKey(l)))
		}
	}
	if layerOf(GUID{Data1: 7}) != LayerOther || layerKey(LayerOther) != (GUID{}) {
		t.Error("an unknown layer must map to LayerOther and back to the zero GUID")
	}
}

// SF3: the enumeration asks the engine for the leakguard provider's filters
// at one layer, any action, no condition: other providers' filters are
// never returned, so they are never parsed.
func TestEnumTemplateSelectsTheLeakguardProviderOnly(t *testing.T) {
	if len(filterLayers) != 4 {
		t.Errorf("filterLayers = %v, want the 4 layers Rules uses", filterLayers)
	}
	for _, l := range filterLayers {
		tm := enumTemplate(&ProviderKey, l)
		if tm.ProviderKey == nil || *tm.ProviderKey != ProviderKey {
			t.Errorf("%s: providerKey %v, want %s", l, tm.ProviderKey, ProviderKey)
		}
		if tm.LayerKey != layerKey(l) || tm.EnumType != fwpFilterEnumOverlapping || tm.Flags != 0 ||
			tm.ProviderContextTemplate != 0 || tm.NumFilterConditions != 0 || tm.FilterCondition != nil ||
			tm.ActionMask != 0xFFFFFFFF || tm.CalloutKey != nil {
			t.Errorf("%s: template %+v", l, tm)
		}
	}
}

// rawFilter builds FWPM_FILTER0 values in Go memory, encoded the way
// tailscale/wf writes leakguard's filters, and keeps what they point to
// alive until the test ends.
type rawFilter struct {
	t *testing.T
}

func (b *rawFilter) keep(v any) {
	b.t.Cleanup(func() { runtime.KeepAlive(v) })
}

func (b *rawFilter) prefix(field GUID, p netip.Prefix) fwpmFilterCondition0 {
	c := fwpmFilterCondition0{FieldKey: field, MatchType: fwpMatchEqual}
	if p.Addr().Is4() {
		a := p.Addr().As4()
		m := &fwpV4AddrAndMask{Addr: uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3]), Mask: ^uint32(0) << (32 - p.Bits())}
		c.Value = fwpValue0{Type: fwpV4AddrMask}
		*(**fwpV4AddrAndMask)(unsafe.Pointer(&c.Value.Value)) = m
		b.keep(m)
	} else {
		m := &fwpV6AddrAndMask{Addr: p.Addr().As16(), PrefixLength: uint8(p.Bits())}
		c.Value = fwpValue0{Type: fwpV6AddrMask}
		*(**fwpV6AddrAndMask)(unsafe.Pointer(&c.Value.Value)) = m
		b.keep(m)
	}
	return c
}

func (b *rawFilter) uint64(field GUID, v uint64) fwpmFilterCondition0 {
	c := fwpmFilterCondition0{FieldKey: field, MatchType: fwpMatchEqual, Value: fwpValue0{Type: fwpUint64}}
	p := &v
	*(**uint64)(unsafe.Pointer(&c.Value.Value)) = p
	b.keep(p)
	return c
}

func (b *rawFilter) filter(id GUID, layer GUID, action, flags uint32, weight uint64, conds ...fwpmFilterCondition0) *fwpmFilter0 {
	f := &fwpmFilter0{FilterKey: id, LayerKey: layer, SublayerKey: SublayerKey, Flags: flags, ActionType: action, NumFilterConditions: uint32(len(conds))}
	pk := ProviderKey
	f.ProviderKey = &pk
	f.Weight = fwpValue0{Type: fwpUint64}
	w := &weight
	*(**uint64)(unsafe.Pointer(&f.Weight.Value)) = w
	b.keep(w)
	if len(conds) > 0 {
		cs := slices.Clone(conds)
		f.FilterCondition = &cs[0]
	}
	return f
}

// encode is what tailscale/wf's AddRule writes for r (see toWF).
func (b *rawFilter) encode(id GUID, r Rule) *fwpmFilter0 {
	conds := []fwpmFilterCondition0{b.prefix(remoteField(r.Layer), r.Remote)}
	if r.LUID != 0 {
		conds = append(conds, b.uint64(interfaceField(r.Layer), r.LUID))
	}
	action := uint32(fwpActionBlock)
	if r.Action == ActionPermit {
		action = fwpActionPermit
	}
	var flags uint32
	if r.Hard {
		flags |= fwpmFilterFlagClearActionRight
	}
	if r.Persistent {
		flags |= fwpmFilterFlagPersistent
	}
	return b.filter(id, layerKey(r.Layer), action, flags, r.Weight, conds...)
}

// SF3: the engine reads its own filters with its own FWPM_FILTER0 layout,
// at every layer Rules uses, and gets back exactly the rule it wrote.
func TestFilterOfReadsWhatLeakguardWrites(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("leakguard reads WFP filters on 64-bit Windows only")
	}
	b := &rawFilter{t: t}
	rules, err := Rules(vpnLUID, services)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range rules {
		id := filterKey(5, uint32(i))
		read := filterOf(b.encode(id, r))
		if read.Key != id || read.Rule != r {
			t.Errorf("filterOf(%s) = %s %s", r, read.Key, read.Rule)
		}
	}
	// A single address, as the engine may store a /32 or a /128.
	one4 := fwpmFilterCondition0{FieldKey: remoteField(LayerForwardV4), Value: fwpValue0{Type: fwpUint32}}
	*(*uint32)(unsafe.Pointer(&one4.Value.Value)) = 0xC0000201 // 192.0.2.1
	a16 := netip.MustParseAddr("2001:db8::1").As16()
	one6 := fwpmFilterCondition0{FieldKey: remoteField(LayerConnectV6), Value: fwpValue0{Type: fwpByteArray16}}
	*(**[16]byte)(unsafe.Pointer(&one6.Value.Value)) = &a16
	b.keep(&a16)
	hard := uint32(fwpmFilterFlagPersistent | fwpmFilterFlagClearActionRight)
	for _, tc := range []struct {
		f    *fwpmFilter0
		want string
	}{
		{b.filter(filterKey(6, 0), layerKey(LayerForwardV4), fwpActionBlock, hard, BlockWeight, one4), "block 192.0.2.1/32 at IPFORWARD_V4, weight 1"},
		{b.filter(filterKey(6, 1), layerKey(LayerConnectV6), fwpActionBlock, hard, BlockWeight, one6), "block 2001:db8::1/128 at ALE_AUTH_CONNECT_V6, weight 1"},
	} {
		if r := filterOf(tc.f).Rule; r.String() != tc.want || r.Other != "" {
			t.Errorf("filterOf() = %s, want %s", r, tc.want)
		}
	}
}

// SF3: whatever a filter holds, reading it never fails and never follows a
// pointer of a data type leakguard never writes (the bogus pointer 1 below
// would crash the test); anything leakguard never writes lands in Other,
// so the filter never matches an expected one.
func TestFilterOfMarksWhatLeakguardNeverWrites(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("leakguard reads WFP filters on 64-bit Windows only")
	}
	b := &rawFilter{t: t}
	p4 := netip.MustParsePrefix("160.79.104.0/23")
	p6 := netip.MustParsePrefix("2607:6bc0::/48")
	hard := uint32(fwpmFilterFlagPersistent | fwpmFilterFlagClearActionRight)
	remote4 := func() fwpmFilterCondition0 { return b.prefix(remoteField(LayerConnectV4), p4) }
	bogus := func(field GUID, match, typ uint32) fwpmFilterCondition0 {
		return fwpmFilterCondition0{FieldKey: field, MatchType: match, Value: fwpValue0{Type: typ, Value: 1}}
	}
	unknown := GUID{0xDEADBEEF, 1, 2, [8]byte{3, 4, 5, 6, 7, 8, 9, 10}}
	noConds := b.filter(filterKey(1, 0), layerKey(LayerConnectV4), fwpActionBlock, hard, BlockWeight)
	noConds.NumFilterConditions = 3 // and no array
	emptyWeight := b.filter(filterKey(1, 0), layerKey(LayerConnectV4), fwpActionBlock, hard, BlockWeight, remote4())
	emptyWeight.Weight = fwpValue0{Type: fwpEmpty}
	otherMatch := remote4()
	otherMatch.MatchType = 3
	for _, tc := range []struct {
		name string
		f    *fwpmFilter0
		want string
	}{
		{"unknown layer", b.filter(filterKey(1, 0), unknown, fwpActionBlock, hard, BlockWeight, bogus(unknown, 0, 20)),
			"at another layer, weight 1, layer {DEADBEEF-0001-0002-0304-05060708090A}, condition {DEADBEEF-0001-0002-0304-05060708090A} (match type 0, data type 20), no remote address condition"},
		{"unknown condition", b.filter(filterKey(1, 0), layerKey(LayerConnectV4), fwpActionBlock, hard, BlockWeight, remote4(), bogus(unknown, 0, 17)),
			"condition {DEADBEEF-0001-0002-0304-05060708090A} (match type 0, data type 17)"},
		{"remote of an unknown data type", b.filter(filterKey(1, 0), layerKey(LayerConnectV4), fwpActionBlock, hard, BlockWeight, bogus(remoteField(LayerConnectV4), 0, 20)),
			"condition IP_REMOTE_ADDRESS (match type 0, data type 20), no remote address condition"},
		{"remote without a value", b.filter(filterKey(1, 0), layerKey(LayerConnectV4), fwpActionBlock, hard, BlockWeight, fwpmFilterCondition0{FieldKey: remoteField(LayerConnectV4), Value: fwpValue0{Type: fwpV4AddrMask}}),
			"condition IP_REMOTE_ADDRESS (match type 0, data type 256), no remote address condition"},
		{"remote of another match type", b.filter(filterKey(1, 0), layerKey(LayerConnectV4), fwpActionBlock, hard, BlockWeight, otherMatch),
			"condition IP_REMOTE_ADDRESS (match type 3, data type 256), no remote address condition"},
		{"two remotes", b.filter(filterKey(1, 0), layerKey(LayerConnectV4), fwpActionBlock, hard, BlockWeight, remote4(), remote4()),
			"condition IP_REMOTE_ADDRESS (match type 0, data type 256)"},
		{"connect remote at a forward layer", b.filter(filterKey(1, 0), layerKey(LayerForwardV4), fwpActionBlock, hard, BlockWeight, remote4()),
			"condition IP_REMOTE_ADDRESS (match type 0, data type 256), no remote address condition"},
		{"interface 0", b.filter(filterKey(1, 0), layerKey(LayerForwardV6), fwpActionPermit, fwpmFilterFlagPersistent, PermitWeight, b.prefix(remoteField(LayerForwardV6), p6), b.uint64(interfaceField(LayerForwardV6), 0)),
			"condition IP_FORWARD_INTERFACE (match type 0, data type 4)"},
		{"interface of another data type", b.filter(filterKey(1, 0), layerKey(LayerConnectV6), fwpActionPermit, fwpmFilterFlagPersistent, PermitWeight, b.prefix(remoteField(LayerConnectV6), p6), bogus(interfaceField(LayerConnectV6), 0, 3)),
			"condition IP_LOCAL_INTERFACE (match type 0, data type 3)"},
		{"no condition array", noConds, "3 conditions without their array, no remote address condition"},
		{"boot-time and disabled", b.filter(filterKey(1, 0), layerKey(LayerConnectV4), fwpActionBlock, hard|fwpmFilterFlagBootTime|fwpmFilterFlagDisabled, BlockWeight, remote4()), "boot-time, disabled"},
		{"callout", b.filter(filterKey(1, 0), layerKey(LayerConnectV4), 0x4003, hard, BlockWeight, remote4()), "another action 160.79.104.0/23"},
		{"automatic weight", emptyWeight, "weight 0, automatic weight (FWP_EMPTY)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := filterOf(tc.f).Rule
			if !strings.Contains(r.String(), tc.want) {
				t.Errorf("filterOf() = %s, want it to contain %q", r, tc.want)
			}
			if tc.name != "callout" && r.Other == "" {
				t.Errorf("filterOf() = %s with Other empty", r)
			}
		})
	}
	bad4 := b.prefix(remoteField(LayerConnectV4), p4)
	(*(**fwpV4AddrAndMask)(unsafe.Pointer(&bad4.Value.Value))).Mask = 0xFF00FF00
	bad6 := b.prefix(remoteField(LayerConnectV6), p6)
	(*(**fwpV6AddrAndMask)(unsafe.Pointer(&bad6.Value.Value))).PrefixLength = 129
	for _, c := range []fwpmFilterCondition0{bad4, bad6} {
		r := filterOf(b.filter(filterKey(1, 0), layerKey(LayerConnectV4), fwpActionBlock, hard, BlockWeight, c)).Rule
		if r.Remote.IsValid() || !strings.Contains(r.Other, "no remote address condition") {
			t.Errorf("an invalid address mask reads as %s", r)
		}
	}
}
