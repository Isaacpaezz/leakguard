package wfp

import (
	"fmt"
	"math/bits"
	"net/netip"
	"strings"
	"unsafe"
)

// This file reads the filters of the leakguard provider as the engine
// stores them, with its own copy of the fwpmtypes.h layouts. It is portable
// so its tests run everywhere; only engine_windows.go calls the engine.
// Other providers' filters are never asked for (see enumTemplate), and
// nothing here follows a pointer of a data type leakguard never writes, so
// no filter, ours or not, can make reading fail.

// fwpValue0 is FWP_VALUE0: a data type and a pointer-sized union. 64-bit
// numbers are stored behind a pointer.
type fwpValue0 struct {
	Type  uint32
	Value uintptr
}

// The FWP_DATA_TYPE values leakguard reads.
const (
	fwpEmpty       = 0   // the engine picks the weight
	fwpUint8       = 1   // a weight range, 0 to 15
	fwpUint32      = 3   // an IPv4 address, host byte order
	fwpUint64      = 4   // a weight or an interface LUID, behind a pointer
	fwpByteArray16 = 11  // an IPv6 address, behind a pointer
	fwpV4AddrMask  = 256 // FWP_V4_ADDR_AND_MASK, behind a pointer
	fwpV6AddrMask  = 257 // FWP_V6_ADDR_AND_MASK, behind a pointer
)

// FWP_MATCH_EQUAL, FWP_ACTION_BLOCK and FWP_ACTION_PERMIT.
const (
	fwpMatchEqual   = 0
	fwpActionBlock  = 0x1001
	fwpActionPermit = 0x1002
)

// The FWPM_FILTER_FLAG values leakguard reads.
const (
	fwpmFilterFlagPersistent       = 0x01
	fwpmFilterFlagBootTime         = 0x02
	fwpmFilterFlagClearActionRight = 0x08
	fwpmFilterFlagDisabled         = 0x20
)

// FWP_FILTER_ENUM_OVERLAPPING: with no condition, every filter matches.
const fwpFilterEnumOverlapping = 1

// fwpmFilter0 is FWPM_FILTER0 of fwpmtypes.h as laid out on 64-bit
// Windows. leakguard reads only its weights. tailscale/wf's copy of this
// struct declares rawContext and providerContextKey as two fields where the
// header has a union, so it reads every field after action 8 bytes off: its
// Rule.Weight always comes back as 0. The engine reads the weights again
// with FwpmFilterGetByKey0 and this layout.
type fwpmFilter0 struct {
	FilterKey           GUID
	Name                *uint16
	Description         *uint16
	Flags               uint32
	ProviderKey         *GUID
	ProviderDataSize    uint32
	ProviderData        *byte
	LayerKey            GUID
	SublayerKey         GUID
	Weight              fwpValue0
	NumFilterConditions uint32
	FilterCondition     *fwpmFilterCondition0
	ActionType          uint32
	ActionKey           GUID
	Context             [2]uint64 // union { UINT64 rawContext; GUID providerContextKey; }
	Reserved            *GUID
	FilterID            uint64
	EffectiveWeight     fwpValue0
}

// fwpmFilterCondition0 is FWPM_FILTER_CONDITION0. FWP_CONDITION_VALUE0
// has the layout of FWP_VALUE0.
type fwpmFilterCondition0 struct {
	FieldKey  GUID
	MatchType uint32
	Value     fwpValue0
}

// fwpV4AddrAndMask is FWP_V4_ADDR_AND_MASK, both in host byte order.
type fwpV4AddrAndMask struct {
	Addr, Mask uint32
}

// fwpV6AddrAndMask is FWP_V6_ADDR_AND_MASK.
type fwpV6AddrAndMask struct {
	Addr         [16]byte
	PrefixLength uint8
}

// fwpmFilterEnumTemplate0 is FWPM_FILTER_ENUM_TEMPLATE0.
type fwpmFilterEnumTemplate0 struct {
	ProviderKey             *GUID
	LayerKey                GUID
	EnumType                uint32
	Flags                   uint32
	ProviderContextTemplate uintptr
	NumFilterConditions     uint32
	FilterCondition         *fwpmFilterCondition0
	ActionMask              uint32
	CalloutKey              *GUID
}

// filterLayers are the layers leakguard adds filters to, so the only ones
// it enumerates.
var filterLayers = []Layer{LayerConnectV4, LayerConnectV6, LayerForwardV4, LayerForwardV6}

// The FWPM_LAYER and FWPM_CONDITION keys of fwpmu.h leakguard uses.
var (
	layerALEAuthConnectV4 = GUID{0xc38d57d1, 0x05a7, 0x4c33, [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	layerALEAuthConnectV6 = GUID{0x4a72393b, 0x319f, 0x44bc, [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}
	layerIPForwardV4      = GUID{0xa82acc24, 0x4ee1, 0x4ee1, [8]byte{0xb4, 0x65, 0xfd, 0x1d, 0x25, 0xcb, 0x10, 0xa4}}
	layerIPForwardV6      = GUID{0x7b964818, 0x19c7, 0x493a, [8]byte{0xb7, 0x1f, 0x83, 0x2c, 0x36, 0x84, 0xd2, 0x8c}}
	fieldIPRemoteAddress  = GUID{0xb235ae9a, 0x1d64, 0x49b8, [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}}
	fieldIPLocalInterface = GUID{0x4cd62a49, 0x59c3, 0x4969, [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4}}
	fieldIPDestination    = GUID{0x2d79133b, 0xb390, 0x45c6, [8]byte{0x86, 0x99, 0xac, 0xac, 0xea, 0xaf, 0xed, 0x33}}
	fieldIPForwardIntf    = GUID{0x1076b8a5, 0x6323, 0x4c5e, [8]byte{0x98, 0x10, 0xe8, 0xd3, 0xfc, 0x9e, 0x61, 0x36}}
	fieldNames            = map[GUID]string{fieldIPRemoteAddress: "IP_REMOTE_ADDRESS", fieldIPLocalInterface: "IP_LOCAL_INTERFACE", fieldIPDestination: "IP_DESTINATION_ADDRESS", fieldIPForwardIntf: "IP_FORWARD_INTERFACE"}
	layerKeys             = map[Layer]GUID{LayerConnectV4: layerALEAuthConnectV4, LayerConnectV6: layerALEAuthConnectV6, LayerForwardV4: layerIPForwardV4, LayerForwardV6: layerIPForwardV6}
	layersByKey           = map[GUID]Layer{layerALEAuthConnectV4: LayerConnectV4, layerALEAuthConnectV6: LayerConnectV6, layerIPForwardV4: LayerForwardV4, layerIPForwardV6: LayerForwardV6}
)

// layerKey is the FWPM_LAYER key of l; LayerOther has none.
func layerKey(l Layer) GUID { return layerKeys[l] }

// layerOf is the Layer whose key is k, LayerOther for any other.
func layerOf(k GUID) Layer { return layersByKey[k] }

// remoteField is the condition a rule's Remote is written to at l: the
// remote address of a connection, or the destination of a forwarded
// packet.
func remoteField(l Layer) GUID {
	if l.Forward() {
		return fieldIPDestination
	}
	return fieldIPRemoteAddress
}

// interfaceField is the condition a rule's LUID is written to at l: the
// interface a connection leaves on, or the one a packet is forwarded to.
func interfaceField(l Layer) GUID {
	if l.Forward() {
		return fieldIPForwardIntf
	}
	return fieldIPLocalInterface
}

// enumTemplate selects the filters of provider at layer l, whatever their
// action, with no other condition. A nil provider selects every
// provider's, for diagnostics only.
func enumTemplate(provider *GUID, l Layer) fwpmFilterEnumTemplate0 {
	return fwpmFilterEnumTemplate0{
		ProviderKey: provider,
		LayerKey:    layerKey(l),
		EnumType:    fwpFilterEnumOverlapping,
		ActionMask:  0xFFFFFFFF,
	}
}

// filterOf is the leakguard Filter f describes. It never fails: anything
// leakguard never writes is described in Rule.Other, so the filter never
// matches an expected one.
func filterOf(f *fwpmFilter0) Filter {
	r := Rule{
		Layer:      layerOf(f.LayerKey),
		Sublayer:   f.SublayerKey,
		Hard:       f.Flags&fwpmFilterFlagClearActionRight != 0,
		Persistent: f.Flags&fwpmFilterFlagPersistent != 0,
	}
	switch f.ActionType {
	case fwpActionBlock:
		r.Action = ActionBlock
	case fwpActionPermit:
		r.Action = ActionPermit
	}
	var other []string
	if r.Layer == LayerOther {
		other = append(other, "layer "+f.LayerKey.String())
	}
	if f.Flags&fwpmFilterFlagBootTime != 0 {
		other = append(other, "boot-time")
	}
	if f.Flags&fwpmFilterFlagDisabled != 0 {
		other = append(other, "disabled")
	}
	var weight string
	if r.Weight, weight = weightOf(&f.Weight); weight != "" {
		other = append(other, weight)
	}
	var conds []fwpmFilterCondition0
	switch {
	case f.FilterCondition != nil:
		conds = unsafe.Slice(f.FilterCondition, f.NumFilterConditions)
	case f.NumFilterConditions > 0:
		other = append(other, fmt.Sprintf("%d conditions without their array", f.NumFilterConditions))
	}
	var remote, local bool
	for i := range conds {
		c := &conds[i]
		switch {
		case r.Layer == LayerOther || c.MatchType != fwpMatchEqual:
		case c.FieldKey == remoteField(r.Layer) && !remote:
			if p, ok := prefixOf(&c.Value); ok {
				r.Remote, remote = p, true
				continue
			}
		case c.FieldKey == interfaceField(r.Layer) && !local && c.Value.Type == fwpUint64 && c.Value.Value != 0:
			if v := **(**uint64)(unsafe.Pointer(&c.Value.Value)); v != 0 {
				r.LUID, local = v, true
				continue
			}
		}
		other = append(other, describeCondition(c))
	}
	if !remote {
		other = append(other, "no remote address condition")
	}
	r.Other = strings.Join(other, ", ")
	return Filter{Key: f.FilterKey, Rule: r}
}

// prefixOf reads an address condition in the forms the engine may store:
// an address and mask, or a single address.
func prefixOf(v *fwpValue0) (netip.Prefix, bool) {
	switch v.Type {
	case fwpUint32:
		a := *(*uint32)(unsafe.Pointer(&v.Value))
		return netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(a >> 24), byte(a >> 16), byte(a >> 8), byte(a)}), 32), true
	case fwpByteArray16:
		if v.Value == 0 {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(netip.AddrFrom16(**(**[16]byte)(unsafe.Pointer(&v.Value))), 128), true
	case fwpV4AddrMask:
		if v.Value == 0 {
			return netip.Prefix{}, false
		}
		m := **(**fwpV4AddrAndMask)(unsafe.Pointer(&v.Value))
		n := bits.OnesCount32(m.Mask)
		if m.Mask != ^uint32(0)<<(32-n) { // not a contiguous mask
			return netip.Prefix{}, false
		}
		a := m.Addr
		return netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(a >> 24), byte(a >> 16), byte(a >> 8), byte(a)}), n), true
	case fwpV6AddrMask:
		if v.Value == 0 {
			return netip.Prefix{}, false
		}
		m := **(**fwpV6AddrAndMask)(unsafe.Pointer(&v.Value))
		if m.PrefixLength > 128 {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(netip.AddrFrom16(m.Addr), int(m.PrefixLength)), true
	}
	return netip.Prefix{}, false
}

// describeCondition names a condition without reading its value.
func describeCondition(c *fwpmFilterCondition0) string {
	name, ok := fieldNames[c.FieldKey]
	if !ok {
		name = c.FieldKey.String()
	}
	return fmt.Sprintf("condition %s (match type %d, data type %d)", name, c.MatchType, c.Value.Type)
}

// weightOf returns the FWP_UINT64 weight in v. Any other weight, which
// leakguard never writes, returns 0 and its description, so the filter
// never matches an expected one.
func weightOf(v *fwpValue0) (uint64, string) {
	switch v.Type {
	case fwpUint64:
		if v.Value == 0 {
			return 0, "weight FWP_UINT64 without a value"
		}
		return **(**uint64)(unsafe.Pointer(&v.Value)), ""
	case fwpUint8:
		return 0, fmt.Sprintf("weight range %d (FWP_UINT8)", uint8(v.Value))
	case fwpEmpty:
		return 0, "automatic weight (FWP_EMPTY)"
	}
	return 0, fmt.Sprintf("weight of data type %d", v.Type)
}

// describeWeight prints a weight as read back, for diagnostics.
func describeWeight(v *fwpValue0) string {
	w, other := weightOf(v)
	if other != "" {
		return other
	}
	return fmt.Sprintf("%d (FWP_UINT64)", w)
}
