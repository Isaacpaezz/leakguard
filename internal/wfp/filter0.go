package wfp

import (
	"fmt"
	"unsafe"
)

// fwpValue0 is FWP_VALUE0: a data type and a pointer-sized union. 64-bit
// numbers are stored behind a pointer.
type fwpValue0 struct {
	Type  uint32
	Value uintptr
}

// The FWP_DATA_TYPE values a filter weight may have.
const (
	fwpEmpty  = 0 // the engine picks the weight
	fwpUint8  = 1 // a weight range, 0 to 15
	fwpUint64 = 4 // the weight itself; leakguard writes this one
)

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
	FilterCondition     uintptr
	ActionType          uint32
	ActionKey           GUID
	Context             [2]uint64 // union { UINT64 rawContext; GUID providerContextKey; }
	Reserved            *GUID
	FilterID            uint64
	EffectiveWeight     fwpValue0
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
