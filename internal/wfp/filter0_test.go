package wfp

import (
	"runtime"
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
