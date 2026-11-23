package wfp

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// Layers map to the library's ALE_AUTH_CONNECT layers.
func TestLayersAreALEAuthConnect(t *testing.T) {
	for _, tc := range []struct {
		layer Layer
		want  wf.LayerID
	}{{LayerConnectV4, wf.LayerALEAuthConnectV4}, {LayerConnectV6, wf.LayerALEAuthConnectV6}} {
		r, err := toWF(Filter{Key: filterKey(1, 0), Rule: Rule{Layer: tc.layer, Sublayer: SublayerKey, Action: ActionBlock, Remote: netip.MustParsePrefix("192.0.2.0/24")}})
		if err != nil {
			t.Fatal(err)
		}
		if r.Layer != tc.want {
			t.Errorf("%s maps to %s, want %s", tc.layer, r.Layer, tc.want)
		}
	}
}

// What toWF writes, fromWF reads back unchanged.
func TestFilterRoundTrip(t *testing.T) {
	rules, err := Rules(vpnLUID, services)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range rules {
		w, err := toWF(Filter{Key: filterKey(3, uint32(i)), Rule: r})
		if err != nil {
			t.Fatalf("toWF(%s): %v", r, err)
		}
		if GUID(w.ID) != filterKey(3, uint32(i)) || GUID(w.Provider) != ProviderKey || GUID(w.Sublayer) != SublayerKey {
			t.Errorf("%s: key %s, provider %s, sublayer %s", r, GUID(w.ID), GUID(w.Provider), GUID(w.Sublayer))
		}
		if got := fromWF(w); got != r {
			t.Errorf("round trip:\n got %s\nwant %s", got, r)
		}
	}
}

func TestFromWFMarksWhatLeakguardNeverWrites(t *testing.T) {
	w, err := toWF(Filter{Key: filterKey(1, 0), Rule: Rule{Layer: LayerConnectV4, Sublayer: SublayerKey, Action: ActionBlock, Remote: netip.MustParsePrefix("192.0.2.0/24"), Hard: true, Persistent: true}})
	if err != nil {
		t.Fatal(err)
	}
	w.Conditions = append(w.Conditions, &wf.Match{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(443)})
	w.BootTime = true
	got := fromWF(w)
	if !strings.Contains(got.Other, "boot-time") || !strings.Contains(got.Other, "condition IP_REMOTE_PORT") {
		t.Errorf("Other = %q", got.Other)
	}
	w.Conditions = nil
	if got := fromWF(w); !strings.Contains(got.Other, "no remote address condition") {
		t.Errorf("Other = %q", got.Other)
	}
	if _, err := toWF(Filter{Key: filterKey(1, 0), Rule: got}); err == nil {
		t.Error("toWF accepted a rule with Other set")
	}
}

// Every Windows computer has a loopback adapter; the resolver finds it.
func TestResolveFindsTheLoopbackAdapter(t *testing.T) {
	alias, luid := loopback(t)
	got, err := resolveLUID(alias)
	if err != nil || got != luid {
		t.Errorf("resolveLUID(%q) = %#x, %v; want %#x", alias, got, err, luid)
	}
	if _, err := resolveLUID("leakguard test: no such adapter"); err == nil {
		t.Error("resolveLUID found an adapter that does not exist")
	}
}

// loopback returns the loopback adapter's alias and LUID.
func loopback(t *testing.T) (string, uint64) {
	t.Helper()
	as, err := adapters()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range as {
		if a.Type == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			return a.Alias, a.LUID
		}
	}
	t.Fatalf("no loopback adapter among %v", as)
	return "", 0
}
