package wfp

import (
	"strings"
	"testing"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// leakguard's own layer and condition keys, which it enumerates and reads
// with, are the ones tailscale/wf adds with.
func TestKeysMatchTheLibrary(t *testing.T) {
	for _, tc := range []struct {
		name      string
		got, want GUID
	}{
		{"ALE_AUTH_CONNECT_V4", layerKey(LayerConnectV4), GUID(wf.LayerALEAuthConnectV4)},
		{"ALE_AUTH_CONNECT_V6", layerKey(LayerConnectV6), GUID(wf.LayerALEAuthConnectV6)},
		{"IPFORWARD_V4", layerKey(LayerForwardV4), GUID(wf.LayerIPForwardV4)},
		{"IPFORWARD_V6", layerKey(LayerForwardV6), GUID(wf.LayerIPForwardV6)},
		{"IP_REMOTE_ADDRESS", remoteField(LayerConnectV4), GUID(wf.FieldIPRemoteAddress)},
		{"IP_LOCAL_INTERFACE", interfaceField(LayerConnectV4), GUID(wf.FieldIPLocalInterface)},
		{"IP_DESTINATION_ADDRESS", remoteField(LayerForwardV4), GUID(wf.FieldIPDestinationAddress)},
		{"IP_FORWARD_INTERFACE", interfaceField(LayerForwardV4), GUID(wf.FieldIPForwardInterface)},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: leakguard %s, tailscale/wf %s", tc.name, tc.got, tc.want)
		}
	}
	if fwpActionBlock != uint32(wf.ActionBlock) || fwpActionPermit != uint32(wf.ActionPermit) || fwpMatchEqual != uint32(wf.MatchTypeEqual) {
		t.Errorf("block %#x, permit %#x, equal %d; tailscale/wf: %#x, %#x, %d", fwpActionBlock, fwpActionPermit, fwpMatchEqual, uint32(wf.ActionBlock), uint32(wf.ActionPermit), uint32(wf.MatchTypeEqual))
	}
}

// toWF writes each rule at its layer with that layer's conditions: the
// remote address and local interface for this computer's connections, the
// destination and forward interface for forwarded packets.
func TestToWFWritesEachLayersConditions(t *testing.T) {
	rules, err := Rules(vpnLUID, services)
	if err != nil {
		t.Fatal(err)
	}
	layers := map[Layer]wf.LayerID{LayerConnectV4: wf.LayerALEAuthConnectV4, LayerConnectV6: wf.LayerALEAuthConnectV6, LayerForwardV4: wf.LayerIPForwardV4, LayerForwardV6: wf.LayerIPForwardV6}
	seen := map[Layer]int{}
	for i, r := range rules {
		w, err := toWF(Filter{Key: filterKey(3, uint32(i)), Rule: r})
		if err != nil {
			t.Fatalf("toWF(%s): %v", r, err)
		}
		seen[r.Layer]++
		if GUID(w.ID) != filterKey(3, uint32(i)) || GUID(w.Provider) != ProviderKey || GUID(w.Sublayer) != SublayerKey || w.Layer != layers[r.Layer] {
			t.Errorf("%s: key %s, provider %s, sublayer %s, layer %s", r, GUID(w.ID), GUID(w.Provider), GUID(w.Sublayer), w.Layer)
		}
		if w.Weight != r.Weight || w.HardAction != r.Hard || !w.Persistent || w.BootTime {
			t.Errorf("%s: weight %d, hard %v, persistent %v, boot-time %v", r, w.Weight, w.HardAction, w.Persistent, w.BootTime)
		}
		if (r.Action == ActionBlock) != (w.Action == wf.ActionBlock) || (r.Action == ActionPermit) != (w.Action == wf.ActionPermit) {
			t.Errorf("%s: action %s", r, w.Action)
		}
		remote, iface := wf.FieldIPRemoteAddress, wf.FieldIPLocalInterface
		if r.Layer.Forward() {
			remote, iface = wf.FieldIPDestinationAddress, wf.FieldIPForwardInterface
		}
		want := []string{(&wf.Match{Field: remote, Op: wf.MatchTypeEqual, Value: r.Remote}).String()}
		if r.LUID != 0 {
			want = append(want, (&wf.Match{Field: iface, Op: wf.MatchTypeEqual, Value: r.LUID}).String())
		}
		var got []string
		for _, m := range w.Conditions {
			got = append(got, m.String())
		}
		if strings.Join(got, "; ") != strings.Join(want, "; ") {
			t.Errorf("%s: conditions %q, want %q", r, got, want)
		}
	}
	for l := range layers {
		if seen[l] != 4 {
			t.Errorf("%d rules at %s, want 4 (2 ranges, block and permit)", seen[l], l)
		}
	}
	bad := rules[0]
	bad.Other = "condition ALE_APP_ID"
	if _, err := toWF(Filter{Key: filterKey(1, 0), Rule: bad}); err == nil {
		t.Error("toWF accepted a rule with Other set")
	}
	bad = rules[0]
	bad.Layer = LayerOther
	if _, err := toWF(Filter{Key: filterKey(1, 0), Rule: bad}); err == nil {
		t.Error("toWF accepted a rule at another layer")
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
