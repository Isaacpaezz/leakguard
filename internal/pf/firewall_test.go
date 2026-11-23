package pf

import (
	"errors"
	"strings"
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/firewall"
)

var _ firewall.Firewall = Firewall{}

func TestFirewallVerifyReadsTheAnchorOnly(t *testing.T) {
	r := loadedFake("Enabled")
	if err := (Firewall{Runner: r}).Verify("ipsec0", services); err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	var got []string
	for _, c := range r.calls {
		got = append(got, c.args)
	}
	if want := "-a " + Anchor + " -s rules|-a " + Anchor + " -t leakguard -T show"; strings.Join(got, "|") != want {
		t.Fatalf("calls = %v", got)
	}

	r.outputs["-a "+Anchor+" -t leakguard -T show"] = "   160.79.104.0/23\n"
	if err := (Firewall{Runner: r}).Verify("ipsec0", services); err == nil || !strings.Contains(err.Error(), "38.46.212.0/24") {
		t.Fatalf("Verify() = %v, want missing range error", err)
	}
	r.fail = map[string]error{"-a " + Anchor + " -s rules": errors.New("pfctl: permission denied")}
	if err := (Firewall{Runner: r}).Verify("ipsec0", services); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("Verify() = %v, want the pfctl error", err)
	}
}

func TestErrNotLoadedIsTheFirewallSentinel(t *testing.T) {
	r := loadedFake("Enabled")
	r.outputs["-a "+Anchor+" -s rules"] = ""
	if err := (Firewall{Runner: r}).Verify("ipsec0", services); !errors.Is(err, firewall.ErrNotLoaded) || err.Error() != "leakguard rules are not loaded" {
		t.Fatalf("Verify() = %v, want firewall.ErrNotLoaded", err)
	}
	r.outputs["-a "+Anchor+" -s rules -v"] = ""
	if _, err := (Firewall{Runner: r}).BlockCount(); !errors.Is(err, firewall.ErrNotLoaded) {
		t.Fatalf("BlockCount() = %v, want firewall.ErrNotLoaded", err)
	}
}

// S2: status names pf when it is disabled.
func TestFirewallName(t *testing.T) {
	if got := (Firewall{}).Name(); got != "pf" {
		t.Fatalf("Name() = %q", got)
	}
}
