//go:build windows

package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/config"
)

// The real adapter alias, and how a user may type it.
const (
	realAlias  = "WireGuard Tunnel"
	typedAlias = "wireguard tunnel"
)

var wireguardUp = Interface{Name: realAlias, Up: true, HasAddress: true}

// S7 (B1): enable --vpn with an alias that differs from the adapter's only
// in case stores and loads the adapter's real alias, which the firewall
// looks up exactly; otherwise it would load blocks only (no permit).
func TestEnableStoresTheAdaptersRealAlias(t *testing.T) {
	var applied []string
	env := aliasEnv(t, &applied, wireguardUp)
	code, out, errOut := runReport(env, "enable", "--vpn", typedAlias, "anthropic")
	if code != 0 {
		t.Fatalf("enable: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if got := savedVPN(t, env); got != realAlias {
		t.Errorf("saved VPN = %q, want %q", got, realAlias)
	}
	if !slices.Equal(applied, []string{realAlias}) {
		t.Errorf("Apply got %q, want [%q]", applied, realAlias)
	}
	if !strings.HasPrefix(out, "Protected through "+realAlias+": ") || strings.Contains(out, "not connected") {
		t.Errorf("stdout = %q, want the real alias, connected", out)
	}
	// An alias no adapter has (the VPN is down) is kept as typed.
	applied = nil
	env = aliasEnv(t, &applied)
	if code, out, errOut := runReport(env, "enable", "--vpn", typedAlias, "anthropic"); code != 0 {
		t.Fatalf("enable without the adapter: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if got := savedVPN(t, env); got != typedAlias || !slices.Equal(applied, []string{typedAlias}) {
		t.Errorf("without the adapter: saved %q, applied %q; want %q", got, applied, typedAlias)
	}
}

// S7 (B1): the daemon's set (the tray's change) stores and loads the
// adapter's real alias too.
func TestSetStoresTheAdaptersRealAlias(t *testing.T) {
	var applied []string
	env := aliasEnv(t, &applied, wireguardUp)
	var stdout, stderr bytes.Buffer
	c := &cli{stdout: &stdout, stderr: &stderr, env: env}
	cfg, err := c.set(typedAlias, []string{"anthropic"}, pfHooks{})
	if err != nil {
		t.Fatalf("set() = %v (stderr %q)", err, stderr.String())
	}
	if cfg.VPNInterface != realAlias || savedVPN(t, env) != realAlias || !slices.Equal(applied, []string{realAlias}) {
		t.Errorf("set() = %+v, saved %q, applied %q; want %q", cfg, savedVPN(t, env), applied, realAlias)
	}
}

// S1, S7 (B1): the daemon's VPN sampling and status find the saved alias
// ignoring case, as Windows does.
func TestVPNSamplingIgnoresAliasCase(t *testing.T) {
	var applied []string
	env := aliasEnv(t, &applied, Interface{Name: typedAlias, Up: true, HasAddress: true})
	env.IsRoot = func() bool { return false }
	if err := config.Save(rooted(env.Root, config.DefaultPath), config.Config{VPNInterface: realAlias, Services: []string{"anthropic"}}); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	c := &cli{stdout: &stdout, stderr: &stderr, env: env}
	if connected, ok := c.newStats().sampleVPN(); !connected || !ok {
		t.Errorf("sampleVPN() = %v, %v; want connected", connected, ok)
	}
	code, out, errOut := runReport(env, "status")
	if code != 0 || !strings.Contains(out, realAlias+" (connected)") {
		t.Errorf("status: exit %d, stdout %q, stderr %q; want %q connected", code, out, errOut, realAlias)
	}
}
