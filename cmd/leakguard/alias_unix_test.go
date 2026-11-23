//go:build !windows

package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/config"
)

// S2: macOS and Linux interface names are case-sensitive: enable and the
// daemon's set store the name as typed, and an interface whose name
// differs only in case is another interface.
func TestInterfaceNamesKeepTheirCase(t *testing.T) {
	other := Interface{Name: "UTUN4", Up: true, HasAddress: true}
	var applied []string
	env := aliasEnv(t, &applied, other)
	code, out, errOut := runReport(env, "enable", "--vpn", "utun4", "anthropic")
	if code != 0 || savedVPN(t, env) != "utun4" || !slices.Equal(applied, []string{"utun4"}) ||
		!strings.Contains(out, "Note: utun4 is not connected right now") {
		t.Fatalf("enable: exit %d, saved %q, applied %q, stdout %q, stderr %q", code, savedVPN(t, env), applied, out, errOut)
	}
	var stdout, stderr bytes.Buffer
	c := &cli{stdout: &stdout, stderr: &stderr, env: env}
	if cfg, err := c.set("utun4", []string{"anthropic"}, pfHooks{}); err != nil || cfg.VPNInterface != "utun4" {
		t.Fatalf("set() = %+v, %v", cfg, err)
	}
	if connected, ok := c.newStats().sampleVPN(); connected || !ok {
		t.Errorf("sampleVPN() = %v, %v; want sampled and not connected", connected, ok)
	}
	if err := config.CheckVPNInterface("utun4"); err != nil {
		t.Fatal(err)
	}
}
