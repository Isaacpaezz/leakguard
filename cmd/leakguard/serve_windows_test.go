package main

import (
	"strings"
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/ipc"
)

// S8 (SF1): without elevation "status" asks the daemon only through a pipe
// the leakguard service (LocalSystem) owns. A pipe anyone else created, a
// test daemon's here, gets nothing: status reads the saved settings
// instead and never shows that pipe's answer.
func TestStatusIgnoresAPipeTheServiceDoesNotOwn(t *testing.T) {
	h := newHarness(t, false)
	h.saveConfig(t, anthropicConfig)
	h.env.Socket = fakeDaemon(t, ipc.Status{Protected: true, VPNInterface: "utun9", VPNConnected: true, Services: []string{"anthropic"}})
	h.env.CheckServer = nil // the real check
	code, out, errOut := h.run("status")
	expect(t, code, out, errOut, 0, []string{"ipsec0 (connected)", "not installed", `run "sudo leakguard status" to verify`}, nil)
	if strings.Contains(out, "utun9") || strings.Contains(out, "PROTECTED") {
		t.Fatalf("status trusted a pipe the service does not own:\n%s", out)
	}
}
