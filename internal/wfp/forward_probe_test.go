package wfp

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// R3-002: a container that docker cannot create or start for a
// virtualization reason, before the probe runs, is "unavailable"; any other
// run without a parsable result line is inconclusive.
func TestProbeResultFromDockerOutput(t *testing.T) {
	exit1 := errors.New("exit status 1")
	for _, tc := range []struct {
		name        string
		create      bool // the output is docker create's, not docker start's
		out         string
		err         error
		ran         bool
		unavailable bool
		outcome     string
		took        time.Duration
		detail      string
		infos       int
	}{
		{name: "connected", out: "=== RUN   TestForwardProbe\nLEAKGUARD-PROBE-INFO: addresses 172.30.1.2/20\nLEAKGUARD-PROBE-INFO: connected from 172.30.1.2:50000 to 1.1.1.1:443\nLEAKGUARD-PROBE: connected 14 connected\n--- PASS: TestForwardProbe (0.02s)",
			ran: true, outcome: outConnected, took: 14 * time.Millisecond, detail: "connected", infos: 2},
		{name: "denied, CRLF lines", out: "=== RUN   TestForwardProbe\r\nLEAKGUARD-PROBE: WSAEACCES 1 WSAEACCES (10013): dial tcp 1.1.1.1:443: forbidden\r\n",
			ran: true, outcome: outDenied, took: time.Millisecond, detail: "WSAEACCES (10013): dial tcp 1.1.1.1:443: forbidden"},
		{name: "no hypervisor at start", out: "Error response from daemon: hcsshim::CreateComputeSystem 1f2e: No hypervisor is present on this system.", err: exit1, unavailable: true},
		{name: "Hyper-V not installed at create", create: true, out: "Error response from daemon: Windows does not support Hyper-V isolation on this host", err: exit1, unavailable: true},
		{name: "virtualization disabled", out: "Error response from daemon: the virtual machine could not be started because virtualization is not enabled", err: exit1, unavailable: true},
		{name: "another docker error at start", out: "Error response from daemon: container 1f2e is not running", err: exit1},
		{name: "another docker error at create", create: true, out: "Error response from daemon: No such image: mcr.microsoft.com/windows/nanoserver:ltsc2025", err: exit1},
		{name: "started, crashed", out: "=== RUN   TestForwardProbe\npanic: runtime error\n", err: errors.New("exit status 2")},
		{name: "started, virtualization words in its output", out: "=== RUN   TestForwardProbe\nLEAKGUARD-PROBE-INFO: addresses on a virtual machine adapter (Hyper-V)\n", err: exit1, infos: 1},
		{name: "malformed result line", out: "=== RUN   TestForwardProbe\nLEAKGUARD-PROBE: connected\n"},
		{name: "result without milliseconds", out: "=== RUN   TestForwardProbe\nLEAKGUARD-PROBE: connected soon connected\n"},
		{name: "exited cleanly with no output", out: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r probeResult
			var infos []string
			if tc.create {
				r = createFailure(tc.out, tc.err)
			} else {
				r, infos = startResult(tc.out, tc.err)
			}
			if r.ran != tc.ran || r.unavailable != tc.unavailable || r.outcome != tc.outcome || r.took != tc.took || r.detail != tc.detail {
				t.Errorf("= %+v, want ran %v, unavailable %v, outcome %q, took %v, detail %q", r, tc.ran, tc.unavailable, tc.outcome, tc.took, tc.detail)
			}
			if !r.ran && r.failure == "" {
				t.Errorf("a probe that did not run must say why: %+v", r)
			}
			if r.ran && r.unavailable {
				t.Errorf("a probe that ran is never unavailable: %+v", r)
			}
			if len(infos) != tc.infos {
				t.Errorf("info lines %q, want %d", infos, tc.infos)
			}
			s := r.String()
			if !r.ran && !strings.Contains(s, r.failure) {
				t.Errorf("String() = %q, want the failure %q", s, r.failure)
			}
		})
	}
}

// The Hyper-V report is one line (CI turns it into a warning) that starts
// with KNOWN GAP while a Hyper-V isolated container reaches the protected
// target with the VPN down, and says the gap may be closed once it does not.
func TestHyperVReport(t *testing.T) {
	connected := probeResult{ran: true, outcome: outConnected, took: 14 * time.Millisecond, detail: "connected"}
	timeout := probeResult{ran: true, outcome: outTimeout, took: 5 * time.Second, detail: "timeout: i/o timeout"}
	denied := probeResult{ran: true, outcome: outDenied, took: time.Millisecond, detail: "WSAEACCES (10013): forbidden"}
	const gap = "KNOWN GAP: Hyper-V guest traffic (WSL2 NAT, Hyper-V VMs, Hyper-V isolated containers) is not filtered by leakguard on Windows: "
	const closed = "KNOWN GAP MAY BE CLOSED: "
	for _, tc := range []struct {
		name   string
		down   probeResult
		closed bool
	}{
		{"reached with the VPN down", connected, false},
		{"timed out with the VPN down", timeout, true},
		{"denied with the VPN down", denied, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, isClosed := hypervReport("Ethernet 3", connected, tc.down, connected, connected)
			if isClosed != tc.closed {
				t.Errorf("closed = %v, want %v: %s", isClosed, tc.closed, line)
			}
			want := gap
			if tc.closed {
				want = closed
			}
			if !strings.HasPrefix(line, want) {
				t.Errorf("line = %q, want prefix %q", line, want)
			}
			if strings.ContainsAny(line, "\r\n") {
				t.Errorf("line %q spans several lines", line)
			}
			for _, s := range []string{"nothing loaded: " + connected.String(), "VPN down: " + tc.down.String(), `"Ethernet 3" as the VPN: ` + connected.String(), "after Flush: " + connected.String(), forwardTarget} {
				if !strings.Contains(line, s) {
					t.Errorf("line %q does not contain %q", line, s)
				}
			}
		})
	}
}

// forwardTarget is a public address that answers on 443. The forwarded
// traffic test protects it, so only the test's own connections to it are
// ever blocked, and only while the test runs.
const forwardTarget = "1.1.1.1:443"

// The outcomes TestForwardProbe reports, first word of its result line.
const (
	outConnected = "connected"
	outDenied    = "WSAEACCES" // refused by a WFP filter at ALE
	outTimeout   = "timeout"   // the packets were dropped
	outRefused   = "refused"   // WSAECONNREFUSED
	outOther     = "other"
)

// probeResult is what one container run reported.
type probeResult struct {
	ran bool // the probe printed a parsable result line
	// unavailable means docker could not create or start a container with
	// this isolation for a virtualization reason, before the probe ran.
	unavailable bool
	outcome     string        // outConnected, outDenied, ...
	took        time.Duration // as the probe measured the connect
	detail      string
	failure     string // why the probe did not run
}

func (r probeResult) String() string {
	switch {
	case r.unavailable:
		return "the container could not start (virtualization): " + r.failure
	case !r.ran:
		return "the probe did not run: " + r.failure
	}
	return fmt.Sprintf("%s after %v: %s", r.outcome, r.took, r.detail)
}

// virtualizationWords mark a docker error about the isolation or the
// hypervisor, compared in lower case.
var virtualizationWords = []string{"hyper-v", "hypervisor", "virtualization", "virtual machine", "isolation"}

// virtualizationError reports whether docker's output names the isolation
// or the hypervisor as the reason it failed.
func virtualizationError(out string) bool {
	out = strings.ToLower(out)
	return slices.ContainsFunc(virtualizationWords, func(w string) bool { return strings.Contains(out, w) })
}

// createFailure is the result of a docker create that failed: unavailable
// for a virtualization reason, otherwise inconclusive.
func createFailure(out string, err error) probeResult {
	return probeResult{unavailable: virtualizationError(out), failure: fmt.Sprintf("docker create: %v: %s", err, out)}
}

// startResult reads what docker start --attach printed and returns the
// probe's result and its info lines. A container whose probe never started
// (no line of the test binary) and that docker failed to start for a
// virtualization reason is unavailable; any other run without a parsable
// result line is inconclusive.
func startResult(out string, err error) (probeResult, []string) {
	r := probeResult{failure: fmt.Sprintf("docker start: %v: %s", err, out)}
	started := false
	var infos []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "=== RUN") || strings.HasPrefix(l, "LEAKGUARD-PROBE") {
			started = true
		}
		if info, ok := strings.CutPrefix(l, "LEAKGUARD-PROBE-INFO: "); ok {
			infos = append(infos, info)
		}
		if res, ok := strings.CutPrefix(l, "LEAKGUARD-PROBE: "); ok {
			parts := strings.SplitN(res, " ", 3)
			if len(parts) != 3 {
				continue
			}
			ms, convErr := strconv.Atoi(parts[1])
			if convErr != nil {
				continue
			}
			r = probeResult{ran: true, outcome: parts[0], took: time.Duration(ms) * time.Millisecond, detail: parts[2]}
		}
	}
	if !r.ran {
		r.unavailable = !started && err != nil && virtualizationError(out)
		if started {
			r.failure = "the probe started but printed no parsable result line: " + r.failure
		}
	}
	return r, infos
}

// hypervReport is the one line TestIntegrationForwardedTraffic logs about
// a Hyper-V isolated container (CI shows every line containing KNOWN GAP as
// a warning). CI (run 45127817057) showed such a container reaching the
// protected target in every phase: its traffic is NAT-translated inside
// the Hyper-V virtual switch and never reaches this computer's ALE or
// IPFORWARD layers. closed is true once it no longer reaches the target
// with the VPN down.
func hypervReport(vpn string, nothing, down, up, flushed probeResult) (line string, closed bool) {
	phases := fmt.Sprintf("a Hyper-V isolated container's connect to %s: nothing loaded: %s; VPN down: %s; %q as the VPN: %s; after Flush: %s",
		forwardTarget, nothing, down, vpn, up, flushed)
	if down.ran && down.outcome != outConnected {
		return "KNOWN GAP MAY BE CLOSED: with the VPN down a Hyper-V isolated container did not reach the protected target; check whether Hyper-V guest traffic is now filtered, then update the docs and this test: " + phases, true
	}
	return "KNOWN GAP: Hyper-V guest traffic (WSL2 NAT, Hyper-V VMs, Hyper-V isolated containers) is not filtered by leakguard on Windows: it is NAT-translated inside the Hyper-V virtual switch and never reaches this computer's ALE or IPFORWARD layers: " + phases, false
}
