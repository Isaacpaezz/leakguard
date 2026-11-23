package main

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/Isaacpaezz/leakguard/internal/daemon"
	"github.com/Isaacpaezz/leakguard/internal/wfp"
)

// requireRoot on Windows is the elevated token.
func TestSystemIsRootIsTheElevatedToken(t *testing.T) {
	if got, want := systemIsRoot(), windows.GetCurrentProcessToken().IsElevated(); got != want {
		t.Fatalf("systemIsRoot() = %v, want IsElevated() = %v", got, want)
	}
}

// main wires the Windows Filtering Platform, the Windows service and the
// Windows help and messages.
func TestWindowsBackends(t *testing.T) {
	if systemFirewall == nil {
		t.Fatal("systemFirewall is nil: Windows changes fail as unsupported")
	}
	if fw, ok := systemFirewall(systemEnv()).(wfp.Firewall); !ok || fw.Check == nil {
		t.Errorf("systemFirewall() = %#v, want wfp.Firewall checking the VPN", systemFirewall(systemEnv()))
	}
	if !windowsWords || strings.Contains(notConfiguredHelp(), "sudo") || strings.Contains(errNotConfigured.Error(), "sudo") {
		t.Errorf("Windows messages say sudo: %q, %q", notConfiguredHelp(), errNotConfigured)
	}
	if systemServices == nil {
		t.Error("systemServices is nil")
	}
	if _, ok := systemSCM.(daemon.SCM); !ok {
		t.Errorf("systemSCM = %T, want daemon.SCM", systemSCM)
	}
	env := systemEnv()
	if env.SCM == nil || env.Services == nil {
		t.Error("systemEnv() lacks the Windows service manager")
	}
	if usage != windowsUsage {
		t.Error("usage is not the Windows help")
	}
	if got := needAdmin("enable"); got != "run from an administrator terminal: leakguard enable" {
		t.Errorf("needAdmin() = %q", got)
	}
}

// The runner has a default route; its adapter has a name.
func TestWindowsDefaultInterfaceReal(t *testing.T) {
	name, err := windowsDefaultInterface()
	if err != nil || name == "" {
		t.Fatalf("windowsDefaultInterface() = %q, %v", name, err)
	}
	t.Logf("default route adapter: %q", name)
}

// GetIpInterfaceEntry reads the interface metric of each default route.
func TestRouteTableReadsInterfaceMetrics(t *testing.T) {
	rows, err := routeTable(false)
	if err != nil {
		t.Fatalf("routeTable() = %v", err)
	}
	found := false
	for _, r := range rows {
		if r.prefixLen != 0 {
			continue
		}
		found = true
		t.Logf("default route on interface %d: route metric %d, interface metric %d", r.ifIndex, r.metric, r.ifMetric)
		if r.ifMetric == math.MaxUint32 {
			t.Errorf("the interface metric of interface %d was not read", r.ifIndex)
		}
	}
	if !found {
		t.Fatal("no IPv4 default route")
	}
}

// A test process is not a service: serve runs as usual.
func TestRunAsSystemServiceOutsideTheSCM(t *testing.T) {
	if _, ok := runAsSystemService([]string{"serve"}); ok {
		t.Fatal("runAsSystemService() ran outside the SCM")
	}
	if _, ok := runAsSystemService([]string{"status"}); ok {
		t.Fatal("runAsSystemService() ran for status")
	}
}

// Execute maps the SCM's requests and states: StartPending, Running with
// Stop and Shutdown accepted, Interrogate answered, StopPending on Stop.
func TestSCMHandlerExecute(t *testing.T) {
	r := make(chan svc.ChangeRequest)
	changes := make(chan svc.Status, 10)
	h := scmHandler{serve: func(ctx context.Context, ready func()) int {
		ready()
		<-ctx.Done()
		return 0
	}}
	type result struct {
		ssec bool
		code uint32
	}
	done := make(chan result, 1)
	go func() {
		ssec, code := h.Execute(nil, r, changes)
		done <- result{ssec, code}
	}()
	next := func(want svc.State, accepts svc.Accepted) {
		t.Helper()
		select {
		case st := <-changes:
			pending := want == svc.StartPending || want == svc.StopPending
			if st.State != want || st.Accepts != accepts || (st.WaitHint > 0) != pending {
				t.Fatalf("status = %+v, want state %d accepts %d, a wait hint only while pending", st, want, accepts)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no status, want state %d", want)
		}
	}
	running := svc.AcceptStop | svc.AcceptShutdown
	next(svc.StartPending, running)
	next(svc.Running, running)
	r <- svc.ChangeRequest{Cmd: svc.Interrogate}
	next(svc.Running, running)
	r <- svc.ChangeRequest{Cmd: svc.Stop}
	next(svc.StopPending, 0)
	select {
	case res := <-done:
		if res.ssec || res.code != 0 {
			t.Fatalf("Execute() = %v, %d", res.ssec, res.code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Execute() did not return")
	}
}
