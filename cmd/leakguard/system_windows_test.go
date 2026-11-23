package main

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/Isaacpaezz/leakguard/internal/daemon"
)

// requireRoot on Windows is the elevated token.
func TestSystemIsRootIsTheElevatedToken(t *testing.T) {
	if got, want := systemIsRoot(), windows.GetCurrentProcessToken().IsElevated(); got != want {
		t.Fatalf("systemIsRoot() = %v, want IsElevated() = %v", got, want)
	}
}

// main wires the Windows service, no firewall yet, the Windows help.
func TestWindowsBackends(t *testing.T) {
	if systemFirewall != nil {
		t.Error("systemFirewall is set; the WFP backend is wired separately")
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
			if st.State != want || st.Accepts != accepts {
				t.Fatalf("status = %+v, want state %d accepts %d", st, want, accepts)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no status, want state %d", want)
		}
	}
	running := svc.AcceptStop | svc.AcceptShutdown
	next(svc.StartPending, 0)
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
