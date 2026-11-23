package daemon

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeControl is one service as the Service Control Manager reports it.
type fakeControl struct {
	state    ServiceState
	starting int // queries left in StartPending before it runs (-1: forever)
	stopping int // queries left in StopPending after a stop (-1: forever)
	refuse   int // stops refused with errCannotAcceptStop while running
	stopErr  error
	stateErr error
	calls    []string
	slept    time.Duration
}

func (f *fakeControl) queryState() (ServiceState, error) {
	f.calls = append(f.calls, "state")
	if f.stateErr != nil {
		return 0, f.stateErr
	}
	st := f.state
	switch {
	case st == ServiceStartPending && f.starting == 0:
		f.state = ServiceRunning
	case st == ServiceStartPending && f.starting > 0:
		f.starting--
	case st == ServiceStopPending && f.stopping == 0:
		f.state = ServiceStopped
	case st == ServiceStopPending && f.stopping > 0:
		f.stopping--
	}
	return st, nil
}

func (f *fakeControl) sendStop() error {
	f.calls = append(f.calls, "stop")
	switch {
	case f.stopErr != nil:
		return f.stopErr
	case f.state == ServiceStopped:
		return errServiceNotActive
	case f.state == ServiceStartPending || f.refuse > 0:
		f.refuse--
		return errCannotAcceptStop
	}
	f.state = ServiceStopPending
	return nil
}

func (f *fakeControl) sleep(d time.Duration) { f.slept += d }

func (f *fakeControl) stop() error {
	return stopService(f, "leakguard", stopWait, stopPoll, f.sleep)
}

func (f *fakeControl) callString() string { return strings.Join(f.calls, " ") }

// A service that is still starting cannot take the stop control: Stop
// waits until it runs, then stops it, instead of failing.
func TestStopWaitsForAStartingService(t *testing.T) {
	f := &fakeControl{state: ServiceStartPending, starting: 3, stopping: 2}
	if err := f.stop(); err != nil {
		t.Fatalf("stop() = %v", err)
	}
	if got, want := f.callString(), "state state state state state stop state state state state"; got != want {
		t.Fatalf("calls = %s\nwant    %s", got, want)
	}
}

func TestStopOfARunningService(t *testing.T) {
	f := &fakeControl{state: ServiceRunning, stopping: 1}
	if err := f.stop(); err != nil {
		t.Fatalf("stop() = %v", err)
	}
	if got, want := f.callString(), "state stop state state state"; got != want {
		t.Fatalf("calls = %s, want %s", got, want)
	}
}

// A stopped service is not an error and gets no control.
func TestStopOfAStoppedService(t *testing.T) {
	f := &fakeControl{state: ServiceStopped}
	if err := f.stop(); err != nil || f.callString() != "state" {
		t.Fatalf("stop() = %v, calls %s", err, f.callString())
	}
	// It stopped between the query and the control.
	f = &fakeControl{state: ServiceRunning, stopErr: errServiceNotActive}
	if err := f.stop(); err != nil {
		t.Fatalf("stop() = %v", err)
	}
}

// A running service that refuses the control for a moment gets it again.
func TestStopRetriesARefusedControl(t *testing.T) {
	f := &fakeControl{state: ServiceRunning, refuse: 2}
	if err := f.stop(); err != nil {
		t.Fatalf("stop() = %v", err)
	}
	if got, want := f.callString(), "state stop state stop state stop state state"; got != want {
		t.Fatalf("calls = %s, want %s", got, want)
	}
}

// The wait is bounded: a service stuck starting, or stuck stopping, fails
// Stop after stopWait.
func TestStopGivesUpAfterTheWait(t *testing.T) {
	f := &fakeControl{state: ServiceStartPending, starting: -1}
	err := f.stop()
	if err == nil || err.Error() != "the leakguard service did not finish starting within 30s, so it could not be stopped" {
		t.Fatalf("stop() = %v", err)
	}
	if f.slept != stopWait || strings.Contains(f.callString(), "stop") {
		t.Fatalf("slept %s, calls %s; want %s and no stop control", f.slept, f.callString(), stopWait)
	}
	f = &fakeControl{state: ServiceRunning, stopping: -1}
	err = f.stop()
	if err == nil || err.Error() != "the leakguard service did not stop within 30s" {
		t.Fatalf("stop() = %v", err)
	}
	if f.slept != stopWait {
		t.Fatalf("slept %s, want %s", f.slept, stopWait)
	}
}

func TestStopReportsErrors(t *testing.T) {
	f := &fakeControl{state: ServiceRunning, stopErr: errors.New("Access is denied.")}
	if err := f.stop(); err == nil || err.Error() != "Access is denied." {
		t.Fatalf("stop() = %v", err)
	}
	f = &fakeControl{stateErr: errors.New("Access is denied.")}
	if err := f.stop(); err == nil || err.Error() != "Access is denied." {
		t.Fatalf("stop() = %v", err)
	}
}
