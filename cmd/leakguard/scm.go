package main

import (
	"context"
	"os"
	"path/filepath"
	"sync"
)

// scmState is what serve reports to the Windows Service Control Manager.
// The SCM itself reports Stopped once the service returns.
type scmState int

const (
	scmStartPending scmState = iota
	scmRunning               // accepts Stop and Shutdown
	scmStopPending
)

// scmRequest is a control request from the Service Control Manager.
type scmRequest int

const (
	scmInterrogate scmRequest = iota
	scmStop
	scmShutdown
)

// runUnderSCM runs serve as a Windows service and returns its exit code.
// It reports StartPending, then Running once serve calls ready (after the
// first load of the rules), and answers Interrogate with the current
// state. Stop and Shutdown report StopPending and cancel serve's context,
// so serve shuts down like on SIGTERM: it reads the counter one last time
// and saves the stats. serve exiting on its own ends the service with its
// exit code, so Windows restarts it.
func runUnderSCM(requests <-chan scmRequest, report func(scmState), serve func(ctx context.Context, ready func()) int) uint32 {
	state := scmStartPending
	report(state)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	var once sync.Once
	done := make(chan int, 1)
	go func() { done <- serve(ctx, func() { once.Do(func() { close(ready) }) }) }()
	for {
		select {
		case <-ready:
			ready = nil
			if state == scmStartPending {
				state = scmRunning
				report(state)
			}
		case req := <-requests:
			switch req {
			case scmInterrogate:
				report(state)
			case scmStop, scmShutdown:
				if state != scmStopPending {
					state = scmStopPending
					report(state)
					cancel()
				}
			}
		case code := <-done:
			return uint32(code)
		}
	}
}

// openServiceLog opens the service log for appending, after prepare made
// its directory (on Windows: writable only by SYSTEM and Administrators).
func openServiceLog(path string, prepare func(dir string) error) (*os.File, error) {
	if err := prepare(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
}
