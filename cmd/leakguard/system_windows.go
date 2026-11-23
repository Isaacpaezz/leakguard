package main

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/daemon"
)

// processElevated reports whether this process has an elevated token: an
// administrator past the UAC prompt, or SYSTEM.
func processElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// windowsDefaultInterface returns the alias of the adapter of the default
// route, from the route table.
func windowsDefaultInterface() (string, error) {
	return windowsDefaultInterfaceFrom(routeTable, func(index uint32) (string, error) {
		ifi, err := net.InterfaceByIndex(int(index))
		if err != nil {
			return "", err
		}
		return ifi.Name, nil
	})
}

// routeTable reads the IPv4 or IPv6 route table with GetIpForwardTable2,
// and the interface metric of each default route with
// GetIpInterfaceEntry. A default route whose interface cannot be read
// ranks last.
func routeTable(ipv6 bool) ([]routeRow, error) {
	family := uint16(windows.AF_INET)
	if ipv6 {
		family = windows.AF_INET6
	}
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(family, &table); err != nil {
		return nil, fmt.Errorf("GetIpForwardTable2: %w", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	var out []routeRow
	for _, r := range table.Rows() {
		row := routeRow{prefixLen: r.DestinationPrefix.PrefixLength, ifIndex: r.InterfaceIndex, metric: r.Metric}
		if row.prefixLen == 0 {
			ifRow := windows.MibIpInterfaceRow{Family: family, InterfaceLuid: r.InterfaceLuid}
			if err := windows.GetIpInterfaceEntry(&ifRow); err != nil {
				row.ifMetric = math.MaxUint32
			} else {
				row.ifMetric = ifRow.Metric
			}
		}
		out = append(out, row)
	}
	return out, nil
}

// runAsSystemService runs "serve" under the Service Control Manager when
// the SCM started this process; otherwise it reports that it did not run.
func runAsSystemService(args []string) (int, bool) {
	if len(args) != 1 || args[0] != "serve" {
		return 0, false
	}
	if isService, err := svc.IsWindowsService(); err != nil || !isService {
		return 0, false
	}
	// A service has no console: everything goes to the log. Without it,
	// serve still protects, unlogged.
	var out io.Writer = io.Discard
	if f, err := openServiceLog(daemon.WindowsLogPath, config.PrepareDir); err == nil {
		defer f.Close()
		out = f
	}
	h := scmHandler{serve: func(ctx context.Context, ready func()) int {
		env := systemEnv()
		env.ServeContext = func() (context.Context, context.CancelFunc) { return context.WithCancel(ctx) }
		env.Ready = ready
		return run([]string{"serve"}, out, out, env)
	}}
	if err := svc.Run(daemon.ServiceName, h); err != nil {
		fmt.Fprintf(out, "%s leakguard: the Windows service failed: %v\n", time.Now().Format(time.RFC3339), err)
		return exitFailure, true
	}
	return exitOK, true
}

// scmHandler adapts runUnderSCM to svc.Handler.
type scmHandler struct {
	serve func(ctx context.Context, ready func()) int
}

// Execute implements svc.Handler. svc.Run reports Stopped with the exit
// code once it returns.
func (h scmHandler) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	reqs := make(chan scmRequest)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case c := <-r:
				var req scmRequest
				switch c.Cmd {
				case svc.Interrogate:
					req = scmInterrogate
				case svc.Stop:
					req = scmStop
				case svc.Shutdown:
					req = scmShutdown
				default:
					continue
				}
				select {
				case reqs <- req:
				case <-done:
					return
				}
			}
		}
	}()
	report := func(s scmState) {
		st := svc.Status{WaitHint: uint32(s.waitHint().Milliseconds())}
		switch s {
		case scmStartPending:
			st.State = svc.StartPending
		case scmRunning:
			st.State = svc.Running
		case scmStopPending:
			st.State = svc.StopPending
		}
		if s.acceptsStop() {
			st.Accepts = svc.AcceptStop | svc.AcceptShutdown
		}
		changes <- st
	}
	return false, runUnderSCM(reqs, report, h.serve)
}
