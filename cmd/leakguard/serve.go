package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/ipc"
)

// applyInterval is how often "serve" re-applies the saved rules.
const applyInterval = 30 * time.Second

// service is the running daemon. One mutex serializes the apply loop and
// every request, so pfctl never runs twice at once.
type service struct {
	c  *cli
	mu sync.Mutex
}

// serve is what the LaunchDaemon runs: it applies the saved rules at start
// and every applyInterval unless paused, and answers the menu-bar app on
// the socket until it is stopped.
func (c *cli) serve(args []string) error {
	if _, err := c.parse(flag.NewFlagSet("serve", flag.ContinueOnError), args, false); err != nil {
		return err
	}
	if err := c.requireRoot("serve"); err != nil {
		return err
	}
	if c.env.Socket == "" {
		return errors.New("no socket path configured")
	}
	ctx, cancel := c.serveContext()
	defer cancel()

	s := &service{c: c}
	s.applySaved()
	srv := &ipc.Server{Path: c.env.Socket, Handler: s.handle, Authorize: c.env.Authorize, Chown: c.env.ChownSocket}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.loop(ctx)
	}()
	err := srv.Serve(ctx)
	cancel()
	wg.Wait()
	return err
}

func (c *cli) serveContext() (context.Context, context.CancelFunc) {
	if c.env.ServeContext != nil {
		return c.env.ServeContext()
	}
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func (s *service) loop(ctx context.Context) {
	every := s.c.env.ApplyEvery
	if every <= 0 {
		every = applyInterval
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.applySaved()
		}
	}
}

// applySaved re-applies the saved rules unless the protection is paused.
// A failure is logged and leaves the loaded rules in place (fail closed).
func (s *service) applySaved() {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, services, err := s.c.loadValid()
	if err == nil && cfg.Paused {
		return
	}
	if err == nil {
		err = s.c.firewall().Apply(cfg.VPNInterface, services)
	}
	s.c.logApply(cfg, err)
}

func (s *service) handle(req ipc.Request) ipc.Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	switch req.Cmd {
	case ipc.CmdSet:
		err = s.c.set(req.VPNInterface, req.Services)
	case ipc.CmdDisable:
		err = s.c.pause()
	}
	if err != nil {
		return ipc.Response{Error: err.Error()}
	}
	st := s.c.daemonStatus()
	return ipc.Response{OK: true, Status: &st}
}

// set validates, saves and applies a new choice, and ends a pause. An invalid
// choice changes nothing; a failed apply leaves the old rules loaded.
func (c *cli) set(vpn string, ids []string) error {
	all, err := catalog.Embedded()
	if err != nil {
		return err
	}
	cfg := config.Config{VPNInterface: vpn, Services: ids}
	if err := cfg.Validate(all); err != nil {
		return err
	}
	if err := config.Save(c.configPath(), cfg); err != nil {
		return fmt.Errorf("could not save the configuration: %w", err)
	}
	err = c.firewall().Apply(cfg.VPNInterface, selected(cfg, all))
	c.logApply(cfg, err)
	if err != nil {
		return fmt.Errorf("could not apply the firewall rules: %w", err)
	}
	return nil
}

// pause removes the rules and saves the pause, keeping the choices. If the
// rules cannot be removed, nothing is saved.
func (c *cli) pause() error {
	cfg, err := config.Load(c.configPath())
	if errors.Is(err, config.ErrNotConfigured) {
		return errNotConfigured
	}
	if err != nil {
		return err
	}
	if err := c.firewall().Flush(); err != nil {
		return fmt.Errorf("could not remove the firewall rules: %w", err)
	}
	cfg.Paused = true
	if err := config.Save(c.configPath(), cfg); err != nil {
		// Not paused on disk: the loop loads the rules again (fail closed).
		return fmt.Errorf("could not save the pause: %w", err)
	}
	fmt.Fprintf(c.stdout, "%s Protection paused\n", c.now().Format(time.RFC3339))
	return nil
}

// daemonStatus is the status as root: protected only when pf is enabled and
// the anchor is verified for the saved choice.
func (c *cli) daemonStatus() ipc.Status {
	st := ipc.Status{Services: []string{}, Catalog: []ipc.Service{}}
	if line, ok := c.daemon().LastLogLine(); ok {
		st.LastRun = line
	}
	all, err := catalog.Embedded()
	if err != nil {
		st.Reason = err.Error()
		return st
	}
	for _, s := range all {
		st.Catalog = append(st.Catalog, ipc.Service{ID: s.ID, Name: s.Name, Status: string(s.Status)})
	}
	cfg, services, err := c.loadValid()
	st.VPNInterface = cfg.VPNInterface
	if cfg.Services != nil {
		st.Services = cfg.Services
	}
	if i, ok := c.findInterface(cfg.VPNInterface); ok && cfg.VPNInterface != "" {
		st.VPNConnected = i.Connected()
	}
	switch {
	case errors.Is(err, errNotConfigured):
		st.Reason = ipc.ReasonNotConfigured
	case err != nil:
		st.Reason = err.Error()
	case cfg.Paused:
		st.Reason = ipc.ReasonPaused
	default:
		if err := c.verify(cfg, services); err != nil {
			st.Reason = err.Error()
		} else {
			st.Protected = true
		}
	}
	return st
}

// printDaemonStatus prints the daemon's answer like "sudo leakguard status".
func (c *cli) printDaemonStatus(st ipc.Status) error {
	if st.Reason == ipc.ReasonNotConfigured {
		fmt.Fprintf(c.stdout, "leakguard is not configured yet.\n%s\n", notConfiguredHelp)
		return nil
	}
	vpnState := "not connected"
	if st.VPNConnected {
		vpnState = "connected"
	}
	w := tabwriter.NewWriter(c.stdout, 0, 4, 1, ' ', 0)
	fmt.Fprintf(w, "VPN interface:\t%s (%s)\n", st.VPNInterface, vpnState)
	fmt.Fprintf(w, "Services:\t%s\n", strings.Join(st.Services, ", "))
	fmt.Fprintf(w, "Background service:\trunning\n")
	if st.LastRun != "" {
		fmt.Fprintf(w, "Last background run:\t%s\n", st.LastRun)
	}
	if !st.Protected {
		fmt.Fprintf(w, "Firewall:\tNOT PROTECTED: %s\n", st.Reason)
		w.Flush()
		return exitError{exitFailure}
	}
	fmt.Fprintf(w, "Firewall:\tPROTECTED\n")
	return w.Flush()
}
