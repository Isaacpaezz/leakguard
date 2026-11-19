package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/ipc"
)

// applyInterval is how often "serve" verifies the saved rules.
const applyInterval = 30 * time.Second

// service is the running daemon. One mutex serializes the check loop and
// every request, so pfctl never runs twice at once.
type service struct {
	c  *cli
	mu sync.Mutex
	// applied is the choice this daemon loaded last, nil when it loaded
	// none or paused. A different saved choice is loaded on the next check.
	applied *config.Config
	stats   *daemonStats
}

// serve is what the LaunchDaemon runs: it loads the saved rules at start,
// verifies them every applyInterval and loads them again only when the
// check fails or the saved choice changed, unless paused. pf resets the
// rules' counters on each load, so the stats read them first. It answers
// the menu-bar app on the socket until it is stopped.
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

	s := &service{c: c, stats: c.loadStats()}
	s.check(true)
	s.stats.sampleVPN()
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
	s.shutdown()
	return err
}

func (c *cli) serveContext() (context.Context, context.CancelFunc) {
	if c.env.ServeContext != nil {
		return c.env.ServeContext()
	}
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func (s *service) loop(ctx context.Context) {
	check := time.NewTicker(interval(s.c.env.ApplyEvery, applyInterval))
	defer check.Stop()
	sample := time.NewTicker(interval(s.c.env.SampleEvery, sampleInterval))
	defer sample.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-check.C:
			s.check(false)
			s.stats.save(false)
		case <-sample.C:
			s.stats.sampleVPN()
			s.stats.save(false)
		}
	}
}

func interval(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// check verifies the saved rules and loads them again when the check fails,
// when the saved choice is not the one loaded, or when force is set. It
// does nothing while paused. A failure is logged and leaves the loaded
// rules in place (fail closed). The block counter is read first, because a
// load resets it.
func (s *service) check(force bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, services, err := s.c.loadValid()
	if err == nil && cfg.Paused {
		return
	}
	if err != nil {
		s.c.logApply(cfg, err)
		return
	}
	s.stats.countBlocks(s.c.firewall())
	if !force && s.isApplied(cfg) {
		verr := s.c.verify(cfg, services)
		if verr == nil {
			s.c.logApply(cfg, nil)
			return
		}
		fmt.Fprintf(s.c.stderr, "%s leakguard: rules not verified, loading them again: %v\n", s.c.now().Format(time.RFC3339), verr)
	}
	err = s.c.firewall().Apply(cfg.VPNInterface, services)
	s.loaded(cfg, err)
	s.c.logApply(cfg, err)
}

// isApplied reports whether cfg is the choice this daemon loaded last.
func (s *service) isApplied(cfg config.Config) bool {
	return s.applied != nil && s.applied.VPNInterface == cfg.VPNInterface && slices.Equal(s.applied.Services, cfg.Services)
}

// loaded records a load of cfg that ended with err. Only a successful load
// surely reset pf's counter; after a failed one, a lower reading still
// counts as a reset, so blocks are never counted twice.
func (s *service) loaded(cfg config.Config, err error) {
	if err != nil {
		return
	}
	s.applied = &config.Config{VPNInterface: cfg.VPNInterface, Services: slices.Clone(cfg.Services)}
	s.stats.counterReset()
}

// countBlocksIfActive reads the block counter while the saved rules are
// supposed to be loaded, before a request reloads or flushes them.
func (s *service) countBlocksIfActive() {
	if cfg, err := config.Load(s.c.configPath()); err == nil && !cfg.Paused {
		s.stats.countBlocks(s.c.firewall())
	}
}

// shutdown reads the counter one last time and saves the stats.
func (s *service) shutdown() {
	s.mu.Lock()
	s.countBlocksIfActive()
	s.mu.Unlock()
	s.stats.save(true)
}

func (s *service) handle(req ipc.Request) ipc.Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	switch req.Cmd {
	case ipc.CmdSet:
		s.countBlocksIfActive()
		err = s.c.set(req.VPNInterface, req.Services)
		if err == nil {
			s.loaded(config.Config{VPNInterface: req.VPNInterface, Services: req.Services}, nil)
		}
	case ipc.CmdPause:
		s.countBlocksIfActive()
		if err = s.c.pause(); err == nil {
			s.applied = nil
			s.stats.counterReset()
		}
	}
	if err != nil {
		return ipc.Response{Error: err.Error()}
	}
	st := s.c.daemonStatus()
	st.Stats = s.stats.ipc()
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
	printStats(w, st.Stats, c.now())
	if !st.Protected {
		fmt.Fprintf(w, "Firewall:\tNOT PROTECTED: %s\n", st.Reason)
		w.Flush()
		return exitError{exitFailure}
	}
	fmt.Fprintf(w, "Firewall:\tPROTECTED\n")
	return w.Flush()
}
