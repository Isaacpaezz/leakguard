package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/daemon"
	"github.com/Isaacpaezz/leakguard/internal/ipc"
	"github.com/Isaacpaezz/leakguard/internal/probe"
)

// windowsWords makes messages name an administrator terminal instead of
// sudo, and a VPN adapter instead of an interface.
var windowsWords = runtime.GOOS == "windows"

// adminCommand is how to run "leakguard args" as an administrator:
// "sudo leakguard args", or on Windows "leakguard args (in an administrator
// terminal)".
func adminCommand(args string) string {
	if windowsWords {
		return "leakguard " + strings.ReplaceAll(args, "IFACE", "ADAPTER") + " (in an administrator terminal)"
	}
	return "sudo leakguard " + args
}

// notConfiguredHelp is what status prints before the first enable.
func notConfiguredHelp() string {
	return "Start with: " + adminCommand("enable --vpn IFACE SERVICE...") + "\nSee your VPN interfaces with: leakguard interfaces"
}

// notConfiguredError is errNotConfigured; its text follows windowsWords.
type notConfiguredError struct{}

func (notConfiguredError) Error() string {
	return "not configured yet; run: " + adminCommand("enable --vpn IFACE SERVICE...")
}

var errNotConfigured error = notConfiguredError{}

func (c *cli) configPath() string { return rooted(c.env.Root, config.DefaultPath) }

// vpnRefusedError is a saved configuration that is valid except for its VPN
// interface, which is refused (for example a real connection that now
// exists under that name). Its rules allow no interface: fail closed.
type vpnRefusedError struct {
	vpn string
	err error // the refusal; it wraps config.ErrVPNRefused
}

func (e vpnRefusedError) Error() string { return "invalid configuration: " + e.err.Error() }
func (e vpnRefusedError) Unwrap() error { return e.err }

// blocked is what the daemon and apply log once the block-all rules load.
func (e vpnRefusedError) blocked() error {
	return fmt.Errorf("%v; protected services are blocked on every interface", e)
}

// notBlocked is what they log when the block-all rules fail to load.
func (e vpnRefusedError) notBlocked(err error) error {
	return fmt.Errorf("%v, and protected services could not be blocked: %w", e, err)
}

// reason is what status says, given how the block-all rules verified.
func (e vpnRefusedError) reason(verr error) string {
	if verr != nil {
		return fmt.Sprintf("the saved VPN %q is not a VPN interface, and protected services are not blocked: %v", e.vpn, verr)
	}
	return fmt.Sprintf("protected services are blocked: the saved VPN %q is not a VPN interface; choose yours with: %s", e.vpn, adminCommand("enable --vpn IFACE"))
}

// asVPNRefused reports whether err is a loadValid error for a configuration
// that is valid except for its VPN interface.
func asVPNRefused(err error) (vpnRefusedError, bool) {
	var e vpnRefusedError
	return e, errors.As(err, &e)
}

// blockAll is the choice whose rules allow no interface (Firewall with an
// empty VPN).
var blockAll = config.Config{}

// loadValid loads the saved configuration and checks it against the catalog.
// When only the VPN interface is refused, it also returns the services with
// a vpnRefusedError, so the caller can block them on every interface.
func (c *cli) loadValid() (config.Config, []catalog.Service, error) {
	all, err := catalog.Embedded()
	if err != nil {
		return config.Config{}, nil, err
	}
	cfg, err := config.Load(c.configPath())
	if errors.Is(err, config.ErrNotConfigured) {
		return cfg, nil, errNotConfigured
	}
	if err != nil {
		return cfg, nil, err
	}
	if err := cfg.Validate(all); err != nil {
		if errors.Is(err, config.ErrVPNRefused) && cfg.ValidateServices(all) == nil {
			return cfg, selected(cfg, all), vpnRefusedError{vpn: cfg.VPNInterface, err: err}
		}
		return cfg, nil, fmt.Errorf("invalid configuration: %w", err)
	}
	return cfg, selected(cfg, all), nil
}

func selected(cfg config.Config, all []catalog.Service) []catalog.Service {
	var out []catalog.Service
	for _, id := range cfg.Services {
		if s, ok := catalog.Find(all, id); ok {
			out = append(out, s)
		}
	}
	return out
}

func names(services []catalog.Service) string {
	var n []string
	for _, s := range services {
		n = append(n, s.Name)
	}
	return strings.Join(n, ", ")
}

func (c *cli) findInterface(name string) (Interface, bool) {
	ifs, err := c.env.Interfaces()
	if err != nil {
		return Interface{}, false
	}
	for _, i := range ifs {
		if i.Name == name {
			return i, true
		}
	}
	return Interface{}, false
}

func (c *cli) services(args []string) error {
	if _, err := c.parse(flag.NewFlagSet("services", flag.ContinueOnError), args, false); err != nil {
		return err
	}
	all, err := catalog.Embedded()
	if err != nil {
		return err
	}
	cfg, err := config.Load(c.configPath())
	if err != nil && !errors.Is(err, config.ErrNotConfigured) {
		c.warn("cannot read the configuration: %v", err)
	}
	on := map[string]bool{}
	for _, id := range cfg.Services {
		on[id] = true
	}
	w := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "  ID\tNAME\tSTATUS")
	for _, s := range all {
		mark := " "
		if on[s.ID] {
			mark = "*"
		}
		fmt.Fprintf(w, "%s %s\t%s\t%s\n", mark, s.ID, s.Name, s.Status)
	}
	w.Flush()
	fmt.Fprintln(c.stdout, "\n* = protected. Only supported services can be protected.")
	return nil
}

func (c *cli) vpnCandidates() ([]Interface, error) {
	ifs, err := c.env.Interfaces()
	if err != nil {
		return nil, err
	}
	byName := map[string]Interface{}
	var all []string
	for _, i := range ifs {
		byName[i.Name] = i
		all = append(all, i.Name)
	}
	var out []Interface
	for _, n := range config.VPNCandidates(all) {
		out = append(out, byName[n])
	}
	return out, nil
}

func (i Interface) state() string {
	switch {
	case i.Connected():
		return "connected"
	case i.Up:
		return "up, no address"
	}
	return "down"
}

func (c *cli) interfaces(args []string) error {
	if _, err := c.parse(flag.NewFlagSet("interfaces", flag.ContinueOnError), args, false); err != nil {
		return err
	}
	cands, err := c.vpnCandidates()
	if err != nil {
		return err
	}
	if len(cands) == 0 {
		fmt.Fprintln(c.stdout, "No VPN interfaces found. Connect your VPN and try again.")
		return nil
	}
	w := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSTATE")
	for _, i := range cands {
		fmt.Fprintf(w, "%s\t%s\n", i.Name, i.state())
	}
	w.Flush()
	fmt.Fprintln(c.stdout, "\nYour VPN is usually the one that appears when you connect it.")
	fmt.Fprintln(c.stdout, "Use it with: "+adminCommand("enable --vpn NAME SERVICE..."))
	return nil
}

// detectVPN returns the only connected VPN interface, and fails otherwise:
// guessing wrong would send protected traffic over the real connection.
func (c *cli) detectVPN() (string, error) {
	cands, err := c.vpnCandidates()
	if err != nil {
		return "", err
	}
	var connected, list []string
	for _, i := range cands {
		list = append(list, i.Name+" ("+i.state()+")")
		if i.Connected() {
			connected = append(connected, i.Name)
		}
	}
	switch {
	case len(connected) == 1:
		fmt.Fprintf(c.stdout, "Detected VPN interface: %s\n", connected[0])
		return connected[0], nil
	case len(cands) == 0:
		return "", errors.New("no VPN interface found; connect your VPN, or name it with --vpn IFACE")
	}
	return "", fmt.Errorf("cannot tell which interface is your VPN: %s; name it with --vpn IFACE", strings.Join(list, ", "))
}

func (c *cli) enable(args []string) error {
	fs := flag.NewFlagSet("enable", flag.ContinueOnError)
	vpn := fs.String("vpn", "", "VPN interface")
	c.reportFlag(fs)
	ids, err := c.parse(fs, args, true)
	if err != nil {
		return err
	}
	if err := c.requireSupported(); err != nil {
		return err
	}
	if err := c.requireRoot("enable"); err != nil {
		return err
	}
	all, err := catalog.Embedded()
	if err != nil {
		return err
	}
	saved, err := config.Load(c.configPath())
	if err != nil && !errors.Is(err, config.ErrNotConfigured) {
		c.warn("ignoring the saved configuration: %v", err)
		saved = config.Config{}
	}
	// A new Config is never paused: enable ends a pause from the menu-bar app.
	cfg := config.Config{VPNInterface: *vpn, Services: ids}
	if len(cfg.Services) == 0 {
		cfg.Services = saved.Services
	}
	if len(cfg.Services) == 0 {
		example := "sudo leakguard enable anthropic (see leakguard services)"
		if windowsWords {
			example = "leakguard enable anthropic (in an administrator terminal; see leakguard services)"
		}
		return usagef("name at least one service, for example: %s", example)
	}
	if cfg.VPNInterface == "" {
		cfg.VPNInterface = saved.VPNInterface
	}
	if cfg.VPNInterface == "" {
		if cfg.VPNInterface, err = c.detectVPN(); err != nil {
			return err
		}
	}
	if err := cfg.Validate(all); err != nil {
		return err
	}
	if err := config.Save(c.configPath(), cfg); err != nil {
		return fmt.Errorf("could not save the configuration: %w", err)
	}
	services := selected(cfg, all)
	if err := c.firewall().Apply(cfg.VPNInterface, services); err != nil {
		return fmt.Errorf("could not apply the firewall rules: %w", err)
	}
	exe, err := c.env.Executable()
	if err != nil {
		return err
	}
	if err := c.daemon().Install(exe); err != nil {
		return fmt.Errorf("could not install the background service: %w", err)
	}
	if c.daemon().LegacyInstalled() {
		c.warn("the macOS prototype is still installed (%s); remove it with: sudo prototypes/macos-pf/uninstall.sh", daemon.LegacyPlistPath)
	}
	fmt.Fprintf(c.stdout, "Protected through %s: %s\n", cfg.VPNInterface, names(services))
	if i, ok := c.findInterface(cfg.VPNInterface); !ok || !i.Connected() {
		fmt.Fprintf(c.stdout, "Note: %s is not connected right now, so these services are offline until it is.\n", cfg.VPNInterface)
	}
	fmt.Fprintf(c.stdout, "If %s goes down, these services stop working instead of using your real connection.\n", cfg.VPNInterface)
	fmt.Fprintln(c.stdout, "Check it with: leakguard status   Prove it with: leakguard test")
	return nil
}

func (c *cli) disable(args []string) error {
	fs := flag.NewFlagSet("disable", flag.ContinueOnError)
	c.reportFlag(fs)
	if _, err := c.parse(fs, args, false); err != nil {
		return err
	}
	if err := c.requireRoot("disable"); err != nil {
		return err
	}
	// Stop the daemon first, so it cannot re-apply the rules after the flush.
	if err := c.daemon().Uninstall(); err != nil {
		return fmt.Errorf("could not remove the background service: %w", err)
	}
	if err := c.firewall().Flush(); err != nil {
		return fmt.Errorf("could not remove the firewall rules: %w", err)
	}
	fmt.Fprintln(c.stdout, "Protection disabled. Protected services now use your normal connection.")
	return nil
}

// apply loads the saved rules. Without a valid configuration it fails and
// leaves any loaded rules in place (fail closed); when only the saved VPN
// interface is refused, it loads rules that block protected services on
// every interface and fails with the reason. Once the rules are loaded it
// ends a pause from the menu-bar app, so the daemon loads them again after a
// reboot.
func (c *cli) apply(args []string) error {
	if _, err := c.parse(flag.NewFlagSet("apply", flag.ContinueOnError), args, false); err != nil {
		return err
	}
	if err := c.requireSupported(); err != nil {
		return err
	}
	if err := c.requireRoot("apply"); err != nil {
		return err
	}
	cfg, services, err := c.loadValid()
	vpn := cfg.VPNInterface
	refused, isRefused := asVPNRefused(err)
	if isRefused {
		vpn, err = blockAll.VPNInterface, nil
	}
	if err == nil {
		if err = c.firewall().Apply(vpn, services); err != nil && isRefused {
			return c.logApply(cfg, refused.notBlocked(err))
		}
	}
	if err == nil && cfg.Paused {
		cfg.Paused = false
		if serr := config.Save(c.configPath(), cfg); serr != nil {
			if isRefused {
				return c.logApply(cfg, fmt.Errorf("%v; the pause could not be cleared: %w", refused.blocked(), serr))
			}
			err = fmt.Errorf("the rules are loaded, but the pause could not be cleared: %w", serr)
		}
	}
	if err == nil && isRefused {
		err = refused.blocked()
	}
	return c.logApply(cfg, err)
}

// logApply prints the result of one apply. The daemon's output goes to
// daemon.LogPath; every line is timestamped so "status" can show when the
// last run happened and how it ended.
func (c *cli) logApply(cfg config.Config, err error) error {
	stamp := c.now().Format(time.RFC3339)
	if err != nil {
		fmt.Fprintf(c.stderr, "%s leakguard: %v\n", stamp, err)
		return exitError{exitFailure}
	}
	fmt.Fprintf(c.stdout, "%s Protected through %s: %s\n", stamp, cfg.VPNInterface, strings.Join(cfg.Services, ", "))
	return nil
}

func (c *cli) now() time.Time {
	if c.env.Now != nil {
		return c.env.Now()
	}
	return time.Now()
}

func (c *cli) status(args []string) error {
	if _, err := c.parse(flag.NewFlagSet("status", flag.ContinueOnError), args, false); err != nil {
		return err
	}
	// Without root, the daemon verifies the rules for us when it answers.
	if !c.env.IsRoot() && c.env.Socket != "" {
		if st, err := (ipc.Client{Path: c.env.Socket}).Status(); err == nil {
			return c.printDaemonStatus(st)
		}
	}
	cfg, services, err := c.loadValid()
	if errors.Is(err, errNotConfigured) {
		fmt.Fprintf(c.stdout, "leakguard is not configured yet.\n%s\n", notConfiguredHelp())
		return nil
	}
	// Root can tell whether a refused VPN left protected services blocked.
	refused, isRefused := asVPNRefused(err)
	isRefused = isRefused && c.env.IsRoot() && !cfg.Paused
	if err != nil && !isRefused {
		return err
	}
	vpnState := "not connected"
	if i, ok := c.findInterface(cfg.VPNInterface); ok && i.Connected() {
		vpnState = "connected"
	}
	daemonState, verifyHint := "not installed (run: sudo leakguard enable)", `run "sudo leakguard status" to verify the rules`
	if windowsWords {
		daemonState = `not installed (run "leakguard enable" in an administrator terminal)`
		verifyHint = `run "leakguard status" in an administrator terminal to verify the rules`
	}
	if c.daemon().Installed() {
		daemonState = "installed"
	}
	w := tabwriter.NewWriter(c.stdout, 0, 4, 1, ' ', 0)
	fmt.Fprintf(w, "VPN interface:\t%s (%s)\n", cfg.VPNInterface, vpnState)
	fmt.Fprintf(w, "Services:\t%s\n", strings.Join(cfg.Services, ", "))
	fmt.Fprintf(w, "Background service:\t%s\n", daemonState)
	if line, ok := c.daemon().LastLogLine(); ok {
		fmt.Fprintf(w, "Last background run:\t%s\n", line)
	}
	printStats(w, c.savedStats(), c.now())
	if !c.env.IsRoot() {
		fmt.Fprintf(w, "Firewall:\t%s\n", verifyHint)
		return w.Flush()
	}
	if isRefused {
		fmt.Fprintf(w, "Firewall:\tNOT PROTECTED: %s\n", refused.reason(c.verify(blockAll, services)))
		w.Flush()
		return exitError{exitFailure}
	}
	if verr := c.verify(cfg, services); verr != nil {
		fmt.Fprintf(w, "Firewall:\tNOT PROTECTED: %v\n", verr)
		w.Flush()
		return exitError{exitFailure}
	}
	fmt.Fprintf(w, "Firewall:\tPROTECTED\n")
	return w.Flush()
}

// verify checks, as root, that the firewall is enabled and its rules
// protect services.
func (c *cli) verify(cfg config.Config, services []catalog.Service) error {
	fw := c.firewall()
	switch on, err := fw.Enabled(); {
	case err != nil:
		return err
	case !on:
		return fmt.Errorf("%s is disabled; turn it back on with: %s", fw.Name(), adminCommand("apply"))
	}
	return fw.Verify(cfg.VPNInterface, services)
}

func isVPN(iface string, cfg config.Config) bool {
	return iface == cfg.VPNInterface || len(config.VPNCandidates([]string{iface})) > 0
}

// realConnections returns the connected interfaces outside the VPN.
func (c *cli) realConnections(cfg config.Config) ([]string, error) {
	ifs, err := c.env.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, i := range ifs {
		if i.Connected() && !isVPN(i.Name, cfg) {
			out = append(out, i.Name)
		}
	}
	return out, nil
}

// checkVia fails before probing when the chosen interface cannot carry
// traffic: probing it would only report unreachable networks.
func (c *cli) checkVia(iface string, cfg config.Config) error {
	ifs, err := c.env.Interfaces()
	if err != nil {
		return fmt.Errorf("cannot list the interfaces: %w", err)
	}
	state := "does not exist"
	for _, i := range ifs {
		if i.Name == iface {
			if i.Connected() {
				return nil
			}
			state = "is not connected"
		}
	}
	conns, _ := c.realConnections(cfg)
	list := "none"
	if len(conns) > 0 {
		list = strings.Join(conns, ", ")
	}
	return fmt.Errorf("%s %s; pick the interface of your real connection with --via (connected: %s)", iface, state, list)
}

// realInterface returns the interface of the real connection: the default
// route, or, when that is the VPN or unreadable, the only connected interface
// outside the VPN. It never guesses between several.
func (c *cli) realInterface(cfg config.Config) (string, error) {
	route, err := c.env.DefaultInterface()
	if err == nil && !isVPN(route, cfg) {
		return route, nil
	}
	reason := fmt.Sprintf("the default route uses %s, a VPN interface", route)
	if err != nil {
		reason = fmt.Sprintf("cannot read the default route (%v)", err)
	}
	conns, lerr := c.realConnections(cfg)
	switch {
	case lerr != nil:
		return "", fmt.Errorf("%s, and the interfaces cannot be listed (%v); name your real connection with --via IFACE", reason, lerr)
	case len(conns) == 0:
		return "", fmt.Errorf("%s, and no other interface is connected; connect Wi-Fi or Ethernet, or name your real connection with --via IFACE", reason)
	case len(conns) > 1:
		return "", fmt.Errorf("%s, and more than one other interface is connected (%s); name your real connection with --via IFACE", reason, strings.Join(conns, ", "))
	}
	fmt.Fprintf(c.stdout, "%s%s; testing through %s, the only connected interface outside the VPN.\n", strings.ToUpper(reason[:1]), reason[1:], conns[0])
	return conns[0], nil
}

func (c *cli) test(args []string) error {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	via := fs.String("via", "", "interface of your normal connection")
	if _, err := c.parse(fs, args, false); err != nil {
		return err
	}
	if *via != "" && !config.ValidInterfaceName(*via) {
		return usagef("%q is not a valid interface name", *via)
	}
	cfg, services, err := c.loadValid()
	if err != nil {
		return err
	}
	iface := *via
	if iface != "" {
		if isVPN(iface, cfg) {
			return fmt.Errorf("%s is a VPN interface; name your Wi-Fi or Ethernet interface with --via IFACE, for example --via %s", iface, viaExampleFor(runtime.GOOS))
		}
		if err := c.checkVia(iface, cfg); err != nil {
			return err
		}
	} else if iface, err = c.realInterface(cfg); err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "Connecting to each protected address through %s, outside the VPN. Every connection must fail.\n\n", iface)
	p := probe.Prober{Resolver: c.env.Resolver, Dial: c.env.Dial}
	results := p.Run(context.Background(), iface, services)
	w := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	for _, r := range results {
		target := r.Domain
		if r.Addr.IsValid() {
			target += " " + r.Addr.Addr().String()
		}
		detail := ""
		if (r.Outcome == probe.Untested || r.Outcome == probe.NotCovered) && r.Err != nil {
			detail = r.Err.Error()
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Outcome, r.Service, target, detail)
	}
	w.Flush()
	if err := probe.Check(results, services); err != nil {
		return err
	}
	fmt.Fprintln(c.stdout, "\nAll protected services are blocked outside the VPN.")
	return nil
}
