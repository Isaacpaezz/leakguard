package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Isaacpaezz/leakguard/internal/daemon"
	"github.com/Isaacpaezz/leakguard/internal/pf"
	"github.com/Isaacpaezz/leakguard/internal/probe"
)

// Exit codes.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// Interface is a network interface as leakguard sees it.
type Interface struct {
	Name       string
	Up         bool
	HasAddress bool // has a routable (non link-local) address
}

// Connected reports whether the interface can carry traffic right now.
func (i Interface) Connected() bool { return i.Up && i.HasAddress }

// Env is everything leakguard needs from the system. Tests replace it so they
// never need root and never touch the real firewall or LaunchDaemons.
type Env struct {
	IsRoot           func() bool
	Root             string // prefixes every file path; empty means the real file system
	Pfctl            pf.Runner
	Launchctl        daemon.Runner
	Secure           func(path string) error // nil means daemon.SecureRootOwned
	Interfaces       func() ([]Interface, error)
	Executable       func() (string, error)
	Resolver         probe.Resolver
	Dial             probe.Dialer
	DefaultInterface func() (string, error)
}

const usage = `leakguard keeps the services you choose off your real connection:
they work only through your VPN, and go offline when the VPN drops.

Usage:
  leakguard services
      List the services you can protect. * marks the protected ones.
  leakguard interfaces
      List the network interfaces that look like a VPN.
  sudo leakguard enable [--vpn IFACE] SERVICE...
      Protect SERVICE... through the VPN interface IFACE and keep the
      protection on across reboots. Without --vpn, the saved interface is
      used, or the only connected VPN interface. Without SERVICE..., the
      saved services are used.
  sudo leakguard disable
      Turn the protection off. Your choices are kept for the next enable.
  leakguard status
      Show what is protected. With sudo it also verifies the firewall rules.
  leakguard test [--via IFACE]
      Prove that protected services are blocked outside the VPN by
      connecting through your normal connection (default: the interface of
      the default route, or IFACE). Every connection must fail.
  sudo leakguard apply
      Re-apply the saved rules. The background service runs this.
  leakguard help
      Show this help.

Examples:
  leakguard interfaces
  sudo leakguard enable --vpn ipsec0 anthropic
  leakguard status
  leakguard test
  sudo leakguard disable

Exit status: 0 on success, 1 on failure, 2 on a usage error.
`

// usageError is a mistake in the command line; it exits with status 2.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

// exitError carries a specific exit code with an already printed message.
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

type command struct {
	name string
	run  func(c *cli, args []string) error
}

var commands = []command{
	{"services", (*cli).services},
	{"interfaces", (*cli).interfaces},
	{"enable", (*cli).enable},
	{"disable", (*cli).disable},
	{"apply", (*cli).apply},
	{"status", (*cli).status},
	{"test", (*cli).test},
}

type cli struct {
	stdout, stderr io.Writer
	env            Env
}

func run(args []string, stdout, stderr io.Writer, env Env) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	}
	c := &cli{stdout: stdout, stderr: stderr, env: env}
	for _, cmd := range commands {
		if cmd.name == args[0] {
			return c.exit(cmd.run(c, args[1:]))
		}
	}
	fmt.Fprintf(stderr, "leakguard: unknown command %q\n\n%s", args[0], usage)
	return exitUsage
}

func (c *cli) exit(err error) int {
	var ue usageError
	var ee exitError
	switch {
	case err == nil:
		return exitOK
	case errors.As(err, &ee):
		return ee.code
	case errors.As(err, &ue):
		fmt.Fprintf(c.stderr, "leakguard: %s\nRun \"leakguard help\" for usage.\n", ue.msg)
		return exitUsage
	}
	fmt.Fprintf(c.stderr, "leakguard: %s\n", err)
	return exitFailure
}

func (c *cli) warn(format string, a ...any) {
	fmt.Fprintf(c.stderr, "leakguard: warning: "+format+"\n", a...)
}

// parse parses the flags of one command; extra arguments are rejected unless
// allowArgs is set.
func (c *cli) parse(fs *flag.FlagSet, args []string, allowArgs bool) ([]string, error) {
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(c.stdout, usage)
			return nil, exitError{exitOK}
		}
		return nil, usageError{err.Error()}
	}
	rest := fs.Args()
	if !allowArgs && len(rest) > 0 {
		return nil, usagef("%s takes no arguments", fs.Name())
	}
	for _, a := range rest {
		if strings.HasPrefix(a, "-") {
			return nil, usagef("put flags before the services (%s)", a)
		}
	}
	return rest, nil
}

func (c *cli) requireRoot(command string) error {
	if !c.env.IsRoot() {
		return fmt.Errorf("run with sudo: sudo leakguard %s", command)
	}
	return nil
}
