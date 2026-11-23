package main

import (
	"fmt"
	"runtime"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/daemon"
	"github.com/Isaacpaezz/leakguard/internal/firewall"
	"github.com/Isaacpaezz/leakguard/internal/pf"
)

// pfFirewall is the macOS firewall: the pf anchor, driven by env.Pfctl.
func pfFirewall(env Env) firewall.Firewall { return pf.Firewall{Runner: env.Pfctl} }

// launchdServices is the macOS background service: the LaunchDaemon.
func launchdServices(env Env) daemon.Manager {
	return daemon.Daemon{Root: env.Root, Launchctl: env.Launchctl, Secure: env.Secure}
}

func (c *cli) firewall() firewall.Firewall {
	if c.env.Firewall == nil {
		return unsupportedFirewall{}
	}
	return c.env.Firewall(c.env)
}

func (c *cli) daemon() daemon.Manager {
	if c.env.Services == nil {
		return unsupportedServices{}
	}
	return c.env.Services(c.env)
}

// requireSupported fails before anything changes when this system has no
// firewall or service backend, so no choice is saved that nothing enforces.
func (c *cli) requireSupported() error {
	if c.env.Firewall == nil || c.env.Services == nil {
		return unsupported("cannot protect services on this computer")
	}
	return nil
}

func unsupported(what string) error {
	return fmt.Errorf("%s: %w (%s)", what, firewall.ErrUnsupported, runtime.GOOS)
}

// unsupportedFirewall is the firewall of a system without a backend. It
// fails closed: it never reports rules as loaded or verified.
type unsupportedFirewall struct{}

func (unsupportedFirewall) Name() string { return "firewall" }

func (unsupportedFirewall) Apply(string, []catalog.Service) error {
	return unsupported("cannot load the firewall rules")
}

func (unsupportedFirewall) Flush() error { return unsupported("cannot remove the firewall rules") }

func (unsupportedFirewall) Enabled() (bool, error) {
	return false, unsupported("cannot read the firewall")
}

func (unsupportedFirewall) Verify(string, []catalog.Service) error {
	return unsupported("cannot verify the firewall rules")
}

func (unsupportedFirewall) BlockCount() (uint64, error) {
	return 0, unsupported("cannot read the block counter")
}

// unsupportedServices is the service manager of a system without a backend.
type unsupportedServices struct{}

func (unsupportedServices) Install(string) error {
	return unsupported("cannot install the background service")
}

func (unsupportedServices) Uninstall() error {
	return unsupported("cannot remove the background service")
}

func (unsupportedServices) Installed() bool             { return false }
func (unsupportedServices) LegacyInstalled() bool       { return false }
func (unsupportedServices) LastLogLine() (string, bool) { return "", false }
