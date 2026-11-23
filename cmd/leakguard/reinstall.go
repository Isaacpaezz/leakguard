package main

import (
	"flag"
	"fmt"

	"github.com/Isaacpaezz/leakguard/internal/version"
)

// reinstallService is internal: the Linux package runs it after an
// upgrade, so the background service runs the new binary. It copies this
// executable to the root-owned place and restarts the service, only when
// the service is installed. It never changes the saved choice and never
// touches the loaded rules: the old service keeps them until the new one
// loads them again at start. Not in the help on purpose.
func (c *cli) reinstallService(args []string) error {
	if _, err := c.parse(flag.NewFlagSet("reinstall-service", flag.ContinueOnError), args, false); err != nil {
		return err
	}
	if err := c.requireSupported(); err != nil {
		return err
	}
	if err := c.requireRoot("reinstall-service"); err != nil {
		return err
	}
	if !c.daemon().Installed() {
		fmt.Fprintln(c.stdout, "The background service is not installed; nothing to update.")
		return nil
	}
	exe, err := c.env.Executable()
	if err != nil {
		return err
	}
	if err := c.daemon().Install(exe); err != nil {
		return fmt.Errorf("could not update the background service: %w", err)
	}
	fmt.Fprintf(c.stdout, "Background service updated to leakguard %s; your saved choice is kept.\n", version.String())
	return nil
}
