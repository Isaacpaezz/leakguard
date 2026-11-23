package menubar

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/ipc"
)

// PkexecPath runs a command as root after the desktop's administrator
// prompt on Linux. It is never looked up in $PATH.
const PkexecPath = "/usr/bin/pkexec"

// SetupCommand is the argv that runs "cli enable --vpn IFACE SERVICE..."
// once as root through pkexec, the Linux counterpart of SetupScript. It is
// run directly, never through a shell. cli and the draft are checked like
// in SetupScript.
func SetupCommand(cli string, d Draft, all []catalog.Service) ([]string, error) {
	if err := checkCLIPath(cli); err != nil {
		return nil, err
	}
	if err := (config.Config{VPNInterface: d.VPNInterface, Services: d.Services}).Validate(all); err != nil {
		return nil, invalidChoice(err)
	}
	argv := []string{PkexecPath, cli, "enable", "--vpn", d.VPNInterface}
	return append(argv, d.Services...), nil
}

// DisableCommand is the argv that runs "cli disable" once as root through
// pkexec, for the uninstall.
func DisableCommand(cli string) ([]string, error) {
	if err := checkCLIPath(cli); err != nil {
		return nil, err
	}
	return []string{PkexecPath, cli, "disable"}, nil
}

// AdminCommandError explains how a pkexec run ended. pkexec exits 126 when
// the user dismissed the prompt (ErrCancelled) and 127 when the user may
// not run it ("Not authorized", read as ipc.ErrNotAuthorized) or no prompt
// could be shown; any other failure is leakguard's own, said by its first
// line of output.
func AdminCommandError(r ToolResult) error {
	line := firstNonEmptyLine(r.Stderr)
	if line == "" {
		line = firstNonEmptyLine(r.Stdout)
	}
	switch {
	case r.Code == 0:
		return nil
	case r.Code == 126:
		return ErrCancelled
	case r.Code == 127 && strings.Contains(line, "Not authorized"):
		return kindError{ipc.ErrNotAuthorized, errors.New(line)}
	case line != "":
		return errors.New(line)
	}
	return fmt.Errorf("leakguard exited with status %d", r.Code)
}

func firstNonEmptyLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}
