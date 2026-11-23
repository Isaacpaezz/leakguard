package menubar

import (
	"errors"
	"slices"
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/ipc"
)

// S1: the Linux setup runs "cli enable --vpn IFACE SERVICE..." through
// pkexec, as an argv and never a shell string.
func TestSetupCommand(t *testing.T) {
	d := Draft{VPNInterface: "ipsec0", Services: []string{"anthropic", "mistral"}}
	got, err := SetupCommand("/usr/bin/leak guard", d, fullCatalog)
	want := []string{"/usr/bin/pkexec", "/usr/bin/leak guard", "enable", "--vpn", "ipsec0", "anthropic", "mistral"}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("SetupCommand = %q, %v; want %q", got, err, want)
	}
	if _, err := SetupCommand("leakguard", d, fullCatalog); !errors.Is(err, ErrUnsafeCLIPath) {
		t.Errorf("relative CLI: err = %v, want ErrUnsafeCLIPath", err)
	}
	if _, err := SetupCommand("/usr/bin/leak\nguard", d, fullCatalog); !errors.Is(err, ErrUnsafeCLIPath) {
		t.Errorf("control character: err = %v, want ErrUnsafeCLIPath", err)
	}
	for _, bad := range []Draft{
		{VPNInterface: "en0", Services: []string{"anthropic"}},
		{VPNInterface: "ipsec0", Services: []string{"openai"}},
		{VPNInterface: "ipsec0", Services: []string{"--vpn"}},
		{VPNInterface: "ipsec0"},
	} {
		if _, err := SetupCommand("/usr/bin/leakguard", bad, fullCatalog); !errors.Is(err, ErrInvalidChoice) {
			t.Errorf("SetupCommand(%+v) err = %v, want ErrInvalidChoice", bad, err)
		}
	}
}

func TestDisableCommand(t *testing.T) {
	got, err := DisableCommand("/usr/local/libexec/leakguard/leakguard")
	want := []string{"/usr/bin/pkexec", "/usr/local/libexec/leakguard/leakguard", "disable"}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("DisableCommand = %q, %v; want %q", got, err, want)
	}
	if _, err := DisableCommand("./leakguard"); !errors.Is(err, ErrUnsafeCLIPath) {
		t.Errorf("relative CLI: err = %v, want ErrUnsafeCLIPath", err)
	}
}

func TestAdminCommandError(t *testing.T) {
	if err := AdminCommandError(ToolResult{Code: 0, Stderr: "warning"}); err != nil {
		t.Errorf("exit 0: err = %v", err)
	}
	if err := AdminCommandError(ToolResult{Code: 126, Stderr: "Error executing command as another user: Request dismissed\n"}); !errors.Is(err, ErrCancelled) {
		t.Errorf("dismissed: err = %v, want ErrCancelled", err)
	}
	notAuth := AdminCommandError(ToolResult{Code: 127, Stderr: "Error executing command as another user: Not authorized\n\nThis incident has been reported.\n"})
	if !errors.Is(notAuth, ipc.ErrNotAuthorized) {
		t.Errorf("not authorized: err = %v, want ipc.ErrNotAuthorized", notAuth)
	}
	if got, want := Explain(English, notAuth), "Only administrators can change leakguard"; got != want {
		t.Errorf("Explain = %q, want %q", got, want)
	}
	noAgent := AdminCommandError(ToolResult{Code: 127, Stderr: "Error executing command as another user: No authentication agent found.\n"})
	if errors.Is(noAgent, ipc.ErrNotAuthorized) || noAgent.Error() != "Error executing command as another user: No authentication agent found." {
		t.Errorf("no agent: err = %v", noAgent)
	}
	failed := AdminCommandError(ToolResult{Code: 1, Stderr: "\nleakguard: wg9 is not a VPN interface\nusage\n"})
	if failed == nil || failed.Error() != "leakguard: wg9 is not a VPN interface" {
		t.Errorf("CLI failure: err = %v", failed)
	}
	if err := AdminCommandError(ToolResult{Code: 3}); err == nil || err.Error() != "leakguard exited with status 3" {
		t.Errorf("silent failure: err = %v", err)
	}
}
