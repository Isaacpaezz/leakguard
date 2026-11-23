package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/daemon"
	"github.com/Isaacpaezz/leakguard/internal/version"
)

// failingSystemctl answers like systemctl, failing the commands in fail.
type failingSystemctl struct {
	calls []string
	fail  map[string]error
}

func (f *failingSystemctl) Run(args ...string) (string, error) {
	key := strings.Join(args, " ")
	f.calls = append(f.calls, key)
	return "", f.fail[key]
}

// systemdHarness is a root harness with the systemd service installed by
// an older binary and a saved, paused choice.
func systemdHarness(t *testing.T, sc daemon.Runner) (*harness, []byte) {
	t.Helper()
	h := newHarness(t, true)
	h.env.Systemctl = sc
	h.env.Services = systemdServices
	h.saveConfig(t, config.Config{VPNInterface: "ipsec0", Services: []string{"anthropic"}, Paused: true})
	for p, data := range map[string]string{daemon.BinaryPath: "old-binary", daemon.UnitPath: daemon.Unit(daemon.BinaryPath)} {
		if err := os.MkdirAll(h.path(p[:strings.LastIndex(p, "/")]), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(h.path(p), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := os.ReadFile(h.path(config.DefaultPath))
	if err != nil {
		t.Fatal(err)
	}
	return h, cfg
}

// keepsChoiceAndRules checks that the saved choice is byte for byte the
// same and that the firewall was never touched.
func keepsChoiceAndRules(t *testing.T, h *harness, cfg []byte) {
	t.Helper()
	if got, err := os.ReadFile(h.path(config.DefaultPath)); err != nil || !bytes.Equal(got, cfg) {
		t.Errorf("saved choice changed: %q, %v; want %q", got, err, cfg)
	}
	if len(h.pfctl.calls) != 0 {
		t.Errorf("the firewall was touched: %v", h.pfctl.calls)
	}
}

// S5: after a package upgrade, reinstall-service puts the new binary in
// the root-owned place and restarts the service with it, keeping the
// saved choice (even a pause) and never touching the loaded rules.
func TestReinstallServiceRestartsTheNewBinary(t *testing.T) {
	sc := &failingSystemctl{}
	h, cfg := systemdHarness(t, sc)
	code, out, errOut := h.run("reinstall-service")
	expect(t, code, out, errOut, 0, nil, nil)
	if want := "Background service updated to leakguard " + version.String() + "; your saved choice is kept.\n"; out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
	if got, err := os.ReadFile(h.path(daemon.BinaryPath)); err != nil || string(got) != "leakguard-binary" {
		t.Errorf("service binary = %q, %v; want the new binary", got, err)
	}
	if got, err := os.ReadFile(h.path(daemon.UnitPath)); err != nil || string(got) != daemon.Unit(daemon.BinaryPath) {
		t.Errorf("unit = %q, %v", got, err)
	}
	want := "daemon-reload|enable leakguard.service|restart leakguard.service"
	if got := strings.Join(sc.calls, "|"); got != want {
		t.Errorf("systemctl calls = %q, want %q", got, want)
	}
	keepsChoiceAndRules(t, h, cfg)
}

// Without the service installed there is nothing to update: nothing is
// written and systemd is not asked.
func TestReinstallServiceWithoutTheServiceDoesNothing(t *testing.T) {
	sc := &failingSystemctl{}
	h := newHarness(t, true)
	h.env.Systemctl = sc
	h.env.Services = systemdServices
	code, out, errOut := h.run("reinstall-service")
	expect(t, code, out, errOut, 0, nil, nil)
	if want := "The background service is not installed; nothing to update.\n"; out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
	if len(sc.calls) != 0 || exists(h.path(daemon.BinaryPath)) || exists(h.path(daemon.UnitPath)) || exists(h.path(config.DefaultPath)) {
		t.Errorf("something changed: systemctl %v", sc.calls)
	}
}

func TestReinstallServiceNeedsRoot(t *testing.T) {
	h := newHarness(t, false)
	h.env.Services = systemdServices
	code, out, errOut := h.run("reinstall-service")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: run with sudo: sudo leakguard reinstall-service\n"})
	if out != "" {
		t.Errorf("stdout = %q, want empty", out)
	}
}

func TestReinstallServiceTakesNoArguments(t *testing.T) {
	h := newHarness(t, true)
	code, out, errOut := h.run("reinstall-service", "anthropic")
	expect(t, code, out, errOut, 2, nil, []string{"leakguard: reinstall-service takes no arguments\n"})
}

// A failed restart is reported with exit 1; the choice and the rules stay.
func TestReinstallServiceReportsAFailedRestart(t *testing.T) {
	sc := &failingSystemctl{fail: map[string]error{"restart leakguard.service": errors.New("systemctl restart leakguard.service: exit status 1: boom")}}
	h, cfg := systemdHarness(t, sc)
	code, out, errOut := h.run("reinstall-service")
	expect(t, code, out, errOut, 1, nil, []string{"leakguard: could not update the background service: the background service is not started: systemctl restart leakguard.service: exit status 1: boom\n"})
	if out != "" {
		t.Errorf("stdout = %q, want empty", out)
	}
	keepsChoiceAndRules(t, h, cfg)
}

// Systems without a backend fail closed before anything changes.
func TestReinstallServiceUnsupported(t *testing.T) {
	h := newHarness(t, true)
	h.env.Services = nil
	code, _, errOut := h.run("reinstall-service")
	expect(t, code, "", errOut, 1, nil, []string{"cannot protect services on this computer"})
}

// The command is internal (the .deb runs it): no help text names it.
func TestReinstallServiceIsNotInTheHelp(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		if strings.Contains(usageFor(goos), "reinstall-service") {
			t.Errorf("%s help names reinstall-service", goos)
		}
	}
}
