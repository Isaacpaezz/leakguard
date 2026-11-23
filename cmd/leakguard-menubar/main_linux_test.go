//go:build linux

package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/ipc"
	"github.com/Isaacpaezz/leakguard/internal/menubar"
)

// S1: runTool reports an exit code as a result, and runAdmin turns how the
// pkexec run ended into the errors the wizard and the uninstaller read.
func TestRunAdmin(t *testing.T) {
	r, err := runTool("/bin/false")
	if err != nil || r.Code != 1 {
		t.Errorf("runTool(/bin/false) = %+v, %v; want code 1, nil", r, err)
	}
	r, err = runTool("/bin/sh", "-c", "echo out; echo err >&2; exit 3")
	if err != nil || r != (menubar.ToolResult{Stdout: "out\n", Stderr: "err\n", Code: 3}) {
		t.Errorf("runTool(sh) = %+v, %v", r, err)
	}
	if _, err := runTool("/nonexistent/leakguard-tool"); err == nil {
		t.Error("runTool of a missing program: no error")
	}

	sh := func(script string) []string { return []string{"/bin/sh", "-c", script} }
	if err := runAdmin(sh("exit 0")); err != nil {
		t.Errorf("exit 0: %v", err)
	}
	if err := runAdmin(sh("exit 126")); !errors.Is(err, menubar.ErrCancelled) {
		t.Errorf("exit 126: err = %v, want ErrCancelled", err)
	}
	if err := runAdmin(sh("echo 'Error executing command as another user: Not authorized' >&2; exit 127")); !errors.Is(err, ipc.ErrNotAuthorized) {
		t.Errorf("exit 127: err = %v, want ErrNotAuthorized", err)
	}
	if err := runAdmin(sh("echo 'leakguard: no such VPN' >&2; exit 1")); err == nil || err.Error() != "leakguard: no such VPN" {
		t.Errorf("exit 1: err = %v", err)
	}
	if err := runAdmin([]string{"/bin/false"}); err == nil || err.Error() != "leakguard exited with status 1" {
		t.Errorf("/bin/false: err = %v", err)
	}
	for _, argv := range [][]string{nil, {}} {
		if err := runAdmin(argv); err == nil {
			t.Errorf("runAdmin(%q): no error", argv)
		}
	}
}

// S1: the Linux tray reads the Linux wording in the session's language.
func TestLanguageReadsLinuxWording(t *testing.T) {
	for _, key := range []string{"LANGUAGE", "LC_ALL", "LC_MESSAGES"} {
		t.Setenv(key, "")
	}
	tests := []struct{ lang, want string }{
		{"es_VE.UTF-8", "Abre este menú cada vez que inicias sesión; no pide contraseña"},
		{"en_US.UTF-8", "Opens this menu every time you log in; no password needed"},
	}
	for _, tc := range tests {
		t.Setenv("LANG", tc.lang)
		got := language().Text(menubar.MsgMenuOpenAtLoginTip)
		if got != tc.want {
			t.Errorf("LANG=%s: tip = %q, want %q", tc.lang, got, tc.want)
		}
		if strings.Contains(got, "Mac") {
			t.Errorf("LANG=%s: tip names the Mac: %q", tc.lang, got)
		}
	}
}
