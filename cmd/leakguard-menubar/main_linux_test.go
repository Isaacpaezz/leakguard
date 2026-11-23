//go:build linux

package main

import (
	"strings"
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/menubar"
)

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
