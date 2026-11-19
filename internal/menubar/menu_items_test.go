package menubar

import (
	"errors"
	"testing"
	"unicode/utf8"

	"github.com/Isaacpaezz/leakguard/internal/ipc"
)

// S3, S5: the new menu items read in both languages.
func TestNewMenuItems(t *testing.T) {
	tests := []struct {
		m      Msg
		es, en string
	}{
		{MsgMenuOpenAtLogin, "Abrir al iniciar sesión", "Open at login"},
		{MsgMenuUninstall, "Desinstalar leakguard…", "Uninstall leakguard…"},
	}
	for _, tc := range tests {
		if got := Spanish.Text(tc.m); got != tc.es {
			t.Errorf("es = %q, want %q", got, tc.es)
		}
		if got := English.Text(tc.m); got != tc.en {
			t.Errorf("en = %q, want %q", got, tc.en)
		}
	}
	for _, m := range []Msg{MsgMenuOpenAtLoginTip, MsgMenuUninstallTip} {
		for _, l := range []Lang{Spanish, English} {
			if s := l.Text(m); s == "" || utf8.RuneCountInString(s) > 2*MenuLineLength {
				t.Errorf("%v tip %q: empty or too long", l, s)
			}
		}
	}
}

// S1: the tooltip ends with the version when the app knows it.
func TestTooltipVersion(t *testing.T) {
	tests := []struct {
		name string
		st   *ipc.Status
		err  error
		l    Lang
		ver  string
		want string
	}{
		{"not set up", nil, ipc.ErrDaemonUnavailable, Spanish, "0.1.0", "leakguard: leakguard no está configurado en esta Mac · versión 0.1.0"},
		{"protected", &ipc.Status{VPNInterface: "ipsec0", Services: []string{"anthropic"}, Protected: true, VPNConnected: true}, nil, English, "0.1.0", "leakguard: Protected · VPN: ipsec0 · version 0.1.0"},
		{"other error", nil, errors.New("boom"), English, "dev", "leakguard: Could not change leakguard: boom · version dev"},
		{"no version", nil, ipc.ErrDaemonUnavailable, English, "", "leakguard: leakguard is not set up on this Mac"},
	}
	for _, tc := range tests {
		m := Build(tc.st, tc.err, Setup{Catalog: fullCatalog, Lang: tc.l, Version: tc.ver})
		if m.Tooltip != tc.want {
			t.Errorf("%s: tooltip = %q, want %q", tc.name, m.Tooltip, tc.want)
		}
	}
}
