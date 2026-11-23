package menubar

import (
	"crypto/sha256"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Isaacpaezz/leakguard/internal/ipc"
)

// macWords name things that exist only on a Mac; the Linux wording never
// uses them.
var macWords = []string{"Mac", "macOS", "Finder", "Aplicaciones", "Applications",
	"Papelera", "Trash", "barra de menú", "menu bar", "Configuración del Sistema",
	"System Settings", "Spotlight"}

// macOnly are the messages the Linux tray never shows: the move to
// Applications hint and dialog, and the quarantine error.
var macOnly = map[Msg]bool{
	MsgMenuMoveToApplications:  true,
	msgMoveToApplicationsFirst: true,
	msgErrQuarantined:          true,
}

var linuxLangs = []Lang{Spanish.ForOS("linux"), English.ForOS("linux")}

// macCatalogDigest hashes every message in es and en, unformatted.
func macCatalogDigest(es, en Lang) string {
	h := sha256.New()
	for m := Msg(0); m < msgCount; m++ {
		fmt.Fprintf(h, "%d\x00%s\x00%s\x00", m, es.Text(m), en.Text(m))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// S2: the macOS catalog is byte-identical to the one before Linux had its
// own wording, read with or without ForOS("darwin").
func TestMacCatalogUnchanged(t *testing.T) {
	const before = "72ee2940a47cd52f4634aca3e87cc7f6dba068183b078b095ce7d29b06512e55"
	if msgCount != 103 {
		t.Errorf("msgCount = %d, want 103", msgCount)
	}
	if got := macCatalogDigest(Spanish, English); got != before {
		t.Errorf("macOS catalog digest = %s, want %s", got, before)
	}
	if got := macCatalogDigest(Spanish.ForOS("darwin"), English.ForOS("darwin")); got != before {
		t.Errorf("ForOS(darwin) catalog digest = %s, want %s", got, before)
	}
	exact := []struct {
		l    Lang
		m    Msg
		want string
	}{
		{Spanish, msgExplainNotSetUp, "leakguard no está configurado en esta Mac"},
		{English, msgDoneShield, "A filled shield in the menu bar means you are protected."},
		{Spanish.ForOS("darwin"), msgUninstallDone, "leakguard se desinstaló. Puedes arrastrar la app a la Papelera."},
		{Spanish.ForOS("linux").ForOS("darwin"), MsgMenuOpenAtLoginTip, "Abre este menú cada vez que entras a tu Mac; no pide contraseña"},
	}
	for _, tc := range exact {
		if got := tc.l.Text(tc.m); got != tc.want {
			t.Errorf("%v message %d = %q, want %q", tc.l, tc.m, got, tc.want)
		}
	}
	if got := Spanish.Text(msgStep3Password, "Claude"); !strings.HasPrefix(got, "Activar la protección.\n\nTu Mac te va a pedir tu contraseña: es la misma que usas para entrar a la Mac.") {
		t.Errorf("macOS step 3 = %q", got)
	}
}

// S1: on Linux no message the tray shows names a Mac thing, in either
// language; every Linux variant exists in both languages with the
// placeholders of the macOS text.
func TestLinuxTextsHaveNoMacWords(t *testing.T) {
	if len(linuxMessages) == 0 {
		t.Fatal("no Linux variants")
	}
	for m, v := range linuxMessages {
		if strings.TrimSpace(v.es) == "" || strings.TrimSpace(v.en) == "" {
			t.Errorf("Linux message %d: es %q, en %q; want both", m, v.es, v.en)
		}
		mac := messages[m]
		if strings.Count(v.es, "%") != strings.Count(mac.es, "%") || strings.Count(v.en, "%") != strings.Count(mac.en, "%") {
			t.Errorf("Linux message %d: placeholders differ from macOS", m)
		}
		if macOnly[m] {
			t.Errorf("message %d is macOS-only but has a Linux variant", m)
		}
	}
	for _, l := range linuxLangs {
		for m := Msg(0); m < msgCount; m++ {
			if macOnly[m] {
				continue
			}
			s := l.Text(m)
			for _, w := range macWords {
				if strings.Contains(s, w) {
					t.Errorf("%v message %d says %q: %q", l, m, w, s)
				}
			}
		}
	}
}

// S1: the Linux wording, read exactly where it matters.
func TestLinuxTexts(t *testing.T) {
	es, en := Spanish.ForOS("linux"), English.ForOS("linux")
	tests := []struct {
		l    Lang
		m    Msg
		args []any
		want string
	}{
		{es, msgExplainNotSetUp, nil, "leakguard no está configurado en esta computadora"},
		{en, msgExplainNotSetUp, nil, "leakguard is not set up on this computer"},
		{es, msgStep3Password, []any{"Claude"}, "Activar la protección.\n\nTu computadora te va a pedir tu contraseña de administrador. La necesitamos una sola vez, para instalar el servicio que bloquea Claude si tu VPN se cae."},
		{en, msgStep3Password, []any{"Claude"}, "Turn on the protection.\n\nYour computer will ask for your administrator password. We need it only this once, to install the background service that blocks Claude if your VPN drops."},
		{es, msgDoneShield, nil, "El escudo verde en la barra superior significa que estás protegido."},
		{en, msgDoneShield, nil, "A green shield in the top bar means you are protected."},
		{es, msgUninstallDone, nil, "leakguard se desinstaló. Para quitar el programa, ejecuta: sudo apt remove leakguard"},
		{en, msgUninstallDone, nil, "leakguard was uninstalled. To remove the program, run: sudo apt remove leakguard"},
		// Not overridden: the shared text reads the same on both systems.
		{es, MsgMenuQuit, nil, "Salir"},
		{Lang("fr").ForOS("linux"), msgExplainNotSetUp, nil, "leakguard is not set up on this computer"},
	}
	for _, tc := range tests {
		if got := tc.l.Text(tc.m, tc.args...); got != tc.want {
			t.Errorf("%v message %d = %q, want %q", tc.l, tc.m, got, tc.want)
		}
	}
	for _, m := range []Msg{msgUninstallConfirm, msgUninstallCleanupFailed} {
		for _, l := range linuxLangs {
			if s := l.Text(m); !strings.Contains(s, "sudo apt remove leakguard") {
				t.Errorf("%v message %d = %q, want the package removal", l, m, s)
			}
		}
	}
	if got := es.list([]string{"A", "B"}); got != "A y B" {
		t.Errorf("Linux list = %q, want %q", got, "A y B")
	}
	m := Build(nil, ipc.ErrDaemonUnavailable, Setup{Catalog: fullCatalog, Lang: es})
	if want := "leakguard: leakguard no está configurado en esta computadora"; m.Tooltip != want {
		t.Errorf("Linux tooltip = %q, want %q", m.Tooltip, want)
	}
}

// S1, S2: the menu lines read in full on both systems, in both languages.
func TestMenuLinesFitOnBothSystems(t *testing.T) {
	lines := []Msg{msgStatusChecking, msgStatusNotSetUp, msgStatusUpdate, msgStatusProtected,
		msgStatusProtectedOffline, msgStatusOffline, msgStatusPaused, msgStatusNotProtected,
		msgExplainNotSetUp, msgExplainNotAuthorized, msgExplainTimeout, MsgMenuMoveToApplications}
	tips := []Msg{MsgMenuSetUpTip, MsgMenuChangeVPNTip, MsgMenuToggleTip, MsgMenuQuitTip,
		MsgMenuServiceTip, MsgMenuErrorTip, MsgMenuOpenAtLoginTip, MsgMenuUninstallTip}
	now := time.Date(2026, 11, 16, 15, 0, 0, 0, time.UTC)
	long := now.Add(-99999 * 24 * time.Hour).Format(time.RFC3339)
	stats := ipc.Stats{Connected: true, SessionSince: long, TodayBlocks: math.MaxUint64, TodayDrops: math.MaxUint32}
	for _, l := range append([]Lang{Spanish, English}, linuxLangs...) {
		for _, m := range lines {
			if s := l.Text(m); s == "" || utf8.RuneCountInString(s) > MenuLineLength {
				t.Errorf("%v line %q: empty or longer than %d runes", l, s, MenuLineLength)
			}
		}
		for _, m := range tips {
			if s := l.Text(m); s == "" || utf8.RuneCountInString(s) > 2*MenuLineLength {
				t.Errorf("%v tip %q: empty or longer than %d runes", l, s, 2*MenuLineLength)
			}
		}
		for _, s := range []string{sessionLine(l, stats, now), todayLine(l, stats)} {
			if s == "" || utf8.RuneCountInString(s) > MenuLineLength {
				t.Errorf("%v stats line %q: empty or longer than %d runes", l, s, MenuLineLength)
			}
		}
	}
}
