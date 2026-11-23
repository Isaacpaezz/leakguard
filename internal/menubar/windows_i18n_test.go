package menubar

import (
	"strings"
	"testing"
	"unicode/utf8"
)

var windowsLangs = []Lang{Spanish.ForOS("windows"), English.ForOS("windows")}

// notOnWindows are the messages the Windows tray never shows: the macOS
// move and quarantine messages, the zenity hint and the reasons of the
// macOS password prompt (UAC shows its own).
var notOnWindows = map[Msg]bool{
	MsgMenuMoveToApplications:  true,
	msgMoveToApplicationsFirst: true,
	msgErrQuarantined:          true,
	msgErrNoDialogTool:         true,
	msgAdminPrompt:             true,
	msgUninstallPrompt:         true,
}

// windowsForbidden are words that name a Mac or Linux thing. "Aplicaciones"
// is checked apart: Windows' own Settings page is called that in Spanish.
var windowsForbidden = []string{"Mac", "macOS", "Finder", "Applications", "Papelera", "Trash",
	"barra de menú", "menu bar", "barra superior", "top bar", "Configuración del Sistema",
	"System Settings", "Spotlight", "sudo", "apt", ".deb", ".tar.gz", "zenity"}

// S1: on Windows no message the tray shows names a Mac or Linux thing, in
// either language; every Windows variant exists in both languages with the
// placeholders of the macOS text.
func TestWindowsTextsHaveNoMacWords(t *testing.T) {
	if len(windowsMessages) == 0 {
		t.Fatal("no Windows variants")
	}
	for m, v := range windowsMessages {
		if strings.TrimSpace(v.es) == "" || strings.TrimSpace(v.en) == "" {
			t.Errorf("Windows message %d: es %q, en %q; want both", m, v.es, v.en)
		}
		mac := messages[m]
		if strings.Count(v.es, "%") != strings.Count(mac.es, "%") || strings.Count(v.en, "%") != strings.Count(mac.en, "%") {
			t.Errorf("Windows message %d: placeholders differ from macOS", m)
		}
		if notOnWindows[m] {
			t.Errorf("message %d is never shown on Windows but has a Windows variant", m)
		}
	}
	for _, l := range windowsLangs {
		for m := Msg(0); m < msgCount; m++ {
			if notOnWindows[m] {
				continue
			}
			s := l.Text(m)
			for _, w := range windowsForbidden {
				if strings.Contains(s, w) {
					t.Errorf("%v message %d says %q: %q", l, m, w, s)
				}
			}
			if strings.Contains(strings.ReplaceAll(s, "Configuración > Aplicaciones", ""), "Aplicaciones") {
				t.Errorf("%v message %d names the macOS Applications folder: %q", l, m, s)
			}
		}
	}
}

// S1: the Windows wording, read exactly where it matters.
func TestWindowsTexts(t *testing.T) {
	es, en := Spanish.ForOS("windows"), English.ForOS("windows")
	tests := []struct {
		l    Lang
		m    Msg
		args []any
		want string
	}{
		{es, msgExplainNotSetUp, nil, "leakguard no está configurado en esta computadora"},
		{en, msgExplainNotSetUp, nil, "leakguard is not set up on this computer"},
		{es, msgStep3Password, []any{"Claude"}, "Activar la protección.\n\nWindows te va a pedir permiso de administrador. Lo necesitamos una sola vez, para instalar el servicio que bloquea Claude si tu VPN se cae."},
		{en, msgStep3Password, []any{"Claude"}, "Turn on the protection.\n\nWindows will ask for administrator permission. We need it only this once, to install the background service that blocks Claude if your VPN drops."},
		{es, msgDoneShield, nil, "El escudo verde en el área de notificación de la barra de tareas significa que estás protegido."},
		{en, msgDoneShield, nil, "A green shield in the notification area of the taskbar means you are protected."},
		{es, msgUninstallDone, nil, "leakguard se desinstaló. Para quitar el programa, desinstala leakguard desde Configuración > Aplicaciones."},
		{en, msgUninstallDone, nil, "leakguard was uninstalled. To remove the program, uninstall leakguard from Settings > Apps."},
		{es, msgUninstallCleanupFailed, []any{"boom"}, "leakguard se desinstaló, pero no se pudo quitar la apertura al iniciar sesión: boom\n\nPara quitar el programa, desinstala leakguard desde Configuración > Aplicaciones."},
		{en, msgUninstallCleanupFailed, []any{"boom"}, "leakguard was uninstalled, but the login item could not be removed: boom\n\nTo remove the program, uninstall leakguard from Settings > Apps."},
		{es, msgUninstallConfirm, nil, "¿Quieres desinstalar leakguard?\n\nSe quitarán las reglas de protección, el servicio de fondo y la apertura al iniciar sesión. Los servicios que protegías volverán a usar tu conexión normal.\n\nEl programa sigue instalado: después puedes desinstalarlo desde Configuración > Aplicaciones. Windows te va a pedir permiso de administrador."},
		{en, msgUninstallConfirm, nil, "Do you want to uninstall leakguard?\n\nThis removes the protection rules, the background service and the login item. The services you protected will use your normal connection again.\n\nThe program stays installed: afterwards you can uninstall it from Settings > Apps. Windows will ask for administrator permission."},
		{es, msgCLINotRootOwned, nil, "El leakguard instalado no está protegido: solo los administradores deberían poder cambiarlo. Reinstálalo con el instalador de leakguard."},
		{en, msgCLIUpdate, nil, "To update leakguard, put the new leakguard.exe next to this app, or run the leakguard installer again"},
		{en, MsgMenuOpenAtLoginTip, nil, "Opens this menu every time you sign in to Windows; no password needed"},
		// Not overridden: the shared text reads the same on every system.
		{es, MsgMenuQuit, nil, "Salir"},
		{ParseLang("fr").ForOS("windows"), msgExplainNotSetUp, nil, "leakguard is not set up on this computer"},
	}
	for _, tc := range tests {
		if got := tc.l.Text(tc.m, tc.args...); got != tc.want {
			t.Errorf("%v message %d = %q, want %q", tc.l, tc.m, got, tc.want)
		}
	}
	if got := es.String(); got != "es+windows" {
		t.Errorf("String = %q, want es+windows", got)
	}
	if !es.IsSpanish() || en.IsSpanish() {
		t.Error("ForOS(windows) changed the language")
	}
	// Each system reads only its own wording.
	if got := Spanish.ForOS("windows").ForOS("linux").Text(msgDoneShield); got != "El escudo verde en la barra superior significa que estás protegido." {
		t.Errorf("windows then linux = %q", got)
	}
	if got := Spanish.ForOS("windows").ForOS("darwin").Text(msgDoneShield); got != "El escudo lleno en la barra de menú significa que estás protegido." {
		t.Errorf("windows then darwin = %q", got)
	}
}

// S1: the menu lines and tips fit on Windows too.
func TestWindowsMenuLinesFit(t *testing.T) {
	lines := []Msg{msgExplainNotSetUp, msgExplainNotAuthorized}
	tips := []Msg{MsgMenuOpenAtLoginTip}
	for _, l := range windowsLangs {
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
	}
}

// S1: GetUserDefaultUILanguage's primary language 0x0A is Spanish, in any
// country; anything else is English. Both read the Windows wording.
func TestWindowsLang(t *testing.T) {
	tests := []struct {
		id      uint16
		spanish bool
	}{
		{0x200A, true},  // es-VE
		{0x0C0A, true},  // es-ES (modern sort)
		{0x080A, true},  // es-MX
		{0x540A, true},  // es-US
		{0x0409, false}, // en-US
		{0x0416, false}, // pt-BR
		{0x000A, true},  // es, no country
		{0x0000, false}, // unknown
		{0x040A | 0xFC00, true},
	}
	for _, tc := range tests {
		l := WindowsLang(tc.id)
		if l.IsSpanish() != tc.spanish {
			t.Errorf("WindowsLang(%#04x) Spanish = %v, want %v", tc.id, l.IsSpanish(), tc.spanish)
		}
		if !strings.HasSuffix(l.String(), "+windows") {
			t.Errorf("WindowsLang(%#04x) = %v, want the Windows wording", tc.id, l)
		}
	}
}

// S1: a tooltip fits the 127 UTF-16 units of the Windows notification area,
// never splitting a surrogate pair, and ends with "…" when cut.
func TestFitUTF16(t *testing.T) {
	if got := FitUTF16("leakguard: Protegido", 127); got != "leakguard: Protegido" {
		t.Errorf("short = %q", got)
	}
	long := strings.Repeat("a", 200)
	got := FitUTF16(long, 127)
	if utf16Len(got) != 127 || !strings.HasSuffix(got, "…") {
		t.Errorf("long: %d units, %q", utf16Len(got), got)
	}
	// 126 ASCII units, then an emoji (2 units): the pair never splits.
	emoji := strings.Repeat("a", 125) + "😀😀"
	got = FitUTF16(emoji, 127)
	if !utf8.ValidString(got) || utf16Len(got) > 127 || strings.Contains(got, "�") {
		t.Errorf("emoji: %d units, %q", utf16Len(got), got)
	}
	if got := FitUTF16(strings.Repeat("ñ", 127), 127); got != strings.Repeat("ñ", 127) {
		t.Errorf("exactly 127 = %q", got)
	}
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n++
		if r >= 0x10000 {
			n++
		}
	}
	return n
}
