package menubar

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type uninstallRun struct {
	dialogs           *fakeDialogs
	disabled, cleaned int
	err               error
}

func runUninstall(t *testing.T, l Lang, loginItem bool, disableErr, cleanupErr error, answers ...answer) uninstallRun {
	t.Helper()
	f := &fakeDialogs{t: t, answers: answers}
	r := uninstallRun{dialogs: f}
	u := Uninstaller{
		Lang:      l,
		Dialogs:   f,
		Disable:   func() error { r.disabled++; return disableErr },
		Cleanup:   func() error { r.cleaned++; return cleanupErr },
		LoginItem: func() bool { return loginItem },
	}
	r.err = u.Run()
	if len(f.answers) != 0 {
		t.Errorf("%d scripted answers left; shown:\n%s", len(f.answers), strings.Join(f.order, "\n"))
	}
	return r
}

const (
	uninstallAskES = "ask: Desinstalar leakguard|¿Quieres desinstalar leakguard?\n\nSe quitarán las reglas de protección, el servicio de fondo y la apertura al iniciar sesión. Los servicios que protegías volverán a usar tu conexión normal.\n\nLa app se queda en Aplicaciones: después puedes arrastrarla a la Papelera. Tu Mac te va a pedir tu contraseña.|Cancelar,Desinstalar"
	uninstallAskEN = "ask: Uninstall leakguard|Do you want to uninstall leakguard?\n\nThis removes the protection rules, the background service and the login item. The services you protected will use your normal connection again.\n\nThe app stays in Applications: afterwards you can drag it to the Trash. Your Mac will ask for your password.|Cancel,Uninstall"
)

// S5, S6: confirm, password, clean up, say it is done; cancel and failures
// change nothing and say so.
func TestUninstall(t *testing.T) {
	failed := errors.New("pfctl: device busy")
	tests := []struct {
		name              string
		lang              Lang
		disableErr        error
		cleanupErr        error
		answers           []answer
		wantErr           error
		noLoginItem       bool
		disabled, cleaned int
		dialogs           []string
		wantMessage       string
	}{
		{
			name:     "confirmed",
			lang:     Spanish,
			answers:  []answer{click(1), click(0)},
			disabled: 1, cleaned: 1,
			dialogs: []string{uninstallAskES, "ask: leakguard|leakguard se desinstaló. Puedes arrastrar la app a la Papelera.|Aceptar"},
		},
		{
			name:     "confirmed in English",
			lang:     English,
			answers:  []answer{click(1), click(0)},
			disabled: 1, cleaned: 1,
			dialogs: []string{uninstallAskEN, "ask: leakguard|leakguard was uninstalled. You can drag the app to the Trash.|OK"},
		},
		{
			name:    "cancel button",
			lang:    Spanish,
			answers: []answer{click(0), click(0)},
			wantErr: ErrCancelled,
			dialogs: []string{uninstallAskES, "ask: leakguard|No se desinstaló nada: leakguard sigue igual que antes.|Aceptar"},
		},
		{
			name:    "escape on the first dialog",
			lang:    Spanish,
			answers: []answer{cancelAsk(), click(0)},
			wantErr: ErrCancelled,
			dialogs: []string{uninstallAskES, "ask: leakguard|No se desinstaló nada: leakguard sigue igual que antes.|Aceptar"},
		},
		{
			name:       "password cancelled",
			lang:       English,
			disableErr: ErrCancelled,
			answers:    []answer{click(1), click(0)},
			wantErr:    ErrCancelled,
			disabled:   1,
			dialogs:    []string{uninstallAskEN, "ask: leakguard|Nothing was uninstalled: leakguard keeps working as before.|OK"},
		},
		{
			name:        "disable failed",
			lang:        Spanish,
			disableErr:  failed,
			answers:     []answer{click(1), click(0)},
			wantErr:     failed,
			disabled:    1,
			dialogs:     []string{uninstallAskES, "ask: leakguard|No se pudo desinstalar leakguard: pfctl: device busy\n\nLa app sigue abriéndose al iniciar sesión. Puedes intentarlo de nuevo desde el menú.|Aceptar"},
			wantMessage: "No se pudo desinstalar leakguard: pfctl: device busy\n\nLa app sigue abriéndose al iniciar sesión. Puedes intentarlo de nuevo desde el menú.",
		},
		{
			name:        "disable failed, no login item",
			lang:        Spanish,
			disableErr:  failed,
			noLoginItem: true,
			answers:     []answer{click(1), click(0)},
			wantErr:     failed,
			disabled:    1,
			dialogs:     []string{uninstallAskES, "ask: leakguard|No se pudo desinstalar leakguard: pfctl: device busy\n\nPuedes intentarlo de nuevo desde el menú.|Aceptar"},
			wantMessage: "No se pudo desinstalar leakguard: pfctl: device busy\n\nPuedes intentarlo de nuevo desde el menú.",
		},
		{
			name:        "disable failed, no login item, English",
			lang:        English,
			disableErr:  failed,
			noLoginItem: true,
			answers:     []answer{click(1), click(0)},
			wantErr:     failed,
			disabled:    1,
			dialogs:     []string{uninstallAskEN, "ask: leakguard|Could not uninstall leakguard: pfctl: device busy\n\nYou can try again from the menu.|OK"},
			wantMessage: "Could not uninstall leakguard: pfctl: device busy\n\nYou can try again from the menu.",
		},
		{
			name:        "disable failed with a login item, English",
			lang:        English,
			disableErr:  failed,
			answers:     []answer{click(1), click(0)},
			wantErr:     failed,
			disabled:    1,
			dialogs:     []string{uninstallAskEN, "ask: leakguard|Could not uninstall leakguard: pfctl: device busy\n\nThe app still opens at login. You can try again from the menu.|OK"},
			wantMessage: "Could not uninstall leakguard: pfctl: device busy\n\nThe app still opens at login. You can try again from the menu.",
		},
		{
			name:        "quarantined CLI",
			lang:        Spanish,
			disableErr:  QuarantineError(errors.New("xattr: [Errno 1] Operation not permitted")),
			answers:     []answer{click(1), click(0)},
			wantErr:     ErrQuarantined,
			disabled:    1,
			dialogs:     []string{uninstallAskES, "ask: leakguard|No se pudo desinstalar leakguard: " + Spanish.Text(msgErrQuarantined) + "\n\nLa app sigue abriéndose al iniciar sesión. Puedes intentarlo de nuevo desde el menú.|Aceptar"},
			wantMessage: "No se pudo desinstalar leakguard: " + Spanish.Text(msgErrQuarantined) + "\n\nLa app sigue abriéndose al iniciar sesión. Puedes intentarlo de nuevo desde el menú.",
		},
		{
			name:       "cleanup failed after disable",
			lang:       English,
			cleanupErr: errors.New("permission denied"),
			answers:    []answer{click(1), click(0)},
			disabled:   1, cleaned: 1,
			dialogs: []string{uninstallAskEN, "ask: leakguard|leakguard was uninstalled, but the login item could not be removed: permission denied\n\nYou can drag the app to the Trash.|OK"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := runUninstall(t, tc.lang, !tc.noLoginItem, tc.disableErr, tc.cleanupErr, tc.answers...)
			if (tc.wantErr == nil) != (r.err == nil) || (tc.wantErr != nil && !errors.Is(r.err, tc.wantErr)) {
				t.Errorf("Run() = %v, want %v", r.err, tc.wantErr)
			}
			if r.disabled != tc.disabled || r.cleaned != tc.cleaned {
				t.Errorf("disable ran %d times, cleanup %d; want %d, %d", r.disabled, r.cleaned, tc.disabled, tc.cleaned)
			}
			if got := r.dialogs.all(); !reflect.DeepEqual(got, tc.dialogs) {
				t.Errorf("dialogs:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(tc.dialogs, "\n"))
			}
			if got := WizardMessage(tc.lang, r.err); got != tc.wantMessage {
				t.Errorf("WizardMessage = %q, want %q", got, tc.wantMessage)
			}
			if len(r.dialogs.asks) > 0 {
				first := r.dialogs.asks[0]
				if first.Default != 0 || first.Cancel != 0 {
					t.Errorf("confirm dialog default %d cancel %d; want Cancelar for both", first.Default, first.Cancel)
				}
			}
		})
	}
}

// A dialog that fails before the password changes nothing.
func TestUninstallDialogFails(t *testing.T) {
	broken := errors.New("osascript failed")
	r := runUninstall(t, Spanish, true, nil, nil, answer{err: broken}, click(0))
	if !errors.Is(r.err, broken) || r.disabled != 0 || r.cleaned != 0 {
		t.Errorf("Run() = %v, disabled %d, cleaned %d; want the dialog error and nothing run", r.err, r.disabled, r.cleaned)
	}
}

// S5: the uninstall password prompt is plain and goes through the same
// quoting as the setup.
func TestDisableScript(t *testing.T) {
	got, err := DisableScript("/usr/local/libexec/leakguard/leakguard", UninstallPrompt(Spanish))
	want := `do shell script "'/usr/local/libexec/leakguard/leakguard' disable" with prompt "leakguard necesita tu contraseña para quitar la protección y el servicio de fondo." with administrator privileges`
	if err != nil || got != want {
		t.Errorf("DisableScript = %s, %v\nwant          %s", got, err, want)
	}
	if got := UninstallPrompt(English); got != "leakguard needs your password to remove the protection and the background service." {
		t.Errorf("English prompt = %q", got)
	}
	const prefix, suffix = `do shell script "`, `" with administrator privileges`
	for _, p := range trickyPaths {
		script, err := DisableScript(p, "")
		if err != nil {
			t.Fatalf("DisableScript(%q): %v", p, err)
		}
		cmd := unAppleScript(t, strings.TrimSuffix(strings.TrimPrefix(script, prefix), suffix))
		if want := ShellQuote(p) + " disable"; cmd != want {
			t.Errorf("shell command = %s, want %s", cmd, want)
		}
	}
	for _, p := range []string{"", "relative/leakguard", "/a\nb/leakguard", "/bad\xff"} {
		if s, err := DisableScript(p, ""); err == nil || s != "" || !errors.Is(err, ErrUnsafeCLIPath) {
			t.Errorf("DisableScript(%q) = %q, %v; want ErrUnsafeCLIPath", p, s, err)
		}
	}
}
