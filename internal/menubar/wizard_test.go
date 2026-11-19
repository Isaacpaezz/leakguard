package menubar

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/ipc"
)

// answer is the scripted reaction to one dialog: a button for Ask, the picked
// items for Choose, or an error (ErrCancelled when the user cancels).
type answer struct {
	choose bool
	button int
	picks  []int
	err    error
}

func click(i int) answer      { return answer{button: i} }
func pick(i ...int) answer    { return answer{choose: true, picks: i} }
func cancelAsk() answer       { return answer{err: ErrCancelled} }
func cancelChoose() answer    { return answer{choose: true, err: ErrCancelled} }
func shown(d Dialog) string   { return d.Title + "|" + d.Text + "|" + strings.Join(d.Buttons, ",") }
func listed(l List) string    { return l.Title + "|" + l.Text + "|" + strings.Join(l.Items, ",") }
func (f *fakeDialogs) n() int { return len(f.asks) + len(f.lists) }
func (f *fakeDialogs) all() []string {
	return f.order
}

// fakeDialogs plays the answers in order and records what was shown.
type fakeDialogs struct {
	t       *testing.T
	answers []answer
	asks    []Dialog
	lists   []List
	order   []string
}

func (f *fakeDialogs) next(choose bool) answer {
	f.t.Helper()
	if len(f.answers) == 0 {
		f.t.Fatalf("unexpected dialog #%d (no scripted answer left); shown so far:\n%s", f.n(), strings.Join(f.order, "\n"))
	}
	a := f.answers[0]
	f.answers = f.answers[1:]
	if a.choose != choose {
		f.t.Fatalf("dialog #%d: got a list=%v, scripted list=%v; shown so far:\n%s", f.n(), choose, a.choose, strings.Join(f.order, "\n"))
	}
	return a
}

func (f *fakeDialogs) Ask(d Dialog) (int, error) {
	f.t.Helper()
	f.asks = append(f.asks, d)
	f.order = append(f.order, "ask: "+shown(d))
	a := f.next(false)
	return a.button, a.err
}

func (f *fakeDialogs) Choose(l List) ([]int, error) {
	f.t.Helper()
	f.lists = append(f.lists, l)
	f.order = append(f.order, "list: "+listed(l))
	a := f.next(true)
	return a.picks, a.err
}

// snapshots returns the scripted interface snapshots in order.
func snapshots(t *testing.T, snaps ...[]string) func() []string {
	return func() []string {
		t.Helper()
		if len(snaps) == 0 {
			t.Fatal("unexpected interface snapshot")
		}
		s := snaps[0]
		snaps = snaps[1:]
		return s
	}
}

type wizardRun struct {
	dialogs   *fakeDialogs
	activated []Draft
	err       error
}

func runWizard(t *testing.T, l Lang, password bool, activateErr error, snaps [][]string, answers ...answer) wizardRun {
	t.Helper()
	f := &fakeDialogs{t: t, answers: answers}
	var r wizardRun
	w := Wizard{Lang: l, Dialogs: f, Catalog: fullCatalog, ConnectedVPNs: snapshots(t, snaps...), NeedsPassword: password}
	r.err = w.Run(func(d Draft) error {
		r.activated = append(r.activated, d)
		return activateErr
	})
	r.dialogs = f
	if len(f.answers) != 0 {
		t.Errorf("%d scripted answers left; shown:\n%s", len(f.answers), strings.Join(f.order, "\n"))
	}
	return r
}

// S1-S3: one service, the VPN found by disconnecting and reconnecting it.
func TestWizardHappyPathOneService(t *testing.T) {
	r := runWizard(t, Spanish, true, nil,
		[][]string{{}, {"ipsec0"}},
		pick(0), click(1), click(1), click(2), click(1), click(0))
	if r.err != nil {
		t.Fatalf("Run() = %v", r.err)
	}
	if want := []Draft{{VPNInterface: "ipsec0", Services: []string{"anthropic"}}}; !reflect.DeepEqual(r.activated, want) {
		t.Fatalf("activated %+v, want %+v", r.activated, want)
	}
	want := []string{
		"list: Paso 1 de 3|Elige qué quieres proteger.\n\nEstos servicios solo podrán usar tu VPN: si tu VPN se cae, dejan de conectarse hasta que vuelva.\n\nPróximamente: OpenAI.|Anthropic (Claude),Mistral",
		"ask: Paso 2 de 3|Ahora vamos a encontrar tu VPN.\n\nDesconecta tu VPN y toca Siguiente.|Cancelar,Siguiente",
		"ask: Paso 2 de 3|Ahora conéctala y toca Siguiente.|Cancelar,Siguiente",
		"ask: Paso 2 de 3|¡Encontramos tu VPN!\n\nLa que conectaste aparece como: VPN IPsec.\n\nSi no es la tuya, toca Elegir otra.|Cancelar,Elegir otra,Siguiente",
		"ask: Paso 3 de 3|Activar la protección.\n\nTu Mac te va a pedir tu contraseña: es la misma que usas para entrar a la Mac. La necesitamos una sola vez, para instalar el servicio que bloquea Anthropic (Claude) si tu VPN se cae.|Cancelar,Activar",
		"ask: leakguard|Listo: Anthropic (Claude) está protegido. Si tu VPN se cae, Anthropic (Claude) deja de conectarse hasta que vuelva.\n\nEl escudo lleno en la barra de menú significa que estás protegido.|Aceptar",
	}
	if got := r.dialogs.all(); !reflect.DeepEqual(got, want) {
		t.Errorf("dialogs:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	l := r.dialogs.lists[0]
	if !l.Multiple || l.OK != "Siguiente" || l.Cancel != "Cancelar" {
		t.Errorf("step 1 list = %+v, want multiple selections with Siguiente/Cancelar", l)
	}
	for _, d := range r.dialogs.asks {
		if d.Cancel != 0 && d.Title != "leakguard" {
			t.Errorf("%q: cancel button %d, want 0", d.Title, d.Cancel)
		}
		if d.Default != len(d.Buttons)-1 {
			t.Errorf("%q: default button %d, want the last one", d.Title, d.Default)
		}
	}
	// S1: no interface name in normal use.
	for _, s := range r.dialogs.all() {
		if strings.Contains(s, "ipsec") || strings.Contains(s, "utun") {
			t.Errorf("interface name shown: %q", s)
		}
	}
}

func TestWizardSeveralServicesInEnglish(t *testing.T) {
	r := runWizard(t, English, true, nil,
		[][]string{{"utun3"}, {"utun3", "ipsec0"}},
		pick(1, 0), click(1), click(1), click(2), click(1), click(0))
	if r.err != nil {
		t.Fatalf("Run() = %v", r.err)
	}
	if want := []Draft{{VPNInterface: "ipsec0", Services: []string{"anthropic", "mistral"}}}; !reflect.DeepEqual(r.activated, want) {
		t.Fatalf("activated %+v, want %+v (catalog order)", r.activated, want)
	}
	asks := r.dialogs.asks
	if got, want := asks[3].Text, "Turn on the protection.\n\nYour Mac will ask for your password: the same one you use to log in to your Mac. We need it only this once, to install the background service that blocks Anthropic (Claude) and Mistral if your VPN drops."; got != want {
		t.Errorf("step 3 = %q\nwant      %q", got, want)
	}
	if got, want := asks[3].Title, "Step 3 of 3"; got != want {
		t.Errorf("step 3 title = %q, want %q", got, want)
	}
	if got, want := asks[4].Text, "Done: Anthropic (Claude) and Mistral are protected. If your VPN drops, they stop connecting until it is back.\n\nA filled shield in the menu bar means you are protected."; got != want {
		t.Errorf("done = %q\nwant  %q", got, want)
	}
	if got, want := shown(asks[2]), "Step 2 of 3|We found your VPN!\n\nThe one you connected shows up as: IPsec VPN.\n\nIf it is not yours, click Choose another.|Cancel,Choose another,Next"; got != want {
		t.Errorf("found = %q\nwant    %q", got, want)
	}
	if got := r.dialogs.lists[0].Text; !strings.HasSuffix(got, "\n\nComing soon: OpenAI.") {
		t.Errorf("step 1 text = %q, want the coming-soon line", got)
	}
}

// S3: when the background service already runs, no password is asked.
func TestWizardWithoutPassword(t *testing.T) {
	for _, tc := range []struct {
		l    Lang
		want string
	}{
		{Spanish, "Activar la protección.\n\nVamos a proteger Mistral con tu VPN. No hace falta tu contraseña: el servicio de leakguard ya está instalado."},
		{English, "Turn on the protection.\n\nWe will protect Mistral with your VPN. No password needed: the leakguard background service is already installed."},
	} {
		r := runWizard(t, tc.l, false, nil,
			[][]string{{}, {"wg0"}},
			pick(1), click(1), click(1), click(2), click(1), click(0))
		if r.err != nil || len(r.activated) != 1 || r.activated[0].VPNInterface != "wg0" {
			t.Fatalf("%s: Run() = %v, activated %+v", tc.l, r.err, r.activated)
		}
		if got := r.dialogs.asks[3].Text; got != tc.want {
			t.Errorf("%s: step 3 = %q\nwant %q", tc.l, got, tc.want)
		}
	}
}

// S6: cancelling at any step changes nothing and sends nothing.
func TestWizardCancelAtEachStep(t *testing.T) {
	found := [][]string{{}, {"ipsec0"}}
	none := [][]string{{"ipsec0"}, {"ipsec0"}, {"ipsec0"}}
	several := [][]string{{}, {"ipsec0", "utun4"}}
	tests := []struct {
		name    string
		snaps   [][]string
		answers []answer
		dialogs int
	}{
		{"step 1 list", nil, []answer{cancelChoose()}, 1},
		{"step 1 with nothing picked", nil, []answer{pick()}, 1},
		{"disconnect", nil, []answer{pick(0), cancelAsk()}, 2},
		{"connect", found[:1], []answer{pick(0), click(1), cancelAsk()}, 3},
		{"found", found, []answer{pick(0), click(1), click(1), cancelAsk()}, 4},
		{"found, cancel button", found, []answer{pick(0), click(1), click(1), click(0)}, 4},
		{"list after choose another", found, []answer{pick(0), click(1), click(1), click(1), cancelChoose()}, 5},
		{"step 3", found, []answer{pick(0), click(1), click(1), click(2), cancelAsk()}, 5},
		{"step 3, cancel button", found, []answer{pick(0), click(1), click(1), click(2), click(0)}, 5},
		{"no new VPN", none[:2], []answer{pick(0), click(1), click(1), click(0)}, 4},
		{"list after no new VPN", none, []answer{pick(0), click(1), click(1), click(1), cancelChoose()}, 5},
		{"list of several new VPNs", several, []answer{pick(0), click(1), click(1), cancelChoose()}, 4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := runWizard(t, Spanish, true, nil, tc.snaps, tc.answers...)
			if !errors.Is(r.err, ErrCancelled) {
				t.Errorf("Run() = %v, want ErrCancelled", r.err)
			}
			if len(r.activated) != 0 {
				t.Errorf("activated %+v after a cancel, want nothing sent", r.activated)
			}
			if got := r.dialogs.n(); got != tc.dialogs {
				t.Errorf("%d dialogs shown, want %d (none after the cancel)", got, tc.dialogs)
			}
		})
	}
}

// S3, S6: cancelling the administrator prompt shows nothing more; a failure
// is explained in the user's language.
func TestWizardActivateFails(t *testing.T) {
	r := runWizard(t, Spanish, true, ErrCancelled, [][]string{{}, {"ipsec0"}},
		pick(0), click(1), click(1), click(2), click(1))
	if !errors.Is(r.err, ErrCancelled) || len(r.activated) != 1 {
		t.Errorf("admin prompt cancelled: Run() = %v, activated %d", r.err, len(r.activated))
	}
	if got := WizardMessage(Spanish, r.err); got != "" {
		t.Errorf("WizardMessage(cancel) = %q, want nothing", got)
	}
	tests := []struct {
		l    Lang
		err  error
		want string
	}{
		{Spanish, errors.New("Set up failed: boom"), "leakguard|No se pudo activar la protección: Set up failed: boom\n\nPuedes intentarlo de nuevo desde el menú.|Aceptar"},
		{English, ErrNoCLI, "leakguard|Could not turn on the protection: Put the leakguard command next to this app, then try again\n\nYou can try again from the menu.|OK"},
		{Spanish, ipc.ErrNotAuthorized, "leakguard|No se pudo activar la protección: Solo un administrador de la Mac puede cambiar leakguard\n\nPuedes intentarlo de nuevo desde el menú.|Aceptar"},
	}
	for _, tc := range tests {
		r = runWizard(t, tc.l, true, tc.err, [][]string{{}, {"ipsec0"}},
			pick(0), click(1), click(1), click(2), click(1), click(0))
		if !errors.Is(r.err, tc.err) {
			t.Errorf("Run() = %v, want %v", r.err, tc.err)
		}
		last := r.dialogs.asks[len(r.dialogs.asks)-1]
		if shown(last) != tc.want {
			t.Errorf("error dialog = %q\nwant           %q", shown(last), tc.want)
		}
		if got, want := WizardMessage(tc.l, r.err), strings.Split(tc.want, "|")[1]; got != want {
			t.Errorf("WizardMessage = %q, want %q", got, want)
		}
	}
}

// R3-001: a failing dialog or an unexpected answer is never silent: the
// wizard says so in a dialog, and WizardMessage gives the menu its line.
func TestWizardShowsErrors(t *testing.T) {
	broken := errors.New("osascript broke")
	_, odd := ParseButton("Otro\n", Dialog{Buttons: []string{"Cancelar", "Siguiente"}})
	tests := []struct {
		name    string
		l       Lang
		snaps   [][]string
		answers []answer
		err     error
		want    string
	}{
		{
			name:    "step 1 list fails",
			l:       Spanish,
			answers: []answer{{choose: true, err: broken}, click(0)},
			err:     broken,
			want:    "leakguard|Algo salió mal: osascript broke\n\nPuedes intentarlo de nuevo desde el menú.|Aceptar",
		},
		{
			name:    "unexpected answer in step 2",
			l:       Spanish,
			answers: []answer{pick(0), {err: odd}, click(0)},
			err:     odd,
			want:    "leakguard|Algo salió mal: La ventana respondió algo inesperado\n\nPuedes intentarlo de nuevo desde el menú.|Aceptar",
		},
		{
			name:    "unexpected answer in English",
			l:       English,
			snaps:   [][]string{{}},
			answers: []answer{pick(0), click(1), {err: odd}, click(0)},
			err:     odd,
			want:    "leakguard|Something went wrong: The dialog gave an unexpected answer\n\nYou can try again from the menu.|OK",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := runWizard(t, tc.l, true, nil, tc.snaps, tc.answers...)
			if !errors.Is(r.err, tc.err) || len(r.activated) != 0 {
				t.Fatalf("Run() = %v, activated %+v; want %v and nothing sent", r.err, r.activated, tc.err)
			}
			if len(r.dialogs.asks) == 0 {
				t.Fatalf("no error dialog shown, want %q", tc.want)
			}
			last := r.dialogs.asks[len(r.dialogs.asks)-1]
			if shown(last) != tc.want {
				t.Errorf("error dialog = %q\nwant           %q", shown(last), tc.want)
			}
			if got, want := WizardMessage(tc.l, r.err), strings.Split(tc.want, "|")[1]; got != want {
				t.Errorf("WizardMessage = %q, want %q", got, want)
			}
		})
	}
}

// R3-001: the message for the menu and the dialog; a cancel says nothing.
func TestWizardMessage(t *testing.T) {
	tests := []struct {
		l    Lang
		err  error
		want string
	}{
		{Spanish, nil, ""},
		{Spanish, ErrCancelled, ""},
		{English, fmt.Errorf("admin prompt: %w", ErrCancelled), ""},
		{Spanish, errors.New("osascript broke\nmore"), "Algo salió mal: osascript broke\n\nPuedes intentarlo de nuevo desde el menú."},
		{English, errors.New("osascript broke"), "Something went wrong: osascript broke\n\nYou can try again from the menu."},
		{Spanish, fmt.Errorf("read: %w", os.ErrDeadlineExceeded), "Algo salió mal: El servicio de leakguard no respondió; inténtalo de nuevo\n\nPuedes intentarlo de nuevo desde el menú."},
		{English, ipc.ErrNotAuthorized, "Something went wrong: Only administrators can change leakguard\n\nYou can try again from the menu."},
	}
	for _, tc := range tests {
		if got := WizardMessage(tc.l, tc.err); got != tc.want {
			t.Errorf("WizardMessage(%s, %v) = %q, want %q", tc.l, tc.err, got, tc.want)
		}
	}
}

// S1, S6: the found VPN is named by its kind only, and the user may still
// choose another one from the list of connected VPNs.
func TestWizardFoundChooseAnother(t *testing.T) {
	r := runWizard(t, Spanish, true, nil, [][]string{{"utun4"}, {"utun4", "ipsec0"}},
		pick(0), click(1), click(1), click(1), pick(0), click(1), click(0))
	if r.err != nil {
		t.Fatalf("Run() = %v", r.err)
	}
	if want := []Draft{{VPNInterface: "utun4", Services: []string{"anthropic"}}}; !reflect.DeepEqual(r.activated, want) {
		t.Fatalf("activated %+v, want %+v", r.activated, want)
	}
	if got, want := listed(r.dialogs.lists[1]), "Paso 2 de 3|¿Cuál es tu VPN? Elige la que conectaste.|VPN (utun4),VPN IPsec (ipsec0)"; got != want {
		t.Errorf("list = %q, want %q", got, want)
	}
	if r.dialogs.lists[1].Multiple {
		t.Errorf("the VPN list allows several choices")
	}
}

// S2, S6: detection never guesses.
func TestWizardDetection(t *testing.T) {
	tests := []struct {
		name    string
		snaps   [][]string
		answers []answer
		want    string
		lists   []string
	}{
		{
			name:    "none, retry, found",
			snaps:   [][]string{{"ipsec0"}, {"ipsec0"}, {}, {"ipsec0"}},
			answers: []answer{click(2), click(1), click(1), click(2)},
			want:    "ipsec0",
		},
		{
			name:    "none, choose from the list of connected VPNs",
			snaps:   [][]string{{"utun4", "ipsec0"}, {"utun4", "ipsec0"}, {"utun4", "ipsec0"}},
			answers: []answer{click(1), pick(1)},
			want:    "ipsec0",
			lists:   []string{"Paso 2 de 3|¿Cuál es tu VPN? Elige la que conectaste.|VPN (utun4),VPN IPsec (ipsec0)"},
		},
		{
			name:    "none, list empty, retry, found",
			snaps:   [][]string{{}, {}, {}, {}, {"utun4"}},
			answers: []answer{click(1), click(1), click(1), click(1), click(2)},
			want:    "utun4",
		},
		{
			name:    "several new VPNs go to the list",
			snaps:   [][]string{{"utun3"}, {"utun3", "utun4", "ipsec0", "utun5"}},
			answers: []answer{pick(0)},
			want:    "utun4",
			lists:   []string{"Paso 2 de 3|¿Cuál es tu VPN? Elige la que conectaste.|VPN 1 (utun4),VPN IPsec (ipsec0),VPN 2 (utun5)"},
		},
		{
			name:    "real connections and unsafe names are never VPNs",
			snaps:   [][]string{{}, {"en0", "utun4; id", "lo0"}, {}, {"utun4", "utun4"}},
			answers: []answer{click(2), click(1), click(1), click(2)},
			want:    "utun4",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			answers := append([]answer{pick(0), click(1), click(1)}, tc.answers...)
			answers = append(answers, click(1), click(0))
			r := runWizard(t, Spanish, true, nil, tc.snaps, answers...)
			if r.err != nil {
				t.Fatalf("Run() = %v", r.err)
			}
			if len(r.activated) != 1 || r.activated[0].VPNInterface != tc.want {
				t.Fatalf("activated %+v, want VPN %s", r.activated, tc.want)
			}
			var lists []string
			for _, l := range r.dialogs.lists[1:] {
				if l.Multiple {
					t.Errorf("the VPN list allows several choices")
				}
				lists = append(lists, listed(l))
			}
			if !reflect.DeepEqual(lists, tc.lists) {
				t.Errorf("VPN lists = %q, want %q", lists, tc.lists)
			}
			if strings.Contains(tc.name, "none") && !slices.ContainsFunc(r.dialogs.asks, func(d Dialog) bool {
				return strings.HasPrefix(d.Text, "No vimos aparecer una VPN nueva.") && reflect.DeepEqual(d.Buttons, []string{"Cancelar", "Elegir de una lista", "Reintentar"})
			}) {
				t.Errorf("no \"No vimos aparecer\" dialog with Cancelar/Elegir de una lista/Reintentar:\n%s", strings.Join(r.dialogs.all(), "\n"))
			}
		})
	}
}

// S1: friendly kinds, numbered when repeated, the technical name only here.
func TestVPNLabels(t *testing.T) {
	names := []string{"utun4", "utun5", "ipsec0", "wg0", "ppp0", "tun0", "tap1"}
	if got, want := VPNLabels(Spanish, names), []string{"VPN 1 (utun4)", "VPN 2 (utun5)", "VPN IPsec (ipsec0)", "WireGuard (wg0)", "VPN PPP (ppp0)", "VPN 3 (tun0)", "VPN 4 (tap1)"}; !reflect.DeepEqual(got, want) {
		t.Errorf("es labels = %q\nwant %q", got, want)
	}
	if got, want := VPNLabels(English, []string{"ipsec0", "ipsec1", "ppp0"}), []string{"IPsec VPN 1 (ipsec0)", "IPsec VPN 2 (ipsec1)", "PPP VPN (ppp0)"}; !reflect.DeepEqual(got, want) {
		t.Errorf("en labels = %q, want %q", got, want)
	}
}

// S5: "Change VPN" runs step 2 only and saves without a password.
func TestWizardChangeVPN(t *testing.T) {
	var saved []string
	f := &fakeDialogs{t: t, answers: []answer{click(1), click(1), click(2), click(0)}}
	w := Wizard{Lang: Spanish, Dialogs: f, Catalog: fullCatalog, ConnectedVPNs: snapshots(t, []string{}, []string{"utun4"})}
	err := w.ChangeVPN(func(vpn string) error { saved = append(saved, vpn); return nil })
	if err != nil || !reflect.DeepEqual(saved, []string{"utun4"}) {
		t.Fatalf("ChangeVPN() = %v, saved %v", err, saved)
	}
	want := []string{
		"ask: Cambiar de VPN|Ahora vamos a encontrar tu VPN.\n\nDesconecta tu VPN y toca Siguiente.|Cancelar,Siguiente",
		"ask: Cambiar de VPN|Ahora conéctala y toca Siguiente.|Cancelar,Siguiente",
		"ask: Cambiar de VPN|¡Encontramos tu VPN!\n\nLa que conectaste aparece como: VPN.\n\nSi no es la tuya, toca Elegir otra.|Cancelar,Elegir otra,Usar esta VPN",
		"ask: leakguard|Listo: leakguard ahora usa esta VPN.|Aceptar",
	}
	if !reflect.DeepEqual(f.all(), want) {
		t.Errorf("dialogs:\n%s\nwant:\n%s", strings.Join(f.all(), "\n"), strings.Join(want, "\n"))
	}

	saved = nil
	f = &fakeDialogs{t: t, answers: []answer{click(1), click(1), cancelAsk()}}
	w = Wizard{Lang: Spanish, Dialogs: f, Catalog: fullCatalog, ConnectedVPNs: snapshots(t, []string{}, []string{"utun4"})}
	if err := w.ChangeVPN(func(vpn string) error { saved = append(saved, vpn); return nil }); !errors.Is(err, ErrCancelled) || saved != nil {
		t.Errorf("cancelled ChangeVPN() = %v, saved %v; want ErrCancelled and nothing saved", err, saved)
	}

	boom := fmt.Errorf("set: %w", ipc.ErrNotAuthorized)
	f = &fakeDialogs{t: t, answers: []answer{click(1), click(1), click(2), click(0)}}
	w = Wizard{Lang: English, Dialogs: f, Catalog: fullCatalog, ConnectedVPNs: snapshots(t, []string{}, []string{"utun4"})}
	err = w.ChangeVPN(func(string) error { return boom })
	if !errors.Is(err, boom) {
		t.Errorf("ChangeVPN() = %v, want %v", err, boom)
	}
	want0 := "Could not change the VPN: Only administrators can change leakguard\n\nYou can try again from the menu."
	if got, want := shown(f.asks[3]), "leakguard|"+want0+"|OK"; got != want {
		t.Errorf("error dialog = %q, want %q", got, want)
	}
	if got := WizardMessage(English, err); got != want0 {
		t.Errorf("WizardMessage = %q, want %q", got, want0)
	}

	// R3-001: a failing dialog is said, not swallowed.
	broken := errors.New("osascript broke")
	f = &fakeDialogs{t: t, answers: []answer{{err: broken}, click(0)}}
	w = Wizard{Lang: Spanish, Dialogs: f, Catalog: fullCatalog, ConnectedVPNs: snapshots(t)}
	err = w.ChangeVPN(func(string) error { t.Fatal("save called"); return nil })
	if !errors.Is(err, broken) {
		t.Errorf("ChangeVPN() = %v, want %v", err, broken)
	}
	if got, want := shown(f.asks[1]), "leakguard|Algo salió mal: osascript broke\n\nPuedes intentarlo de nuevo desde el menú.|Aceptar"; got != want {
		t.Errorf("error dialog = %q, want %q", got, want)
	}
}

// S2: planned services are never offered; without any supported service the
// wizard explains and stops.
func TestWizardNoSupportedServices(t *testing.T) {
	f := &fakeDialogs{t: t, answers: []answer{click(0)}}
	w := Wizard{Lang: English, Dialogs: f, Catalog: fullCatalog[1:2], ConnectedVPNs: snapshots(t)}
	err := w.Run(func(Draft) error { t.Fatal("activate called"); return nil })
	if err == nil || errors.Is(err, ErrCancelled) {
		t.Errorf("Run() = %v, want an error", err)
	}
	if want := []string{"ask: leakguard|There are no services that can be protected yet.\n\nComing soon: OpenAI.|OK"}; !reflect.DeepEqual(f.all(), want) {
		t.Errorf("dialogs = %q, want %q", f.all(), want)
	}
	if got, want := WizardMessage(English, err), "There are no services that can be protected yet."; got != want {
		t.Errorf("WizardMessage = %q, want %q", got, want)
	}
}
