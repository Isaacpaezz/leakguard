package menubar

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/ipc"
)

var testCatalog = []ipc.Service{
	{ID: "anthropic", Name: "Anthropic (Claude)", Status: "supported"},
	{ID: "openai", Name: "OpenAI", Status: "planned"},
	{ID: "mistral", Name: "Mistral", Status: "supported"},
}

// fullCatalog matches testCatalog for the wizard and the setup script.
var fullCatalog = []catalog.Service{
	{ID: "anthropic", Name: "Anthropic (Claude)", Status: catalog.StatusSupported},
	{ID: "openai", Name: "OpenAI", Status: catalog.StatusPlanned},
	{ID: "mistral", Name: "Mistral", Status: catalog.StatusSupported},
}

func status(mod func(*ipc.Status)) ipc.Status {
	st := ipc.Status{
		Protected:    true,
		VPNInterface: "ipsec0",
		VPNConnected: true,
		Services:     []string{"anthropic"},
		Catalog:      testCatalog,
	}
	if mod != nil {
		mod(&st)
	}
	return st
}

func ptr(st ipc.Status) *ipc.Status { return &st }

var (
	pauseES  = ToggleItem{Visible: true, Label: "Pausar la protección"}
	resumeES = ToggleItem{Visible: true, Resume: true, Label: "Reanudar la protección"}
	pauseEN  = ToggleItem{Visible: true, Label: "Pause protection"}
)

func services(l Lang, checked ...string) []ServiceItem {
	is := map[string]bool{}
	for _, id := range checked {
		is[id] = true
	}
	soon := "OpenAI (coming soon)"
	if l == Spanish {
		soon = "OpenAI (próximamente)"
	}
	return []ServiceItem{
		{ID: "anthropic", Label: "Anthropic (Claude)", Checked: is["anthropic"], Enabled: true},
		{ID: "openai", Label: soon, Checked: is["openai"], Enabled: false},
		{ID: "mistral", Label: "Mistral", Checked: is["mistral"], Enabled: true},
	}
}

// S5: a plain status, the service checkboxes, Change VPN, Pause/Resume; the
// interface name only in the tooltip.
func TestBuild(t *testing.T) {
	notAuthorized := fmt.Errorf("pause: %w", ipc.ErrNotAuthorized)
	unavailable := fmt.Errorf("%w (dial unix: no such file)", ipc.ErrDaemonUnavailable)
	notConfigured := status(func(s *ipc.Status) {
		s.Protected = false
		s.Reason = ipc.ReasonNotConfigured
		s.VPNInterface = ""
		s.VPNConnected = false
		s.Services = []string{}
	})
	tests := []struct {
		name   string
		st     *ipc.Status
		err    error
		lang   Lang
		update bool
		want   Menu
	}{
		{
			name: "protected",
			st:   ptr(status(nil)),
			lang: Spanish,
			want: Menu{
				State:     StateProtected,
				Status:    "Protegido",
				Tooltip:   "leakguard: Protegido · VPN: ipsec0",
				Services:  services(Spanish, "anthropic"),
				ChangeVPN: true,
				Toggle:    pauseES,
			},
		},
		{
			name: "protected in English",
			st:   ptr(status(nil)),
			lang: English,
			want: Menu{
				State:     StateProtected,
				Status:    "Protected",
				Tooltip:   "leakguard: Protected · VPN: ipsec0",
				Services:  services(English, "anthropic"),
				ChangeVPN: true,
				Toggle:    pauseEN,
			},
		},
		{
			name: "protected while the VPN is down: blocked, not leaking",
			st:   ptr(status(func(s *ipc.Status) { s.VPNConnected = false })),
			lang: Spanish,
			want: Menu{
				State:     StateProtected,
				Status:    "Protegido: tu VPN está desconectada, así que estos servicios no se conectan",
				Tooltip:   "leakguard: Protegido: tu VPN está desconectada, así que estos servicios no se conectan · VPN: ipsec0",
				Services:  services(Spanish, "anthropic"),
				ChangeVPN: true,
				Toggle:    pauseES,
			},
		},
		{
			name: "not protected with the VPN down",
			st: ptr(status(func(s *ipc.Status) {
				s.Protected = false
				s.VPNConnected = false
				s.Reason = "the rules are not loaded"
			})),
			lang: Spanish,
			want: Menu{
				State:     StateNotProtected,
				Status:    "Sin protección: tu VPN está desconectada",
				Tooltip:   "leakguard: Sin protección: tu VPN está desconectada · VPN: ipsec0 · the rules are not loaded",
				Services:  services(Spanish, "anthropic"),
				ChangeVPN: true,
				Toggle:    pauseES,
			},
		},
		{
			name: "not protected: the technical reason only in the tooltip",
			st: ptr(status(func(s *ipc.Status) {
				s.Protected = false
				s.Reason = "pf is disabled\nmore detail"
				s.Services = []string{"anthropic", "mistral"}
			})),
			lang: Spanish,
			want: Menu{
				State:     StateNotProtected,
				Status:    "Sin protección: leakguard no pudo comprobar sus reglas",
				Tooltip:   "leakguard: Sin protección: leakguard no pudo comprobar sus reglas · VPN: ipsec0 · pf is disabled",
				Services:  services(Spanish, "anthropic", "mistral"),
				ChangeVPN: true,
				Toggle:    pauseES,
			},
		},
		{
			name: "paused offers resume",
			st: ptr(status(func(s *ipc.Status) {
				s.Protected = false
				s.Reason = ipc.ReasonPaused
			})),
			lang: Spanish,
			want: Menu{
				State:     StatePaused,
				Status:    "En pausa",
				Tooltip:   "leakguard: En pausa · VPN: ipsec0",
				Services:  services(Spanish, "anthropic"),
				ChangeVPN: true,
				Toggle:    resumeES,
			},
		},
		{
			name: "daemon running without a configuration opens the setup",
			st:   &notConfigured,
			lang: Spanish,
			want: Menu{
				State:   StateNotSetUp,
				Status:  "leakguard todavía no está configurado",
				Tooltip: "leakguard: leakguard todavía no está configurado",
				SetUp:   true,
			},
		},
		{
			name: "daemon with a VPN but no services opens the setup",
			st:   ptr(status(func(s *ipc.Status) { s.Protected = false; s.Services = []string{} })),
			lang: English,
			want: Menu{
				State:   StateNotSetUp,
				Status:  "leakguard is not set up yet",
				Tooltip: "leakguard: leakguard is not set up yet",
				SetUp:   true,
			},
		},
		{
			name: "daemon unavailable: only the setup and quit",
			err:  unavailable,
			lang: Spanish,
			want: Menu{
				State:   StateNotSetUp,
				Status:  "leakguard todavía no está configurado",
				Tooltip: "leakguard: leakguard no está configurado en esta Mac",
				SetUp:   true,
			},
		},
		{
			name:   "older install needs the same setup",
			err:    unavailable,
			lang:   Spanish,
			update: true,
			want: Menu{
				State:   StateNotSetUp,
				Status:  "Hay que actualizar leakguard: toca Configurar",
				Tooltip: "leakguard: leakguard no está configurado en esta Mac",
				SetUp:   true,
			},
		},
		{
			name: "not authorized by the daemon",
			err:  notAuthorized,
			lang: Spanish,
			want: Menu{State: StateNotProtected, Status: "Solo un administrador de la Mac puede cambiar leakguard", Tooltip: "leakguard: Solo un administrador de la Mac puede cambiar leakguard"},
		},
		{
			name: "socket permission denied",
			err:  &os.SyscallError{Syscall: "connect", Err: syscall.EACCES},
			lang: English,
			want: Menu{State: StateNotProtected, Status: "Only administrators can change leakguard", Tooltip: "leakguard: Only administrators can change leakguard"},
		},
		{
			name: "no status yet",
			lang: Spanish,
			want: Menu{State: StateNotProtected, Status: "Comprobando…", Tooltip: "leakguard: Comprobando…"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Build(tc.st, tc.err, Setup{Catalog: fullCatalog, Update: tc.update, Lang: tc.lang})
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Build:\n got %+v\nwant %+v", got, tc.want)
			}
			// S1: no interface name outside the tooltip.
			for _, s := range []string{got.Status, got.Toggle.Label} {
				if strings.Contains(s, "ipsec") || strings.Contains(s, "utun") {
					t.Errorf("interface name in %q", s)
				}
			}
		})
	}
}

func TestClicks(t *testing.T) {
	paused := status(func(s *ipc.Status) {
		s.Protected = false
		s.Reason = ipc.ReasonPaused
		s.Services = []string{"anthropic", "mistral"}
	})
	noVPN := status(func(s *ipc.Status) {
		s.Protected = false
		s.Reason = ipc.ReasonNotConfigured
		s.VPNInterface = ""
		s.Services = []string{}
	})
	set := func(vpn string, ids ...string) Request {
		return Request{VPNInterface: vpn, Services: ids}
	}
	tests := []struct {
		name    string
		click   func() (Request, error)
		want    Request
		wantErr string
	}{
		{
			name: "tick a service adds it in catalog order",
			click: func() (Request, error) {
				return ToggleService(English, status(func(s *ipc.Status) { s.Services = []string{"mistral"} }), "anthropic")
			},
			want: set("ipsec0", "anthropic", "mistral"),
		},
		{
			name: "untick one of two services",
			click: func() (Request, error) {
				return ToggleService(English, status(func(s *ipc.Status) { s.Services = []string{"anthropic", "mistral"} }), "anthropic")
			},
			want: set("ipsec0", "mistral"),
		},
		{
			name:  "untick the last service pauses instead of sending an empty list",
			click: func() (Request, error) { return ToggleService(English, status(nil), "anthropic") },
			want:  Request{Pause: true},
		},
		{
			name:  "unticking one while paused resumes with the rest",
			click: func() (Request, error) { return ToggleService(English, paused, "mistral") },
			want:  set("ipsec0", "anthropic"),
		},
		{
			name:    "a planned service cannot be ticked",
			click:   func() (Request, error) { return ToggleService(English, status(nil), "openai") },
			wantErr: "OpenAI is coming soon and cannot be protected yet",
		},
		{
			name:    "a planned service cannot be ticked, in Spanish",
			click:   func() (Request, error) { return ToggleService(Spanish, status(nil), "openai") },
			wantErr: "OpenAI llegará pronto y todavía no se puede proteger",
		},
		{
			name:    "an unknown service cannot be ticked",
			click:   func() (Request, error) { return ToggleService(English, status(nil), "nope") },
			wantErr: `Unknown service "nope"`,
		},
		{
			name:    "without a saved VPN nothing is sent: set up first",
			click:   func() (Request, error) { return ToggleService(Spanish, noVPN, "anthropic") },
			wantErr: "Configura leakguard primero",
		},
		{
			name:  "change VPN keeps the saved services",
			click: func() (Request, error) { return ChangeVPNRequest(English, paused, "utun4") },
			want:  set("utun4", "anthropic", "mistral"),
		},
		{
			name:    "change VPN without saved services sends nothing",
			click:   func() (Request, error) { return ChangeVPNRequest(Spanish, noVPN, "utun4") },
			wantErr: "Configura leakguard primero",
		},
		{
			name:    "change VPN refuses a real connection",
			click:   func() (Request, error) { return ChangeVPNRequest(English, paused, "en0") },
			wantErr: `"en0" is not a VPN interface; it carries your real connection`,
		},
		{
			name:  "pause",
			click: func() (Request, error) { return PauseRequest(), nil },
			want:  Request{Pause: true},
		},
		{
			name:  "resume sends the saved choice",
			click: func() (Request, error) { return ResumeRequest(English, paused) },
			want:  set("ipsec0", "anthropic", "mistral"),
		},
		{
			name:    "resume without a saved choice",
			click:   func() (Request, error) { return ResumeRequest(Spanish, noVPN) },
			wantErr: "No hay nada que reanudar: configura leakguard primero",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.click()
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("error = %v, want %q", err, tc.wantErr)
				}
				if !reflect.DeepEqual(got, Request{}) {
					t.Errorf("request with an error = %+v, want none", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("request = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestErrorLineAfterPoll(t *testing.T) {
	failed := errors.New("boom")
	tests := []struct {
		name  string
		line  string
		fresh bool
		err   error
		want  string
	}{
		{"a fresh error survives the poll right after the click", "Could not change leakguard: x", true, nil, "Could not change leakguard: x"},
		{"an older error is cleared once the daemon answers", "Could not change leakguard: x", false, nil, ""},
		{"an older error stays while the daemon does not answer", "Set up canceled", false, failed, "Set up canceled"},
		{"no error stays empty", "", false, nil, ""},
	}
	for _, tc := range tests {
		if got := ErrorLineAfterPoll(tc.line, tc.fresh, tc.err); got != tc.want {
			t.Errorf("%s: ErrorLineAfterPoll() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestToggleServiceDoesNotChangeTheStatus(t *testing.T) {
	st := status(func(s *ipc.Status) { s.Services = []string{"anthropic", "mistral"} })
	if _, err := ToggleService(English, st, "anthropic"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(st.Services, []string{"anthropic", "mistral"}) {
		t.Errorf("status services changed to %v", st.Services)
	}
}

func TestExplain(t *testing.T) {
	tests := []struct {
		l    Lang
		err  error
		want string
	}{
		{English, fmt.Errorf("%w (dial)", ipc.ErrDaemonUnavailable), "leakguard is not set up on this Mac"},
		{Spanish, fmt.Errorf("%w (dial)", ipc.ErrDaemonUnavailable), "leakguard no está configurado en esta Mac"},
		{English, ipc.ErrNotAuthorized, "Only administrators can change leakguard"},
		{English, fmt.Errorf("set: %w", ipc.ErrNotAuthorized), "Only administrators can change leakguard"},
		{Spanish, ipc.ErrNotAuthorized, "Solo un administrador de la Mac puede cambiar leakguard"},
		// Only the sentinel counts, never an error that happens to read the same.
		{English, errors.New("not authorized"), "Could not change leakguard: not authorized"},
		{English, &os.SyscallError{Syscall: "connect", Err: syscall.EACCES}, "Only administrators can change leakguard"},
		{English, fmt.Errorf("read: %w", os.ErrDeadlineExceeded), "The leakguard background service did not answer; try again"},
		{Spanish, fmt.Errorf("read: %w", os.ErrDeadlineExceeded), "El servicio de leakguard no respondió; inténtalo de nuevo"},
		{English, errors.New("could not apply the firewall rules: pfctl failed\nmore detail"), "Could not change leakguard: could not apply the firewall rules: pfctl failed"},
		{Spanish, errors.New("could not apply the firewall rules: pfctl failed"), "No se pudo cambiar leakguard: could not apply the firewall rules: pfctl failed"},
		{English, nil, ""},
		// What FindCLI refuses, in plain words.
		{Spanish, ErrCLINotRootOwned, "El leakguard instalado no pertenece a root. Reinstálalo con: sudo leakguard enable"},
		{English, ErrCLINotRootOwned, "The installed leakguard is not owned by root. Reinstall it with: sudo leakguard enable"},
		{Spanish, ErrCLIUpdate, "Para actualizar leakguard, pon el nuevo comando leakguard junto a esta app o ejecuta: sudo leakguard enable"},
		{Spanish, ErrNoCLI, "Pon el comando leakguard junto a esta app e inténtalo de nuevo"},
		{English, ErrNoCLI, "Put the leakguard command next to this app, then try again"},
	}
	for _, tc := range tests {
		if got := Explain(tc.l, tc.err); got != tc.want {
			t.Errorf("Explain(%s, %v) = %q, want %q", tc.l, tc.err, got, tc.want)
		}
	}
}

func TestSetupNeeded(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"daemon still unavailable", fmt.Errorf("%w (dial)", ipc.ErrDaemonUnavailable), true},
		{"daemon answers now", nil, false},
		{"daemon answers but refuses", ipc.ErrNotAuthorized, false},
		{"daemon slow", fmt.Errorf("read: %w", os.ErrDeadlineExceeded), false},
	}
	for _, tc := range tests {
		if got := SetupNeeded(tc.err); got != tc.want {
			t.Errorf("%s: SetupNeeded = %v, want %v", tc.name, got, tc.want)
		}
	}
}
