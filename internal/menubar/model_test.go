package menubar

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

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
				Status:    "Protegido: tu VPN está desconectada y estos servicios no conectan",
				Tooltip:   "leakguard: Protegido: tu VPN está desconectada y estos servicios no conectan · VPN: ipsec0",
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

// R3-002: the setup opens by itself only on the first poll of a launch, and
// only when leakguard is not installed or an older install needs updating;
// a daemon that restarts later never opens it.
func TestShouldAutoOpen(t *testing.T) {
	down := fmt.Errorf("%w (dial)", ipc.ErrDaemonUnavailable)
	slow := fmt.Errorf("read: %w", os.ErrDeadlineExceeded)
	tests := []struct {
		name            string
		first, answered bool
		err             error
		inst            Install
		want            bool
	}{
		{"first poll, nothing installed", true, false, down, InstallNone, true},
		{"first poll, older install needs updating", true, false, down, InstallOld, true},
		{"first poll, installed service still starting", true, false, down, InstallCurrent, false},
		{"first poll, daemon answers", true, false, nil, InstallCurrent, false},
		{"first poll, daemon refuses", true, false, ipc.ErrNotAuthorized, InstallNone, false},
		{"first poll, daemon slow", true, false, slow, InstallNone, false},
		{"later poll, daemon restarting after it answered", false, true, down, InstallNone, false},
		{"later poll, daemon restarting, current install", false, true, down, InstallCurrent, false},
		{"later poll, never answered", false, false, down, InstallNone, false},
		{"daemon answered before", true, true, down, InstallNone, false},
	}
	for _, tc := range tests {
		if got := ShouldAutoOpen(tc.first, tc.answered, tc.err, tc.inst); got != tc.want {
			t.Errorf("%s: ShouldAutoOpen = %v, want %v", tc.name, got, tc.want)
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

var statsNow = time.Date(2026, 11, 16, 15, 0, 0, 0, time.UTC)

func withStats(s ipc.Stats) *ipc.Status {
	return ptr(status(func(st *ipc.Status) { st.Stats = &s }))
}

// S1, S2, S3, S6: two plain lines under the status and today's VPN time in
// the tooltip; no interface names in the lines.
func TestBuildStats(t *testing.T) {
	since := statsNow.Add(-(2*time.Hour + 15*time.Minute)).Format(time.RFC3339)
	tests := []struct {
		name                   string
		st                     *ipc.Status
		lang                   Lang
		now                    time.Time
		session, today, tipEnd string
	}{
		{"connected, es", withStats(ipc.Stats{Connected: true, SessionSince: since, TodayVPNSeconds: 5*3600 + 20*60, TodayBlocks: 14, TodayDrops: 2}), Spanish, statsNow,
			"VPN conectada hace 2 h 15 min", "Hoy: 14 bloqueos · la VPN se cayó 2 veces", "leakguard: Protegido · VPN: ipsec0 · Hoy: 5 h 20 min por la VPN"},
		{"connected, en", withStats(ipc.Stats{Connected: true, SessionSince: since, TodayVPNSeconds: 5*3600 + 20*60, TodayBlocks: 14, TodayDrops: 2}), English, statsNow,
			"VPN connected for 2 h 15 min", "Today: 14 blocks · VPN dropped 2 times", "leakguard: Protected · VPN: ipsec0 · Today: 5 h 20 min on the VPN"},
		{"singular, es", withStats(ipc.Stats{SessionSince: statsNow.Add(-3 * time.Minute).Format(time.RFC3339), TodayBlocks: 1, TodayDrops: 1, TodayVPNSeconds: 45}), Spanish, statsNow,
			"VPN desconectada hace 3 min", "Hoy: 1 bloqueo · la VPN se cayó 1 vez", "leakguard: Protegido · VPN: ipsec0 · Hoy: 45 s por la VPN"},
		{"singular, en", withStats(ipc.Stats{SessionSince: statsNow.Add(-3 * time.Minute).Format(time.RFC3339), TodayBlocks: 1, TodayDrops: 1}), English, statsNow,
			"VPN disconnected for 3 min", "Today: 1 block · VPN dropped 1 time", "leakguard: Protected · VPN: ipsec0 · Today: 0 s on the VPN"},
		{"zero, es", withStats(ipc.Stats{Connected: true, SessionSince: statsNow.Add(-45 * time.Second).Format(time.RFC3339)}), Spanish, statsNow,
			"VPN conectada hace 45 s", "Hoy: sin bloqueos", "leakguard: Protegido · VPN: ipsec0 · Hoy: 0 s por la VPN"},
		{"zero, en", withStats(ipc.Stats{Connected: true}), English, statsNow,
			"", "Today: no blocks", "leakguard: Protected · VPN: ipsec0 · Today: 0 s on the VPN"},
		{"no blocks, drops", withStats(ipc.Stats{TodayDrops: 3, SessionSince: "not a time"}), Spanish, statsNow,
			"", "Hoy: sin bloqueos · la VPN se cayó 3 veces", "leakguard: Protegido · VPN: ipsec0 · Hoy: 0 s por la VPN"},
		{"days", withStats(ipc.Stats{Connected: true, SessionSince: statsNow.Add(-(76 * time.Hour)).Format(time.RFC3339)}), English, statsNow,
			"VPN connected for 3 d 4 h", "Today: no blocks", "leakguard: Protected · VPN: ipsec0 · Today: 0 s on the VPN"},
		{"no clock: no session line", withStats(ipc.Stats{Connected: true, SessionSince: since}), English, time.Time{},
			"", "Today: no blocks", "leakguard: Protected · VPN: ipsec0 · Today: 0 s on the VPN"},
		{"older daemon: no stats", ptr(status(nil)), Spanish, statsNow, "", "", "leakguard: Protegido · VPN: ipsec0"},
	}
	for _, tc := range tests {
		m := Build(tc.st, nil, Setup{Lang: tc.lang, Now: tc.now})
		if m.Session != tc.session || m.Today != tc.today || m.Tooltip != tc.tipEnd {
			t.Errorf("%s: session %q, today %q, tooltip %q\nwant %q, %q, %q", tc.name, m.Session, m.Today, m.Tooltip, tc.session, tc.today, tc.tipEnd)
		}
		if strings.Contains(m.Session+m.Today, "ipsec0") {
			t.Errorf("%s: an interface name in the menu lines", tc.name)
		}
	}
	// Paused or offline menus keep the lines; a reason stays in the tooltip.
	off := withStats(ipc.Stats{SessionSince: statsNow.Add(-3 * time.Minute).Format(time.RFC3339), TodayDrops: 1})
	off.Protected, off.VPNConnected, off.Reason = false, false, "leakguard rules are not loaded"
	m := Build(off, nil, Setup{Lang: English, Now: statsNow})
	if m.Session != "VPN disconnected for 3 min" || m.Today != "Today: no blocks · VPN dropped 1 time" ||
		m.Tooltip != "leakguard: Not protected: your VPN is disconnected · VPN: ipsec0 · leakguard rules are not loaded · Today: 0 s on the VPN" {
		t.Errorf("offline menu = %+v", m)
	}
	// Menus without a choice have no stats lines.
	for _, st := range []*ipc.Status{nil, ptr(ipc.Status{Stats: &ipc.Stats{TodayBlocks: 3}})} {
		if m := Build(st, nil, Setup{Lang: English, Now: statsNow}); m.Session != "" || m.Today != "" {
			t.Errorf("Build(%+v) shows stats: %+v", st, m)
		}
	}
}
