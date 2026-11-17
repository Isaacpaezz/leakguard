package menubar

import (
	"errors"
	"fmt"
	"os"
	"reflect"
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

// fullCatalog matches testCatalog for the "not set up" menu.
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
	pauseItem  = ToggleItem{Visible: true, Label: "Pause protection"}
	resumeItem = ToggleItem{Visible: true, Resume: true, Label: "Resume protection"}
)

func services(checked ...string) []ServiceItem {
	is := map[string]bool{}
	for _, id := range checked {
		is[id] = true
	}
	return []ServiceItem{
		{ID: "anthropic", Label: "Anthropic (Claude)", Checked: is["anthropic"], Enabled: true},
		{ID: "openai", Label: "OpenAI (coming soon)", Checked: is["openai"], Enabled: false},
		{ID: "mistral", Label: "Mistral", Checked: is["mistral"], Enabled: true},
	}
}

func TestBuild(t *testing.T) {
	notAuthorized := errors.New("not authorized")
	tests := []struct {
		name       string
		st         *ipc.Status
		err        error
		candidates []string
		want       Menu
	}{
		{
			name:       "protected",
			st:         ptr(status(nil)),
			candidates: []string{"ipsec0", "utun3"},
			want: Menu{
				State:    StateProtected,
				Status:   "Protected through ipsec0",
				Services: services("anthropic"),
				VPNs: []VPNItem{
					{Name: "ipsec0", Label: "ipsec0", Checked: true},
					{Name: "utun3", Label: "utun3"},
				},
				Toggle: pauseItem,
			},
		},
		{
			name: "protected while the VPN is down",
			st: ptr(status(func(s *ipc.Status) {
				s.VPNConnected = false
			})),
			candidates: []string{"ipsec0"},
			want: Menu{
				State:    StateProtected,
				Status:   "Protected through ipsec0 (not connected: these services are offline)",
				Services: services("anthropic"),
				VPNs:     []VPNItem{{Name: "ipsec0", Label: "ipsec0 (not connected)", Checked: true}},
				Toggle:   pauseItem,
			},
		},
		{
			name: "saved interface missing from the candidates is still listed and checked",
			st: ptr(status(func(s *ipc.Status) {
				s.VPNInterface = "ppp0"
			})),
			candidates: []string{"utun3", "utun3"},
			want: Menu{
				State:    StateProtected,
				Status:   "Protected through ppp0",
				Services: services("anthropic"),
				VPNs: []VPNItem{
					{Name: "utun3", Label: "utun3"},
					{Name: "ppp0", Label: "ppp0", Checked: true},
				},
				Toggle: pauseItem,
			},
		},
		{
			name: "not protected shows the reason",
			st: ptr(status(func(s *ipc.Status) {
				s.Protected = false
				s.Reason = "pf is disabled"
				s.Services = []string{"anthropic", "mistral"}
			})),
			candidates: []string{"ipsec0"},
			want: Menu{
				State:    StateNotProtected,
				Status:   "Not protected: pf is disabled",
				Services: services("anthropic", "mistral"),
				VPNs:     []VPNItem{{Name: "ipsec0", Label: "ipsec0", Checked: true}},
				Toggle:   pauseItem,
			},
		},
		{
			name: "paused offers resume",
			st: ptr(status(func(s *ipc.Status) {
				s.Protected = false
				s.Reason = ipc.ReasonPaused
			})),
			candidates: []string{"ipsec0"},
			want: Menu{
				State:    StatePaused,
				Status:   "Paused: the selected services are not protected",
				Services: services("anthropic"),
				VPNs:     []VPNItem{{Name: "ipsec0", Label: "ipsec0", Checked: true}},
				Toggle:   resumeItem,
			},
		},
		{
			name: "daemon running without a configuration",
			st: ptr(status(func(s *ipc.Status) {
				s.Protected = false
				s.Reason = ipc.ReasonNotConfigured
				s.VPNInterface = ""
				s.VPNConnected = false
				s.Services = []string{}
			})),
			candidates: []string{"ipsec0"},
			want: Menu{
				State:    StateNotProtected,
				Status:   "Not set up yet: choose a VPN interface, then a service",
				Services: services(),
				VPNs:     []VPNItem{{Name: "ipsec0", Label: "ipsec0"}},
			},
		},
		{
			name: "not authorized by the daemon",
			err:  notAuthorized,
			want: Menu{State: StateNotProtected, Status: "Only administrators can change leakguard"},
		},
		{
			name: "socket permission denied",
			err:  &os.SyscallError{Syscall: "connect", Err: syscall.EACCES},
			want: Menu{State: StateNotProtected, Status: "Only administrators can change leakguard"},
		},
		{
			name: "no status yet",
			want: Menu{State: StateNotProtected, Status: "Checking…"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Build(tc.st, tc.err, tc.candidates, Setup{Catalog: fullCatalog})
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Build:\n got %+v\nwant %+v", got, tc.want)
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
				return ToggleService(status(func(s *ipc.Status) { s.Services = []string{"mistral"} }), "anthropic")
			},
			want: set("ipsec0", "anthropic", "mistral"),
		},
		{
			name: "untick one of two services",
			click: func() (Request, error) {
				return ToggleService(status(func(s *ipc.Status) { s.Services = []string{"anthropic", "mistral"} }), "anthropic")
			},
			want: set("ipsec0", "mistral"),
		},
		{
			name:  "untick the last service pauses instead of sending an empty list",
			click: func() (Request, error) { return ToggleService(status(nil), "anthropic") },
			want:  Request{Pause: true},
		},
		{
			name:  "unticking one while paused resumes with the rest",
			click: func() (Request, error) { return ToggleService(paused, "mistral") },
			want:  set("ipsec0", "anthropic"),
		},
		{
			name:    "a planned service cannot be ticked",
			click:   func() (Request, error) { return ToggleService(status(nil), "openai") },
			wantErr: "OpenAI is coming soon and cannot be protected yet",
		},
		{
			name:    "an unknown service cannot be ticked",
			click:   func() (Request, error) { return ToggleService(status(nil), "nope") },
			wantErr: `unknown service "nope"`,
		},
		{
			name:    "a service needs a VPN interface first",
			click:   func() (Request, error) { return ToggleService(noVPN, "anthropic") },
			wantErr: "Choose a VPN interface first",
		},
		{
			name: "choose a VPN keeps the services",
			click: func() (Request, error) {
				return ChooseVPN(status(func(s *ipc.Status) { s.Services = []string{"anthropic", "mistral"} }), "utun3")
			},
			want: set("utun3", "anthropic", "mistral"),
		},
		{
			name:    "choose a VPN without services",
			click:   func() (Request, error) { return ChooseVPN(noVPN, "utun3") },
			wantErr: "Tick a service to protect through utun3",
		},
		{
			name:  "pause",
			click: func() (Request, error) { return PauseRequest(), nil },
			want:  Request{Pause: true},
		},
		{
			name:  "resume sends the saved choice",
			click: func() (Request, error) { return ResumeRequest(paused) },
			want:  set("ipsec0", "anthropic", "mistral"),
		},
		{
			name:    "resume without a saved choice",
			click:   func() (Request, error) { return ResumeRequest(noVPN) },
			wantErr: "Nothing to resume: choose a VPN interface and a service",
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

func TestToggleServiceDoesNotChangeTheStatus(t *testing.T) {
	st := status(func(s *ipc.Status) { s.Services = []string{"anthropic", "mistral"} })
	if _, err := ToggleService(st, "anthropic"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(st.Services, []string{"anthropic", "mistral"}) {
		t.Errorf("status services changed to %v", st.Services)
	}
}

func TestExplain(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{fmt.Errorf("%w (dial)", ipc.ErrDaemonUnavailable), "leakguard is not set up on this Mac (its background service is not running)"},
		{errors.New("not authorized"), "Only administrators can change leakguard"},
		{&os.SyscallError{Syscall: "connect", Err: syscall.EACCES}, "Only administrators can change leakguard"},
		{fmt.Errorf("read: %w", os.ErrDeadlineExceeded), "The leakguard background service did not answer; try again"},
		{errors.New("could not apply the firewall rules: pfctl failed\nmore detail"), "Could not change leakguard: could not apply the firewall rules: pfctl failed"},
	}
	for _, tc := range tests {
		if got := Explain(tc.err); got != tc.want {
			t.Errorf("Explain(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestBuildNotSetUp(t *testing.T) {
	unavailable := fmt.Errorf("%w (dial unix: no such file)", ipc.ErrDaemonUnavailable)
	tests := []struct {
		name       string
		draft      Draft
		candidates []string
		want       Menu
	}{
		{
			name:       "empty draft asks for the VPN first",
			candidates: []string{"ipsec0", "utun3"},
			want: Menu{
				State:    StateNotSetUp,
				Status:   "Choose your VPN interface",
				Services: services(),
				VPNs:     []VPNItem{{Name: "ipsec0", Label: "ipsec0"}, {Name: "utun3", Label: "utun3"}},
				SetUp:    SetUpItem{Visible: true},
			},
		},
		{
			name:       "VPN chosen asks for a service",
			draft:      Draft{VPNInterface: "utun3"},
			candidates: []string{"ipsec0", "utun3"},
			want: Menu{
				State:    StateNotSetUp,
				Status:   "Choose at least one service",
				Services: services(),
				VPNs:     []VPNItem{{Name: "ipsec0", Label: "ipsec0"}, {Name: "utun3", Label: "utun3", Checked: true}},
				SetUp:    SetUpItem{Visible: true},
			},
		},
		{
			name:       "service without a VPN still asks for the VPN",
			draft:      Draft{Services: []string{"anthropic"}},
			candidates: []string{"ipsec0"},
			want: Menu{
				State:    StateNotSetUp,
				Status:   "Choose your VPN interface",
				Services: services("anthropic"),
				VPNs:     []VPNItem{{Name: "ipsec0", Label: "ipsec0"}},
				SetUp:    SetUpItem{Visible: true},
			},
		},
		{
			name:       "complete draft enables set up",
			draft:      Draft{VPNInterface: "ipsec0", Services: []string{"anthropic", "mistral"}},
			candidates: []string{"ipsec0"},
			want: Menu{
				State:    StateNotSetUp,
				Status:   "Ready: click Set up leakguard…",
				Services: services("anthropic", "mistral"),
				VPNs:     []VPNItem{{Name: "ipsec0", Label: "ipsec0", Checked: true}},
				SetUp:    SetUpItem{Visible: true, Enabled: true},
			},
		},
		{
			name:       "drafted VPN that disappeared stays listed",
			draft:      Draft{VPNInterface: "ppp0", Services: []string{"anthropic"}},
			candidates: nil,
			want: Menu{
				State:    StateNotSetUp,
				Status:   "Ready: click Set up leakguard…",
				Services: services("anthropic"),
				VPNs:     []VPNItem{{Name: "ppp0", Label: "ppp0", Checked: true}},
				SetUp:    SetUpItem{Visible: true, Enabled: true},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Build(nil, unavailable, tc.candidates, Setup{Catalog: fullCatalog, Draft: tc.draft})
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Build:\n got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestDefaultDraft(t *testing.T) {
	tests := []struct {
		connected []string
		want      Draft
	}{
		{nil, Draft{}},
		{[]string{"ipsec0"}, Draft{VPNInterface: "ipsec0"}},
		{[]string{"ipsec0", "utun3"}, Draft{}},
		{[]string{"ipsec0", "ipsec0"}, Draft{VPNInterface: "ipsec0"}},
		{[]string{"en0"}, Draft{}},
	}
	for _, tc := range tests {
		if got := DefaultDraft(tc.connected); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("DefaultDraft(%v) = %+v, want %+v", tc.connected, got, tc.want)
		}
	}
}

func TestDraftClicks(t *testing.T) {
	tests := []struct {
		name    string
		click   func() (Draft, error)
		want    Draft
		wantErr string
	}{
		{
			name:  "tick a service",
			click: func() (Draft, error) { return Draft{}.ToggleService(fullCatalog, "mistral") },
			want:  Draft{Services: []string{"mistral"}},
		},
		{
			name: "tick keeps catalog order and the VPN",
			click: func() (Draft, error) {
				return Draft{VPNInterface: "ipsec0", Services: []string{"mistral"}}.ToggleService(fullCatalog, "anthropic")
			},
			want: Draft{VPNInterface: "ipsec0", Services: []string{"anthropic", "mistral"}},
		},
		{
			name: "untick the last service leaves an empty draft",
			click: func() (Draft, error) {
				return Draft{Services: []string{"anthropic"}}.ToggleService(fullCatalog, "anthropic")
			},
			want: Draft{},
		},
		{
			name:    "planned service",
			click:   func() (Draft, error) { return Draft{}.ToggleService(fullCatalog, "openai") },
			wantErr: "OpenAI is coming soon and cannot be protected yet",
		},
		{
			name:    "unknown service",
			click:   func() (Draft, error) { return Draft{}.ToggleService(fullCatalog, "nope") },
			wantErr: `unknown service "nope"`,
		},
		{
			name:  "choose a VPN keeps the services",
			click: func() (Draft, error) { return Draft{Services: []string{"anthropic"}}.ChooseVPN("utun3") },
			want:  Draft{VPNInterface: "utun3", Services: []string{"anthropic"}},
		},
		{
			name:    "a real connection is not a VPN",
			click:   func() (Draft, error) { return Draft{}.ChooseVPN("en0") },
			wantErr: `"en0" is not a VPN interface; it carries your real connection`,
		},
		{
			name:    "an unsafe name is rejected",
			click:   func() (Draft, error) { return Draft{}.ChooseVPN("utun0; id") },
			wantErr: `"utun0; id" is not a valid interface name`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.click()
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("draft = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestDraftToggleDoesNotChangeTheOriginal(t *testing.T) {
	d := Draft{Services: []string{"anthropic", "mistral"}}
	if _, err := d.ToggleService(fullCatalog, "anthropic"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d.Services, []string{"anthropic", "mistral"}) {
		t.Errorf("original draft changed to %v", d.Services)
	}
}

func TestBuildNotSetUpOlderInstall(t *testing.T) {
	unavailable := fmt.Errorf("%w (dial unix: no such file)", ipc.ErrDaemonUnavailable)
	tests := []struct {
		name  string
		draft Draft
		want  Menu
	}{
		{
			name:  "complete draft asks to update",
			draft: Draft{VPNInterface: "ipsec0", Services: []string{"anthropic"}},
			want: Menu{
				State:    StateNotSetUp,
				Status:   "Update needed: click Set up leakguard… to update",
				Services: services("anthropic"),
				VPNs:     []VPNItem{{Name: "ipsec0", Label: "ipsec0", Checked: true}},
				SetUp:    SetUpItem{Visible: true, Enabled: true},
			},
		},
		{
			name:  "incomplete draft still keeps set up disabled",
			draft: Draft{VPNInterface: "ipsec0"},
			want: Menu{
				State:    StateNotSetUp,
				Status:   "Update needed. Choose at least one service",
				Services: services(),
				VPNs:     []VPNItem{{Name: "ipsec0", Label: "ipsec0", Checked: true}},
				SetUp:    SetUpItem{Visible: true},
			},
		},
		{
			name: "empty draft asks for the VPN",
			want: Menu{
				State:    StateNotSetUp,
				Status:   "Update needed. Choose your VPN interface",
				Services: services(),
				VPNs:     []VPNItem{{Name: "ipsec0", Label: "ipsec0"}},
				SetUp:    SetUpItem{Visible: true},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Build(nil, unavailable, []string{"ipsec0"}, Setup{Catalog: fullCatalog, Draft: tc.draft, Update: true})
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Build:\n got %+v\nwant %+v", got, tc.want)
			}
		})
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
		{"daemon answers but refuses", errors.New("not authorized"), false},
		{"daemon slow", fmt.Errorf("read: %w", os.ErrDeadlineExceeded), false},
	}
	for _, tc := range tests {
		if got := SetupNeeded(tc.err); got != tc.want {
			t.Errorf("%s: SetupNeeded = %v, want %v", tc.name, got, tc.want)
		}
	}
}
