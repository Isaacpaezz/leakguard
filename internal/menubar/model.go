// Package menubar is the logic of the menu-bar app, without any GUI: it turns
// the daemon's status into a menu description and turns each click into the
// request to send. cmd/leakguard-menubar only draws what it returns.
package menubar

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/ipc"
)

// State is what the menu-bar icon shows.
type State string

const (
	StateProtected    State = "protected"
	StateNotProtected State = "not protected"
	StatePaused       State = "paused"
	StateNotSetUp     State = "not set up"
)

// Menu describes everything the app shows.
type Menu struct {
	State State
	// Status is the first, informational line of the menu.
	Status   string
	Services []ServiceItem
	VPNs     []VPNItem
	Toggle   ToggleItem
	// SetUp is "Set up leakguard…": shown only when the daemon is unavailable.
	SetUp SetUpItem
}

// SetUpItem is "Set up leakguard…". It is enabled once the draft has a VPN
// interface and at least one supported service.
type SetUpItem struct {
	Visible bool
	Enabled bool
}

// Draft is the choice the user makes in the menu before leakguard is set up.
// It lives in the app only; nothing reaches the daemon until "Set up".
type Draft struct {
	VPNInterface string
	Services     []string
}

// Setup is what Build needs when the daemon is unavailable: the embedded
// catalog and the user's draft.
type Setup struct {
	Catalog []catalog.Service
	Draft   Draft
	// Update is set when an older leakguard is installed: its background
	// service predates the socket, so "Set up" updates it.
	Update bool
}

// DefaultDraft is the first draft: no services, and the VPN interface when
// exactly one VPN candidate is connected.
func DefaultDraft(connectedCandidates []string) Draft {
	var names []string
	for _, n := range config.VPNCandidates(connectedCandidates) {
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	if len(names) == 1 && config.CheckVPNInterface(names[0]) == nil {
		return Draft{VPNInterface: names[0]}
	}
	return Draft{}
}

// ToggleService ticks or unticks service id in the draft, keeping the
// catalog order. It never changes d.
func (d Draft) ToggleService(all []catalog.Service, id string) (Draft, error) {
	s, ok := catalog.Find(all, id)
	if !ok {
		return d, fmt.Errorf("unknown service %q", id)
	}
	if s.Status != catalog.StatusSupported {
		return d, fmt.Errorf("%s is coming soon and cannot be protected yet", s.Name)
	}
	ids := toggled(catalogItems(all), d.Services, id)
	return Draft{VPNInterface: d.VPNInterface, Services: ids}, nil
}

// ChooseVPN sets the draft's VPN interface after the same check the firewall
// uses, so only a plain VPN interface name ever reaches the setup script.
func (d Draft) ChooseVPN(name string) (Draft, error) {
	if err := config.CheckVPNInterface(name); err != nil {
		return d, err
	}
	return Draft{VPNInterface: name, Services: slices.Clone(d.Services)}, nil
}

// missing reports what the draft still misses, or "" when it can be set up.
func (d Draft) missing(all []catalog.Service) string {
	switch {
	case d.VPNInterface == "":
		return "Choose your VPN interface"
	case !slices.ContainsFunc(d.Services, func(id string) bool {
		s, ok := catalog.Find(all, id)
		return ok && s.Status == catalog.StatusSupported
	}):
		return "Choose at least one service"
	}
	return ""
}

func catalogItems(all []catalog.Service) []ipc.Service {
	out := make([]ipc.Service, 0, len(all))
	for _, s := range all {
		out = append(out, ipc.Service{ID: s.ID, Name: s.Name, Status: string(s.Status)})
	}
	return out
}

// toggled flips id in selected and returns the result in catalog order.
func toggled(cat []ipc.Service, selected []string, id string) []string {
	var ids []string
	for _, s := range cat {
		want := slices.Contains(selected, s.ID)
		if s.ID == id {
			want = !want
		}
		if want {
			ids = append(ids, s.ID)
		}
	}
	return ids
}

// buildNotSetUp is the menu while the daemon is unavailable: the clicks only
// change the draft, and "Set up leakguard…" is enabled once it is complete.
func buildNotSetUp(candidates []string, setup Setup) Menu {
	d := setup.Draft
	st := ipc.Status{VPNInterface: d.VPNInterface, VPNConnected: true, Services: d.Services, Catalog: catalogItems(setup.Catalog)}
	m := Menu{
		State:    StateNotSetUp,
		Status:   d.missing(setup.Catalog),
		Services: serviceItems(st),
		VPNs:     vpnItems(st, candidates),
		SetUp:    SetUpItem{Visible: true},
	}
	switch {
	case m.Status != "" && setup.Update:
		m.Status = "Update needed. " + m.Status
	case m.Status != "":
	case setup.Update:
		m.Status = "Update needed: click Set up leakguard… to update"
		m.SetUp.Enabled = true
	default:
		m.Status = "Ready: click Set up leakguard…"
		m.SetUp.Enabled = true
	}
	return m
}

// ServiceItem is one catalog service.
type ServiceItem struct {
	ID      string
	Label   string
	Checked bool
	Enabled bool
}

// VPNItem is one VPN interface the user can choose.
type VPNItem struct {
	Name    string
	Label   string
	Checked bool
}

// ToggleItem is "Pause protection" or "Resume protection".
type ToggleItem struct {
	Visible bool
	Resume  bool
	Label   string
}

// Request is what a click asks the daemon to do: Pause, or Set with
// VPNInterface and Services.
type Request struct {
	Pause        bool
	VPNInterface string
	Services     []string
}

// Build describes the menu for a status, or for the error that replaced it,
// and the VPN candidate interfaces. It never reports protected unless the
// daemon verified it.
func Build(st *ipc.Status, err error, candidates []string, setup Setup) Menu {
	switch {
	case errors.Is(err, ipc.ErrDaemonUnavailable):
		return buildNotSetUp(candidates, setup)
	case err != nil:
		return Menu{State: StateNotProtected, Status: Explain(err)}
	case st == nil:
		return Menu{State: StateNotProtected, Status: "Checking…"}
	}
	m := Menu{
		Services: serviceItems(*st),
		VPNs:     vpnItems(*st, candidates),
	}
	configured := st.VPNInterface != "" && len(st.Services) > 0
	switch {
	case st.Protected:
		m.State = StateProtected
		m.Status = "Protected through " + st.VPNInterface
		if !st.VPNConnected {
			m.Status += " (not connected: these services are offline)"
		}
	case st.Reason == ipc.ReasonPaused:
		m.State = StatePaused
		m.Status = "Paused: the selected services are not protected"
	case st.Reason == ipc.ReasonNotConfigured || !configured:
		m.State = StateNotProtected
		m.Status = "Not set up yet: choose a VPN interface, then a service"
	default:
		m.State = StateNotProtected
		m.Status = "Not protected: " + firstLine(st.Reason)
	}
	switch {
	case m.State == StatePaused:
		m.Toggle = ToggleItem{Visible: true, Resume: true, Label: "Resume protection"}
	case configured:
		m.Toggle = ToggleItem{Visible: true, Label: "Pause protection"}
	}
	return m
}

func serviceItems(st ipc.Status) []ServiceItem {
	items := make([]ServiceItem, 0, len(st.Catalog))
	for _, s := range st.Catalog {
		item := ServiceItem{
			ID:      s.ID,
			Label:   s.Name,
			Checked: slices.Contains(st.Services, s.ID),
			Enabled: s.Status == "supported",
		}
		if s.Status == "planned" {
			item.Label += " (coming soon)"
		}
		items = append(items, item)
	}
	return items
}

func vpnItems(st ipc.Status, candidates []string) []VPNItem {
	names := []string{}
	for _, n := range candidates {
		if n != "" && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	if st.VPNInterface != "" && !slices.Contains(names, st.VPNInterface) {
		names = append(names, st.VPNInterface)
	}
	items := make([]VPNItem, 0, len(names))
	for _, n := range names {
		item := VPNItem{Name: n, Label: n, Checked: n == st.VPNInterface}
		if item.Checked && !st.VPNConnected {
			item.Label += " (not connected)"
		}
		items = append(items, item)
	}
	return items
}

// ToggleService is the request for a click on service id. Unticking the last
// service pauses instead of sending an empty list, which the daemon refuses.
func ToggleService(st ipc.Status, id string) (Request, error) {
	i := slices.IndexFunc(st.Catalog, func(s ipc.Service) bool { return s.ID == id })
	if i < 0 {
		return Request{}, fmt.Errorf("unknown service %q", id)
	}
	if st.Catalog[i].Status != "supported" {
		return Request{}, fmt.Errorf("%s is coming soon and cannot be protected yet", st.Catalog[i].Name)
	}
	ids := toggled(st.Catalog, st.Services, id)
	if len(ids) == 0 {
		return PauseRequest(), nil
	}
	if st.VPNInterface == "" {
		return Request{}, errors.New("Choose a VPN interface first")
	}
	return Request{VPNInterface: st.VPNInterface, Services: ids}, nil
}

// ChooseVPN is the request for a click on VPN interface name: the same
// services through name.
func ChooseVPN(st ipc.Status, name string) (Request, error) {
	if len(st.Services) == 0 {
		return Request{}, fmt.Errorf("Tick a service to protect through %s", name)
	}
	return Request{VPNInterface: name, Services: slices.Clone(st.Services)}, nil
}

// PauseRequest is the request for "Pause protection".
func PauseRequest() Request {
	return Request{Pause: true}
}

// ResumeRequest is the request for "Resume protection": the saved choice.
func ResumeRequest(st ipc.Status) (Request, error) {
	if st.VPNInterface == "" || len(st.Services) == 0 {
		return Request{}, errors.New("Nothing to resume: choose a VPN interface and a service")
	}
	return Request{VPNInterface: st.VPNInterface, Services: slices.Clone(st.Services)}, nil
}

// SetupNeeded reports whether "Set up leakguard…" may run after a fresh
// status check returned err: only when the daemon is still unavailable.
func SetupNeeded(err error) bool {
	return errors.Is(err, ipc.ErrDaemonUnavailable)
}

// notAuthorized is the daemon's answer to a peer that is not an administrator.
const notAuthorized = "not authorized"

// Explain turns an error from the daemon or the socket into a short sentence
// for the user.
func Explain(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ipc.ErrDaemonUnavailable):
		return "leakguard is not set up on this Mac (its background service is not running)"
	case err.Error() == notAuthorized, errors.Is(err, fs.ErrPermission):
		return "Only administrators can change leakguard"
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "The leakguard background service did not answer; try again"
	}
	return "Could not change leakguard: " + firstLine(err.Error())
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}
