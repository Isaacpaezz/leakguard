// Package menubar is the logic of the menu-bar app, without any GUI: it turns
// the daemon's status into a menu description, turns each click into the
// request to send, and runs the 3-step setup wizard through an injected
// dialog driver. cmd/leakguard-menubar only draws what it returns.
package menubar

import (
	"errors"
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

// Menu describes everything the app shows. Interface names appear only in
// Tooltip.
type Menu struct {
	State State
	// Status is the first, informational line of the menu.
	Status string
	// Tooltip is the icon's tooltip, with the technical details.
	Tooltip  string
	Services []ServiceItem
	// ChangeVPN shows "Change VPN…" (step 2 of the wizard, no password).
	ChangeVPN bool
	Toggle    ToggleItem
	// SetUp shows "Set up leakguard (3 steps)…": while leakguard is not set
	// up, the menu is only the status, this item and Quit.
	SetUp bool
}

// Draft is a complete choice to protect: what the wizard returns and what
// SetupScript installs.
type Draft struct {
	VPNInterface string
	Services     []string
}

// Setup is what Build needs besides the status.
type Setup struct {
	Catalog []catalog.Service
	// Update is set when an older leakguard is installed: its background
	// service predates the socket, so the wizard updates it.
	Update bool
	Lang   Lang
}

// ServiceItem is one catalog service.
type ServiceItem struct {
	ID      string
	Label   string
	Checked bool
	Enabled bool
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

// Build describes the menu for a status, or for the error that replaced it.
// It never reports protected unless the daemon verified it.
func Build(st *ipc.Status, err error, setup Setup) Menu {
	l := setup.Lang
	var m Menu
	switch {
	case errors.Is(err, ipc.ErrDaemonUnavailable):
		m = notSetUp(l, setup.Update)
		m.Tooltip = l.Text(msgTooltip, Explain(l, err))
		return m
	case err != nil:
		m = Menu{State: StateNotProtected, Status: Explain(l, err)}
	case st == nil:
		m = Menu{State: StateNotProtected, Status: l.Text(msgStatusChecking)}
	case st.VPNInterface == "" || len(st.Services) == 0:
		m = notSetUp(l, false)
	default:
		return configured(l, *st)
	}
	m.Tooltip = l.Text(msgTooltip, m.Status)
	return m
}

func notSetUp(l Lang, update bool) Menu {
	m := Menu{State: StateNotSetUp, Status: l.Text(msgStatusNotSetUp), SetUp: true}
	if update {
		m.Status = l.Text(msgStatusUpdate)
	}
	return m
}

// configured is the menu once the daemon has a VPN and services.
func configured(l Lang, st ipc.Status) Menu {
	m := Menu{
		Services:  serviceItems(l, st),
		ChangeVPN: true,
		Toggle:    ToggleItem{Visible: true, Label: l.Text(MsgMenuPause)},
	}
	reason := ""
	switch {
	case st.Protected && st.VPNConnected:
		m.State, m.Status = StateProtected, l.Text(msgStatusProtected)
	case st.Protected:
		m.State, m.Status = StateProtected, l.Text(msgStatusProtectedOffline)
	case st.Reason == ipc.ReasonPaused:
		m.State, m.Status = StatePaused, l.Text(msgStatusPaused)
		m.Toggle = ToggleItem{Visible: true, Resume: true, Label: l.Text(MsgMenuResume)}
	case !st.VPNConnected:
		m.State, m.Status = StateNotProtected, l.Text(msgStatusOffline)
		reason = firstLine(st.Reason)
	default:
		m.State, m.Status = StateNotProtected, l.Text(msgStatusNotProtected)
		reason = firstLine(st.Reason)
	}
	m.Tooltip = l.Text(msgTooltipVPN, l.Text(msgTooltip, m.Status), st.VPNInterface)
	if reason != "" {
		m.Tooltip = l.Text(msgTooltipReason, m.Tooltip, reason)
	}
	return m
}

func serviceItems(l Lang, st ipc.Status) []ServiceItem {
	items := make([]ServiceItem, 0, len(st.Catalog))
	for _, s := range st.Catalog {
		item := ServiceItem{
			ID:      s.ID,
			Label:   s.Name,
			Checked: slices.Contains(st.Services, s.ID),
			Enabled: s.Status == string(catalog.StatusSupported),
		}
		if s.Status == string(catalog.StatusPlanned) {
			item.Label = l.Text(msgComingSoonItem, s.Name)
		}
		items = append(items, item)
	}
	return items
}

// ToggleService is the request for a click on service id while the daemon
// has a saved choice. Unticking the last service pauses instead of sending
// an empty list, which the daemon refuses. Without a saved VPN nothing is
// sent: the wizard sets it up first.
func ToggleService(l Lang, st ipc.Status, id string) (Request, error) {
	i := slices.IndexFunc(st.Catalog, func(s ipc.Service) bool { return s.ID == id })
	if i < 0 {
		return Request{}, errors.New(l.Text(msgErrUnknownService, id))
	}
	if st.Catalog[i].Status != string(catalog.StatusSupported) {
		return Request{}, errors.New(l.Text(msgErrComingSoon, st.Catalog[i].Name))
	}
	if st.VPNInterface == "" {
		return Request{}, errors.New(l.Text(msgErrNotSetUp))
	}
	ids := toggled(st.Catalog, st.Services, id)
	if len(ids) == 0 {
		return PauseRequest(), nil
	}
	return Request{VPNInterface: st.VPNInterface, Services: ids}, nil
}

// ChangeVPNRequest is the request that protects the saved services through
// vpn, the VPN "Change VPN…" found. It needs a saved choice and a plain VPN
// interface name.
func ChangeVPNRequest(l Lang, st ipc.Status, vpn string) (Request, error) {
	if len(st.Services) == 0 {
		return Request{}, errors.New(l.Text(msgErrNotSetUp))
	}
	if err := config.CheckVPNInterface(vpn); err != nil {
		return Request{}, invalidChoice(err)
	}
	return Request{VPNInterface: vpn, Services: slices.Clone(st.Services)}, nil
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

// ErrorLineAfterPoll is the menu's error line after a status poll that
// returned err. A line set by the click just handled (fresh) stays for the
// poll right after it; an older one is cleared once the daemon answers
// again, so a past failure does not stay on the menu.
func ErrorLineAfterPoll(line string, fresh bool, err error) string {
	if fresh || err != nil {
		return line
	}
	return ""
}

// PauseRequest is the request for "Pause protection".
func PauseRequest() Request {
	return Request{Pause: true}
}

// ResumeRequest is the request for "Resume protection": the saved choice.
func ResumeRequest(l Lang, st ipc.Status) (Request, error) {
	if st.VPNInterface == "" || len(st.Services) == 0 {
		return Request{}, errors.New(l.Text(msgErrNothingToResume))
	}
	return Request{VPNInterface: st.VPNInterface, Services: slices.Clone(st.Services)}, nil
}

// SetupNeeded reports whether the administrator setup may run after a fresh
// status check returned err: only when the daemon is still unavailable.
func SetupNeeded(err error) bool {
	return errors.Is(err, ipc.ErrDaemonUnavailable)
}

// Explain turns an error from the daemon, the socket, FindCLI, SetupScript,
// a choice check or the dialog driver into a short sentence for the user, in
// language l.
func Explain(l Lang, err error) string {
	if err == nil {
		return ""
	}
	if s, ok := explainKnown(l, err); ok {
		return s
	}
	return l.Text(msgExplainOther, firstLine(err.Error()))
}

// explainDetail is Explain without the "Could not change leakguard" prefix
// for an error it does not know: the caller's message says what failed.
func explainDetail(l Lang, err error) string {
	if s, ok := explainKnown(l, err); ok {
		return s
	}
	return firstLine(err.Error())
}

func explainKnown(l Lang, err error) (string, bool) {
	var m Msg
	switch {
	case errors.Is(err, ipc.ErrDaemonUnavailable):
		m = msgExplainNotSetUp
	case errors.Is(err, ipc.ErrNotAuthorized), errors.Is(err, fs.ErrPermission):
		m = msgExplainNotAuthorized
	case errors.Is(err, os.ErrDeadlineExceeded):
		m = msgExplainTimeout
	case errors.Is(err, ErrCLINotRootOwned):
		m = msgCLINotRootOwned
	case errors.Is(err, ErrCLIUpdate):
		m = msgCLIUpdate
	case errors.Is(err, ErrNoCLI):
		m = msgCLIMissing
	case errors.Is(err, ErrUnsafeCLIPath):
		m = msgErrUnsafeCLIPath
	case errors.Is(err, ErrInvalidChoice):
		m = msgErrInvalidChoice
	case errors.Is(err, ErrUnexpectedAnswer):
		m = msgErrUnexpectedAnswer
	default:
		return "", false
	}
	return l.Text(m), true
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}

// ShouldAutoOpen reports whether the setup opens by itself after a status
// poll that returned err. It does only on the first poll of this launch
// (firstPoll), when the daemon never answered (everAnswered), is
// unavailable, and no current install exists (inst is InstallNone, or
// InstallOld, which needs updating). A daemon that restarts later, or one
// that is installed but still starting, never opens it: the menu only shows
// the status.
func ShouldAutoOpen(firstPoll, everAnswered bool, err error, inst Install) bool {
	return firstPoll && !everAnswered && errors.Is(err, ipc.ErrDaemonUnavailable) && inst != InstallCurrent
}

// kindError keeps err's text for the logs and tests and adds kind, a
// sentinel Explain recognises, so the user reads it in their language.
type kindError struct{ kind, err error }

func (e kindError) Error() string   { return e.err.Error() }
func (e kindError) Unwrap() []error { return []error{e.kind, e.err} }

// invalidChoice marks a VPN or service choice that config refused.
func invalidChoice(err error) error {
	if err == nil {
		return nil
	}
	return kindError{ErrInvalidChoice, err}
}
