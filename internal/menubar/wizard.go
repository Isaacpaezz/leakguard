package menubar

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/config"
)

// ErrCancelled means the user cancelled a dialog or the administrator
// prompt. It is never shown as an error.
var ErrCancelled = errors.New("cancelled")

// errNoServices: the catalog has nothing to protect yet; step 1 already
// said so.
var errNoServices = errors.New("no supported services in the catalog")

// stepError is a failure the wizard names with msg ("Could not turn on the
// protection: %s") instead of the general "Something went wrong: %s".
type stepError struct {
	msg Msg
	err error
}

func (e stepError) Error() string { return e.err.Error() }
func (e stepError) Unwrap() error { return e.err }

// WizardMessage is what the user reads after the wizard returned err: the
// failure in plain words in language l, ending with "You can try again from
// the menu.". Its first line fits the menu's error line. A cancel, or no
// error, says nothing.
func WizardMessage(l Lang, err error) string {
	if err == nil || errors.Is(err, ErrCancelled) {
		return ""
	}
	if errors.Is(err, errNoServices) {
		return l.Text(msgStep1NoServices)
	}
	msg := msgWizardFailed
	var se stepError
	if errors.As(err, &se) {
		msg, err = se.msg, se.err
	}
	return l.Text(msg, explainDetail(l, err))
}

// Dialog is a message with buttons. Default is the index of the button that
// Return clicks; Cancel is the index of the button that cancels (Escape), or
// -1 for none.
type Dialog struct {
	Title   string
	Text    string
	Buttons []string
	Default int
	Cancel  int
}

// List asks the user to choose one item, or several when Multiple is set.
type List struct {
	Title    string
	Text     string
	Items    []string
	OK       string
	Cancel   string
	Multiple bool
}

// Dialogs shows native dialogs. Both methods return ErrCancelled when the
// user cancels; Ask returns the index of the clicked button and Choose the
// indexes of the chosen items.
type Dialogs interface {
	Ask(Dialog) (int, error)
	Choose(List) ([]int, error)
}

// Wizard is the 3-step setup: what to protect, find the VPN, turn the
// protection on. It has no GUI of its own: Dialogs draws it.
type Wizard struct {
	Lang    Lang
	Dialogs Dialogs
	// Catalog offers its supported services; planned ones are only named.
	Catalog []catalog.Service
	// ConnectedVPNs returns the VPN interfaces connected right now.
	ConnectedVPNs func() []string
	// NeedsPassword is set when step 3 installs the background service with
	// the administrator prompt; otherwise the running service saves the
	// choice and no password is asked.
	NeedsPassword bool
}

// Run walks the user through the three steps and then calls activate once
// with a complete, validated choice. Cancelling any step returns
// ErrCancelled before activate is called: nothing partial is ever sent.
// After activate it says, in plain words, whether it worked; any other
// failure (a dialog that fails, an unexpected answer, a refused choice) is
// said too, with WizardMessage.
func (w Wizard) Run(activate func(Draft) error) error {
	return w.report(w.run(activate))
}

func (w Wizard) run(activate func(Draft) error) error {
	services, err := w.chooseServices()
	if err != nil {
		return err
	}
	vpn, err := w.findVPN(w.Lang.Text(msgStepTitle, 2), msgButtonNext)
	if err != nil {
		return err
	}
	d := Draft{VPNInterface: vpn, Services: services}
	if err := (config.Config{VPNInterface: d.VPNInterface, Services: d.Services}).Validate(w.Catalog); err != nil {
		return invalidChoice(err)
	}
	names := w.Lang.list(w.names(services))
	step3 := msgStep3NoPassword
	if w.NeedsPassword {
		step3 = msgStep3Password
	}
	if err := w.next(w.Lang.Text(msgStepTitle, 3), w.Lang.Text(step3, names), msgButtonActivate); err != nil {
		return err
	}
	if err := activate(d); err != nil {
		return stepError{msgActivateFailed, err}
	}
	done := w.Lang.Text(msgDoneMany, names)
	if len(services) == 1 {
		done = w.Lang.Text(msgDoneOne, names, names)
	}
	w.tell(done + "\n\n" + w.Lang.Text(msgDoneShield))
	return nil
}

// ChangeVPN runs step 2 only and calls save with the VPN found. Cancelling
// returns ErrCancelled without calling save; any failure is said with
// WizardMessage.
func (w Wizard) ChangeVPN(save func(vpn string) error) error {
	vpn, err := w.findVPN(w.Lang.Text(msgChangeVPNTitle), msgButtonUseVPN)
	if err != nil {
		return w.report(err)
	}
	if err := save(vpn); err != nil {
		return w.report(stepError{msgChangeVPNFailed, err})
	}
	w.tell(w.Lang.Text(msgChangeVPNDone))
	return nil
}

// report shows err in plain words, unless it is a cancel or was already
// said, and returns it.
func (w Wizard) report(err error) error {
	if !errors.Is(err, errNoServices) {
		if msg := WizardMessage(w.Lang, err); msg != "" {
			w.tell(msg)
		}
	}
	return err
}

// AdminPrompt is the short reason the macOS password dialog shows.
func AdminPrompt(l Lang) string {
	return l.Text(msgAdminPrompt)
}

// chooseServices is step 1: the supported services, in catalog order.
func (w Wizard) chooseServices() ([]string, error) {
	var supported, planned []catalog.Service
	for _, s := range w.Catalog {
		switch s.Status {
		case catalog.StatusSupported:
			supported = append(supported, s)
		case catalog.StatusPlanned:
			planned = append(planned, s)
		}
	}
	soon := ""
	if len(planned) > 0 {
		var names []string
		for _, s := range planned {
			names = append(names, s.Name)
		}
		soon = "\n\n" + w.Lang.Text(msgStep1ComingSoon, w.Lang.list(names))
	}
	if len(supported) == 0 {
		w.tell(w.Lang.Text(msgStep1NoServices) + soon)
		return nil, errNoServices
	}
	items := make([]string, len(supported))
	for i, s := range supported {
		items[i] = s.Name
	}
	picks, err := w.Dialogs.Choose(List{
		Title:    w.Lang.Text(msgStepTitle, 1),
		Text:     w.Lang.Text(msgStep1) + soon,
		Items:    items,
		OK:       w.Lang.Text(msgButtonNext),
		Cancel:   w.Lang.Text(msgButtonCancel),
		Multiple: true,
	})
	if err != nil {
		return nil, err
	}
	if len(picks) == 0 {
		return nil, ErrCancelled
	}
	var ids []string
	for i, s := range supported {
		if slices.Contains(picks, i) {
			ids = append(ids, s.ID)
		}
	}
	return ids, nil
}

// findVPN is step 2: the VPN is the one interface that appears between a
// snapshot with the VPN disconnected and one with it connected. The user
// sees its kind ("VPN IPsec") and may choose another from the connected
// VPNs. With none, the user may retry or choose from the connected VPNs;
// with several, the user chooses. It never guesses.
func (w Wizard) findVPN(title string, accept Msg) (string, error) {
	for {
		if err := w.next(title, w.Lang.Text(msgStep2Disconnect), msgButtonNext); err != nil {
			return "", err
		}
		before := vpnNames(w.ConnectedVPNs())
		if err := w.next(title, w.Lang.Text(msgStep2Connect), msgButtonNext); err != nil {
			return "", err
		}
		after := vpnNames(w.ConnectedVPNs())
		var fresh []string
		for _, n := range after {
			if !slices.Contains(before, n) {
				fresh = append(fresh, n)
			}
		}
		switch len(fresh) {
		case 1:
			b, err := w.Dialogs.Ask(Dialog{
				Title:   title,
				Text:    w.Lang.Text(msgStep2Found, w.Lang.Text(vpnKind(fresh[0]))),
				Buttons: []string{w.Lang.Text(msgButtonCancel), w.Lang.Text(msgButtonChooseAnother), w.Lang.Text(accept)},
				Default: 2,
				Cancel:  0,
			})
			switch {
			case err != nil:
				return "", err
			case b == 2:
				return fresh[0], nil
			case b == 1:
				return w.pickVPN(title, after)
			}
			return "", ErrCancelled
		case 0:
			b, err := w.Dialogs.Ask(Dialog{
				Title:   title,
				Text:    w.Lang.Text(msgStep2None),
				Buttons: []string{w.Lang.Text(msgButtonCancel), w.Lang.Text(msgButtonList), w.Lang.Text(msgButtonRetry)},
				Default: 2,
				Cancel:  0,
			})
			switch {
			case err != nil:
				return "", err
			case b == 0:
				return "", ErrCancelled
			case b == 2:
				continue
			}
			fresh = vpnNames(w.ConnectedVPNs())
		}
		if len(fresh) == 0 {
			if err := w.next(title, w.Lang.Text(msgStep2NoneConnected), msgButtonRetry); err != nil {
				return "", err
			}
			continue
		}
		return w.pickVPN(title, fresh)
	}
}

func (w Wizard) pickVPN(title string, names []string) (string, error) {
	picks, err := w.Dialogs.Choose(List{
		Title:  title,
		Text:   w.Lang.Text(msgStep2List),
		Items:  VPNLabels(w.Lang, names),
		OK:     w.Lang.Text(msgButtonNext),
		Cancel: w.Lang.Text(msgButtonCancel),
	})
	if err != nil {
		return "", err
	}
	if len(picks) != 1 || picks[0] < 0 || picks[0] >= len(names) {
		return "", ErrCancelled
	}
	return names[picks[0]], nil
}

// next shows text with [Cancel] and the button named by ok; anything but ok
// is a cancel.
func (w Wizard) next(title, text string, ok Msg) error {
	b, err := w.Dialogs.Ask(Dialog{
		Title:   title,
		Text:    text,
		Buttons: []string{w.Lang.Text(msgButtonCancel), w.Lang.Text(ok)},
		Default: 1,
		Cancel:  0,
	})
	if err != nil {
		return err
	}
	if b != 1 {
		return ErrCancelled
	}
	return nil
}

// tell shows a message with only [OK].
func (w Wizard) tell(text string) {
	w.Dialogs.Ask(Dialog{
		Title:   w.Lang.Text(msgAppTitle),
		Text:    text,
		Buttons: []string{w.Lang.Text(msgButtonOK)},
		Default: 0,
		Cancel:  -1,
	})
}

func (w Wizard) names(ids []string) []string {
	var names []string
	for _, id := range ids {
		if s, ok := catalog.Find(w.Catalog, id); ok {
			names = append(names, s.Name)
		}
	}
	return names
}

// vpnNames keeps the plain VPN interface names, each once: a real
// connection or an unsafe name is never offered.
func vpnNames(names []string) []string {
	var out []string
	for _, n := range config.VPNCandidates(names) {
		if config.CheckVPNInterface(n) == nil && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// VPNLabels names VPN interfaces for the fallback list: a friendly kind,
// numbered when several share it, with the technical name in parentheses.
func VPNLabels(l Lang, names []string) []string {
	kinds := make([]string, len(names))
	count := map[string]int{}
	for i, n := range names {
		kinds[i] = l.Text(vpnKind(n))
		count[kinds[i]]++
	}
	seen := map[string]int{}
	labels := make([]string, len(names))
	for i, n := range names {
		k := kinds[i]
		if count[k] > 1 {
			seen[k]++
			k = fmt.Sprintf("%s %d", k, seen[k])
		}
		labels[i] = k + " (" + n + ")"
	}
	return labels
}

func vpnKind(name string) Msg {
	switch {
	case strings.HasPrefix(name, "ipsec"):
		return msgKindIPsec
	case strings.HasPrefix(name, "wg"):
		return msgKindWireGuard
	case strings.HasPrefix(name, "ppp"):
		return msgKindPPP
	}
	return msgKindVPN
}
