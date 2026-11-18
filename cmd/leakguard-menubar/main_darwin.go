//go:build darwin

// Command leakguard-menubar is the macOS menu-bar app. It shows whether the
// chosen services are protected, guides the first setup in three steps with
// native dialogs, and lets an administrator tick services, change the VPN and
// pause the protection. It only talks to the root daemon over its socket:
// quitting the app never stops the protection.
package main

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/systray"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/ipc"
	"github.com/Isaacpaezz/leakguard/internal/menubar"
)

const (
	pollEvery = 3 * time.Second
	// lineLength bounds the status and error lines, in characters.
	lineLength = 70
)

func main() {
	a := &app{
		client:  ipc.Client{Path: ipc.DefaultPath},
		actions: make(chan action),
		lang:    macLanguage(),
	}
	a.catalog, a.catalogErr = catalog.Embedded()
	systray.Run(a.ready, func() {})
}

// macLanguage is the language of the Mac's first preferred language.
func macLanguage() menubar.Lang {
	out, _ := exec.Command("/usr/bin/defaults", "read", "-g", "AppleLanguages").Output()
	return menubar.ParseLang(string(out))
}

type actionKind int

const (
	actService actionKind = iota
	actToggle
	actSetUp
	actChangeVPN
	actWizardDone
)

type action struct {
	kind actionKind
	arg  string
}

// app keeps the state; only its loop goroutine reads or changes it.
type app struct {
	client  ipc.Client
	actions chan action
	lang    menubar.Lang

	st      *ipc.Status
	stErr   error
	errLine string
	// errFresh is set when the click just handled wrote errLine, so the
	// poll right after it keeps the line (see menubar.ErrorLineAfterPoll).
	errFresh bool
	menu     menubar.Menu
	icon     menubar.State

	// wizardOpen is set while the setup or "Change VPN" dialogs run in
	// their own goroutine: one at a time, and polling goes on meanwhile.
	wizardOpen bool
	// autoOpened is set once the setup opened by itself on this launch.
	autoOpened bool

	catalog    []catalog.Service
	catalogErr error

	layout string
	done   chan struct{}
	items  items
}

type items struct {
	status, errLine, setUp, changeVPN, toggle, quit *systray.MenuItem
	services                                        map[string]*systray.MenuItem
}

func (a *app) ready() {
	systray.SetTemplateIcon(iconNotSetUp, iconNotSetUp)
	systray.SetTooltip("leakguard")
	go a.loop()
}

// loop serializes polling, clicks and drawing, so at most one request is in
// flight and the menu always matches the last answer.
func (a *app) loop() {
	a.poll()
	tick := time.NewTicker(pollEvery)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			a.poll()
		case act := <-a.actions:
			a.handle(act)
			a.poll()
		}
	}
}

func (a *app) poll() {
	st, err := a.client.Status()
	if err != nil {
		a.st, a.stErr = nil, err
	} else {
		a.st, a.stErr = &st, nil
	}
	a.errLine = menubar.ErrorLineAfterPoll(a.errLine, a.errFresh, err)
	a.errFresh = false
	a.draw()
	// The first time leakguard is found not set up (or an older install
	// needs updating), the setup opens by itself, once per launch.
	if !a.autoOpened && a.menu.SetUp && a.catalogErr == nil {
		a.autoOpened = true
		a.startSetUp()
	}
}

func (a *app) handle(act action) {
	a.errFresh = true
	switch act.kind {
	case actSetUp:
		a.startSetUp()
		return
	case actChangeVPN:
		a.startChangeVPN()
		return
	case actWizardDone:
		a.wizardOpen = false
		a.errLine = act.arg
		return
	}
	if a.st == nil {
		a.errLine = menubar.Explain(a.lang, a.stErr)
		return
	}
	if a.menu.State == menubar.StateNotSetUp {
		return
	}
	var req menubar.Request
	var err error
	switch act.kind {
	case actService:
		req, err = menubar.ToggleService(a.lang, *a.st, act.arg)
	case actToggle:
		if a.menu.Toggle.Resume {
			req, err = menubar.ResumeRequest(a.lang, *a.st)
		} else {
			req = menubar.PauseRequest()
		}
	}
	if err != nil {
		a.errLine = err.Error()
		return
	}
	if req.Pause {
		_, err = a.client.Pause()
	} else {
		_, err = a.client.Set(req.VPNInterface, req.Services)
	}
	a.errLine = ""
	if err != nil {
		a.errLine = menubar.Explain(a.lang, err)
	}
}

func (a *app) notSetUp() bool {
	return errors.Is(a.stErr, ipc.ErrDaemonUnavailable)
}

func (a *app) wizard(needsPassword bool) menubar.Wizard {
	return menubar.Wizard{
		Lang:          a.lang,
		Dialogs:       osaDialogs{},
		Catalog:       a.catalog,
		ConnectedVPNs: connectedVPNCandidates,
		NeedsPassword: needsPassword,
	}
}

// startSetUp opens the 3-step setup. Without the daemon, step 3 runs
// "leakguard enable" once through the macOS administrator prompt; with a
// daemon that has no choice yet, it saves the choice without a password.
func (a *app) startSetUp() {
	if a.wizardOpen || !a.menu.SetUp || a.catalogErr != nil {
		return
	}
	a.wizardOpen = true
	w := a.wizard(a.notSetUp())
	client, lang, all := a.client, a.lang, a.catalog
	go func() {
		w.Run(func(d menubar.Draft) error {
			if w.NeedsPassword {
				return install(client, lang, all, d)
			}
			return save(client, lang, d)
		})
		a.actions <- action{kind: actWizardDone}
	}()
}

// startChangeVPN runs step 2 again and saves the VPN through the daemon.
func (a *app) startChangeVPN() {
	if a.wizardOpen || !a.menu.ChangeVPN {
		return
	}
	a.wizardOpen = true
	w := a.wizard(false)
	client, lang := a.client, a.lang
	go func() {
		w.ChangeVPN(func(vpn string) error {
			st, err := client.Status()
			if err != nil {
				return errors.New(menubar.Explain(lang, err))
			}
			req, err := menubar.ChangeVPNRequest(lang, st, vpn)
			if err != nil {
				return err
			}
			return save(client, lang, menubar.Draft{VPNInterface: req.VPNInterface, Services: req.Services})
		})
		a.actions <- action{kind: actWizardDone}
	}()
}

// save sends d to the running daemon, which needs no password.
func save(client ipc.Client, lang menubar.Lang, d menubar.Draft) error {
	if _, err := client.Set(d.VPNInterface, d.Services); err != nil {
		return errors.New(menubar.Explain(lang, err))
	}
	return nil
}

// install runs "leakguard enable" for d once with administrator rights.
func install(client ipc.Client, lang menubar.Lang, all []catalog.Service, d menubar.Draft) error {
	// The daemon may have come up since the wizard opened: then it saves the
	// choice and no password is needed.
	_, err := client.Status()
	if !menubar.SetupNeeded(err) {
		return save(client, lang, d)
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		exe = ""
	}
	cli, err := menubar.FindCLI(exe, menubar.InstalledState(""), isExecutable, menubar.CheckInstalledCLI)
	if err != nil {
		return errors.New(menubar.Explain(lang, err))
	}
	script, err := menubar.SetupScript(cli, d, all, menubar.AdminPrompt(lang))
	if err != nil {
		return err
	}
	_, err = runScript(script)
	return err
}

// osaDialogs draws the wizard with osascript: "display dialog" and "choose
// from list". Cancelling returns menubar.ErrCancelled.
type osaDialogs struct{}

func (osaDialogs) Ask(d menubar.Dialog) (int, error) {
	out, err := runScript(menubar.DialogScript(d))
	if err != nil {
		return 0, err
	}
	return menubar.ParseButton(out, d)
}

func (osaDialogs) Choose(l menubar.List) ([]int, error) {
	out, err := runScript(menubar.ListScript(l))
	if err != nil {
		return nil, err
	}
	return menubar.ParseChoice(out, l)
}

// runScript runs an AppleScript with osascript and returns what it printed.
func runScript(script string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("/usr/bin/osascript", "-e", script)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", menubar.ScriptError(stderr.String()+stdout.String(), err)
	}
	return stdout.String(), nil
}

func isExecutable(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// connectedVPNCandidates are the VPN candidates that are up with an address.
// macOS keeps system tunnels (utun0-3) up without an address; they are never
// the user's VPN.
func connectedVPNCandidates() []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var names []string
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			n, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap().IsGlobalUnicast() {
				names = append(names, i.Name)
				break
			}
		}
	}
	return config.VPNCandidates(names)
}

func (a *app) draw() {
	setup := menubar.Setup{Catalog: a.catalog, Lang: a.lang}
	if a.notSetUp() {
		setup.Update = menubar.InstalledState("") == menubar.InstallOld
	}
	m := menubar.Build(a.st, a.stErr, setup)
	if m.State == menubar.StateNotSetUp && a.catalogErr != nil {
		m.Status = a.lang.Text(menubar.MsgCatalogError, a.catalogErr.Error())
		m.SetUp = false
	}
	a.menu = m

	if m.State != a.icon {
		a.icon = m.State
		switch m.State {
		case menubar.StateProtected:
			systray.SetTemplateIcon(iconProtected, iconProtected)
		case menubar.StateNotSetUp:
			systray.SetTemplateIcon(iconNotSetUp, iconNotSetUp)
		default:
			systray.SetTemplateIcon(iconOutline, iconOutline)
		}
	}
	systray.SetTooltip(m.Tooltip)

	if key := layoutKey(m); key != a.layout {
		a.rebuild(m)
		a.layout = key
	}
	it := a.items
	it.status.SetTitle(menubar.Short(m.Status, lineLength))
	if a.errLine != "" {
		it.errLine.SetTitle(menubar.Short(a.errLine, lineLength))
		it.errLine.Show()
	} else {
		it.errLine.Hide()
	}
	for _, s := range m.Services {
		item := it.services[s.ID]
		item.SetTitle(s.Label)
		setChecked(item, s.Checked)
		setEnabled(item, s.Enabled)
	}
	if it.setUp != nil {
		setEnabled(it.setUp, !a.wizardOpen)
	}
	if it.changeVPN != nil {
		setEnabled(it.changeVPN, !a.wizardOpen)
	}
	if it.toggle != nil {
		it.toggle.SetTitle(m.Toggle.Label)
	}
}

// layoutKey changes when items must be added or removed.
func layoutKey(m menubar.Menu) string {
	var b strings.Builder
	b.WriteString(string(m.State))
	for _, s := range m.Services {
		b.WriteString("|s:" + s.ID)
	}
	if m.ChangeVPN {
		b.WriteString("|vpn")
	}
	if m.Toggle.Visible {
		b.WriteString("|toggle")
	}
	if m.SetUp {
		b.WriteString("|setup")
	}
	return b.String()
}

// rebuild recreates the menu in order. Items keep their place because
// systray appends new items at the end.
func (a *app) rebuild(m menubar.Menu) {
	if a.done != nil {
		close(a.done)
	}
	a.done = make(chan struct{})
	systray.ResetMenu()
	l := a.lang

	it := items{services: map[string]*systray.MenuItem{}}
	it.status = systray.AddMenuItem("", "")
	it.status.Disable()
	it.errLine = systray.AddMenuItem("", l.Text(menubar.MsgMenuErrorTip))
	it.errLine.Disable()
	systray.AddSeparator()
	if m.SetUp {
		it.setUp = systray.AddMenuItem(l.Text(menubar.MsgMenuSetUp), l.Text(menubar.MsgMenuSetUpTip))
		a.forward(it.setUp, action{kind: actSetUp})
	}
	if len(m.Services) > 0 {
		header := systray.AddMenuItem(l.Text(menubar.MsgMenuServicesHeader), "")
		header.Disable()
		for _, s := range m.Services {
			item := systray.AddMenuItemCheckbox(s.Label, l.Text(menubar.MsgMenuServiceTip), s.Checked)
			it.services[s.ID] = item
			a.forward(item, action{kind: actService, arg: s.ID})
		}
	}
	if m.ChangeVPN || m.Toggle.Visible {
		systray.AddSeparator()
	}
	if m.ChangeVPN {
		it.changeVPN = systray.AddMenuItem(l.Text(menubar.MsgMenuChangeVPN), l.Text(menubar.MsgMenuChangeVPNTip))
		a.forward(it.changeVPN, action{kind: actChangeVPN})
	}
	if m.Toggle.Visible {
		it.toggle = systray.AddMenuItem(m.Toggle.Label, l.Text(menubar.MsgMenuToggleTip))
		a.forward(it.toggle, action{kind: actToggle})
	}
	systray.AddSeparator()
	it.quit = systray.AddMenuItem(l.Text(menubar.MsgMenuQuit), l.Text(menubar.MsgMenuQuitTip))
	done := a.done
	go func() {
		select {
		case <-it.quit.ClickedCh:
			systray.Quit()
		case <-done:
		}
	}()
	a.items = it
}

// forward sends act to the loop on each click, until the next rebuild.
func (a *app) forward(item *systray.MenuItem, act action) {
	done := a.done
	go func() {
		for {
			select {
			case <-item.ClickedCh:
				select {
				case a.actions <- act:
				case <-done:
					return
				}
			case <-done:
				return
			}
		}
	}()
}

func setChecked(item *systray.MenuItem, on bool) {
	if on != item.Checked() {
		if on {
			item.Check()
		} else {
			item.Uncheck()
		}
	}
}

func setEnabled(item *systray.MenuItem, on bool) {
	if on == item.Disabled() {
		if on {
			item.Enable()
		} else {
			item.Disable()
		}
	}
}
