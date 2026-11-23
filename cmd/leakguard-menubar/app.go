//go:build darwin || linux

// Command leakguard-menubar is the menu-bar app on macOS and the tray app on
// Linux. It shows whether the chosen services are protected, guides the
// first setup in three steps with native dialogs, and lets an administrator
// tick services, change the VPN and pause the protection. It only talks to
// the root daemon over its socket: quitting the app never stops the
// protection. Everything that differs between systems is in platform.
package main

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/systray"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/ipc"
	"github.com/Isaacpaezz/leakguard/internal/menubar"
	"github.com/Isaacpaezz/leakguard/internal/version"
)

const (
	pollEvery = 3 * time.Second
	// lineLength bounds the status, session, today and error lines, in runes.
	lineLength = menubar.MenuLineLength
)

// platform is what differs between macOS and Linux: dialogs, icons, the
// installed state, the administrator prompt and the login item.
type platform interface {
	// dialogs draws the wizard and the uninstall.
	dialogs() menubar.Dialogs
	// setIcon shows the icon for state.
	setIcon(state menubar.State)
	// installed reads what the background service definition says.
	installed() menubar.Install
	// setUp runs "leakguard enable" for d once with administrator rights;
	// disable runs "leakguard disable" the same way. Their errors stay as
	// they are: the wizard says them in the user's language.
	setUp(lang menubar.Lang, all []catalog.Service, d menubar.Draft) error
	disable(lang menubar.Lang) error
	// loginMenu is what the menu offers for opening at login; the other
	// login item methods follow the menubar functions of each system.
	loginMenu() menubar.LoginMenuItem
	syncLoginItem() (bool, error)
	setOpenAtLogin(on bool) error
	removeLoginItem() error
	loginItemPresent() bool
	// mustMove reports whether the app must be moved before setup and
	// uninstall (macOS only); guardMove then tells the user so.
	mustMove() bool
	guardMove(lang menubar.Lang)
}

func main() {
	a := &app{
		client:  ipc.Client{Path: ipc.DefaultPath},
		actions: make(chan action),
		lang:    language(),
	}
	a.catalog, a.catalogErr = catalog.Embedded()
	a.exe = executable()
	a.home, _ = os.UserHomeDir()
	a.plat = newPlatform(a.exe, a.home)
	a.loginMenu = a.plat.loginMenu()
	if a.loginMenu == menubar.LoginItemToggle {
		// Written, never loaded: the system opens the app at the next login,
		// and no second copy starts now.
		on, err := a.plat.syncLoginItem()
		a.openAtLogin = on
		if err != nil {
			a.errLine = a.lang.Text(menubar.MsgLoginItemFailed, err.Error())
			a.errFresh = true
		}
	}
	systray.Run(a.ready, func() {})
}

// executable is the absolute path of this app, with symlinks resolved, or
// "" when it cannot be known.
func executable() string {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return ""
	}
	return exe
}

type actionKind int

const (
	actService actionKind = iota
	actToggle
	actSetUp
	actChangeVPN
	actWizardDone
	actOpenAtLogin
	actUninstall
	actUninstallDone
)

// action is a click, or the end of the wizard. service is the clicked
// service's ID; err is what the wizard returned (nil, a cancel or a failure).
type action struct {
	kind    actionKind
	service string
	err     error
}

// app keeps the state; only its loop goroutine reads or changes it.
type app struct {
	client  ipc.Client
	actions chan action
	lang    menubar.Lang
	plat    platform

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
	// polled is set after the first status poll of this launch; answered
	// once the daemon answered any poll. Both decide whether the setup opens
	// by itself (menubar.ShouldAutoOpen).
	polled, answered bool

	catalog    []catalog.Service
	catalogErr error

	// exe is this app's executable and home the user's home folder.
	exe, home string
	// loginMenu is what the menu offers for opening at login (see
	// platform.loginMenu): on macOS the toggle when the app runs from a .app
	// bundle that survives a restart, a hint to move it to Applications when
	// it runs from the DMG or translocated, nothing for a development build.
	// openAtLogin is the user's choice.
	loginMenu   menubar.LoginMenuItem
	openAtLogin bool

	layout string
	done   chan struct{}
	items  items
}

type items struct {
	status, session, today, errLine *systray.MenuItem
	setUp, changeVPN, toggle, quit  *systray.MenuItem
	openAtLogin, uninstall          *systray.MenuItem
	services                        map[string]*systray.MenuItem
}

func (a *app) ready() {
	a.plat.setIcon(menubar.StateNotSetUp)
	systray.SetTooltip("leakguard " + version.String())
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
	// Only the first poll of this launch may open the setup by itself, and
	// only when leakguard is not installed or needs updating; a daemon that
	// restarts later just shows its status.
	first, answeredBefore := !a.polled, a.answered
	a.polled = true
	if err == nil {
		a.answered = true
	}
	if first && a.catalogErr == nil &&
		menubar.ShouldAutoOpen(first, answeredBefore, err, a.plat.installed()) {
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
		// The wizard already showed a failure in a dialog; the menu keeps
		// its first line. A cancel clears the line.
		a.wizardOpen = false
		a.errLine = menubar.WizardMessage(a.lang, act.err)
		return
	case actOpenAtLogin:
		a.errLine = ""
		on := !a.openAtLogin
		if err := a.plat.setOpenAtLogin(on); err != nil {
			a.errLine = a.lang.Text(menubar.MsgLoginItemFailed, err.Error())
			return
		}
		a.openAtLogin = on
		return
	case actUninstall:
		a.startUninstall()
		return
	case actUninstallDone:
		a.wizardOpen = false
		if act.err == nil {
			systray.Quit()
			return
		}
		a.errLine = menubar.WizardMessage(a.lang, act.err)
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
		req, err = menubar.ToggleService(a.lang, *a.st, act.service)
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

// daemonUnavailable reports whether the last poll found no daemon: then the
// setup installs it with the administrator prompt.
func (a *app) daemonUnavailable() bool {
	return errors.Is(a.stErr, ipc.ErrDaemonUnavailable)
}

func (a *app) wizard(needsPassword bool) menubar.Wizard {
	return menubar.Wizard{
		Lang:          a.lang,
		Dialogs:       a.plat.dialogs(),
		Catalog:       a.catalog,
		ConnectedVPNs: connectedVPNCandidates,
		NeedsPassword: needsPassword,
	}
}

// startSetUp opens the 3-step setup. Without the daemon, step 3 runs
// "leakguard enable" once through the administrator prompt; with a daemon
// that has no choice yet, it saves the choice without a password.
func (a *app) startSetUp() {
	if a.wizardOpen || !a.menu.SetUp || a.catalogErr != nil || a.guardMoveIfNeeded() {
		return
	}
	a.wizardOpen = true
	w := a.wizard(a.daemonUnavailable())
	client, plat, lang, all := a.client, a.plat, a.lang, a.catalog
	go func() {
		err := w.Run(func(d menubar.Draft) error {
			if w.NeedsPassword {
				return install(client, plat, lang, all, d)
			}
			return save(client, d)
		})
		a.actions <- action{kind: actWizardDone, err: err}
	}()
}

// guardMoveIfNeeded reports whether the app runs from where it cannot be
// set up (the platform's mustMove: on macOS, the mounted DMG or a
// translocated copy, see menubar.MustMoveToApplications). Then it asks the
// user, in one dialog of its own goroutine, to move the app to Applications
// first, and setup and uninstall do nothing else.
func (a *app) guardMoveIfNeeded() bool {
	if !a.plat.mustMove() {
		return false
	}
	a.wizardOpen = true
	lang, plat := a.lang, a.plat
	go func() {
		plat.guardMove(lang)
		a.actions <- action{kind: actWizardDone}
	}()
	return true
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
		err := w.ChangeVPN(func(vpn string) error {
			st, err := client.Status()
			if err != nil {
				return err
			}
			req, err := menubar.ChangeVPNRequest(lang, st, vpn)
			if err != nil {
				return err
			}
			return save(client, menubar.Draft{VPNInterface: req.VPNInterface, Services: req.Services})
		})
		a.actions <- action{kind: actWizardDone, err: err}
	}()
}

// save sends d to the running daemon, which needs no password. Its errors
// stay as they are: the wizard says them in the user's language.
func save(client ipc.Client, d menubar.Draft) error {
	_, err := client.Set(d.VPNInterface, d.Services)
	return err
}

// install runs "leakguard enable" for d once with administrator rights.
// Its errors stay as they are: the wizard says them in the user's language.
func install(client ipc.Client, plat platform, lang menubar.Lang, all []catalog.Service, d menubar.Draft) error {
	// The daemon may have come up since the wizard opened: then it saves the
	// choice and no password is needed.
	_, err := client.Status()
	if !menubar.SetupNeeded(err) {
		return save(client, d)
	}
	return plat.setUp(lang, all, d)
}

// startUninstall runs "Uninstall leakguard…": one administrator prompt for
// "leakguard disable", then the login item and the preferences go. The app
// quits once it is done.
func (a *app) startUninstall() {
	if a.wizardOpen || a.guardMoveIfNeeded() {
		return
	}
	a.wizardOpen = true
	lang, plat := a.lang, a.plat
	u := menubar.Uninstaller{
		Lang:      lang,
		Dialogs:   plat.dialogs(),
		Disable:   func() error { return plat.disable(lang) },
		Cleanup:   plat.removeLoginItem,
		LoginItem: plat.loginItemPresent,
	}
	go func() {
		a.actions <- action{kind: actUninstallDone, err: u.Run()}
	}()
}

func isExecutable(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// connectedVPNCandidates are the VPN candidates that are up with an address.
// macOS keeps system tunnels (utun0-3) up without an address; they are never
// the user's VPN. config.VPNCandidates applies each system's own rules.
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
	setup := menubar.Setup{Catalog: a.catalog, Lang: a.lang, Now: time.Now(), Version: version.String()}
	if a.daemonUnavailable() {
		setup.Update = a.plat.installed() == menubar.InstallOld
	}
	m := menubar.Build(a.st, a.stErr, setup)
	if m.State == menubar.StateNotSetUp && a.catalogErr != nil {
		m.Status = a.lang.Text(menubar.MsgCatalogError, a.catalogErr.Error())
		m.SetUp = false
	}
	a.menu = m

	if m.State != a.icon {
		a.icon = m.State
		a.plat.setIcon(m.State)
	}
	systray.SetTooltip(m.Tooltip)

	if key := layoutKey(m); key != a.layout {
		a.rebuild(m)
		a.layout = key
	}
	it := a.items
	it.status.SetTitle(menubar.Short(m.Status, lineLength))
	setInfoLine(it.session, m.Session)
	setInfoLine(it.today, m.Today)
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
	if it.openAtLogin != nil {
		setChecked(it.openAtLogin, a.openAtLogin)
	}
	setEnabled(it.uninstall, !a.wizardOpen)
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
	it.session = systray.AddMenuItem("", "")
	it.session.Disable()
	it.today = systray.AddMenuItem("", "")
	it.today.Disable()
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
			a.forward(item, action{kind: actService, service: s.ID})
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
	switch a.loginMenu {
	case menubar.LoginItemToggle:
		it.openAtLogin = systray.AddMenuItemCheckbox(l.Text(menubar.MsgMenuOpenAtLogin), l.Text(menubar.MsgMenuOpenAtLoginTip), a.openAtLogin)
		a.forward(it.openAtLogin, action{kind: actOpenAtLogin})
	case menubar.LoginItemMoveHint:
		hint := systray.AddMenuItem(l.Text(menubar.MsgMenuMoveToApplications), "")
		hint.Disable()
	}
	it.uninstall = systray.AddMenuItem(l.Text(menubar.MsgMenuUninstall), l.Text(menubar.MsgMenuUninstallTip))
	a.forward(it.uninstall, action{kind: actUninstall})
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

// setInfoLine shows a disabled, informational line, or hides it when empty.
func setInfoLine(item *systray.MenuItem, line string) {
	if line == "" {
		item.Hide()
		return
	}
	item.SetTitle(menubar.Short(line, lineLength))
	item.Show()
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
