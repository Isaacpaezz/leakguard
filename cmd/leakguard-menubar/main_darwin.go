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
	"github.com/Isaacpaezz/leakguard/internal/version"
)

const (
	pollEvery = 3 * time.Second
	// lineLength bounds the status, session, today and error lines, in runes.
	lineLength = menubar.MenuLineLength
)

func main() {
	a := &app{
		client:  ipc.Client{Path: ipc.DefaultPath},
		actions: make(chan action),
		lang:    macLanguage(),
	}
	a.catalog, a.catalogErr = catalog.Embedded()
	a.exe = executable()
	a.home, _ = os.UserHomeDir()
	_, inBundle := menubar.AppBundle(a.exe)
	a.loginItem = inBundle && filepath.IsAbs(a.home)
	if a.loginItem {
		// Written, never loaded: launchd opens the app at the next login,
		// and no second copy starts now.
		on, err := menubar.SyncLoginItem(a.home, a.exe)
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
	// loginItem is set when the app runs from a .app bundle, so it may open
	// at login (development builds never write the LaunchAgent);
	// openAtLogin is the user's choice.
	loginItem, openAtLogin bool

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
	systray.SetTemplateIcon(iconNotSetUp, iconNotSetUp)
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
		menubar.ShouldAutoOpen(first, answeredBefore, err, menubar.InstalledState("")) {
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
		if err := menubar.SetOpenAtLogin(a.home, a.exe, on); err != nil {
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
	w := a.wizard(a.daemonUnavailable())
	client, lang, all := a.client, a.lang, a.catalog
	go func() {
		err := w.Run(func(d menubar.Draft) error {
			if w.NeedsPassword {
				return install(client, lang, all, d)
			}
			return save(client, d)
		})
		a.actions <- action{kind: actWizardDone, err: err}
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
func install(client ipc.Client, lang menubar.Lang, all []catalog.Service, d menubar.Draft) error {
	// The daemon may have come up since the wizard opened: then it saves the
	// choice and no password is needed.
	_, err := client.Status()
	if !menubar.SetupNeeded(err) {
		return save(client, d)
	}
	cli, err := adminCLI()
	if err != nil {
		return err
	}
	script, err := menubar.SetupScript(cli, d, all, menubar.AdminPrompt(lang))
	if err != nil {
		return err
	}
	_, err = runScript(script)
	return err
}

// adminCLI is the leakguard command to run as administrator (see
// menubar.FindCLI), with the quarantine mark cleared when it is the one
// inside this app's bundle.
func adminCLI() (string, error) {
	exe := executable()
	cli, err := menubar.FindCLI(exe, menubar.InstalledState(""), isExecutable, menubar.CheckInstalledCLI)
	if err != nil {
		return "", err
	}
	if err := menubar.PrepareCLI(exe, cli, quarantined, clearQuarantine); err != nil {
		return "", err
	}
	return cli, nil
}

// quarantined reports whether path has the quarantine mark.
func quarantined(path string) (bool, error) {
	err := exec.Command("/usr/bin/xattr", "-p", menubar.QuarantineAttr, path).Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &exit):
		// xattr exits 1 when the attribute is not there.
		return false, nil
	}
	return false, err
}

// clearQuarantine removes the quarantine mark from exactly path.
func clearQuarantine(path string) error {
	out, err := exec.Command("/usr/bin/xattr", menubar.ClearQuarantineArgs(path)...).CombinedOutput()
	if err != nil {
		return menubar.ScriptError(string(out), err)
	}
	return nil
}

// startUninstall runs "Uninstall leakguard…": one administrator prompt for
// "leakguard disable", then the login item and the preferences go. The app
// quits once it is done.
func (a *app) startUninstall() {
	if a.wizardOpen {
		return
	}
	a.wizardOpen = true
	lang, home := a.lang, a.home
	u := menubar.Uninstaller{
		Lang:    lang,
		Dialogs: osaDialogs{},
		Disable: func() error {
			cli, err := adminCLI()
			if err != nil {
				return err
			}
			script, err := menubar.DisableScript(cli, menubar.UninstallPrompt(lang))
			if err != nil {
				return err
			}
			_, err = runScript(script)
			return err
		},
		Cleanup: func() error { return menubar.RemoveLoginItem(home) },
	}
	go func() {
		a.actions <- action{kind: actUninstallDone, err: u.Run()}
	}()
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
	setup := menubar.Setup{Catalog: a.catalog, Lang: a.lang, Now: time.Now(), Version: version.String()}
	if a.daemonUnavailable() {
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
	if a.loginItem {
		it.openAtLogin = systray.AddMenuItemCheckbox(l.Text(menubar.MsgMenuOpenAtLogin), l.Text(menubar.MsgMenuOpenAtLoginTip), a.openAtLogin)
		a.forward(it.openAtLogin, action{kind: actOpenAtLogin})
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
