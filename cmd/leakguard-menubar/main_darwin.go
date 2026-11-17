//go:build darwin

// Command leakguard-menubar is the macOS menu-bar app. It shows whether the
// chosen services are protected and lets an administrator tick services,
// choose the VPN interface and pause the protection. It only talks to the
// root daemon over its socket: quitting the app never stops the protection.
package main

import (
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
	}
	a.catalog, a.catalogErr = catalog.Embedded()
	systray.Run(a.ready, func() {})
}

type actionKind int

const (
	actService actionKind = iota
	actVPN
	actToggle
	actSetUp
	actSetUpDone
)

type action struct {
	kind actionKind
	arg  string
}

// app keeps the state; only its loop goroutine reads or changes it.
type app struct {
	client  ipc.Client
	actions chan action

	st        *ipc.Status
	stErr     error
	errLine   string
	menu      menubar.Menu
	icon      menubar.State
	settingUp bool

	// catalog and draft drive the menu while leakguard is not set up: the
	// clicks change the draft only, and "Set up" sends it to enable.
	catalog    []catalog.Service
	catalogErr error
	draft      *menubar.Draft

	layout string
	done   chan struct{}
	items  items
}

type items struct {
	status, errLine, setUp, vpn, toggle, quit *systray.MenuItem
	services                                  map[string]*systray.MenuItem
	vpns                                      map[string]*systray.MenuItem
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
	a.draw()
}

func (a *app) handle(act action) {
	switch act.kind {
	case actSetUp:
		a.setUp()
		return
	case actSetUpDone:
		a.settingUp = false
		a.errLine = act.arg
		return
	}
	if a.notSetUp() {
		a.editDraft(act)
		return
	}
	if a.st == nil {
		a.errLine = menubar.Explain(a.stErr)
		return
	}
	var req menubar.Request
	var err error
	switch act.kind {
	case actService:
		req, err = menubar.ToggleService(*a.st, act.arg)
	case actVPN:
		req, err = menubar.ChooseVPN(*a.st, act.arg)
	case actToggle:
		if a.menu.Toggle.Resume {
			req, err = menubar.ResumeRequest(*a.st)
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
		a.errLine = menubar.Explain(err)
	}
}

func (a *app) notSetUp() bool {
	return errors.Is(a.stErr, ipc.ErrDaemonUnavailable)
}

// editDraft applies a click to the local draft; nothing reaches the daemon.
func (a *app) editDraft(act action) {
	d := a.currentDraft()
	var err error
	switch act.kind {
	case actService:
		d, err = d.ToggleService(a.catalog, act.arg)
	case actVPN:
		d, err = d.ChooseVPN(act.arg)
	default:
		return
	}
	a.errLine = ""
	if err != nil {
		a.errLine = err.Error()
		return
	}
	a.draft = &d
}

// currentDraft is the draft, starting from the default on first use.
func (a *app) currentDraft() menubar.Draft {
	if a.draft == nil {
		d := menubar.DefaultDraft(connectedVPNCandidates())
		a.draft = &d
	}
	return *a.draft
}

// setUp runs "leakguard enable" once through the macOS administrator prompt.
func (a *app) setUp() {
	if a.settingUp || !a.notSetUp() || !a.menu.SetUp.Enabled {
		return
	}
	// The daemon may have come up since the last poll: then there is
	// nothing to set up, and the draft is dropped.
	st, err := a.client.Status()
	if !menubar.SetupNeeded(err) {
		if err == nil {
			a.st, a.stErr = &st, nil
		} else {
			a.st, a.stErr = nil, err
		}
		a.draft = nil
		a.errLine = ""
		return
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
		a.errLine = err.Error()
		return
	}
	script, err := menubar.SetupScript(cli, a.currentDraft(), a.catalog)
	if err != nil {
		a.errLine = err.Error()
		return
	}
	a.settingUp = true
	a.errLine = "Setting up leakguard…"
	go func() {
		out, err := exec.Command("/usr/bin/osascript", "-e", script).CombinedOutput()
		msg := ""
		if err != nil {
			msg = menubar.SetupFailure(string(out))
		}
		a.actions <- action{kind: actSetUpDone, arg: msg}
	}()
}

func isExecutable(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// connectedVPNCandidates are the VPN candidates that are up with an address.
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

func vpnCandidates() []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(ifs))
	for _, i := range ifs {
		names = append(names, i.Name)
	}
	return config.VPNCandidates(names)
}

func (a *app) draw() {
	setup := menubar.Setup{Catalog: a.catalog}
	if a.notSetUp() {
		setup.Draft = a.currentDraft()
		setup.Update = menubar.InstalledState("") == menubar.InstallOld
	} else if a.st != nil {
		a.draft = nil // a later "not set up" starts from the default again
	}
	m := menubar.Build(a.st, a.stErr, vpnCandidates(), setup)
	if m.State == menubar.StateNotSetUp && a.catalogErr != nil {
		m.Status = "Could not read the service list: " + a.catalogErr.Error()
		m.SetUp.Enabled = false
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
	if m.State == menubar.StateNotSetUp {
		systray.SetTooltip(menubar.Explain(a.stErr))
	} else {
		systray.SetTooltip("leakguard: " + m.Status)
	}

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
	if it.vpn != nil {
		title := "VPN interface"
		for _, v := range m.VPNs {
			item := it.vpns[v.Name]
			item.SetTitle(v.Label)
			setChecked(item, v.Checked)
			if v.Checked {
				title = "VPN interface: " + v.Name
			}
		}
		it.vpn.SetTitle(title)
	}
	if it.setUp != nil {
		setEnabled(it.setUp, m.SetUp.Enabled)
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
	for _, v := range m.VPNs {
		b.WriteString("|v:" + v.Name)
	}
	if m.Toggle.Visible {
		b.WriteString("|toggle")
	}
	if m.SetUp.Visible {
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

	it := items{services: map[string]*systray.MenuItem{}, vpns: map[string]*systray.MenuItem{}}
	it.status = systray.AddMenuItem("", "")
	it.status.Disable()
	it.errLine = systray.AddMenuItem("", "The last change did not work")
	it.errLine.Disable()
	systray.AddSeparator()
	if len(m.Services) > 0 {
		header := systray.AddMenuItem("Protect these services:", "")
		header.Disable()
		for _, s := range m.Services {
			item := systray.AddMenuItemCheckbox(s.Label, "Allow this service only through the VPN", s.Checked)
			it.services[s.ID] = item
			a.forward(item, action{kind: actService, arg: s.ID})
		}
	}
	if len(m.VPNs) > 0 {
		it.vpn = systray.AddMenuItem("VPN interface", "The only interface the protected services may use")
		for _, v := range m.VPNs {
			item := it.vpn.AddSubMenuItemCheckbox(v.Label, "", v.Checked)
			it.vpns[v.Name] = item
			a.forward(item, action{kind: actVPN, arg: v.Name})
		}
	}
	if m.SetUp.Visible {
		systray.AddSeparator()
		it.setUp = systray.AddMenuItem("Set up leakguard…", "Protects the ticked services through the chosen VPN and installs the background service; asks for an administrator password once")
		it.setUp.Disable()
		a.forward(it.setUp, action{kind: actSetUp})
	}
	if m.Toggle.Visible {
		systray.AddSeparator()
		it.toggle = systray.AddMenuItem(m.Toggle.Label, "Pause lets the services use your normal connection until you resume")
		a.forward(it.toggle, action{kind: actToggle})
	}
	systray.AddSeparator()
	it.quit = systray.AddMenuItem("Quit", "Closes this menu only; the protection keeps running in the background")
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
