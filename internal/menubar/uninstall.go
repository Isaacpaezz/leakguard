package menubar

import "errors"

// Uninstaller is "Uninstall leakguard…": it explains what will be removed,
// runs "leakguard disable" once with the administrator prompt (Disable),
// then removes the login item and the app's preferences (Cleanup). The app
// itself stays, for the user to drag to the Trash. It has no GUI of its
// own: Dialogs draws it.
type Uninstaller struct {
	Lang    Lang
	Dialogs Dialogs
	// Disable removes the protection rules and the background service with
	// administrator rights; it returns ErrCancelled when the user cancels
	// the password prompt.
	Disable func() error
	// Cleanup removes the LaunchAgent and menubar.json.
	Cleanup func() error
}

// Run asks first, with Cancel as the default button. Cancelling, at the
// first dialog or at the password prompt, changes nothing and says so; a
// failed Disable leaves the login item in place and says why. It returns
// nil once leakguard is uninstalled: the app should quit then. Errors read
// in plain words with WizardMessage.
func (u Uninstaller) Run() error {
	b, err := u.Dialogs.Ask(Dialog{
		Title:   u.Lang.Text(msgUninstallTitle),
		Text:    u.Lang.Text(msgUninstallConfirm),
		Buttons: []string{u.Lang.Text(msgButtonCancel), u.Lang.Text(msgButtonUninstall)},
		Default: 0,
		Cancel:  0,
	})
	if err == nil && b != 1 {
		err = ErrCancelled
	}
	if err == nil {
		err = u.Disable()
		if err != nil && !errors.Is(err, ErrCancelled) {
			err = stepError{msgUninstallFailed, err}
		}
	}
	if errors.Is(err, ErrCancelled) {
		u.tell(u.Lang.Text(msgUninstallCancelled))
		return err
	}
	if err != nil {
		if msg := WizardMessage(u.Lang, err); msg != "" {
			u.tell(msg)
		}
		return err
	}
	if err := u.Cleanup(); err != nil {
		u.tell(u.Lang.Text(msgUninstallCleanupFailed, firstLine(err.Error())))
		return nil
	}
	u.tell(u.Lang.Text(msgUninstallDone))
	return nil
}

func (u Uninstaller) tell(text string) {
	Wizard{Lang: u.Lang, Dialogs: u.Dialogs}.tell(text)
}

// UninstallPrompt is the short reason the macOS password dialog shows for
// the uninstall.
func UninstallPrompt(l Lang) string {
	return l.Text(msgUninstallPrompt)
}
