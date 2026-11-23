package daemon

import "golang.org/x/sys/windows"

// ownByAdministrators gives the file at path to the Administrators group.
// The default owner of an elevated administrator's token can be the user,
// whose file config.PrepareDir would remove from the service directory
// and the tray would refuse to run.
func ownByAdministrators(path string) error {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil)
}
