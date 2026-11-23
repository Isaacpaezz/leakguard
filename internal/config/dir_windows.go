package config

import (
	"os"

	"golang.org/x/sys/windows"
)

// dataDirSDDL lets only SYSTEM and Administrators write the directory and
// what it holds, and everyone read it, so status works unelevated. P
// protects it from the ACL of %ProgramData%, where every user can create
// files and folders.
const dataDirSDDL = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GRGX;;;BU)"

// PrepareDir creates dir when it is missing and, every time, gives it to
// the Administrators group with an ACL that lets only SYSTEM and
// Administrators write it. A directory a user created first is taken back
// too. It fails when the ACL cannot be set: nothing is saved then.
func PrepareDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return SecureWindowsPath(dir)
}

// SecureWindowsPath gives path to the Administrators group with an ACL that
// lets only SYSTEM and Administrators write it.
func SecureWindowsPath(path string) error {
	sd, err := windows.SecurityDescriptorFromString(dataDirSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		admins, nil, dacl, nil)
}
