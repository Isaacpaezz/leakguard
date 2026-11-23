package menubar

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CheckInstalledCLI checks that path, the installed copy, is a regular
// file and that it and its folder are not links and are admin-only (see
// AdminOnly): only then may the tray run it with administrator rights. A
// missing file returns an error that wraps fs.ErrNotExist.
func CheckInstalledCLI(path string) error {
	if err := checkWindowsPath(path); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	for _, p := range []string{path, filepath.Dir(path)} {
		if err := checkAdminOnly(p); err != nil {
			return err
		}
	}
	return nil
}

// checkAdminOnly reads the owner and access list of p and checks them.
func checkAdminOnly(p string) error {
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(name)
	if err != nil {
		return fmt.Errorf("%s: %w", p, err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s is a link", p)
	}
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("cannot read the permissions of %s: %w", p, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("cannot read the owner of %s: %v", p, err)
	}
	dacl, _, err := sd.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || err == nil && dacl == nil {
		return AdminOnly(p, owner.String(), nil, false)
	}
	if err != nil {
		return fmt.Errorf("cannot read the access list of %s: %w", p, err)
	}
	var aces []ACE
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var e *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &e); err != nil {
			return fmt.Errorf("cannot read the access list of %s: %w", p, err)
		}
		ace := ACE{Type: e.Header.AceType, Flags: e.Header.AceFlags, Mask: uint32(e.Mask)}
		// Allow and deny entries hold the SID right after the mask.
		if ace.Type == aceAllowed || ace.Type == aceDenied {
			ace.SID = (*windows.SID)(unsafe.Pointer(&e.SidStart)).String()
		}
		aces = append(aces, ace)
	}
	return AdminOnly(p, owner.String(), aces, true)
}
