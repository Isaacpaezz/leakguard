//go:build windows

package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// linkCount returns the number of hard links of the open file f.
func linkCount(f *os.File) (uint64, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return 0, err
	}
	return uint64(info.NumberOfLinks), nil
}

// checkReportOwner refuses the open report file f unless it is owned by
// the user who started this run: its token's user, or the token's default
// owner (an elevated administrator's files belong to Administrators). An
// owner that cannot be read refuses too.
func checkReportOwner(path string, f *os.File) error {
	invoker, err := invokerSIDs()
	if err != nil {
		return fmt.Errorf("%s: cannot tell who started leakguard: %w", path, err)
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: cannot read its owner: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%s: cannot read its owner: %v", path, err)
	}
	return reportOwnedBy(path, owner.String(), invoker)
}

// invokerSIDs returns this process's token user and default owner SIDs.
func invokerSIDs() ([]string, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	// TOKEN_OWNER holds one SID pointer, like TOKEN_PRIMARY_GROUP.
	var n uint32
	buf := make([]byte, 128)
	for {
		err = windows.GetTokenInformation(token, windows.TokenOwner, &buf[0], uint32(len(buf)), &n)
		if err != windows.ERROR_INSUFFICIENT_BUFFER || n <= uint32(len(buf)) {
			break
		}
		buf = make([]byte, n)
	}
	if err != nil {
		return nil, fmt.Errorf("reading the token's owner: %w", err)
	}
	owner := (*windows.Tokenprimarygroup)(unsafe.Pointer(&buf[0])).PrimaryGroup
	return []string{user.User.Sid.String(), owner.String()}, nil
}
