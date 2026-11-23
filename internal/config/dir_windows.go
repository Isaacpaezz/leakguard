package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dataDirSDDL lets only SYSTEM and Administrators write the directory and
// what it holds, and everyone read it, so status works unelevated. P
// protects it from the ACL of %ProgramData%, where every user can create
// files and folders. The rights are file rights (FA: all; FRFX: read and
// execute), never generic ones, because secure sets the ACL as it is,
// without the generic mapping the higher-level calls do.
const dataDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)"

// prepareDir makes dir the data directory that only SYSTEM and
// Administrators can write, whoever created it first (see
// prepareDataDir): a junction is removed and a real directory made, a
// directory a user created is taken over, and every entry in it someone
// else could write, or a link, is removed. A directory in use is waited
// for about 2 s, never removed. It fails when that cannot be done:
// nothing is saved then.
func prepareDir(dir string) error { return prepareDataDir(winFS{}, dir) }

// SecureWindowsPath gives the directory at path to the Administrators
// group with the protected ACL of the data directory, without following a
// reparse point.
func SecureWindowsPath(path string) error {
	d, err := winFS{}.openDir(path)
	if err != nil {
		return err
	}
	defer d.Close()
	f, err := d.facts()
	if err != nil {
		return err
	}
	if f.reparse || !f.dir {
		return unsafeEntry(path, f, true)
	}
	return d.secure()
}

// OpenTrusted opens the file at path for reading only when SYSTEM's
// daemon can trust it: not a link or junction, one hard link, owned by
// SYSTEM or Administrators, and nobody else may write it. Otherwise it
// fails with ErrUnsafePath. The checks and the read use the same handle.
func OpenTrusted(path string) (*os.File, error) {
	h, err := openNoFollow(path, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	f, err := handleFacts(h)
	if err == nil {
		err = unsafeEntry(path, f, false)
	}
	if err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

// ownFile gives a file Save just created in the data directory to
// Administrators: the default owner of an elevated administrator's token
// can be the user, whose file OpenTrusted would refuse.
func ownFile(path string) error {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil)
}

// openNoFollow opens path itself, a reparse point too, never its target.
// Backup semantics lets it open directories.
func openNoFollow(path string, access, share uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(p, access, share, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
}

// handleFacts reads the attributes, links, owner and DACL of an open file.
func handleFacts(h windows.Handle) (secFacts, error) {
	var f secFacts
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return f, err
	}
	f.reparse = info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
	f.dir = info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	f.links = info.NumberOfLinks
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return f, err
	}
	if owner, _, err := sd.Owner(); err == nil && owner != nil {
		f.owner = owner.String()
	}
	if control, _, err := sd.Control(); err == nil {
		f.protected = control&windows.SE_DACL_PROTECTED != 0
	}
	dacl, _, err := sd.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || (err == nil && dacl == nil) {
		f.noDACL = true
		return f, nil
	}
	if err != nil {
		return f, err
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return f, err
		}
		a := aceFact{kind: ace.Header.AceType, mask: uint32(ace.Mask)}
		if a.kind == aceAllowed || a.kind == aceDenied {
			a.sid = (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		}
		f.aces = append(f.aces, a)
	}
	return f, nil
}

// dataDirSD is the security descriptor of the data directory: owner
// Administrators and the protected DACL of dataDirSDDL.
func dataDirSD() (*windows.SECURITY_DESCRIPTOR, error) {
	sd, err := windows.SecurityDescriptorFromString(dataDirSDDL)
	if err != nil {
		return nil, err
	}
	abs, err := sd.ToAbsolute()
	if err != nil {
		return nil, err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	if err := abs.SetOwner(admins, false); err != nil {
		return nil, err
	}
	if err := abs.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return nil, err
	}
	return abs.ToSelfRelative()
}

// winFS is the real file system of PrepareDir.
type winFS struct{}

// openDir opens the directory to read and change its security. Sharing
// only reading, it fails while anyone else holds it open for writing
// (adding entries) or deleting (renaming), and keeps them out while open.
func (winFS) openDir(dir string) (dataDir, error) {
	const access = windows.READ_CONTROL | windows.WRITE_DAC | windows.WRITE_OWNER |
		windows.FILE_LIST_DIRECTORY | windows.FILE_READ_ATTRIBUTES
	h, err := openNoFollow(dir, access, windows.FILE_SHARE_READ)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: dir, Err: err}
	}
	return winDir{h: h, path: dir}, nil
}

func (winFS) facts(path string) (secFacts, error) {
	h, err := openNoFollow(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if err != nil {
		return secFacts{}, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	defer windows.CloseHandle(h)
	return handleFacts(h)
}

// mkdir creates the directory with its protected ACL from the start, so
// no user can add anything before secure runs. CreateDirectory fails
// when the name exists. Missing parents are created as usual.
func (winFS) mkdir(dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(dataDirSDDL)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(p, &sa); err != nil {
		return &fs.PathError{Op: "mkdir", Path: dir, Err: err}
	}
	return nil
}

// remove deletes the entry: DeleteFile, then RemoveDirectory, which
// removes a junction itself, never what it points to.
func (winFS) remove(path string) error { return os.Remove(path) }

// inUse reports a sharing or lock violation: another handle, such as a
// rename into the directory, keeps the open out for now.
func (winFS) inUse(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}

func (winFS) sleep(d time.Duration) { time.Sleep(d) }

type winDir struct {
	h    windows.Handle
	path string
}

func (d winDir) facts() (secFacts, error) { return handleFacts(d.h) }

// secure sets the owner and the DACL on the open handle with
// SetKernelObjectSecurity, which changes only this directory: unlike
// SetSecurityInfo it does not walk (and so cannot follow links among)
// the entries inside.
func (d winDir) secure() error {
	sd, err := dataDirSD()
	if err != nil {
		return err
	}
	if err := windows.SetKernelObjectSecurity(d.h, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION, sd); err != nil {
		return fmt.Errorf("SetKernelObjectSecurity: %w", err)
	}
	return nil
}

func (d winDir) names() ([]string, error) {
	f, err := os.Open(d.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Readdirnames(-1)
}

func (d winDir) Close() error { return windows.CloseHandle(d.h) }
