package config

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"
)

// ErrUnsafePath means a file or directory leakguard's SYSTEM daemon would
// trust can be written by someone other than SYSTEM and Administrators,
// or is a link to somewhere else. Windows only.
var ErrUnsafePath = errors.New("only SYSTEM and Administrators may write it")

// errInUse means an entry of the data directory stayed in use by another
// handle whose sharing mode keeps us out (ERROR_SHARING_VIOLATION or
// ERROR_LOCK_VIOLATION) for the whole retry window.
var errInUse = errors.New("is in use by another program; try again in a moment")

// inUseDelays are the waits before each new attempt to open an entry that
// is in use: about 1.9 s in all. Being in use is never a reason to remove
// anything: it is usually leakguard itself, or another administrator's
// leakguard, writing a file into the directory.
var inUseDelays = []time.Duration{
	10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond, 80 * time.Millisecond, 160 * time.Millisecond,
	320 * time.Millisecond, 320 * time.Millisecond, 320 * time.Millisecond, 320 * time.Millisecond, 320 * time.Millisecond,
}

// whileInUse runs op, and runs it again after each of inUseDelays while it
// fails because the entry is in use. It returns op's last error.
func whileInUse(fsys dataFS, op func() error) error {
	err := op()
	for _, d := range inUseDelays {
		if err == nil || !fsys.inUse(err) {
			return err
		}
		fsys.sleep(d)
		err = op()
	}
	return err
}

// Trusted owners and writers (SIDs): SYSTEM and BUILTIN\Administrators.
const (
	sidLocalSystem    = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
)

// Access entry types (winnt.h).
const (
	aceAllowed = 0 // ACCESS_ALLOWED_ACE_TYPE
	aceDenied  = 1 // ACCESS_DENIED_ACE_TYPE
)

// writeRights are the access rights that let someone change a file or
// what a directory holds: GENERIC_ALL, GENERIC_WRITE, WRITE_OWNER,
// WRITE_DAC, DELETE, FILE_WRITE_ATTRIBUTES, FILE_DELETE_CHILD,
// FILE_WRITE_EA, FILE_APPEND_DATA (add subdirectory) and FILE_WRITE_DATA
// (add file).
const writeRights = 0x10000000 | 0x40000000 | 0x80000 | 0x40000 | 0x10000 | 0x100 | 0x40 | 0x10 | 0x4 | 0x2

// secFacts is what Windows says about a file or directory, read without
// following a reparse point.
type secFacts struct {
	reparse   bool   // FILE_ATTRIBUTE_REPARSE_POINT: a junction or a link
	dir       bool   // FILE_ATTRIBUTE_DIRECTORY
	links     uint32 // hard links (files)
	owner     string // owner SID; empty when unknown
	protected bool   // SE_DACL_PROTECTED: no ACEs inherited from the parent
	noDACL    bool   // a NULL or missing DACL: everyone has full access
	aces      []aceFact
}

// aceFact is one access entry of the DACL.
type aceFact struct {
	kind uint8  // aceAllowed, aceDenied or another ACE type
	sid  string // the trustee of allowed and denied entries
	mask uint32
}

func trustedSID(sid string) bool { return sid == sidLocalSystem || sid == sidAdministrators }

// unsafeEntry reports why path, described by f, cannot be trusted by the
// SYSTEM daemon: a reparse point, the wrong kind, more than one hard link
// (a file), an owner other than SYSTEM or Administrators, or anyone else
// allowed to write it. Every reason wraps ErrUnsafePath.
func unsafeEntry(path string, f secFacts, wantDir bool) error {
	kind := "file"
	if wantDir {
		kind = "directory"
	}
	var reason string
	switch {
	case f.reparse:
		reason = fmt.Sprintf("%s is a link (reparse point), not a real %s", path, kind)
	case wantDir && !f.dir:
		reason = path + " is not a directory"
	case !wantDir && f.dir:
		reason = path + " is a directory, not a file"
	case !wantDir && f.links > 1:
		reason = fmt.Sprintf("%s has %d hard links", path, f.links)
	case f.owner == "":
		reason = path + " has no owner"
	case !trustedSID(f.owner):
		reason = fmt.Sprintf("%s is owned by %s", path, f.owner)
	case f.noDACL:
		reason = path + " has no access list, so everyone may write it"
	}
	for _, a := range f.aces {
		if reason != "" {
			break
		}
		switch {
		case a.kind == aceDenied || a.mask&writeRights == 0:
		case a.kind != aceAllowed:
			reason = fmt.Sprintf("%s has an access entry of type %d that allows writing", path, a.kind)
		case !trustedSID(a.sid):
			reason = fmt.Sprintf("%s is writable by %s (access %#x)", path, a.sid, a.mask)
		}
	}
	if reason == "" {
		return nil
	}
	return fmt.Errorf("%s; %w", reason, ErrUnsafePath)
}

// unsafeDataDir is unsafeEntry for the data directory, which must not
// inherit the ACL of its parent either: an inherited entry of
// %ProgramData% would let users add files to it.
func unsafeDataDir(path string, f secFacts) error {
	if err := unsafeEntry(path, f, true); err != nil {
		return err
	}
	if !f.protected {
		return fmt.Errorf("%s inherits the access list of its parent; %w", path, ErrUnsafePath)
	}
	return nil
}

// dataFS is the part of the Windows file system prepareDataDir uses; the
// tests use a fake.
type dataFS interface {
	// openDir opens dir without following a reparse point, failing when
	// anyone else holds it open for writing or deleting. A missing dir
	// wraps fs.ErrNotExist.
	openDir(dir string) (dataDir, error)
	// facts describes path without following a reparse point. A missing
	// path wraps fs.ErrNotExist.
	facts(path string) (secFacts, error)
	// mkdir creates a real directory, secured from the start, and fails
	// when the name exists (a junction recreated meanwhile included).
	mkdir(dir string) error
	// remove deletes the entry itself, never what a reparse point names.
	remove(path string) error
	// inUse reports whether err says another handle's sharing mode kept
	// the open out (ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION).
	inUse(err error) bool
	// sleep waits d before the next attempt.
	sleep(d time.Duration)
}

// dataDir is the open data directory. While it is open nobody else can
// open it for writing, rename it or delete it.
type dataDir interface {
	facts() (secFacts, error)
	// secure gives the directory to Administrators with the protected
	// ACL of dataDirSDDL. It changes only the directory, never what it
	// holds.
	secure() error
	names() ([]string, error)
	Close() error
}

// prepareDataDir makes dir the data directory only SYSTEM and
// Administrators can write, whoever created it first:
//   - a missing dir is created, secured from the start;
//   - a junction, link or file where dir goes is removed (the entry, never
//     its target) and a real directory made instead;
//   - a directory someone else owns or may write is taken over: owner
//     Administrators and the protected ACL, set on the open directory so
//     no reparse point is followed;
//   - then every entry in it that is unsafe (a link, more than one hard
//     link, not owned by SYSTEM or Administrators, writable by anyone
//     else, or unreadable) is removed, so the daemon never reads a config,
//     stats or log someone else planted.
//
// The directory or an entry in use (another handle's sharing mode keeps
// us out, often leakguard's own rename into the directory) is opened
// again for about 2 s, never removed; when it stays in use PrepareDir
// fails with errInUse, removing nothing more. So a directory someone holds
// open for writing is still refused.
//
// It fails, removing nothing, when the directory cannot be secured, and
// fails when an unsafe entry cannot be removed.
func prepareDataDir(fsys dataFS, dir string) error {
	d, err := openRealDir(fsys, dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.secure(); err != nil {
		return fmt.Errorf("cannot secure %s: %w", dir, err)
	}
	f, err := d.facts()
	if err == nil {
		err = unsafeDataDir(dir, f)
	}
	if err != nil {
		return fmt.Errorf("cannot secure %s: %w", dir, err)
	}
	names, err := d.names()
	if err != nil {
		return err
	}
	for _, n := range names {
		p := filepath.Join(dir, n)
		var f secFacts
		err := whileInUse(fsys, func() (err error) {
			f, err = fsys.facts(p)
			return err
		})
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil && fsys.inUse(err) {
			return fmt.Errorf("cannot check %s: it %w (%w)", p, errInUse, err)
		}
		if err == nil && unsafeEntry(p, f, f.dir && !f.reparse) == nil {
			continue
		}
		if err := fsys.remove(p); err != nil {
			return fmt.Errorf("cannot remove %s, which only SYSTEM and Administrators may write: %w", p, err)
		}
	}
	return nil
}

// openRealDir opens dir, creating it when missing. Whatever else holds
// the name (a junction, a link, a file, or a directory that cannot be
// opened for a reason other than being in use) is removed, when it can be,
// and a real directory made instead. A directory in use is waited for,
// never removed.
func openRealDir(fsys dataFS, dir string) (dataDir, error) {
	d, err := openDirWaiting(fsys, dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := fsys.mkdir(dir); err != nil {
			return nil, err
		}
		return openDirWaiting(fsys, dir)
	case errors.Is(err, errInUse):
		return nil, err
	case err != nil:
		if rerr := fsys.remove(dir); rerr != nil {
			return nil, fmt.Errorf("cannot open %s: %v; it cannot be removed either: %w", dir, err, rerr)
		}
	default:
		f, err := d.facts()
		if err == nil && f.dir && !f.reparse {
			return d, nil
		}
		d.Close()
		if err := fsys.remove(dir); err != nil {
			return nil, fmt.Errorf("cannot remove %s, which is not a real directory: %w", dir, err)
		}
	}
	if err := fsys.mkdir(dir); err != nil {
		return nil, err
	}
	return openDirWaiting(fsys, dir)
}

// openDirWaiting opens dir, waiting while it is in use; when it stays in
// use the error wraps errInUse and the last open error.
func openDirWaiting(fsys dataFS, dir string) (dataDir, error) {
	var d dataDir
	err := whileInUse(fsys, func() (err error) {
		d, err = fsys.openDir(dir)
		return err
	})
	if err != nil && fsys.inUse(err) {
		return nil, fmt.Errorf("cannot open %s: the folder %w (%w)", dir, errInUse, err)
	}
	return d, err
}
