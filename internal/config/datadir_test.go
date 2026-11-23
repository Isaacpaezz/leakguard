package config

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	sidSystem = "S-1-5-18"
	sidAdmins = "S-1-5-32-544"
	sidUsers  = "S-1-5-32-545"
	sidUser   = "S-1-5-21-1-2-3-1001"
	fileAll   = 0x1f01ff // FILE_ALL_ACCESS
	fileRead  = 0x1200a9 // FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
)

// trustedFile is what a file created inside the secured directory looks like.
func trustedFile() secFacts {
	return secFacts{owner: sidAdmins, links: 1, aces: []aceFact{
		{aceAllowed, sidSystem, fileAll}, {aceAllowed, sidAdmins, fileAll}, {aceAllowed, sidUsers, fileRead},
	}}
}

// trustedDir is the secured data directory.
func trustedDir() secFacts {
	f := trustedFile()
	f.dir, f.protected, f.links = true, true, 0
	return f
}

// userDir is a directory a non-administrator created first: their own,
// writable by everyone, inheriting from %ProgramData%.
func userDir() secFacts {
	return secFacts{dir: true, owner: sidUser, aces: []aceFact{{aceAllowed, "S-1-1-0", fileAll}}}
}

func TestUnsafeJudgesFiles(t *testing.T) {
	const p = `C:\ProgramData\leakguard\config.json`
	with := func(change func(*secFacts)) secFacts {
		f := trustedFile()
		change(&f)
		return f
	}
	userWrites := func(mask uint32) secFacts {
		return with(func(f *secFacts) { f.aces = append(f.aces, aceFact{aceAllowed, sidUser, mask}) })
	}
	for _, tc := range []struct {
		name  string
		facts secFacts
		want  string // empty: trusted
	}{
		{"trusted", trustedFile(), ""},
		{"owned by SYSTEM", with(func(f *secFacts) { f.owner = sidSystem }), ""},
		{"users may read", userWrites(fileRead), ""},
		{"a deny entry", with(func(f *secFacts) { f.aces = append(f.aces, aceFact{aceDenied, sidUser, fileAll}) }), ""},
		{"unknown entry without write", with(func(f *secFacts) { f.aces = append(f.aces, aceFact{9, "", fileRead}) }), ""},
		{"reparse point", with(func(f *secFacts) { f.reparse = true }), p + " is a link (reparse point), not a real file"},
		{"a directory", with(func(f *secFacts) { f.dir = true }), p + " is a directory, not a file"},
		{"hard links", with(func(f *secFacts) { f.links = 2 }), p + " has 2 hard links"},
		{"owned by a user", with(func(f *secFacts) { f.owner = sidUser }), p + " is owned by " + sidUser},
		{"no owner", with(func(f *secFacts) { f.owner = "" }), p + " has no owner"},
		{"no access list", with(func(f *secFacts) { f.noDACL, f.aces = true, nil }), p + " has no access list, so everyone may write it"},
		{"unknown entry with write", with(func(f *secFacts) { f.aces = append(f.aces, aceFact{9, "", 0x2}) }), p + " has an access entry of type 9 that allows writing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkUnsafe(t, unsafeEntry(p, tc.facts, false), tc.want)
		})
	}
	// Every write right given to anyone else makes the file unsafe.
	for _, mask := range []uint32{0x2, 0x4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000} {
		checkUnsafe(t, unsafeEntry(p, userWrites(mask), false), fmt.Sprintf("%s is writable by %s (access %#x)", p, sidUser, mask))
	}
}

func TestUnsafeJudgesDirectories(t *testing.T) {
	const p = `C:\ProgramData\leakguard`
	checkUnsafe(t, unsafeDataDir(p, trustedDir()), "")
	f := trustedDir()
	f.links = 3 // directories count their links differently: ignored
	checkUnsafe(t, unsafeDataDir(p, f), "")
	f = trustedDir()
	f.protected = false
	checkUnsafe(t, unsafeDataDir(p, f), p+" inherits the access list of its parent")
	// Inside the data directory a subdirectory may inherit.
	checkUnsafe(t, unsafeEntry(p, f, true), "")
	f = trustedDir()
	f.dir = false
	checkUnsafe(t, unsafeEntry(p, f, true), p+" is not a directory")
	f = trustedDir()
	f.reparse = true
	checkUnsafe(t, unsafeEntry(p, f, true), p+" is a link (reparse point), not a real directory")
	checkUnsafe(t, unsafeEntry(p, userDir(), true), p+" is owned by "+sidUser)
}

func checkUnsafe(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Errorf("unsafeEntry() = %v, want trusted", err)
		}
		return
	}
	want += "; only SYSTEM and Administrators may write it"
	if err == nil || err.Error() != want || !errors.Is(err, ErrUnsafePath) {
		t.Errorf("unsafeEntry() = %v\nwant %s (wrapping ErrUnsafePath)", err, want)
	}
}

// fakeDataFS is a file system of entries described by their facts.
type fakeDataFS struct {
	entries    map[string]secFacts
	unreadable map[string]bool // facts fail with "Access is denied."
	failOpen   map[string]error
	failRemove map[string]error
	failMkdir  error
	failSecure error
	// secured is what secure turns the directory into.
	secured secFacts
	calls   []string
}

func newFakeDataFS(entries map[string]secFacts) *fakeDataFS {
	return &fakeDataFS{entries: entries, unreadable: map[string]bool{}, failOpen: map[string]error{}, failRemove: map[string]error{}, secured: trustedDir()}
}

func (f *fakeDataFS) log(format string, a ...any) {
	f.calls = append(f.calls, fmt.Sprintf(format, a...))
}

func (f *fakeDataFS) openDir(dir string) (dataDir, error) {
	f.log("openDir %s", dir)
	if err := f.failOpen[dir]; err != nil {
		return nil, err
	}
	if _, ok := f.entries[dir]; !ok {
		return nil, &fs.PathError{Op: "open", Path: dir, Err: fs.ErrNotExist}
	}
	return &fakeDir{f: f, path: dir}, nil
}

func (f *fakeDataFS) facts(path string) (secFacts, error) {
	if f.unreadable[path] {
		return secFacts{}, errors.New("Access is denied.")
	}
	e, ok := f.entries[path]
	if !ok {
		return secFacts{}, fs.ErrNotExist
	}
	return e, nil
}

func (f *fakeDataFS) mkdir(dir string) error {
	f.log("mkdir %s", dir)
	if f.failMkdir != nil {
		return f.failMkdir
	}
	if _, ok := f.entries[dir]; ok {
		return fs.ErrExist
	}
	f.entries[dir] = trustedDir()
	return nil
}

func (f *fakeDataFS) remove(path string) error {
	f.log("remove %s", path)
	if err := f.failRemove[path]; err != nil {
		return err
	}
	if len(f.children(path)) > 0 && !f.entries[path].reparse {
		return errors.New("The directory is not empty.")
	}
	delete(f.entries, path)
	delete(f.unreadable, path)
	return nil
}

func (f *fakeDataFS) children(dir string) []string {
	var out []string
	for p := range f.entries {
		if filepath.Dir(p) == dir && p != dir {
			out = append(out, filepath.Base(p))
		}
	}
	sort.Strings(out)
	return out
}

type fakeDir struct {
	f    *fakeDataFS
	path string
}

func (d *fakeDir) facts() (secFacts, error) { return d.f.facts(d.path) }

func (d *fakeDir) secure() error {
	d.f.log("secure %s", d.path)
	if d.f.failSecure != nil {
		return d.f.failSecure
	}
	d.f.entries[d.path] = d.f.secured
	return nil
}

func (d *fakeDir) names() ([]string, error) { return d.f.children(d.path), nil }

func (d *fakeDir) Close() error {
	d.f.log("close %s", d.path)
	return nil
}

const dataDirPath = "/ProgramData/leakguard"

func (f *fakeDataFS) callsString() string { return strings.Join(f.calls, " | ") }

// A missing directory is created secured, then secured again (owner).
func TestPrepareDataDirCreatesAMissingDirectory(t *testing.T) {
	f := newFakeDataFS(map[string]secFacts{})
	if err := prepareDataDir(f, dataDirPath); err != nil {
		t.Fatalf("prepareDataDir() = %v", err)
	}
	want := "openDir {D} | mkdir {D} | openDir {D} | secure {D} | close {D}"
	if got := f.callsString(); got != strings.ReplaceAll(want, "{D}", dataDirPath) {
		t.Fatalf("calls = %s\nwant    %s", got, strings.ReplaceAll(want, "{D}", dataDirPath))
	}
}

// S7: a junction (or a file) where the directory goes is removed itself,
// never followed or secured, and a real directory takes its place.
func TestPrepareDataDirReplacesAJunctionOrAFile(t *testing.T) {
	junction := trustedDir()
	junction.reparse = true
	file := trustedFile()
	for name, facts := range map[string]secFacts{"junction": junction, "file": file} {
		f := newFakeDataFS(map[string]secFacts{dataDirPath: facts})
		if err := prepareDataDir(f, dataDirPath); err != nil {
			t.Fatalf("%s: prepareDataDir() = %v", name, err)
		}
		want := strings.ReplaceAll("openDir {D} | close {D} | remove {D} | mkdir {D} | openDir {D} | secure {D} | close {D}", "{D}", dataDirPath)
		if got := f.callsString(); got != want {
			t.Errorf("%s: calls = %s\nwant    %s", name, got, want)
		}
	}
}

// S7: a directory a user created first is secured before anything in it
// is looked at; then every entry only SYSTEM and Administrators can write
// stays and every other entry is removed, links and unreadable ones too.
func TestPrepareDataDirTakesOverAUserDirectory(t *testing.T) {
	link := trustedFile()
	link.reparse = true
	hardLink := trustedFile()
	hardLink.links = 2
	userFile := trustedFile()
	userFile.owner = sidUser
	usersWrite := trustedFile()
	usersWrite.aces = append(usersWrite.aces, aceFact{aceAllowed, sidUsers, 0x6})
	j := func(name string) string { return filepath.Join(dataDirPath, name) }
	f := newFakeDataFS(map[string]secFacts{
		dataDirPath:          userDir(),
		j("config.json"):     userFile,
		j("stats.json"):      link,
		j("leakguard.log"):   hardLink,
		j(".config-1.json"):  usersWrite,
		j("good.json"):       trustedFile(),
		j("denied.json"):     {},
		j(".stats-2.json"):   trustedFile(),
		j("sub"):             userDir(),
		j("sub/inside.json"): trustedFile(),
	})
	f.unreadable[j("denied.json")] = true
	err := prepareDataDir(f, dataDirPath)
	// sub is a user's directory with something inside: it cannot be
	// removed, so PrepareDir refuses.
	want := "cannot remove " + j("sub") + ", which only SYSTEM and Administrators may write: The directory is not empty."
	if err == nil || err.Error() != want {
		t.Fatalf("prepareDataDir() = %v\nwant %s", err, want)
	}
	delete(f.entries, j("sub/inside.json"))
	f.calls = nil
	if err := prepareDataDir(f, dataDirPath); err != nil {
		t.Fatalf("prepareDataDir() = %v", err)
	}
	wantCalls := "openDir {D} | secure {D} | remove {D}/sub | close {D}"
	if got := f.callsString(); got != strings.ReplaceAll(wantCalls, "{D}", dataDirPath) {
		t.Fatalf("calls = %s\nwant    %s", got, strings.ReplaceAll(wantCalls, "{D}", dataDirPath))
	}
	var left []string
	for p := range f.entries {
		left = append(left, p)
	}
	sort.Strings(left)
	if got, want := strings.Join(left, " "), dataDirPath+" "+j(".stats-2.json")+" "+j("good.json"); got != want {
		t.Fatalf("entries = %s\nwant      %s", got, want)
	}
}

// The first pass, in order: secure, then remove the unsafe entries.
func TestPrepareDataDirSecuresBeforeItRemoves(t *testing.T) {
	userFile := trustedFile()
	userFile.owner = sidUser
	f := newFakeDataFS(map[string]secFacts{dataDirPath: userDir(), filepath.Join(dataDirPath, "config.json"): userFile})
	if err := prepareDataDir(f, dataDirPath); err != nil {
		t.Fatalf("prepareDataDir() = %v", err)
	}
	want := strings.ReplaceAll("openDir {D} | secure {D} | remove {D}/config.json | close {D}", "{D}", dataDirPath)
	if got := f.callsString(); got != want {
		t.Fatalf("calls = %s\nwant    %s", got, want)
	}
}

// When the directory cannot be secured, or is still unsafe afterwards,
// nothing in it is touched and PrepareDir fails.
func TestPrepareDataDirFailsWhenTheDirectoryStaysUnsafe(t *testing.T) {
	userFile := trustedFile()
	userFile.owner = sidUser
	entries := func() map[string]secFacts {
		return map[string]secFacts{dataDirPath: userDir(), filepath.Join(dataDirPath, "config.json"): userFile}
	}
	f := newFakeDataFS(entries())
	f.failSecure = errors.New("Access is denied.")
	err := prepareDataDir(f, dataDirPath)
	if err == nil || err.Error() != "cannot secure "+dataDirPath+": Access is denied." {
		t.Fatalf("prepareDataDir() = %v", err)
	}
	f = newFakeDataFS(entries())
	f.secured = userDir()
	err = prepareDataDir(f, dataDirPath)
	if want := "cannot secure " + dataDirPath + ": " + dataDirPath + " is owned by " + sidUser + "; only SYSTEM and Administrators may write it"; err == nil || err.Error() != want || !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("prepareDataDir() = %v\nwant %s", err, want)
	}
	if strings.Contains(f.callsString(), "remove") {
		t.Fatalf("removed entries of an unsafe directory: %s", f.callsString())
	}
}

// A directory that cannot be opened (held open for writing by someone
// else, or denying SYSTEM) is removed when it can be, else refused.
func TestPrepareDataDirWhenTheDirectoryCannotBeOpened(t *testing.T) {
	held := errors.New("The process cannot access the file because it is being used by another process.")
	f := newFakeDataFS(map[string]secFacts{dataDirPath: userDir()})
	f.failOpen[dataDirPath] = held
	f.failRemove[dataDirPath] = errors.New("The directory is not empty.")
	err := prepareDataDir(f, dataDirPath)
	want := "cannot open " + dataDirPath + ": " + held.Error() + "; it cannot be removed either: The directory is not empty."
	if err == nil || err.Error() != want {
		t.Fatalf("prepareDataDir() = %v\nwant %s", err, want)
	}
	// An empty one (or a junction) is removed and made again.
	f = newFakeDataFS(map[string]secFacts{dataDirPath: userDir()})
	opens := 0
	f.failOpen[dataDirPath] = held
	g := &openOnceFailing{fakeDataFS: f, opens: &opens}
	if err := prepareDataDir(g, dataDirPath); err != nil {
		t.Fatalf("prepareDataDir() = %v", err)
	}
	wantCalls := strings.ReplaceAll("openDir {D} | remove {D} | mkdir {D} | openDir {D} | secure {D} | close {D}", "{D}", dataDirPath)
	if got := f.callsString(); got != wantCalls {
		t.Fatalf("calls = %s\nwant    %s", got, wantCalls)
	}
}

// openOnceFailing fails only the first openDir.
type openOnceFailing struct {
	*fakeDataFS
	opens *int
}

func (o *openOnceFailing) openDir(dir string) (dataDir, error) {
	if *o.opens++; *o.opens > 1 {
		delete(o.failOpen, dir)
	}
	return o.fakeDataFS.openDir(dir)
}

// A name taken again between the removal and the new directory (someone
// recreated the junction) fails, never follows it.
func TestPrepareDataDirFailsWhenTheNameIsTakenAgain(t *testing.T) {
	junction := trustedDir()
	junction.reparse = true
	f := newFakeDataFS(map[string]secFacts{dataDirPath: junction})
	f.failMkdir = fs.ErrExist
	err := prepareDataDir(f, dataDirPath)
	if err == nil || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("prepareDataDir() = %v, want fs.ErrExist", err)
	}
	if strings.Contains(f.callsString(), "secure") {
		t.Fatalf("secured a path it did not create: %s", f.callsString())
	}
}
