package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
)

// The report file: the Windows tray app runs enable and disable elevated,
// where it cannot read their console, so it passes the internal flag
// --report-file PATH (not in the help) and shows the final error message
// they write there. A successful run writes nothing. Only Windows defines
// the flag; elsewhere enable and disable refuse it as an unknown flag.

// reportFileFlag is whether enable and disable define --report-file.
var reportFileFlag = runtime.GOOS == "windows"

// maxReport bounds the report file, in bytes, with its newline.
const maxReport = 4096

// reportFlag adds the internal --report-file flag to fs; run writes the
// final error message to the path it names.
func (c *cli) reportFlag(fs *flag.FlagSet) {
	if !reportFileFlag {
		return
	}
	fs.StringVar(&c.report, "report-file", "", "")
}

// reportMessage is the final error message, what stderr shows after
// "leakguard: ": nothing for success or an already printed exit status.
func reportMessage(err error) string {
	var ue usageError
	var ee exitError
	switch {
	case err == nil, errors.As(err, &ee):
		return ""
	case errors.As(err, &ue):
		return ue.msg
	}
	return err.Error()
}

// writeReport writes err's message and a newline to path, cut to maxReport
// bytes without splitting a character. The file must already exist and be
// a regular file with a single link, not a symbolic link, and on Windows
// be owned by the user who started this run: this process may run as an
// administrator and path comes from a user's program, so it never creates
// a file and never writes through a link to a file the user may not write.
func writeReport(path string, err error) error {
	msg := reportMessage(err)
	if msg == "" {
		return nil
	}
	msg = strings.ToValidUTF8(msg, "�")
	for len(msg)+1 > maxReport {
		msg = strings.ToValidUTF8(msg[:maxReport-1], "")
	}
	before, lerr := os.Lstat(path)
	if lerr != nil {
		return lerr
	}
	if !before.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	// Truncate only once the opened file is known to be the one checked.
	f, oerr := os.OpenFile(path, os.O_WRONLY, 0)
	if oerr != nil {
		return oerr
	}
	after, serr := f.Stat()
	if serr != nil || !os.SameFile(before, after) {
		f.Close()
		return fmt.Errorf("%s changed while it was opened", path)
	}
	if n, lerr := linkCount(f); lerr != nil || n != 1 {
		f.Close()
		if lerr != nil {
			return fmt.Errorf("cannot count the links of %s: %w", path, lerr)
		}
		return fmt.Errorf("%s has more than one link", path)
	}
	if err := checkReportOwner(path, f); err != nil {
		f.Close()
		return err
	}
	werr := f.Truncate(0)
	if werr == nil {
		_, werr = f.WriteString(msg + "\n")
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// reportOwnedBy refuses a report file whose owner is not one of the
// invoker's SIDs (its token's user and default owner): the elevated run
// writes only to a file the user who started it created.
func reportOwnedBy(path, owner string, invoker []string) error {
	if owner != "" && slices.Contains(invoker, owner) {
		return nil
	}
	return fmt.Errorf("%s is not owned by the user who started leakguard", path)
}
