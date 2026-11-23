package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

// The report file: the Windows tray app runs enable and disable elevated,
// where it cannot read their console, so it passes the internal flag
// --report-file PATH (not in the help) and shows the final error message
// they write there. A successful run writes nothing.

// maxReport bounds the report file, in bytes, with its newline.
const maxReport = 4096

// reportFlag adds the internal --report-file flag to fs; run writes the
// final error message to the path it names.
func (c *cli) reportFlag(fs *flag.FlagSet) {
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
// a regular file, not a link: this process may run as an administrator
// and path comes from a user's program, so it never creates a file and
// never writes through a link.
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
	werr := f.Truncate(0)
	if werr == nil {
		_, werr = f.WriteString(msg + "\n")
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}
