package menubar

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/Isaacpaezz/leakguard/internal/daemon"
)

// Install is what the LaunchDaemon plist says about the installed leakguard.
type Install int

const (
	// InstallNone: no LaunchDaemon plist.
	InstallNone Install = iota
	// InstallOld: a plist from before "serve" (it runs a periodic apply), or
	// one that cannot be read; the installed copy must not be reused.
	InstallOld
	// InstallCurrent: the plist runs "leakguard serve".
	InstallCurrent
)

// maxPlist bounds how much of the plist is read.
const maxPlist = 64 << 10

// InstalledState reads the LaunchDaemon plist under root ("" or "/" for the
// real system). Only a plist whose ProgramArguments include "serve" is
// current; anything else that exists counts as an older install.
func InstalledState(root string) Install {
	f, err := os.Open(filepath.Join(root, daemon.PlistPath))
	if errors.Is(err, fs.ErrNotExist) {
		return InstallNone
	}
	if err != nil {
		return InstallOld
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxPlist))
	if err != nil {
		return InstallOld
	}
	args, ok := programArguments(data)
	if ok && slices.Contains(args, "serve") {
		return InstallCurrent
	}
	return InstallOld
}

// programArguments returns the strings of the ProgramArguments array in the
// top-level dict of an XML property list.
func programArguments(data []byte) ([]string, bool) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	depth := 0
	var lastKey string
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			// plist > dict > key/array: the top-level entries are at depth 3.
			if depth != 3 {
				continue
			}
			switch t.Name.Local {
			case "key":
				var k string
				if err := dec.DecodeElement(&k, &t); err != nil {
					return nil, false
				}
				depth--
				lastKey = k
				continue
			case "array":
				if lastKey == "ProgramArguments" {
					var arr struct {
						Strings []string `xml:"string"`
					}
					if err := dec.DecodeElement(&arr, &t); err != nil {
						return nil, false
					}
					return arr.Strings, true
				}
			}
			lastKey = ""
		case xml.EndElement:
			depth--
		}
	}
}
