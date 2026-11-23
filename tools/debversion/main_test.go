package main

import (
	"bytes"
	"fmt"
	"testing"
)

func convert(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

// S5: the .deb's Version field. A pre-release must sort before its release
// in dpkg, so its hyphens become tildes; a release stays as it is.
func TestDebianVersion(t *testing.T) {
	for in, want := range map[string]string{
		"0.2.0":        "0.2.0\n",
		"1.10.3":       "1.10.3\n",
		"0.2.0-beta.1": "0.2.0~beta.1\n",
		"0.0.0-ci":     "0.0.0~ci\n",
		"1.0.0-rc.1-x": "1.0.0~rc.1~x\n",
	} {
		code, out, errOut := convert(in)
		if code != 0 || out != want || errOut != "" {
			t.Errorf("%q: exit %d, stdout %q, stderr %q; want exit 0, stdout %q", in, code, out, errOut, want)
		}
	}
}

// Only the versions scripts/build-macos.sh accepts reach the control file.
func TestRefusesWhatIsNotAVersion(t *testing.T) {
	for _, in := range []string{"", "v0.2.0", "0.2", "01.2.3", "0.2.0+build.1", "0.2.0-", "0.2.0-beta..1", "0.2.0\nDepends: x"} {
		code, out, errOut := convert(in)
		want := fmt.Sprintf("debversion: %q is not a version like 1.2.3 or 1.2.3-rc.1\n", in) + usage
		if code != 2 || out != "" || errOut != want {
			t.Errorf("%q: exit %d, stdout %q, stderr %q; want exit 2 and %q", in, code, out, errOut, want)
		}
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"0.1.0", "0.2.0"}} {
		code, out, errOut := convert(args...)
		if code != 2 || out != "" || errOut != usage {
			t.Errorf("%q: exit %d, stdout %q, stderr %q; want exit 2 and the usage", args, code, out, errOut)
		}
	}
}
