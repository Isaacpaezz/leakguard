package menubar

import (
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"
)

func lookPathOf(found ...string) func(string) (string, error) {
	return func(name string) (string, error) {
		if slices.Contains(found, name) {
			return "/usr/bin/" + name, nil
		}
		return "", fs.ErrNotExist
	}
}

// S1: zenity first, kdialog as the fallback, and a plain error when neither
// is installed.
func TestFindDialogTool(t *testing.T) {
	tests := []struct {
		found    []string
		wantPath string
		wantTool DialogTool
	}{
		{[]string{"zenity", "kdialog"}, "/usr/bin/zenity", Zenity},
		{[]string{"zenity"}, "/usr/bin/zenity", Zenity},
		{[]string{"kdialog"}, "/usr/bin/kdialog", KDialog},
	}
	for _, tc := range tests {
		path, tool, err := FindDialogTool(lookPathOf(tc.found...))
		if err != nil || path != tc.wantPath || tool != tc.wantTool {
			t.Errorf("FindDialogTool(%v) = %q, %q, %v; want %q, %q, nil", tc.found, path, tool, err, tc.wantPath, tc.wantTool)
		}
	}
	_, _, err := FindDialogTool(lookPathOf())
	if !errors.Is(err, ErrNoDialogTool) {
		t.Fatalf("no tool: err = %v, want ErrNoDialogTool", err)
	}
	if got, want := Explain(English, err), "Install zenity to see leakguard's windows"; got != want {
		t.Errorf("Explain(en) = %q, want %q", got, want)
	}
	if got, want := Explain(Spanish, err), "Instala zenity para ver las ventanas de leakguard"; got != want {
		t.Errorf("Explain(es) = %q, want %q", got, want)
	}
	if got, want := WizardMessage(English, err), "Something went wrong: Install zenity to see leakguard's windows\n\nYou can try again from the menu."; got != want {
		t.Errorf("WizardMessage = %q, want %q", got, want)
	}
	if got := Short(WizardMessage(Spanish, err), MenuLineLength); strings.HasSuffix(got, "…") {
		t.Errorf("the Spanish menu line is cut: %q", got)
	}
}

var (
	tellDialog   = Dialog{Title: "leakguard", Text: "Done", Buttons: []string{"OK"}, Default: 0, Cancel: -1}
	nextDialog   = Dialog{Title: "Step 2 of 3", Text: "Disconnect", Buttons: []string{"Cancel", "Next"}, Default: 1, Cancel: 0}
	foundDialog  = Dialog{Title: "Step 2 of 3", Text: "Found", Buttons: []string{"Cancel", "Choose another", "Use this VPN"}, Default: 2, Cancel: 0}
	uninstDialog = Dialog{Title: "Uninstall leakguard", Text: "Sure?", Buttons: []string{"Cancel", "Uninstall"}, Default: 0, Cancel: 0}
	// No dialog of the app has these; they pin the tools' closing rule.
	safe3Dialog   = Dialog{Title: "T", Text: "Sure?", Buttons: []string{"Cancel", "Keep", "Erase"}, Default: 0, Cancel: 0}
	noCancelTwo   = Dialog{Title: "T", Text: "Pick", Buttons: []string{"Later", "Now"}, Default: 1, Cancel: -1}
	noCancelThree = Dialog{Title: "T", Text: "Pick", Buttons: []string{"A", "B", "C"}, Default: 2, Cancel: -1}
)

func TestAskArgsZenity(t *testing.T) {
	tests := []struct {
		d    Dialog
		want []string
	}{
		{tellDialog, []string{"--info", "--title=leakguard", "--text=Done", "--ok-label=OK", "--width=420"}},
		{nextDialog, []string{"--question", "--title=Step 2 of 3", "--text=Disconnect", "--ok-label=Next", "--cancel-label=Cancel", "--width=420"}},
		{foundDialog, []string{"--question", "--title=Step 2 of 3", "--text=Found", "--ok-label=Use this VPN", "--cancel-label=Cancel", "--extra-button=Choose another", "--width=420"}},
		// Return must not uninstall: Cancel keeps the focus.
		{uninstDialog, []string{"--question", "--title=Uninstall leakguard", "--text=Sure?", "--ok-label=Uninstall", "--cancel-label=Cancel", "--default-cancel", "--width=420"}},
	}
	for _, tc := range tests {
		got, err := AskArgs(Zenity, tc.d)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("AskArgs(zenity, %q) = %q, %v; want %q", tc.d.Buttons, got, err, tc.want)
		}
	}
}

func TestAskArgsKDialog(t *testing.T) {
	tests := []struct {
		d    Dialog
		want []string
	}{
		{tellDialog, []string{"--title=leakguard", "--ok-label=OK", "--msgbox=<qt>Done</qt>"}},
		{nextDialog, []string{"--title=Step 2 of 3", "--yes-label=Next", "--no-label=Cancel", "--yesno=<qt>Disconnect</qt>"}},
		{foundDialog, []string{"--title=Step 2 of 3", "--yes-label=Use this VPN", "--no-label=Choose another", "--cancel-label=Cancel", "--yesnocancel=<qt>Found</qt>"}},
		// Return must not uninstall: kdialog's warning boxes focus the
		// cancelling button (No, or Cancel with three) and Escape picks it.
		{uninstDialog, []string{"--title=Uninstall leakguard", "--yes-label=Uninstall", "--no-label=Cancel", "--warningyesno=<qt>Sure?</qt>"}},
		{safe3Dialog, []string{"--title=T", "--yes-label=Erase", "--no-label=Keep", "--cancel-label=Cancel", "--warningyesnocancel=<qt>Sure?</qt>"}},
	}
	for _, tc := range tests {
		got, err := AskArgs(KDialog, tc.d)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("AskArgs(kdialog, %q) = %q, %v; want %q", tc.d.Buttons, got, err, tc.want)
		}
	}
	four := Dialog{Buttons: []string{"a", "b", "c", "d"}, Default: 0, Cancel: -1}
	if _, err := AskArgs(KDialog, four); err == nil {
		t.Error("kdialog with four buttons: no error")
	}
	if _, err := AskArgs(Zenity, Dialog{}); err == nil {
		t.Error("a dialog without buttons: no error")
	}
}

// S1: user-visible text never turns into markup, escapes or options.
func TestDialogTextIsEscaped(t *testing.T) {
	d := Dialog{Title: `--title <b>&`, Text: "a <b>&</b> \\n z\nnext", Buttons: []string{"OK"}, Default: 0, Cancel: -1}
	z, _ := AskArgs(Zenity, d)
	if want := "--text=a &lt;b&gt;&amp;&lt;/b&gt; \\\\n z\nnext"; z[2] != want {
		t.Errorf("zenity text = %q, want %q", z[2], want)
	}
	if want := "--title=--title <b>&"; z[1] != want {
		t.Errorf("zenity title = %q, want %q", z[1], want)
	}
	k, _ := AskArgs(KDialog, d)
	if want := "--msgbox=<qt>a &lt;b&gt;&amp;&lt;/b&gt; \\n z<br>next</qt>"; k[2] != want {
		t.Errorf("kdialog text = %q, want %q", k[2], want)
	}
	l := List{Title: "T", Text: "pick <one> & go", Items: []string{"-x", "b"}, OK: "Next", Cancel: "Cancel"}
	zl := ChooseArgs(Zenity, l)
	if !slices.Contains(zl, "--text=pick &lt;one&gt; &amp; go") {
		t.Errorf("zenity list text not escaped: %q", zl)
	}
	if i := slices.Index(zl, "--"); i < 0 || slices.Index(zl, "-x") < i {
		t.Errorf("zenity list items are not after --: %q", zl)
	}
	kl := ChooseArgs(KDialog, l)
	if !slices.Contains(kl, "--radiolist=<qt>pick &lt;one&gt; &amp; go</qt>") {
		t.Errorf("kdialog list text not escaped: %q", kl)
	}
	if i := slices.Index(kl, "--"); i < 0 || slices.Index(kl, "-x") < i {
		t.Errorf("kdialog list items are not after --: %q", kl)
	}
}

func TestChooseArgs(t *testing.T) {
	multi := List{Title: "Step 1 of 3", Text: "Choose", Items: []string{"Claude", "OpenAI"}, OK: "Next", Cancel: "Cancel", Multiple: true}
	single := List{Title: "Change VPN", Text: "Which", Items: []string{"WireGuard (wg0)", "VPN (tun0)"}, OK: "Next", Cancel: "Cancel"}
	tests := []struct {
		tool DialogTool
		l    List
		want []string
	}{
		{Zenity, multi, []string{"--list", "--checklist", "--title=Step 1 of 3", "--text=Choose", "--ok-label=Next", "--cancel-label=Cancel",
			"--column=", "--column=", "--column=", "--hide-header", "--hide-column=2", "--print-column=2", "--separator=,", "--width=420", "--height=320",
			"--", "FALSE", "1", "Claude", "FALSE", "2", "OpenAI"}},
		// One choice: radio buttons with the first row chosen, so OK always
		// answers with a row.
		{Zenity, single, []string{"--list", "--radiolist", "--title=Change VPN", "--text=Which", "--ok-label=Next", "--cancel-label=Cancel",
			"--column=", "--column=", "--column=", "--hide-header", "--hide-column=2", "--print-column=2", "--separator=,", "--width=420", "--height=320",
			"--", "TRUE", "1", "WireGuard (wg0)", "FALSE", "2", "VPN (tun0)"}},
		{KDialog, multi, []string{"--title=Step 1 of 3", "--ok-label=Next", "--cancel-label=Cancel", "--separate-output", "--checklist=<qt>Choose</qt>",
			"--", "1", "Claude", "off", "2", "OpenAI", "off"}},
		{KDialog, single, []string{"--title=Change VPN", "--ok-label=Next", "--cancel-label=Cancel", "--radiolist=<qt>Which</qt>",
			"--", "1", "WireGuard (wg0)", "on", "2", "VPN (tun0)", "off"}},
	}
	for _, tc := range tests {
		if got := ChooseArgs(tc.tool, tc.l); !slices.Equal(got, tc.want) {
			t.Errorf("ChooseArgs(%s, multiple=%v) =\n%q\nwant\n%q", tc.tool, tc.l.Multiple, got, tc.want)
		}
	}
}

func TestParseAsk(t *testing.T) {
	tests := []struct {
		tool DialogTool
		d    Dialog
		r    ToolResult
		want int
		err  error
	}{
		{Zenity, tellDialog, ToolResult{Code: 0}, 0, nil},
		{Zenity, tellDialog, ToolResult{Code: 1}, 0, ErrCancelled},
		{Zenity, nextDialog, ToolResult{Code: 0}, 1, nil},
		{Zenity, nextDialog, ToolResult{Code: 1}, 0, ErrCancelled},
		{Zenity, foundDialog, ToolResult{Code: 0}, 2, nil},
		{Zenity, foundDialog, ToolResult{Code: 1, Stdout: "Choose another\n"}, 1, nil},
		{Zenity, foundDialog, ToolResult{Code: 1}, 0, ErrCancelled},
		{Zenity, foundDialog, ToolResult{Code: 1, Stdout: "Other\n"}, 0, ErrUnexpectedAnswer},
		{Zenity, uninstDialog, ToolResult{Code: 0}, 1, nil},
		{Zenity, uninstDialog, ToolResult{Code: 1}, 0, ErrCancelled},
		{KDialog, tellDialog, ToolResult{Code: 0}, 0, nil},
		{KDialog, nextDialog, ToolResult{Code: 0}, 1, nil},
		{KDialog, nextDialog, ToolResult{Code: 1}, 0, ErrCancelled},
		{KDialog, foundDialog, ToolResult{Code: 0}, 2, nil},
		{KDialog, foundDialog, ToolResult{Code: 1}, 1, nil},
		{KDialog, foundDialog, ToolResult{Code: 2}, 0, ErrCancelled},
		{KDialog, uninstDialog, ToolResult{Code: 0}, 1, nil},
		{KDialog, uninstDialog, ToolResult{Code: 1}, 0, ErrCancelled},
		{KDialog, safe3Dialog, ToolResult{Code: 0}, 2, nil},
		{KDialog, safe3Dialog, ToolResult{Code: 1}, 1, nil},
		{KDialog, safe3Dialog, ToolResult{Code: 2}, 0, ErrCancelled},
		// Without a cancel button of its own, closing the dialog (Escape,
		// the window's close button) never picks a button.
		{Zenity, noCancelTwo, ToolResult{Code: 0}, 1, nil},
		{Zenity, noCancelTwo, ToolResult{Code: 1}, 0, ErrCancelled},
		{KDialog, noCancelTwo, ToolResult{Code: 0}, 1, nil},
		{KDialog, noCancelTwo, ToolResult{Code: 1}, 0, ErrCancelled},
		{Zenity, noCancelThree, ToolResult{Code: 0}, 2, nil},
		{Zenity, noCancelThree, ToolResult{Code: 1, Stdout: "B\n"}, 1, nil},
		{Zenity, noCancelThree, ToolResult{Code: 1}, 0, ErrCancelled},
		{KDialog, noCancelThree, ToolResult{Code: 0}, 2, nil},
		{KDialog, noCancelThree, ToolResult{Code: 1}, 1, nil},
		{KDialog, noCancelThree, ToolResult{Code: 2}, 0, ErrCancelled},
	}
	for i, tc := range tests {
		got, err := ParseAsk(tc.tool, tc.d, tc.r)
		if tc.err != nil {
			if !errors.Is(err, tc.err) {
				t.Errorf("%d: ParseAsk(%s, %+v) err = %v, want %v", i, tc.tool, tc.r, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%d: ParseAsk(%s, %+v) = %d, %v; want %d", i, tc.tool, tc.r, got, err, tc.want)
		}
	}
	_, err := ParseAsk(Zenity, nextDialog, ToolResult{Code: 255, Stderr: "cannot open display\nmore"})
	if err == nil || err.Error() != "zenity failed: cannot open display" {
		t.Errorf("failed zenity: err = %v", err)
	}
}

func TestParseChoose(t *testing.T) {
	multi := List{Items: []string{"a", "b", "c"}, Multiple: true}
	single := List{Items: []string{"a", "b"}}
	tests := []struct {
		tool DialogTool
		l    List
		r    ToolResult
		want []int
		err  error
	}{
		{Zenity, multi, ToolResult{Stdout: "1,3\n"}, []int{0, 2}, nil},
		{Zenity, multi, ToolResult{Stdout: "\n"}, []int{}, nil},
		{Zenity, single, ToolResult{Stdout: "2\n"}, []int{1}, nil},
		{Zenity, single, ToolResult{Stdout: "1,2\n"}, nil, ErrUnexpectedAnswer},
		{Zenity, multi, ToolResult{Code: 1}, nil, ErrCancelled},
		{KDialog, multi, ToolResult{Stdout: "1\n3\n"}, []int{0, 2}, nil},
		{KDialog, multi, ToolResult{Stdout: ""}, []int{}, nil},
		{KDialog, single, ToolResult{Stdout: "2\n"}, []int{1}, nil},
		{KDialog, single, ToolResult{Stdout: "4\n"}, nil, ErrUnexpectedAnswer},
		{KDialog, single, ToolResult{Code: 1}, nil, ErrCancelled},
		// OK with no row chosen is never an empty choice of one.
		{Zenity, single, ToolResult{Stdout: "\n"}, nil, ErrCancelled},
		{Zenity, single, ToolResult{Stdout: ""}, nil, ErrCancelled},
		{KDialog, single, ToolResult{Stdout: ""}, nil, ErrCancelled},
		{KDialog, single, ToolResult{Stdout: "\n"}, nil, ErrCancelled},
	}
	for i, tc := range tests {
		got, err := ParseChoose(tc.tool, tc.l, tc.r)
		if tc.err != nil {
			if !errors.Is(err, tc.err) {
				t.Errorf("%d: ParseChoose(%s, %+v) err = %v, want %v", i, tc.tool, tc.r, err, tc.err)
			}
			continue
		}
		if err != nil || !slices.Equal(got, tc.want) || got == nil {
			t.Errorf("%d: ParseChoose(%s, %+v) = %v, %v; want %v", i, tc.tool, tc.r, got, err, tc.want)
		}
	}
}

// ToolDialogs runs the tool it found with the argv for the dialog.
func TestToolDialogs(t *testing.T) {
	var gotPath string
	var gotArgs []string
	d := ToolDialogs{
		LookPath: lookPathOf("kdialog"),
		Run: func(path string, args ...string) (ToolResult, error) {
			gotPath, gotArgs = path, args
			return ToolResult{Code: 1}, nil
		},
	}
	b, err := d.Ask(foundDialog)
	if err != nil || b != 1 {
		t.Errorf("Ask = %d, %v; want 1, nil", b, err)
	}
	want, _ := AskArgs(KDialog, foundDialog)
	if gotPath != "/usr/bin/kdialog" || !slices.Equal(gotArgs, want) {
		t.Errorf("ran %q %q, want /usr/bin/kdialog %q", gotPath, gotArgs, want)
	}
	if _, err := d.Choose(List{Items: []string{"a"}}); !errors.Is(err, ErrCancelled) {
		t.Errorf("Choose err = %v, want ErrCancelled", err)
	}
	none := ToolDialogs{LookPath: lookPathOf(), Run: func(string, ...string) (ToolResult, error) {
		t.Fatal("ran a program without a dialog tool")
		return ToolResult{}, nil
	}}
	if _, err := none.Ask(tellDialog); !errors.Is(err, ErrNoDialogTool) {
		t.Errorf("Ask without a tool: err = %v", err)
	}
	if _, err := none.Choose(List{Items: []string{"a"}}); !errors.Is(err, ErrNoDialogTool) {
		t.Errorf("Choose without a tool: err = %v", err)
	}
	broken := ToolDialogs{LookPath: lookPathOf("zenity"), Run: func(string, ...string) (ToolResult, error) {
		return ToolResult{}, errors.New("exec format error")
	}}
	if _, err := broken.Ask(tellDialog); err == nil || err.Error() != "zenity failed: exec format error" {
		t.Errorf("a tool that cannot start: err = %v", err)
	}
}
