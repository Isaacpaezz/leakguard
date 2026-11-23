package menubar

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The Linux dialogs: zenity (GNOME and most desktops) or, without it,
// kdialog (KDE). Every argument is passed as its own argv entry with
// --option=value, never through a shell; user-visible text is escaped for
// the tool's markup, so it shows exactly as written.

// DialogTool is the program that draws the Linux dialogs.
type DialogTool string

const (
	Zenity  DialogTool = "zenity"
	KDialog DialogTool = "kdialog"
)

// ErrNoDialogTool: neither zenity nor kdialog is installed; Explain asks the
// user to install zenity.
var ErrNoDialogTool = errors.New("no dialog program found: install zenity")

// ToolResult is how a program run ended: what it printed and its exit code.
type ToolResult struct {
	Stdout, Stderr string
	Code           int
}

// CommandRunner runs the program at path with args. The error is only for
// a program that could not run or did not exit; an exit code is a result.
type CommandRunner func(path string, args ...string) (ToolResult, error)

// FindDialogTool returns the path and kind of the dialog program: zenity
// first, then kdialog.
func FindDialogTool(lookPath func(string) (string, error)) (string, DialogTool, error) {
	for _, tool := range []DialogTool{Zenity, KDialog} {
		if path, err := lookPath(string(tool)); err == nil {
			return path, tool, nil
		}
	}
	return "", "", ErrNoDialogTool
}

// zenityText escapes s for zenity's --text: zenity reads it as Pango markup
// after expanding backslash escapes.
func zenityText(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.NewReplacer(`\`, `\\`, "&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
	return s
}

// kdialogText makes s rich text for kdialog, so a "<" in it can never
// switch the text to markup: escaped, with line breaks as <br>.
func kdialogText(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\n", "<br>").Replace(s)
	return "<qt>" + s + "</qt>"
}

// buttons sorts d's buttons into the tool's roles: ok answers with exit 0,
// cancel with exit 1 (zenity) and real tells whether it is d's cancel
// button; extra holds the rest, in order. With no cancel button of its own,
// the first other button takes that role; the tools answer for it exactly
// as for a closed dialog, so ParseAsk reads it as ErrCancelled.
func buttons(d Dialog) (ok, cancel int, real bool, extra []int) {
	n := len(d.Buttons)
	valid := func(i int) bool { return i >= 0 && i < n }
	cancel, real = d.Cancel, valid(d.Cancel)
	if !real {
		cancel = -1
	}
	ok = d.Default
	if !valid(ok) || ok == cancel {
		for i := n - 1; i >= 0; i-- {
			if i != cancel {
				ok = i
				break
			}
		}
	}
	for i := range n {
		if i == ok {
			continue
		}
		if cancel < 0 {
			cancel = i
			continue
		}
		if i != cancel {
			extra = append(extra, i)
		}
	}
	return ok, cancel, real, extra
}

// AskArgs is the argv, without the program, that shows d with tool.
func AskArgs(tool DialogTool, d Dialog) ([]string, error) {
	n := len(d.Buttons)
	if n == 0 {
		return nil, errors.New("a dialog needs a button")
	}
	if tool == KDialog && n > 3 {
		return nil, fmt.Errorf("kdialog cannot show %d buttons", n)
	}
	title := "--title=" + d.Title
	if n == 1 {
		if tool == KDialog {
			return []string{title, "--ok-label=" + d.Buttons[0], "--msgbox=" + kdialogText(d.Text)}, nil
		}
		return []string{"--info", title, "--text=" + zenityText(d.Text), "--ok-label=" + d.Buttons[0], "--width=420"}, nil
	}
	ok, cancel, real, extra := buttons(d)
	defaultCancel := real && d.Default == cancel
	if tool == KDialog {
		// kdialog cannot move the focus, but its warning boxes focus the
		// button that cancels (No, or Cancel with three buttons), which
		// is d's cancel button here; Escape picks it in every box.
		kind := "--"
		if defaultCancel {
			kind = "--warning"
		}
		args := []string{title, "--yes-label=" + d.Buttons[ok]}
		if len(extra) == 0 {
			return append(args, "--no-label="+d.Buttons[cancel], kind+"yesno="+kdialogText(d.Text)), nil
		}
		return append(args, "--no-label="+d.Buttons[extra[0]], "--cancel-label="+d.Buttons[cancel],
			kind+"yesnocancel="+kdialogText(d.Text)), nil
	}
	args := []string{"--question", title, "--text=" + zenityText(d.Text),
		"--ok-label=" + d.Buttons[ok], "--cancel-label=" + d.Buttons[cancel]}
	for _, i := range extra {
		args = append(args, "--extra-button="+d.Buttons[i])
	}
	if defaultCancel {
		args = append(args, "--default-cancel")
	}
	return append(args, "--width=420"), nil
}

// ParseAsk returns the index of the button the user clicked in d, or
// ErrCancelled for d's cancel button or a closed dialog. A closed dialog
// answers like the button in the cancel role, so without a cancel button of
// its own that answer is ErrCancelled too: closing never picks a button.
func ParseAsk(tool DialogTool, d Dialog, r ToolResult) (int, error) {
	n := len(d.Buttons)
	if n == 0 {
		return 0, errors.New("a dialog needs a button")
	}
	ok, cancel, _, extra := buttons(d)
	pick := -1
	switch {
	case r.Code == 0:
		pick = ok
	case n == 1 && r.Code == 1:
		return 0, ErrCancelled
	case tool == Zenity && r.Code == 1:
		name := strings.TrimSuffix(r.Stdout, "\n")
		if name == "" {
			pick = cancel
			break
		}
		for _, i := range extra {
			if d.Buttons[i] == name {
				return i, nil
			}
		}
		return 0, unexpected("unexpected dialog answer %q", name)
	case tool == KDialog && r.Code == 1:
		pick = cancel
		if len(extra) > 0 {
			pick = extra[0]
		}
	case tool == KDialog && r.Code == 2 && n == 3:
		pick = cancel
	default:
		return 0, toolFailed(tool, r)
	}
	if pick == cancel {
		return 0, ErrCancelled
	}
	return pick, nil
}

// ChooseArgs is the argv, without the program, that shows l with tool:
// checkboxes for several items, none ticked; radio buttons for one, with
// the first chosen, so OK always answers with an item. Each item is tagged
// with its 1-based position, which the tool prints back.
func ChooseArgs(tool DialogTool, l List) []string {
	title := "--title=" + l.Title
	chosen := func(i int) bool { return i == 0 && !l.Multiple }
	if tool == KDialog {
		args := []string{title, "--ok-label=" + l.OK, "--cancel-label=" + l.Cancel}
		if l.Multiple {
			args = append(args, "--separate-output", "--checklist="+kdialogText(l.Text))
		} else {
			args = append(args, "--radiolist="+kdialogText(l.Text))
		}
		args = append(args, "--")
		for i, item := range l.Items {
			state := "off"
			if chosen(i) {
				state = "on"
			}
			args = append(args, strconv.Itoa(i+1), item, state)
		}
		return args
	}
	kind := "--radiolist"
	if l.Multiple {
		kind = "--checklist"
	}
	args := []string{"--list", kind, title, "--text=" + zenityText(l.Text), "--ok-label=" + l.OK, "--cancel-label=" + l.Cancel,
		"--column=", "--column=", "--column=", "--hide-header", "--hide-column=2", "--print-column=2",
		"--separator=,", "--width=420", "--height=320", "--"}
	for i, item := range l.Items {
		state := "FALSE"
		if chosen(i) {
			state = "TRUE"
		}
		args = append(args, state, strconv.Itoa(i+1), item)
	}
	return args
}

// ParseChoose returns the 0-based indexes the user chose in l (none when
// the user ticked nothing in a list of several), or ErrCancelled, also for
// a list of one choice answered with none: it is never an empty choice.
func ParseChoose(tool DialogTool, l List, r ToolResult) ([]int, error) {
	switch r.Code {
	case 0:
	case 1:
		return nil, ErrCancelled
	default:
		return nil, toolFailed(tool, r)
	}
	var tags []string
	for _, f := range strings.FieldsFunc(r.Stdout, func(r rune) bool { return r == ',' || r == '\n' }) {
		if f = strings.Trim(strings.TrimSpace(f), `"`); f != "" {
			tags = append(tags, f)
		}
	}
	if len(tags) == 0 {
		if !l.Multiple {
			return nil, ErrCancelled
		}
		return []int{}, nil
	}
	return ParseChoice(strings.Join(tags, ","), l)
}

func toolFailed(tool DialogTool, r ToolResult) error {
	if line := firstNonEmptyLine(r.Stderr); line != "" {
		return fmt.Errorf("%s failed: %s", tool, line)
	}
	return fmt.Errorf("%s exited with status %d", tool, r.Code)
}

// ToolDialogs draws the wizard with zenity or kdialog (see FindDialogTool).
// Cancelling returns ErrCancelled; with neither tool installed every dialog
// returns ErrNoDialogTool.
type ToolDialogs struct {
	LookPath func(string) (string, error)
	Run      CommandRunner
}

func (t ToolDialogs) run(args func(DialogTool) ([]string, error)) (DialogTool, ToolResult, error) {
	path, tool, err := FindDialogTool(t.LookPath)
	if err != nil {
		return "", ToolResult{}, err
	}
	argv, err := args(tool)
	if err != nil {
		return "", ToolResult{}, err
	}
	r, err := t.Run(path, argv...)
	if err != nil {
		return "", ToolResult{}, fmt.Errorf("%s failed: %s", tool, firstLine(err.Error()))
	}
	return tool, r, nil
}

func (t ToolDialogs) Ask(d Dialog) (int, error) {
	tool, r, err := t.run(func(tool DialogTool) ([]string, error) { return AskArgs(tool, d) })
	if err != nil {
		return 0, err
	}
	return ParseAsk(tool, d, r)
}

func (t ToolDialogs) Choose(l List) ([]int, error) {
	tool, r, err := t.run(func(tool DialogTool) ([]string, error) { return ChooseArgs(tool, l), nil })
	if err != nil {
		return nil, err
	}
	return ParseChoose(tool, l, r)
}

var _ Dialogs = ToolDialogs{}
