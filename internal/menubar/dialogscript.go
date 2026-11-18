package menubar

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// The AppleScript the app runs with osascript for the setup dialogs, and how
// it reads the answers. Every string goes through appleScriptString, so a
// title, text, button or list item can never end the literal early.

// DialogScript is "display dialog" for d. It prints the clicked button's
// name; the cancel button (d.Cancel, -1 for none) makes osascript fail with
// error -128, which ScriptError turns into ErrCancelled.
func DialogScript(d Dialog) string {
	var b strings.Builder
	b.WriteString("activate\n")
	b.WriteString(`return button returned of (display dialog ` + quoteAS(d.Text) + ` with title ` + quoteAS(d.Title))
	b.WriteString(` buttons ` + listAS(d.Buttons))
	if d.Default >= 0 && d.Default < len(d.Buttons) {
		b.WriteString(` default button ` + quoteAS(d.Buttons[d.Default]))
	}
	if d.Cancel >= 0 && d.Cancel < len(d.Buttons) {
		b.WriteString(` cancel button ` + quoteAS(d.Buttons[d.Cancel]))
	}
	b.WriteString(` with icon note)`)
	return b.String()
}

// ListScript is "choose from list" for l. It prints the 1-based positions
// of the chosen items, separated by commas (names could contain commas), and
// fails with error -128 when the user cancels.
func ListScript(l List) string {
	multiple := ""
	if l.Multiple {
		multiple = " with multiple selections allowed"
	}
	return `set L to ` + listAS(l.Items) + `
activate
set picked to choose from list L with title ` + quoteAS(l.Title) + ` with prompt ` + quoteAS(l.Text) +
		` OK button name ` + quoteAS(l.OK) + ` cancel button name ` + quoteAS(l.Cancel) + multiple + `
if picked is false then error number -128
set out to {}
considering case
	repeat with p in picked
		repeat with i from 1 to count of L
			if item i of L is (contents of p) then set end of out to i
		end repeat
	end repeat
end considering
set AppleScript's text item delimiters to ","
return out as text`
}

// ParseButton returns the index of the button whose name DialogScript printed.
func ParseButton(out string, d Dialog) (int, error) {
	name := strings.TrimSuffix(out, "\n")
	if i := slices.Index(d.Buttons, name); i >= 0 {
		return i, nil
	}
	return 0, fmt.Errorf("unexpected dialog answer %q", name)
}

// ParseChoice returns the 0-based indexes of the items ListScript printed,
// refusing anything out of range, repeated, empty, or several for a
// single-choice list.
func ParseChoice(out string, l List) ([]int, error) {
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, errors.New("nothing was chosen")
	}
	var picks []int
	for _, f := range strings.Split(out, ",") {
		n, err := strconv.Atoi(f)
		if err != nil || n < 1 || n > len(l.Items) || slices.Contains(picks, n-1) {
			return nil, fmt.Errorf("unexpected list answer %q", out)
		}
		picks = append(picks, n-1)
	}
	if !l.Multiple && len(picks) != 1 {
		return nil, fmt.Errorf("unexpected list answer %q", out)
	}
	return picks, nil
}

// ScriptError explains a failed osascript run from its output, such as
// "0:95: execution error: User canceled. (-128)". A cancel (error -128, in
// any language) is ErrCancelled. Without any output, it reports err, the
// error from running osascript.
func ScriptError(output string, err error) error {
	if strings.TrimSpace(output) == "" {
		if err != nil {
			return errors.New(firstLine(err.Error()))
		}
		return errors.New("osascript failed")
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	if _, msg, ok := strings.Cut(last, "execution error: "); ok {
		last = msg
	}
	if strings.HasSuffix(last, "(-128)") {
		return ErrCancelled
	}
	if i := strings.LastIndex(last, " ("); i > 0 && strings.HasSuffix(last, ")") {
		if _, err := strconv.Atoi(last[i+2 : len(last)-1]); err == nil {
			last = last[:i]
		}
	}
	if last == "" {
		return errors.New("osascript failed")
	}
	return errors.New(last)
}

func quoteAS(s string) string { return `"` + appleScriptString(s) + `"` }

func listAS(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = quoteAS(s)
	}
	return "{" + strings.Join(q, ", ") + "}"
}
