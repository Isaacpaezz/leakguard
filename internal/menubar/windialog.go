package menubar

import (
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

// The Windows dialogs: TaskDialogIndirect (comctl32 version 6, which needs
// the application manifest) and, without it, MessageBoxW. This file builds
// their parameters and reads their answers without calling Windows; the
// calls are in windialog_windows.go.

// Button IDs, flags and icons of TaskDialogIndirect and MessageBoxW
// (winuser.h, commctrl.h).
const (
	idOK     = 1
	idCancel = 2
	idYes    = 6
	idNo     = 7

	tdfAllowDialogCancellation = 0x0008
	tdcbfYes                   = 0x0002
	tdcbfNo                    = 0x0004
	tdcbfCancel                = 0x0008
	tdWarningIcon              = 0xFFFF // MAKEINTRESOURCEW(-1)
	tdInformationIcon          = 0xFFFD // MAKEINTRESOURCEW(-3)

	mbOK              = 0x00000000
	mbOKCancel        = 0x00000001
	mbYesNoCancel     = 0x00000003
	mbIconQuestion    = 0x00000020
	mbIconWarning     = 0x00000030
	mbIconInformation = 0x00000040
	mbDefButton2      = 0x00000100
	mbDefButton3      = 0x00000200
	mbSetForeground   = 0x00010000
	mbTopmost         = 0x00040000

	// Custom buttons and radio buttons get IDs far from Windows' own.
	buttonBase = 100
	radioBase  = 200
)

// taskButton is one custom button or radio button of a task dialog.
type taskButton struct {
	ID   int32
	Text string
}

// taskDialog is what TaskDialogIndirect shows.
type taskDialog struct {
	Title, Instruction, Content string
	Buttons                     []taskButton
	CommonButtons               uint32
	DefaultButton               int32
	Radios                      []taskButton
	DefaultRadio                int32
	Flags                       uint32
	Icon                        uint64
}

// messageBox is what MessageBoxW shows.
type messageBox struct {
	Caption, Text string
	Type          uint32
}

// buttonLabel keeps "&" literal: Windows reads it as an accelerator.
func buttonLabel(s string) string { return strings.ReplaceAll(s, "&", "&&") }

// defaultCancels reports whether d focuses its own cancel button: a
// destructive confirmation, shown with a warning icon.
func defaultCancels(d Dialog) bool {
	return d.Cancel >= 0 && d.Cancel < len(d.Buttons) && d.Default == d.Cancel
}

// askTaskDialog shows d's buttons in the Windows order, the macOS order
// reversed (the action first, Cancel last), with d's default focused.
// Escape and the close box answer IDCANCEL.
func askTaskDialog(d Dialog) (taskDialog, error) {
	n := len(d.Buttons)
	if n == 0 {
		return taskDialog{}, errors.New("a dialog needs a button")
	}
	c := taskDialog{Title: d.Title, Content: d.Text, Flags: tdfAllowDialogCancellation, Icon: tdInformationIcon}
	for i := n - 1; i >= 0; i-- {
		c.Buttons = append(c.Buttons, taskButton{int32(buttonBase + i), buttonLabel(d.Buttons[i])})
	}
	def := d.Default
	if def < 0 || def >= n {
		def, _, _, _ = buttons(d)
	}
	c.DefaultButton = int32(buttonBase + def)
	if defaultCancels(d) {
		c.Icon = tdWarningIcon
	}
	return c, nil
}

// parseTaskDialogAsk returns the index of the button clicked in d, or
// ErrCancelled for d's cancel button, Escape or the close box.
func parseTaskDialogAsk(d Dialog, button int32) (int, error) {
	if button == idCancel {
		return 0, ErrCancelled
	}
	i := int(button) - buttonBase
	if i < 0 || i >= len(d.Buttons) {
		return 0, unexpected("unexpected dialog answer %q", strconv.Itoa(int(button)))
	}
	if i == d.Cancel {
		return 0, ErrCancelled
	}
	return i, nil
}

// chooseTaskDialog shows l, a list of one choice, as radio buttons with
// the first chosen, and [OK] [Cancel].
func chooseTaskDialog(l List) taskDialog {
	c := taskDialog{Title: l.Title, Content: l.Text, Flags: tdfAllowDialogCancellation, Icon: tdInformationIcon,
		Buttons:       []taskButton{{buttonBase, buttonLabel(l.OK)}, {buttonBase + 1, buttonLabel(l.Cancel)}},
		DefaultButton: buttonBase, DefaultRadio: radioBase}
	for i, item := range l.Items {
		c.Radios = append(c.Radios, taskButton{int32(radioBase + i), buttonLabel(item)})
	}
	return c
}

// parseTaskDialogChoose returns the chosen item, or ErrCancelled for
// Cancel and for no item: one choice is never empty.
func parseTaskDialogChoose(l List, button, radio int32) ([]int, error) {
	switch button {
	case buttonBase:
	case buttonBase + 1, idCancel:
		return nil, ErrCancelled
	default:
		return nil, unexpected("unexpected dialog answer %q", strconv.Itoa(int(button)))
	}
	i := int(radio) - radioBase
	if i < 0 || i >= len(l.Items) {
		return nil, ErrCancelled
	}
	return []int{i}, nil
}

// itemTaskDialog asks whether item i of l is chosen: Yes (the default),
// No or Cancel, named by Windows in its own language.
func itemTaskDialog(lang Lang, l List, i int) taskDialog {
	return taskDialog{Title: l.Title, Instruction: lang.word(winChooseItem, l.Items[i]), Content: l.Text,
		Flags: tdfAllowDialogCancellation, Icon: tdInformationIcon,
		CommonButtons: tdcbfYes | tdcbfNo | tdcbfCancel, DefaultButton: idYes}
}

// parseItemAnswer reads the answer to itemTaskDialog or itemMessageBox.
func parseItemAnswer(id int32) (bool, error) {
	switch id {
	case idYes:
		return true, nil
	case idNo:
		return false, nil
	case idCancel:
		return false, ErrCancelled
	}
	return false, unexpected("unexpected dialog answer %q", strconv.Itoa(int(id)))
}

// askMessageBox maps d's buttons to MessageBoxW's own: one button is [OK];
// two are [OK] [Cancel]; three are [Yes] [No] [Cancel], Yes for the default
// and No for the other. A line names what each button does when its label
// differs. A destructive confirmation focuses Cancel and shows a warning.
func askMessageBox(lang Lang, d Dialog) (messageBox, error) {
	n := len(d.Buttons)
	switch {
	case n == 0:
		return messageBox{}, errors.New("a dialog needs a button")
	case n > 3:
		return messageBox{}, errors.New("a message box cannot show " + strconv.Itoa(n) + " buttons")
	}
	b := messageBox{Caption: d.Title, Text: d.Text, Type: mbOK | mbIconInformation | mbSetForeground | mbTopmost}
	if n == 1 {
		return b, nil
	}
	ok, cancel, _, extra := buttons(d)
	var hints []string
	hint := func(word text, i int) {
		if name := lang.word(word); d.Buttons[i] != name {
			hints = append(hints, name+": "+d.Buttons[i])
		}
	}
	kind, icon, focusCancel := uint32(mbOKCancel), uint32(mbIconInformation), uint32(mbDefButton2)
	if n == 2 {
		hint(winWordOK, ok)
	} else {
		kind, focusCancel = mbYesNoCancel, mbDefButton3
		hint(winWordYes, ok)
		hint(winWordNo, extra[0])
	}
	hint(winWordCancel, cancel)
	if defaultCancels(d) {
		icon = mbIconWarning | focusCancel
	}
	b.Type = kind | icon | mbSetForeground | mbTopmost
	if len(hints) > 0 {
		b.Text += "\n\n" + strings.Join(hints, "\n")
	}
	return b, nil
}

// parseMessageBoxAsk returns the index of the button clicked in the box of
// askMessageBox, or ErrCancelled for Cancel and the close box.
func parseMessageBoxAsk(d Dialog, id int32) (int, error) {
	n := len(d.Buttons)
	if n == 0 {
		return 0, errors.New("a dialog needs a button")
	}
	ok, _, _, extra := buttons(d)
	switch {
	case n == 1 && id == idOK:
		return 0, nil
	case id == idCancel:
		return 0, ErrCancelled
	case n == 2 && id == idOK, n == 3 && id == idYes:
		return ok, nil
	case n == 3 && id == idNo:
		return extra[0], nil
	}
	return 0, unexpected("unexpected dialog answer %q", strconv.Itoa(int(id)))
}

// itemMessageBox asks whether item i of l is chosen: Yes, No or Cancel.
func itemMessageBox(lang Lang, l List, i int) messageBox {
	return messageBox{Caption: l.Title, Text: l.Text + "\n\n" + lang.word(winChooseItem, l.Items[i]),
		Type: mbYesNoCancel | mbIconQuestion | mbSetForeground | mbTopmost}
}

// WinDialogs draws the wizard on Windows with TaskDialog, or with
// MessageBox when TaskDialog is nil (TaskDialogIndirect is missing). Both
// return the ID of the button clicked; TaskDialog also the radio button.
// Cancelling returns ErrCancelled.
//
// Neither has a list of checkboxes, so a list of several choices (the
// services) is one Yes/No/Cancel question per item, in order: the simplest
// safe way, and Cancel at any question cancels it all. Without a task
// dialog, a list of one choice is asked the same way and the first Yes is
// the choice.
type WinDialogs struct {
	Lang       Lang
	TaskDialog func(taskDialog) (button, radio int32, err error)
	MessageBox func(messageBox) (int32, error)
}

var _ Dialogs = WinDialogs{}

func (w WinDialogs) Ask(d Dialog) (int, error) {
	if w.TaskDialog != nil {
		c, err := askTaskDialog(d)
		if err != nil {
			return 0, err
		}
		button, _, err := w.TaskDialog(c)
		if err != nil {
			return 0, err
		}
		return parseTaskDialogAsk(d, button)
	}
	b, err := askMessageBox(w.Lang, d)
	if err != nil {
		return 0, err
	}
	id, err := w.MessageBox(b)
	if err != nil {
		return 0, err
	}
	return parseMessageBoxAsk(d, id)
}

func (w WinDialogs) Choose(l List) ([]int, error) {
	if len(l.Items) == 0 {
		if l.Multiple {
			return []int{}, nil
		}
		return nil, ErrCancelled
	}
	if !l.Multiple && w.TaskDialog != nil {
		button, radio, err := w.TaskDialog(chooseTaskDialog(l))
		if err != nil {
			return nil, err
		}
		return parseTaskDialogChoose(l, button, radio)
	}
	picks := []int{}
	for i := range l.Items {
		yes, err := w.askItem(l, i)
		if err != nil {
			return nil, err
		}
		if !yes {
			continue
		}
		if !l.Multiple {
			return []int{i}, nil
		}
		picks = append(picks, i)
	}
	if !l.Multiple {
		return nil, ErrCancelled
	}
	return picks, nil
}

func (w WinDialogs) askItem(l List, i int) (bool, error) {
	var id int32
	var err error
	if w.TaskDialog != nil {
		id, _, err = w.TaskDialog(itemTaskDialog(w.Lang, l, i))
	} else {
		id, err = w.MessageBox(itemMessageBox(w.Lang, l, i))
	}
	if err != nil {
		return false, err
	}
	return parseItemAnswer(id)
}

// TASKDIALOGCONFIG's fields in order: 4 is a 32-bit field, 0 a pointer.
// commctrl.h packs it to 1 byte (pshpack1.h) on every architecture, so no
// Go struct matches it; packTaskDialog writes it byte by byte.
var taskDialogFields = [tdcCount]int{4, 0, 0, 4, 4, 0, 0, 0, 0, 4, 0, 4, 4, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 4}

// TASKDIALOGCONFIG's fields.
const (
	tdcSize = iota
	tdcParent
	tdcInstance
	tdcFlags
	tdcCommonButtons
	tdcTitle
	tdcIcon
	tdcInstruction
	tdcContent
	tdcButtonCount
	tdcButtons
	tdcDefaultButton
	tdcRadioCount
	tdcRadios
	tdcDefaultRadio
	tdcVerification
	tdcExpandedInformation
	tdcExpandedControl
	tdcCollapsedControl
	tdcFooterIcon
	tdcFooter
	tdcCallback
	tdcCallbackData
	tdcWidth
	tdcCount
)

// packTaskDialog lays out TASKDIALOGCONFIG for pointers of ptrSize bytes,
// little-endian, with cbSize set to its size.
func packTaskDialog(ptrSize int, values [tdcCount]uint64) []byte {
	size := 0
	for _, f := range taskDialogFields {
		size += fieldSize(f, ptrSize)
	}
	values[tdcSize] = uint64(size)
	b := make([]byte, 0, size)
	for i, f := range taskDialogFields {
		b = appendField(b, fieldSize(f, ptrSize), values[i])
	}
	return b
}

// packTaskDialogButtons lays out TASKDIALOG_BUTTON (an int and a pointer,
// packed) for each button, with texts the pointers to their labels.
func packTaskDialogButtons(ptrSize int, buttons []taskButton, texts []uint64) []byte {
	var b []byte
	for i, button := range buttons {
		b = appendField(b, 4, uint64(uint32(button.ID)))
		b = appendField(b, ptrSize, texts[i])
	}
	return b
}

func fieldSize(f, ptrSize int) int {
	if f == 0 {
		return ptrSize
	}
	return f
}

func appendField(b []byte, size int, v uint64) []byte {
	if size == 4 {
		return binary.LittleEndian.AppendUint32(b, uint32(v))
	}
	return binary.LittleEndian.AppendUint64(b, v)
}
