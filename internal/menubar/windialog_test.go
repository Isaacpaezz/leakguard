package menubar

import (
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var (
	winUninstallDialog = Dialog{Title: "Uninstall leakguard", Text: "Sure?", Buttons: []string{"Cancel", "Uninstall"}, Default: 0, Cancel: 0}
	winNextDialog      = Dialog{Title: "Step 2 of 3", Text: "Disconnect", Buttons: []string{"Cancel", "Next"}, Default: 1, Cancel: 0}
	vpnList            = List{Title: "Step 2 of 3", Text: "Which one?", Items: []string{"VPN (WireGuard Tunnel)", "VPN (R&D VPN)"}, OK: "Next", Cancel: "Cancel"}
	servicesList       = List{Title: "Step 1 of 3", Text: "Choose what to protect.", Items: []string{"Anthropic (Claude)", "Mistral", "Perplexity"}, OK: "Next", Cancel: "Cancel", Multiple: true}
)

// S1: TaskDialogIndirect shows the buttons in the Windows order (the
// macOS order reversed, so Cancel comes last), focuses the dialog's
// default, Cancel for a destructive confirmation with a warning icon, and
// lets Escape and the close box cancel.
func TestTaskDialogAsk(t *testing.T) {
	tests := []struct {
		d    Dialog
		want taskDialog
	}{
		{winUninstallDialog, taskDialog{Title: "Uninstall leakguard", Content: "Sure?", Flags: tdfAllowDialogCancellation, Icon: tdWarningIcon,
			Buttons: []taskButton{{101, "Uninstall"}, {100, "Cancel"}}, DefaultButton: 100}},
		{winNextDialog, taskDialog{Title: "Step 2 of 3", Content: "Disconnect", Flags: tdfAllowDialogCancellation, Icon: tdInformationIcon,
			Buttons: []taskButton{{101, "Next"}, {100, "Cancel"}}, DefaultButton: 101}},
		{foundDialog, taskDialog{Title: "Step 2 of 3", Content: "Found", Flags: tdfAllowDialogCancellation, Icon: tdInformationIcon,
			Buttons: []taskButton{{102, "Use this VPN"}, {101, "Choose another"}, {100, "Cancel"}}, DefaultButton: 102}},
		{tellDialog, taskDialog{Title: "leakguard", Content: "Done", Flags: tdfAllowDialogCancellation, Icon: tdInformationIcon,
			Buttons: []taskButton{{100, "OK"}}, DefaultButton: 100}},
		// "&" would underline the next letter in a button.
		{Dialog{Title: "t", Text: "R&D", Buttons: []string{"Cancel", "R&D"}, Default: 9, Cancel: 0},
			taskDialog{Title: "t", Content: "R&D", Flags: tdfAllowDialogCancellation, Icon: tdInformationIcon,
				Buttons: []taskButton{{101, "R&&D"}, {100, "Cancel"}}, DefaultButton: 101}},
	}
	for _, tc := range tests {
		got, err := askTaskDialog(tc.d)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("askTaskDialog(%q) =\n%+v, %v\nwant\n%+v", tc.d.Buttons, got, err, tc.want)
		}
	}
	if _, err := askTaskDialog(Dialog{Title: "t"}); err == nil {
		t.Error("a dialog without buttons: no error")
	}
}

// S1: the answer of TaskDialogIndirect: the dialog's cancel button,
// Escape and the close box (IDCANCEL) are ErrCancelled; anything unknown
// is an unexpected answer, never a button.
func TestTaskDialogAskAnswer(t *testing.T) {
	tests := []struct {
		d      Dialog
		button int32
		want   int
		err    error
	}{
		{winUninstallDialog, 101, 1, nil},
		{winUninstallDialog, 100, 0, ErrCancelled},
		{winUninstallDialog, idCancel, 0, ErrCancelled},
		{foundDialog, 102, 2, nil},
		{foundDialog, 101, 1, nil},
		{foundDialog, 100, 0, ErrCancelled},
		{tellDialog, 100, 0, nil},
		{tellDialog, idCancel, 0, ErrCancelled},
		{winNextDialog, 102, 0, ErrUnexpectedAnswer},
		{winNextDialog, idOK, 0, ErrUnexpectedAnswer},
		{winNextDialog, 0, 0, ErrUnexpectedAnswer},
	}
	for _, tc := range tests {
		got, err := parseTaskDialogAsk(tc.d, tc.button)
		if got != tc.want || !errors.Is(err, tc.err) || (tc.err == nil) != (err == nil) {
			t.Errorf("parseTaskDialogAsk(%q, %d) = %d, %v; want %d, %v", tc.d.Buttons, tc.button, got, err, tc.want, tc.err)
		}
	}
}

// S1: choosing one item is a radio list with the first item chosen, and
// [Next] [Cancel]; no item is an empty choice, read as a cancel.
func TestTaskDialogChoose(t *testing.T) {
	got := chooseTaskDialog(vpnList)
	want := taskDialog{Title: "Step 2 of 3", Content: "Which one?", Flags: tdfAllowDialogCancellation, Icon: tdInformationIcon,
		Buttons: []taskButton{{100, "Next"}, {101, "Cancel"}}, DefaultButton: 100,
		Radios: []taskButton{{200, "VPN (WireGuard Tunnel)"}, {201, "VPN (R&&D VPN)"}}, DefaultRadio: 200}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("chooseTaskDialog =\n%+v\nwant\n%+v", got, want)
	}
	tests := []struct {
		button, radio int32
		want          []int
		err           error
	}{
		{100, 200, []int{0}, nil},
		{100, 201, []int{1}, nil},
		{101, 201, nil, ErrCancelled},
		{idCancel, 200, nil, ErrCancelled},
		{100, 0, nil, ErrCancelled},
		{100, 202, nil, ErrCancelled},
		{100, 199, nil, ErrCancelled},
		{7, 200, nil, ErrUnexpectedAnswer},
	}
	for _, tc := range tests {
		got, err := parseTaskDialogChoose(vpnList, tc.button, tc.radio)
		if !reflect.DeepEqual(got, tc.want) || !errors.Is(err, tc.err) || (tc.err == nil) != (err == nil) {
			t.Errorf("parseTaskDialogChoose(%d, %d) = %v, %v; want %v, %v", tc.button, tc.radio, got, err, tc.want, tc.err)
		}
	}
}

// S1: MessageBoxW, used when TaskDialogIndirect is missing (no comctl32 v6
// manifest), has only its own buttons: the dialog's roles map to
// OK/Cancel or Yes/No/Cancel, a line names what each button does when its
// label differs, and a destructive confirmation focuses Cancel.
func TestMessageBoxAsk(t *testing.T) {
	es := Spanish.ForOS("windows")
	tests := []struct {
		l    Lang
		d    Dialog
		want messageBox
	}{
		{English, winUninstallDialog, messageBox{Caption: "Uninstall leakguard", Text: "Sure?\n\nOK: Uninstall",
			Type: mbOKCancel | mbDefButton2 | mbIconWarning | mbSetForeground | mbTopmost}},
		{English, winNextDialog, messageBox{Caption: "Step 2 of 3", Text: "Disconnect\n\nOK: Next",
			Type: mbOKCancel | mbIconInformation | mbSetForeground | mbTopmost}},
		{English, foundDialog, messageBox{Caption: "Step 2 of 3", Text: "Found\n\nYes: Use this VPN\nNo: Choose another",
			Type: mbYesNoCancel | mbIconInformation | mbSetForeground | mbTopmost}},
		{English, Dialog{Title: "t", Text: "x", Buttons: []string{"Stop", "Choose another", "Use this VPN"}, Default: 0, Cancel: 0},
			messageBox{Caption: "t", Text: "x\n\nYes: Use this VPN\nNo: Choose another\nCancel: Stop",
				Type: mbYesNoCancel | mbDefButton3 | mbIconWarning | mbSetForeground | mbTopmost}},
		{English, Dialog{Title: "t", Text: "x", Buttons: []string{"Cancel", "List", "Retry"}, Default: 1, Cancel: 0},
			messageBox{Caption: "t", Text: "x\n\nYes: List\nNo: Retry",
				Type: mbYesNoCancel | mbIconInformation | mbSetForeground | mbTopmost}},
		{English, tellDialog, messageBox{Caption: "leakguard", Text: "Done",
			Type: mbOK | mbIconInformation | mbSetForeground | mbTopmost}},
		{es, Dialog{Title: "Paso 2 de 3", Text: "Desconecta", Buttons: []string{"Cancelar", "Siguiente"}, Default: 1, Cancel: 0},
			messageBox{Caption: "Paso 2 de 3", Text: "Desconecta\n\nAceptar: Siguiente",
				Type: mbOKCancel | mbIconInformation | mbSetForeground | mbTopmost}},
		{es, Dialog{Title: "t", Text: "x", Buttons: []string{"Cancelar", "Elegir otra", "Usar esta VPN"}, Default: 2, Cancel: 0},
			messageBox{Caption: "t", Text: "x\n\nSí: Usar esta VPN\nNo: Elegir otra",
				Type: mbYesNoCancel | mbIconInformation | mbSetForeground | mbTopmost}},
		// The label already is the OK button's: no extra line.
		{es, Dialog{Title: "t", Text: "x", Buttons: []string{"Cancelar", "Aceptar"}, Default: 1, Cancel: 0},
			messageBox{Caption: "t", Text: "x", Type: mbOKCancel | mbIconInformation | mbSetForeground | mbTopmost}},
	}
	for _, tc := range tests {
		got, err := askMessageBox(tc.l, tc.d)
		if err != nil || got != tc.want {
			t.Errorf("askMessageBox(%v, %q) =\n%+v, %v\nwant\n%+v", tc.l, tc.d.Buttons, got, err, tc.want)
		}
	}
	for _, bad := range []Dialog{{Title: "t"}, {Title: "t", Buttons: []string{"a", "b", "c", "d"}}} {
		if _, err := askMessageBox(English, bad); err == nil {
			t.Errorf("askMessageBox(%q): no error", bad.Buttons)
		}
	}
}

// S1: the answer of MessageBoxW. Closing a box with a Cancel button
// answers IDCANCEL: a cancel, never a button.
func TestMessageBoxAskAnswer(t *testing.T) {
	tests := []struct {
		d    Dialog
		id   int32
		want int
		err  error
	}{
		{winUninstallDialog, idOK, 1, nil},
		{winUninstallDialog, idCancel, 0, ErrCancelled},
		{winNextDialog, idOK, 1, nil},
		{foundDialog, idYes, 2, nil},
		{foundDialog, idNo, 1, nil},
		{foundDialog, idCancel, 0, ErrCancelled},
		{tellDialog, idOK, 0, nil},
		{winNextDialog, idYes, 0, ErrUnexpectedAnswer},
		{foundDialog, idOK, 0, ErrUnexpectedAnswer},
		{tellDialog, idCancel, 0, ErrCancelled},
		{tellDialog, idYes, 0, ErrUnexpectedAnswer},
	}
	for _, tc := range tests {
		got, err := parseMessageBoxAsk(tc.d, tc.id)
		if got != tc.want || !errors.Is(err, tc.err) || (tc.err == nil) != (err == nil) {
			t.Errorf("parseMessageBoxAsk(%q, %d) = %d, %v; want %d, %v", tc.d.Buttons, tc.id, got, err, tc.want, tc.err)
		}
	}
}

// fakeWin records what the Windows driver shows and answers from a script.
type fakeWin struct {
	tasks   []taskDialog
	boxes   []messageBox
	answers []int32 // button (or message box) IDs, in order
	radio   int32
	err     error
}

func (f *fakeWin) next() int32 {
	if len(f.answers) == 0 {
		panic("no answer left")
	}
	a := f.answers[0]
	f.answers = f.answers[1:]
	return a
}

func (f *fakeWin) task(c taskDialog) (int32, int32, error) {
	f.tasks = append(f.tasks, c)
	if f.err != nil {
		return 0, 0, f.err
	}
	return f.next(), f.radio, nil
}

func (f *fakeWin) box(c messageBox) (int32, error) {
	f.boxes = append(f.boxes, c)
	if f.err != nil {
		return 0, f.err
	}
	return f.next(), nil
}

func (f *fakeWin) dialogs(l Lang, taskDialogs bool) WinDialogs {
	w := WinDialogs{Lang: l, MessageBox: f.box}
	if taskDialogs {
		w.TaskDialog = f.task
	}
	return w
}

// S1: the driver uses TaskDialogIndirect when it exists and MessageBoxW
// otherwise; both answer the same way.
func TestWinDialogsAsk(t *testing.T) {
	for _, task := range []bool{true, false} {
		f := &fakeWin{answers: []int32{101}}
		if task {
			f.answers = []int32{101}
		} else {
			f.answers = []int32{idOK}
		}
		b, err := f.dialogs(English, task).Ask(winUninstallDialog)
		if err != nil || b != 1 {
			t.Errorf("task dialogs %v: Ask = %d, %v; want 1", task, b, err)
		}
		if task && (len(f.tasks) != 1 || len(f.boxes) != 0) || !task && (len(f.tasks) != 0 || len(f.boxes) != 1) {
			t.Errorf("task dialogs %v: %d task dialogs, %d message boxes", task, len(f.tasks), len(f.boxes))
		}
	}
	f := &fakeWin{err: errors.New("TaskDialogIndirect failed: HRESULT 0x80070057")}
	if _, err := f.dialogs(English, true).Ask(winNextDialog); err == nil || err.Error() != "TaskDialogIndirect failed: HRESULT 0x80070057" {
		t.Errorf("failed dialog: err = %v", err)
	}
	if len(f.boxes) != 0 {
		t.Error("a failed task dialog fell back to a message box: the user would answer twice")
	}
}

// S1: one choice is a radio list in a task dialog; without task dialogs
// each item is a Yes/No/Cancel question and the first Yes is the choice.
// Answering No to every item, or an empty list, is a cancel.
func TestWinDialogsChooseOne(t *testing.T) {
	f := &fakeWin{answers: []int32{100}, radio: 201}
	got, err := f.dialogs(English, true).Choose(vpnList)
	if err != nil || !reflect.DeepEqual(got, []int{1}) {
		t.Errorf("radio list: %v, %v; want [1]", got, err)
	}
	if len(f.tasks) != 1 || len(f.tasks[0].Radios) != 2 {
		t.Errorf("radio list showed %+v", f.tasks)
	}

	es := Spanish.ForOS("windows")
	f = &fakeWin{answers: []int32{idNo, idYes}}
	got, err = f.dialogs(es, false).Choose(vpnList)
	if err != nil || !reflect.DeepEqual(got, []int{1}) {
		t.Errorf("questions: %v, %v; want [1]", got, err)
	}
	wantBox := messageBox{Caption: "Step 2 of 3", Text: "Which one?\n\n¿Elegir VPN (R&D VPN)?",
		Type: mbYesNoCancel | mbIconQuestion | mbSetForeground | mbTopmost}
	if len(f.boxes) != 2 || f.boxes[1] != wantBox {
		t.Errorf("questions showed %+v, want the second %+v", f.boxes, wantBox)
	}

	f = &fakeWin{answers: []int32{idNo, idNo}}
	if got, err := f.dialogs(English, false).Choose(vpnList); !errors.Is(err, ErrCancelled) {
		t.Errorf("No to every item: %v, %v; want ErrCancelled", got, err)
	}
	f = &fakeWin{answers: []int32{idCancel}}
	if got, err := f.dialogs(English, false).Choose(vpnList); !errors.Is(err, ErrCancelled) || len(f.boxes) != 1 {
		t.Errorf("Cancel: %v, %v after %d questions; want ErrCancelled after 1", got, err, len(f.boxes))
	}
	for _, task := range []bool{true, false} {
		f = &fakeWin{}
		empty := vpnList
		empty.Items = nil
		if got, err := f.dialogs(English, task).Choose(empty); !errors.Is(err, ErrCancelled) || len(f.tasks)+len(f.boxes) != 0 {
			t.Errorf("task %v, empty list: %v, %v; want ErrCancelled without a dialog", task, got, err)
		}
	}
}

// S1: several choices (the services) are one Yes/No/Cancel question per
// item, in order, Yes the default: TaskDialogIndirect has no checkbox
// list. Cancel at any question cancels the whole list.
func TestWinDialogsChooseSeveral(t *testing.T) {
	es := Spanish.ForOS("windows")
	f := &fakeWin{answers: []int32{idYes, idNo, idYes}}
	got, err := f.dialogs(es, true).Choose(servicesList)
	if err != nil || !reflect.DeepEqual(got, []int{0, 2}) {
		t.Errorf("Yes, No, Yes: %v, %v; want [0 2]", got, err)
	}
	want := taskDialog{Title: "Step 1 of 3", Instruction: "¿Elegir Mistral?", Content: "Choose what to protect.",
		Flags: tdfAllowDialogCancellation, Icon: tdInformationIcon, CommonButtons: tdcbfYes | tdcbfNo | tdcbfCancel, DefaultButton: idYes}
	if len(f.tasks) != 3 || !reflect.DeepEqual(f.tasks[1], want) {
		t.Errorf("questions = %+v, want the second %+v", f.tasks, want)
	}

	f = &fakeWin{answers: []int32{idNo, idNo, idNo}}
	got, err = f.dialogs(English, false).Choose(servicesList)
	if err != nil || got == nil || len(got) != 0 {
		t.Errorf("No to all: %#v, %v; want an empty choice", got, err)
	}
	if want := "Choose what to protect.\n\nChoose Perplexity?"; len(f.boxes) != 3 || f.boxes[2].Text != want {
		t.Errorf("message boxes = %+v, want the last text %q", f.boxes, want)
	}

	f = &fakeWin{answers: []int32{idYes, idCancel}}
	if got, err := f.dialogs(English, true).Choose(servicesList); !errors.Is(err, ErrCancelled) || len(f.tasks) != 2 {
		t.Errorf("Cancel at the second: %v, %v after %d questions; want ErrCancelled after 2", got, err, len(f.tasks))
	}
	f = &fakeWin{answers: []int32{idOK}}
	if _, err := f.dialogs(English, true).Choose(servicesList); !errors.Is(err, ErrUnexpectedAnswer) {
		t.Errorf("unknown answer: err = %v, want ErrUnexpectedAnswer", err)
	}
}

// S1: the wizard's services step on Windows: an empty choice cancels.
func TestWizardOnWindowsDialogs(t *testing.T) {
	f := &fakeWin{answers: []int32{idNo, idNo}}
	w := Wizard{Lang: English.ForOS("windows"), Dialogs: f.dialogs(English.ForOS("windows"), true), Catalog: fullCatalog}
	called := false
	err := w.Run(func(Draft) error { called = true; return nil })
	if !errors.Is(err, ErrCancelled) || called {
		t.Errorf("no service chosen: err = %v, activate called %v; want ErrCancelled, never called", err, called)
	}
}

// S1: TASKDIALOGCONFIG and TASKDIALOG_BUTTON are packed to 1 byte
// (commctrl.h, pshpack1.h): 160 bytes with 8-byte pointers, 96 with 4.
func TestPackTaskDialog(t *testing.T) {
	var v [tdcCount]uint64
	for i := range v {
		v[i] = uint64(0x1100 + i)
	}
	offsets64 := map[int]int{tdcSize: 0, tdcParent: 4, tdcInstance: 12, tdcFlags: 20, tdcCommonButtons: 24, tdcTitle: 28,
		tdcIcon: 36, tdcInstruction: 44, tdcContent: 52, tdcButtonCount: 60, tdcButtons: 64, tdcDefaultButton: 72,
		tdcRadioCount: 76, tdcRadios: 80, tdcDefaultRadio: 88, tdcVerification: 92, tdcFooter: 132, tdcCallback: 140,
		tdcCallbackData: 148, tdcWidth: 156}
	offsets32 := map[int]int{tdcSize: 0, tdcParent: 4, tdcInstance: 8, tdcFlags: 12, tdcCommonButtons: 16, tdcTitle: 20,
		tdcIcon: 24, tdcInstruction: 28, tdcContent: 32, tdcButtonCount: 36, tdcButtons: 40, tdcDefaultButton: 44,
		tdcRadioCount: 48, tdcRadios: 52, tdcDefaultRadio: 56, tdcVerification: 60, tdcFooter: 80, tdcCallback: 84,
		tdcCallbackData: 88, tdcWidth: 92}
	for _, tc := range []struct {
		ptr     int
		size    int
		offsets map[int]int
	}{{8, 160, offsets64}, {4, 96, offsets32}} {
		b := packTaskDialog(tc.ptr, v)
		if len(b) != tc.size {
			t.Fatalf("pointer size %d: %d bytes, want %d", tc.ptr, len(b), tc.size)
		}
		for field, off := range tc.offsets {
			want := v[field]
			if field == tdcSize {
				want = uint64(tc.size)
			}
			n := 4
			if taskDialogFields[field] == 0 {
				n = tc.ptr
			}
			got := readLE(b[off:], n)
			if got != want {
				t.Errorf("pointer size %d, field %d at %d = %#x, want %#x", tc.ptr, field, off, got, want)
			}
		}
	}
	buttons := packTaskDialogButtons(8, []taskButton{{100, "a"}, {101, "b"}}, []uint64{0xAAAA, 0xBBBB})
	if len(buttons) != 24 || readLE(buttons, 4) != 100 || readLE(buttons[4:], 8) != 0xAAAA ||
		readLE(buttons[12:], 4) != 101 || readLE(buttons[16:], 8) != 0xBBBB {
		t.Errorf("buttons = %x", buttons)
	}
	if b := packTaskDialogButtons(4, []taskButton{{-1, "a"}}, []uint64{0xCC}); len(b) != 8 || readLE(b, 4) != 0xFFFFFFFF {
		t.Errorf("32-bit buttons = %x", b)
	}
}

func readLE(b []byte, n int) uint64 {
	if n == 4 {
		return uint64(binary.LittleEndian.Uint32(b))
	}
	return binary.LittleEndian.Uint64(b)
}

// The Windows driver answers like the other drivers in the wizard tests.
var _ Dialogs = WinDialogs{}

func ExampleWinDialogs() {
	f := &fakeWin{answers: []int32{idOK}}
	b, err := f.dialogs(English, false).Ask(winUninstallDialog)
	fmt.Println(b, err, strings.Split(f.boxes[0].Text, "\n\n")[1])
	// Output: 1 <nil> OK: Uninstall
}
