package menubar

import (
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modcomctl32            = windows.NewLazySystemDLL("comctl32.dll")
	procTaskDialogIndirect = modcomctl32.NewProc("TaskDialogIndirect")
)

// taskDialogAvailable reports whether TaskDialogIndirect exists: only
// comctl32 version 6 has it, and a process loads version 6 only when its
// manifest asks for it. Without it the dialogs fall back to MessageBoxW.
func taskDialogAvailable() bool { return procTaskDialogIndirect.Find() == nil }

// NewWinDialogs draws the Windows dialogs in language l with
// TaskDialogIndirect when it exists, MessageBoxW otherwise.
func NewWinDialogs(l Lang) WinDialogs {
	w := WinDialogs{Lang: l, MessageBox: showMessageBox}
	if taskDialogAvailable() {
		w.TaskDialog = showTaskDialog
	}
	return w
}

// winText is s for a Windows call: NUL characters would end it early.
func winText(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(strings.ReplaceAll(s, "\x00", ""))
	return p
}

// showTaskDialog shows c with TaskDialogIndirect, without an owner window,
// and returns the button and radio button the user picked.
func showTaskDialog(c taskDialog) (button, radio int32, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// The configuration holds pointers as plain numbers: pin what they
	// point to, so nothing moves or is freed until the dialog is closed.
	var pin runtime.Pinner
	defer pin.Unpin()
	ptr := func(s string) uint64 {
		if s == "" {
			return 0
		}
		p := winText(s)
		pin.Pin(p)
		return uint64(uintptr(unsafe.Pointer(p)))
	}
	const ptrSize = int(unsafe.Sizeof(uintptr(0)))
	list := func(buttons []taskButton) uint64 {
		if len(buttons) == 0 {
			return 0
		}
		texts := make([]uint64, len(buttons))
		for i, b := range buttons {
			texts[i] = ptr(b.Text)
		}
		packed := packTaskDialogButtons(ptrSize, buttons, texts)
		pin.Pin(&packed[0])
		return uint64(uintptr(unsafe.Pointer(&packed[0])))
	}
	var v [tdcCount]uint64
	v[tdcFlags] = uint64(c.Flags)
	v[tdcCommonButtons] = uint64(c.CommonButtons)
	v[tdcTitle] = ptr(c.Title)
	v[tdcIcon] = c.Icon
	v[tdcInstruction] = ptr(c.Instruction)
	v[tdcContent] = ptr(c.Content)
	v[tdcButtonCount] = uint64(len(c.Buttons))
	v[tdcButtons] = list(c.Buttons)
	v[tdcDefaultButton] = uint64(uint32(c.DefaultButton))
	v[tdcRadioCount] = uint64(len(c.Radios))
	v[tdcRadios] = list(c.Radios)
	v[tdcDefaultRadio] = uint64(uint32(c.DefaultRadio))
	config := packTaskDialog(ptrSize, v)
	pin.Pin(&config[0])
	hr, _, _ := procTaskDialogIndirect.Call(uintptr(unsafe.Pointer(&config[0])),
		uintptr(unsafe.Pointer(&button)), uintptr(unsafe.Pointer(&radio)), 0)
	if int32(hr) < 0 {
		return 0, 0, fmt.Errorf("TaskDialogIndirect failed: HRESULT 0x%08X", uint32(hr))
	}
	return button, radio, nil
}

// showMessageBox shows c with MessageBoxW and returns the button clicked.
func showMessageBox(c messageBox) (int32, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	id, err := windows.MessageBox(0, winText(c.Text), winText(c.Caption), c.Type)
	if id == 0 {
		return 0, fmt.Errorf("MessageBoxW failed: %v", err)
	}
	return id, nil
}
