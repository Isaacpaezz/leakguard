package menubar

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// goWinres embeds resources in an executable; the release build makes the
// tray's manifest with the same tool.
const goWinres = "github.com/tc-hib/go-winres@v0.3.3"

// taskDialogChildEnv marks the copy of this test binary that carries the
// comctl32 version 6 manifest.
const taskDialogChildEnv = "LEAKGUARD_TASKDIALOG_CHILD"

// The application manifest the tray gets: comctl32 version 6.
const taskDialogManifest = `{"RT_MANIFEST":{"#1":{"0409":{"execution-level":"as invoker","dpi-awareness":"per monitor v2","use-common-controls-v6":true}}}}`

// S1: with the comctl32 version 6 manifest the tray gets from the
// installer build, TaskDialogIndirect exists, accepts the packed
// TASKDIALOGCONFIG and its buttons, and the button and radio button
// clicked come back and parse. The test copies this test binary, embeds
// the manifest with go-winres (go run, never committed), and runs the
// copy, which shows real dialogs and clicks them through the task dialog
// messages from another thread, headless.
func TestTaskDialogIndirectWithManifest(t *testing.T) {
	if os.Getenv(taskDialogChildEnv) == "1" {
		taskDialogChild(t)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	patched := filepath.Join(dir, "menubar-manifest.test.exe")
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(patched, data, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, "winres.json")
	if err := os.WriteFile(manifest, []byte(taskDialogManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go command embeds the manifest: %v", err)
	}
	patch := exec.Command(goTool, "run", goWinres, "patch", "--in", manifest, "--no-backup", patched)
	patch.Dir = dir
	patch.Env = append(os.Environ(), "GOFLAGS=")
	if out, err := patch.CombinedOutput(); err != nil {
		t.Fatalf("go-winres patch: %v\n%s", err, out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	child := exec.CommandContext(ctx, patched, "-test.run=^TestTaskDialogIndirectWithManifest$", "-test.v", "-test.count=1")
	child.Env = append(os.Environ(), taskDialogChildEnv+"=1")
	out, err := child.CombinedOutput()
	t.Logf("the copy with the manifest:\n%s", out)
	if err != nil || !strings.Contains(string(out), "--- PASS: TestTaskDialogIndirectWithManifest") {
		t.Fatalf("the copy with the manifest failed: %v", err)
	}
}

// Task dialog messages (commctrl.h).
const (
	tdmClickButton      = 0x0400 + 102 // TDM_CLICK_BUTTON
	tdmClickRadioButton = 0x0400 + 110 // TDM_CLICK_RADIO_BUTTON
)

var (
	moduser32        = windows.NewLazySystemDLL("user32.dll")
	procFindWindowW  = moduser32.NewProc("FindWindowW")
	procPostMessageW = moduser32.NewProc("PostMessageW")
	procSendMessageW = moduser32.NewProc("SendMessageW")
)

// dialogClick is what to do in one dialog: pick radio (0 for none), then click
// button.
type dialogClick struct{ radio, button int32 }

// clickDialogs clicks each dialog titled title, in order: it waits for the
// dialog of this process, clicks, and waits for it to close. A dialog
// that never shows or never closes ends the process: the test cannot
// close a dialog it cannot find.
func clickDialogs(title string, clicks []dialogClick) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i, c := range clicks {
			h := waitWindow(title, i)
			if c.radio != 0 {
				procSendMessageW.Call(uintptr(h), tdmClickRadioButton, uintptr(c.radio), 0)
			}
			procPostMessageW.Call(uintptr(h), tdmClickButton, uintptr(c.button), 0)
			deadline := time.Now().Add(30 * time.Second)
			for windows.IsWindow(h) {
				if time.Now().After(deadline) {
					fmt.Fprintf(os.Stderr, "dialog %d of %q did not close after a click\n", i+1, title)
					os.Exit(3)
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
	}()
	return done
}

func waitWindow(title string, i int) windows.HWND {
	p, _ := windows.UTF16PtrFromString(title)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		h, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(p)))
		if h != 0 && windows.IsWindowVisible(windows.HWND(h)) {
			var pid uint32
			windows.GetWindowThreadProcessId(windows.HWND(h), &pid)
			if pid == uint32(os.Getpid()) {
				return windows.HWND(h)
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "dialog %d of %q never showed\n", i+1, title)
	os.Exit(3)
	return 0
}

// taskDialogChild runs in the copy with the manifest.
func taskDialogChild(t *testing.T) {
	if err := procTaskDialogIndirect.Find(); err != nil {
		t.Fatalf("TaskDialogIndirect is missing with the comctl32 v6 manifest: %v", err)
	}
	w := NewWinDialogs(English.ForOS("windows"))
	if w.TaskDialog == nil {
		t.Fatal("NewWinDialogs did not pick TaskDialogIndirect")
	}
	title := fmt.Sprintf("leakguard dialog test %d", os.Getpid())
	found := Dialog{Title: title, Text: "Found WireGuard Tunnel", Buttons: []string{"Cancel", "Choose another", "Use this VPN"}, Default: 2, Cancel: 0}

	// Three custom buttons: the middle one, then Escape (IDCANCEL).
	done := clickDialogs(title, []dialogClick{{0, buttonBase + 1}, {0, idCancel}})
	b, err := w.Ask(found)
	if err != nil || b != 1 {
		t.Errorf("Ask, clicking Choose another: %d, %v; want 1", b, err)
	}
	b, err = w.Ask(found)
	if !errors.Is(err, ErrCancelled) {
		t.Errorf("Ask, cancelled: %d, %v; want ErrCancelled", b, err)
	}
	<-done

	// One choice: radio buttons, the second one, then Next.
	vpns := List{Title: title, Text: "Which one?", Items: []string{"VPN (WireGuard Tunnel)", "VPN (Conexión VPN)"}, OK: "Next", Cancel: "Cancel"}
	done = clickDialogs(title, []dialogClick{{radioBase + 1, buttonBase}})
	got, err := w.Choose(vpns)
	if err != nil || !reflect.DeepEqual(got, []int{1}) {
		t.Errorf("Choose one, the second radio button: %v, %v; want [1]", got, err)
	}
	<-done

	// Several choices: Windows' own Yes, No, Yes buttons.
	services := List{Title: title, Text: "Choose what to protect.", Items: []string{"Anthropic (Claude)", "Mistral", "Perplexity"}, OK: "Next", Cancel: "Cancel", Multiple: true}
	done = clickDialogs(title, []dialogClick{{0, idYes}, {0, idNo}, {0, idYes}})
	got, err = w.Choose(services)
	if err != nil || !reflect.DeepEqual(got, []int{0, 2}) {
		t.Errorf("Choose several, Yes No Yes: %v, %v; want [0 2]", got, err)
	}
	<-done
}
