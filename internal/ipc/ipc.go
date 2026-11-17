// Package ipc is the protocol between the root leakguard daemon and the apps
// that control it, such as the menu-bar app. Each connection carries one
// newline-terminated JSON request and one JSON response.
//
// Only administrators may talk to the daemon: the socket belongs to
// root:admin with mode 0660, and the server also checks the peer's
// credentials and refuses anyone who is not root or in group admin.
package ipc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	// DefaultPath is where the daemon listens.
	DefaultPath = "/var/run/leakguard.sock"
	// MaxMessage bounds a request or response, in bytes, newline included.
	MaxMessage = 64 << 10
	// Deadline bounds one connection: request, handling and response.
	Deadline = 5 * time.Second
	// DialTimeout bounds how long a client waits to connect.
	DialTimeout = 2 * time.Second
	// AdminGID is the group admin on macOS: the Mac's administrators.
	AdminGID = 80
)

// Commands.
const (
	// CmdStatus asks for the current Status.
	CmdStatus = "status"
	// CmdSet saves and applies a VPN interface and services; it also ends a pause.
	CmdSet = "set"
	// CmdPause pauses the protection: the rules are removed until the next
	// set. It never uninstalls anything, unlike "sudo leakguard disable".
	CmdPause = "pause"
)

// ReasonPaused is the Status reason while the protection is paused.
const ReasonPaused = "paused"

// ReasonNotConfigured is the Status reason before the first configuration.
const ReasonNotConfigured = "not configured"

// Request is one command to the daemon.
type Request struct {
	Cmd          string   `json:"cmd"`
	VPNInterface string   `json:"vpn_interface,omitempty"`
	Services     []string `json:"services,omitempty"`
}

// Response is the daemon's answer. Error is set exactly when OK is false.
type Response struct {
	OK     bool    `json:"ok"`
	Status *Status `json:"status,omitempty"`
	Error  string  `json:"error,omitempty"`
}

// Status is what the daemon knows, verified as root.
type Status struct {
	// Protected is true only when pf is enabled and the anchor is verified.
	Protected bool `json:"protected"`
	// Reason says why Protected is false.
	Reason       string    `json:"reason,omitempty"`
	VPNInterface string    `json:"vpn_interface"`
	VPNConnected bool      `json:"vpn_connected"`
	Services     []string  `json:"services"`
	Catalog      []Service `json:"catalog"`
	LastRun      string    `json:"last_run,omitempty"`
}

// Service is one catalog entry as the apps show it.
type Service struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// ReadRequest reads and checks one request. It reads at most MaxMessage+1
// bytes and rejects unknown fields, unknown commands, arguments to commands
// that take none, and anything after the request.
func ReadRequest(r io.Reader) (Request, error) {
	var req Request
	line, err := readLine(r, "request")
	if err != nil {
		return req, err
	}
	if err := decode(line, &req, "request", true); err != nil {
		return Request{}, err
	}
	switch req.Cmd {
	case CmdSet:
	case CmdStatus, CmdPause:
		if req.VPNInterface != "" || req.Services != nil {
			return Request{}, fmt.Errorf("%s takes no arguments", req.Cmd)
		}
	default:
		return Request{}, fmt.Errorf("unknown command %q", req.Cmd)
	}
	return req, nil
}

// readResponse reads one response with the same limits as ReadRequest, but
// ignores unknown fields: a newer daemon may add status fields, and an older
// app must still read the ones it knows.
func readResponse(r io.Reader) (Response, error) {
	var resp Response
	line, err := readLine(r, "response")
	if err != nil {
		return resp, err
	}
	if err := decode(line, &resp, "response", false); err != nil {
		return Response{}, err
	}
	if !resp.OK && resp.Error == "" {
		return Response{}, errors.New("invalid response: an error without a message")
	}
	if resp.OK && resp.Status == nil {
		return Response{}, errors.New("invalid response: no status")
	}
	return resp, nil
}

func readLine(r io.Reader, what string) ([]byte, error) {
	line, err := bufio.NewReader(io.LimitReader(r, MaxMessage+1)).ReadBytes('\n')
	switch {
	case len(line) > MaxMessage:
		return nil, fmt.Errorf("%s is larger than %d bytes", what, MaxMessage)
	case errors.Is(err, io.EOF):
		return nil, fmt.Errorf("incomplete %s: no newline", what)
	case err != nil:
		return nil, err
	}
	return line, nil
}

// decode reads exactly one JSON value from line. strict rejects unknown fields.
func decode(line []byte, v any, what string, strict bool) error {
	dec := json.NewDecoder(bytes.NewReader(line))
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid %s: %w", what, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("unexpected data after the %s", what)
	}
	return nil
}

// writeMessage writes v as one JSON line.
func writeMessage(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}
