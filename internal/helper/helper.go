// Package helper is how PortalGuard runs as root without asking for a
// password every time: a small service, installed once with sudo, that runs
// PortalGuard's own commands for the one user who installed it, over a local
// socket. The app and the terminal are its clients.
//
// It is deliberately narrow. It answers only the installing user (checked on
// every connection, from the kernel, not from anything the client says),
// runs only PortalGuard's commands, and refuses every option that names a
// file: as root, "write the trace to this path" would be "overwrite any file
// on the machine". So the worst a program running as that user can do
// through it is what PortalGuard itself does, never more.
package helper

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// SocketPath is where the helper listens.
const SocketPath = "/var/run/portalguard.sock"

// ConfigPath records who installed the helper, and so whom it answers.
const ConfigPath = "/etc/portalguard/helper.json"

// Config is the helper's own settings, written by install-helper.
type Config struct {
	UID int `json:"uid"`
	GID int `json:"gid"`
}

// Request opens a connection: the command to run, and for a Wi-Fi join with a
// password, the password (written by the helper to a file only root can read,
// never put on a command line).
type Request struct {
	Args     []string `json:"args"`
	Password string   `json:"password,omitempty"`
	// TTY: the user is at a terminal, so the command talks as it would to
	// one (guided steps, the "type y" prompt).
	TTY bool `json:"tty,omitempty"`
}

// ==== frames ================================================================
// One byte of kind, four of length, then the bytes. Both directions.

// Frame kinds.
const (
	Stdout = 'o' // helper to client: the command's output
	Stderr = 'e' // helper to client: its errors
	Meta   = 'm' // helper to client: JSON, e.g. where the trace is
	Exit   = 'x' // helper to client: the exit code, then the stream ends
	Stdin  = 'i' // client to helper: input for the command
	Close  = 'c' // client to helper: no more input
	Signal = 's' // client to helper: Ctrl+C, passed on to the command
)

// maxFrame bounds one frame, so a client cannot make the helper allocate
// without limit.
const maxFrame = 1 << 20

// WriteFrame sends one frame.
func WriteFrame(w io.Writer, kind byte, p []byte) error {
	if len(p) > maxFrame {
		return fmt.Errorf("helper: frame of %d bytes is too large", len(p))
	}
	var h [5]byte
	h[0] = kind
	binary.BigEndian.PutUint32(h[1:], uint32(len(p)))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}

// ReadFrame reads one frame.
func ReadFrame(r io.Reader) (byte, []byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(h[1:])
	if n > maxFrame {
		return 0, nil, fmt.Errorf("helper: frame of %d bytes is too large", n)
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, err
	}
	return h[0], p, nil
}

// FrameWriter turns every Write into one frame of a kind: a command's stdout
// or stderr, straight onto the connection.
type FrameWriter struct {
	W    io.Writer
	Kind byte
	Mu   interface {
		Lock()
		Unlock()
	}
}

func (f FrameWriter) Write(p []byte) (int, error) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	total := len(p)
	for len(p) > 0 {
		n := len(p)
		if n > maxFrame {
			n = maxFrame
		}
		if err := WriteFrame(f.W, f.Kind, p[:n]); err != nil {
			return 0, err
		}
		p = p[n:]
	}
	return total, nil
}

// ==== what the helper will run =============================================

// commands are the PortalGuard commands the helper runs. Not "helper",
// "install-helper" or "uninstall-helper": a client cannot reconfigure the
// thing that decides what it may do.
var commands = map[string]bool{
	"detect": true, "check": true, "status": true, "doctor": true,
	"lockdown": true, "allow": true, "remember": true, "seal": true,
	"handoff": true, "release": true, "run": true, "arm": true,
	"trust": true, "untrust": true, "vpn": true, "leave": true,
	"install-anchor": true, "uninstall-anchor": true, "print-rules": true,
	"version": true,
}

// fileFlags name files. As root, any of them is a way to read, overwrite or
// delete any file on the machine, so none is accepted from a client: the
// helper supplies its own trace path, and its own password file.
var fileFlags = []string{"trace", "audit-log", "join-password-file", "probes-file"}

// ErrNotAllowed is a request the helper will not run.
var ErrNotAllowed = errors.New("helper: not allowed")

// Check says whether the helper may run args, and why not.
func Check(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: no command", ErrNotAllowed)
	}
	if !commands[args[0]] {
		return fmt.Errorf("%w: %q is not a command the helper runs", ErrNotAllowed, args[0])
	}
	for _, a := range args[1:] {
		name := strings.TrimLeft(a, "-")
		if name == a {
			continue // not a flag
		}
		name, _, _ = strings.Cut(name, "=")
		for _, f := range fileFlags {
			if name == f {
				return fmt.Errorf("%w: -%s names a file, which the helper does not accept", ErrNotAllowed, f)
			}
		}
	}
	return nil
}

// MarshalRequest and UnmarshalRequest carry a Request in the first frame.
func MarshalRequest(r Request) ([]byte, error) { return json.Marshal(r) }

func UnmarshalRequest(p []byte) (Request, error) {
	var r Request
	err := json.Unmarshal(p, &r)
	return r, err
}
