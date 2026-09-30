package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ==== a record of one run, for reading afterwards ==========================
//
// A real portal cannot be debugged while you stand in front of it: the
// network is paid for by the hour, and the moment passes. -trace keeps
// everything the run printed, and every DNS query the filter answered with
// what it did about it, each line timestamped, in one file to read later.
//
// It holds real hostnames, so it is opt-in, written 0600, and handed to the
// user who ran sudo rather than left owned by root.

type tracer struct {
	mu   sync.Mutex
	f    *os.File
	wg   sync.WaitGroup
	outs []*os.File // the pipe ends standing in for stdout and stderr
	orig [2]*os.File
}

// startTrace opens path and copies everything written to stdout and stderr
// into it, as well as to the terminal, until close.
func startTrace(path string, args []string) (*tracer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("-trace: %w", err)
	}
	giveToSudoUser(path)
	t := &tracer{f: f, orig: [2]*os.File{os.Stdout, os.Stderr}}
	t.line("trace", fmt.Sprintf("portalguard %s, %s, args: %s", version, time.Now().Format(time.RFC1123Z), strings.Join(args, " ")))

	for i, target := range []**os.File{&os.Stdout, &os.Stderr} {
		r, w, err := os.Pipe()
		if err != nil {
			t.close()
			return nil, fmt.Errorf("-trace: %w", err)
		}
		orig := t.orig[i]
		stream := [2]string{"out", "err"}[i]
		*target = w
		t.outs = append(t.outs, w)
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			t.copy(r, orig, stream)
		}()
	}
	return t, nil
}

// copy passes one stream through to the terminal, and each line of it into
// the trace. Byte for byte to the terminal, so a prompt without a newline
// still shows.
func (t *tracer) copy(r io.ReadCloser, to *os.File, stream string) {
	defer r.Close()
	br := bufio.NewReader(r)
	for {
		s, err := br.ReadString('\n')
		if s != "" {
			_, _ = to.WriteString(s)
			t.line(stream, strings.TrimRight(s, "\n"))
		}
		if err != nil {
			return
		}
	}
}

// line writes one timestamped line to the trace.
func (t *tracer) line(stream, text string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	fmt.Fprintf(t.f, "%s %-5s %s\n", time.Now().Format("15:04:05.000"), stream, text)
}

// dns records one query the filter answered.
func (t *tracer) dns(name, qtype, verdict string) {
	t.line("dns", fmt.Sprintf("%-9s %-5s %s", verdict, qtype, name))
}

// close puts stdout and stderr back and finishes the file. Safe on nil.
func (t *tracer) close() {
	if t == nil {
		return
	}
	os.Stdout, os.Stderr = t.orig[0], t.orig[1]
	for _, w := range t.outs {
		w.Close()
	}
	t.wg.Wait()
	t.line("trace", "end")
	t.f.Close()
}

// giveToSudoUser hands a file created under sudo to the user who ran sudo,
// so they can read their own trace without it.
func giveToSudoUser(path string) {
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 == nil && err2 == nil {
		_ = os.Chown(path, uid, gid)
	}
}
