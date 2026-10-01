//go:build darwin

package helper

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestPeerUIDIsTheKernelsAnswer: the uid comes from the kernel, for the real
// process on the other end.
func TestPeerUIDIsTheKernelsAnswer(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := net.Dial("unix", sock)
		if err == nil {
			defer c.Close()
			c.Write([]byte("x"))
		}
	}()
	c, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	uid, err := PeerUID(c)
	if err != nil || uid != os.Getuid() {
		t.Fatalf("PeerUID = %d, %v; want %d", uid, err, os.Getuid())
	}
}

func TestFrameWriterReportsWhatItWrote(t *testing.T) {
	var b bytesBuf
	var mu fakeMu
	n, err := FrameWriter{W: &b, Kind: Stdout, Mu: &mu}.Write([]byte("abc"))
	if err != nil || n != 3 {
		t.Fatalf("Write = %d, %v; want 3", n, err)
	}
}

type fakeMu struct{}

func (*fakeMu) Lock()   {}
func (*fakeMu) Unlock() {}

type bytesBuf struct{ b []byte }

func (w *bytesBuf) Write(p []byte) (int, error) { w.b = append(w.b, p...); return len(p), nil }
