package helper

import (
	"bytes"
	"errors"
	"testing"
)

func TestFramesRoundTrip(t *testing.T) {
	var b bytes.Buffer
	for _, f := range []struct {
		k byte
		p string
	}{{Stdout, "hello\n"}, {Stdin, "cdn.btwifi.com\n"}, {Exit, "0"}, {Close, ""}} {
		if err := WriteFrame(&b, f.k, []byte(f.p)); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{"o:hello\n", "i:cdn.btwifi.com\n", "x:0", "c:"} {
		k, p, err := ReadFrame(&b)
		if err != nil || string(k)+":"+string(p) != want {
			t.Fatalf("frame = %c:%q, %v; want %q", k, p, err, want)
		}
	}
}

func TestReadFrameRefusesAHugeLength(t *testing.T) {
	b := bytes.NewReader([]byte{Stdout, 0xff, 0xff, 0xff, 0xff})
	if _, _, err := ReadFrame(b); err == nil {
		t.Fatal("accepted a 4 GB frame")
	}
}

// TestCheckRefusesAnythingThatNamesAFile: as root, a path option is a way to
// overwrite or delete any file, so none gets through, in any spelling.
func TestCheckRefusesAnythingThatNamesAFile(t *testing.T) {
	ok := [][]string{
		{"arm", "-json", "-join", "EE WiFi"},
		{"run", "-verbose"},
		{"release"},
		{"vpn", "use", "My VPN"},
		{"allow", "cdn.btwifi.com", "-trace-is-just-a-host.com"},
	}
	for _, a := range ok {
		if err := Check(a); err != nil {
			t.Errorf("Check(%q) = %v, want allowed", a, err)
		}
	}
	bad := [][]string{
		{},
		{"helper"},
		{"install-helper"},
		{"uninstall-helper"},
		{"rm", "-rf", "/"},
		{"run", "-trace", "/etc/sudoers"},
		{"run", "--trace=/etc/sudoers"},
		{"run", "-audit-log", "/etc/passwd"},
		{"arm", "-join", "x", "-join-password-file", "/etc/master.passwd"},
		{"run", "-probes-file=/var/root/secret"},
	}
	for _, a := range bad {
		if err := Check(a); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("Check(%q) = %v, want refused", a, err)
		}
	}
}
