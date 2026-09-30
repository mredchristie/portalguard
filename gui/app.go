package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is what the page calls: window.go.main.App.
//
// Each run lives in a private temporary folder (0700, so only this user and
// root can touch it) holding a FIFO the engine reads as stdin, the file its
// feed is written to, and its trace. The engine runs as root, started once
// through the standard password prompt; this process stays unprivileged, and
// speaks to it only through that folder.
type App struct {
	ctx context.Context

	mu      sync.Mutex
	dir     string
	in      *os.File // the FIFO's write end: the engine's stdin
	running bool
}

func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	// Folders left by earlier runs that did not finish (the app was quit
	// mid-run, or the engine never started).
	old, _ := filepath.Glob(filepath.Join(os.TempDir(), "portalguard-app-*"))
	for _, d := range old {
		os.RemoveAll(d)
	}
}

// shutdown closes the engine's stdin. It reads that as the app having gone
// and releases the firewall: a closed app never leaves the network locked.
func (a *App) shutdown(context.Context) { a.finish() }

// Networks scans for Wi-Fi networks in range, for the list.
func (a *App) Networks() Scan { return scanWiFi() }

// AskLocation shows macOS's Location prompt, which is what lets the list
// show network names. macOS asks once and remembers the answer.
func (a *App) AskLocation() { requestLocation() }

// Arm starts `portalguard arm -json` as root, joining ssid once locked down
// (or, with no ssid, detecting whatever network the Mac is on or joins).
// password is for the rare hotspot that has one. It returns once the engine
// has started, or with the reason it did not (the password prompt closed,
// say); from then on everything arrives on the "feed" event.
func (a *App) Arm(ssid, password string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.running {
		return errors.New("already running")
	}
	bin, err := engineBinary()
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "portalguard-app-")
	if err != nil {
		return err
	}
	in := filepath.Join(dir, "in")
	feed := filepath.Join(dir, "feed")
	if err := syscall.Mkfifo(in, 0o600); err != nil {
		os.RemoveAll(dir)
		return fmt.Errorf("make the engine's input: %w", err)
	}
	if err := os.WriteFile(feed, nil, 0o600); err != nil {
		os.RemoveAll(dir)
		return err
	}
	// Read and write, so opening it does not wait for the engine to open its
	// end, and so the engine sees stdin end only when this app closes it.
	w, err := os.OpenFile(in, os.O_RDWR, 0)
	if err != nil {
		os.RemoveAll(dir)
		return err
	}

	// The network to join, and its password in a file only this user and
	// root can read, which the engine deletes as soon as it has read it: a
	// password on a command line would be visible to every process.
	join := ""
	if ssid != "" {
		join = " -join " + shq(ssid)
		if password != "" {
			pw := filepath.Join(dir, "pw")
			if err := os.WriteFile(pw, []byte(password), 0o600); err != nil {
				w.Close()
				os.RemoveAll(dir)
				return err
			}
			join += " -join-password-file " + shq(pw)
		}
	}

	// SUDO_UID and SUDO_GID make the engine hand its trace to this user, as
	// it does under sudo, so the log can be kept and read afterwards.
	// Backgrounded with every stream redirected, so it outlives the shell
	// the password prompt runs it in. Not nohup: with no terminal there,
	// nohup refuses to start at all ("can't detach from console").
	cmd := fmt.Sprintf("SUDO_UID=%d SUDO_GID=%d %s arm -json%s -trace %s < %s > %s 2> %s &",
		os.Getuid(), os.Getgid(), shq(bin), join, shq(filepath.Join(dir, "trace")), shq(in), shq(feed), shq(filepath.Join(dir, "err")))
	script := "do shell script " + appleString(cmd) + " with administrator privileges with prompt \"PortalGuard needs your password to control the firewall.\""
	if out, err := exec.Command("/usr/bin/osascript", "-e", script).CombinedOutput(); err != nil {
		w.Close()
		os.RemoveAll(dir)
		if strings.Contains(string(out), "-128") || strings.Contains(string(out), "User canceled") {
			return errors.New("cancelled at the password prompt")
		}
		return fmt.Errorf("could not start the engine: %s", strings.TrimSpace(string(out)))
	}

	a.dir, a.in, a.running = dir, w, true
	go a.tail(feed, filepath.Join(dir, "err"))
	return nil
}

// Release gives the network back after a run that stopped with the lockdown
// still in place: the engine fails closed, and has exited, so this is a new
// `portalguard release` through the password prompt.
func (a *App) Release() error {
	bin, err := engineBinary()
	if err != nil {
		return err
	}
	script := "do shell script " + appleString(shq(bin)+" release") +
		" with administrator privileges with prompt \"PortalGuard needs your password to give the network back.\""
	if out, err := exec.Command("/usr/bin/osascript", "-e", script).CombinedOutput(); err != nil {
		if strings.Contains(string(out), "-128") {
			return errors.New("cancelled at the password prompt")
		}
		return fmt.Errorf("release: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// Cancel asks the engine to stop and give the network back.
func (a *App) Cancel() { a.send("cancel") }

// Open asks the engine to open one more host, as `portalguard allow` would.
func (a *App) Open(host string) { a.send(host) }

// OpenURL opens the login page in the default browser.
func (a *App) OpenURL(url string) { runtime.BrowserOpenURL(a.ctx, url) }

// Doctor is `portalguard doctor -json`, for the idle screen. It runs as this
// user, so it cannot see the firewall itself; everything else it can.
func (a *App) Doctor() ([]map[string]any, error) {
	bin, err := engineBinary()
	if err != nil {
		return nil, err
	}
	out, _ := exec.Command(bin, "doctor", "-json").Output()
	var fs []map[string]any
	if err := json.Unmarshal(out, &fs); err != nil {
		return nil, fmt.Errorf("doctor: %w", err)
	}
	return fs, nil
}

func (a *App) send(line string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.in != nil {
		fmt.Fprintln(a.in, strings.TrimSpace(line))
	}
}

// tail reads the feed as the engine writes it and hands each event to the
// page, until the run is done. If nothing arrives at all, the engine did not
// start, and what it said on stderr is the reason.
func (a *App) tail(feedPath, errPath string) {
	f, err := os.Open(feedPath)
	if err != nil {
		a.emit(map[string]any{"type": "error", "text": err.Error()})
		a.finish()
		return
	}
	defer f.Close()
	r := bufio.NewReader(f)
	var partial strings.Builder
	started := time.Now()
	seen := false
	for {
		chunk, err := r.ReadString('\n')
		partial.WriteString(chunk)
		if err == io.EOF {
			if !seen && time.Since(started) > 15*time.Second {
				msg, _ := os.ReadFile(errPath)
				a.emit(map[string]any{"type": "error", "text": "the engine did not start: " + strings.TrimSpace(string(msg))})
				a.finish()
				return
			}
			time.Sleep(120 * time.Millisecond)
			continue
		}
		if err != nil {
			a.emit(map[string]any{"type": "error", "text": err.Error()})
			a.finish()
			return
		}
		line := partial.String()
		partial.Reset()
		var ev map[string]any
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue
		}
		seen = true
		a.emit(ev)
		if t := ev["type"]; t == "done" || t == "error" {
			a.finish()
			return
		}
	}
}

func (a *App) emit(ev map[string]any) {
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "feed", ev)
	}
}

// finish closes the engine's stdin and keeps its trace in
// ~/Library/Logs/PortalGuard, then removes the run's folder.
func (a *App) finish() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.in != nil {
		a.in.Close()
		a.in = nil
	}
	if a.dir != "" {
		dir := a.dir
		a.dir = ""
		go func() {
			time.Sleep(2 * time.Second) // the engine closes its trace on the way out
			keepTrace(filepath.Join(dir, "trace"))
			os.RemoveAll(dir)
		}()
	}
	a.running = false
}

func keepTrace(path string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	logs := filepath.Join(home, "Library", "Logs", "PortalGuard")
	if os.MkdirAll(logs, 0o700) != nil {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return
	}
	_ = os.WriteFile(filepath.Join(logs, time.Now().Format("2006-01-02 15.04.05")+".log"), data, 0o600)
}

// engineBinary finds the portalguard command: inside the app bundle when
// built with `make app`, otherwise $PORTALGUARD_BIN or the repo's bin/.
func engineBinary() (string, error) {
	if p := os.Getenv("PORTALGUARD_BIN"); p != "" {
		return p, nil
	}
	exe, err := os.Executable()
	if err == nil {
		bundled := filepath.Join(filepath.Dir(exe), "..", "Resources", "portalguard")
		if _, err := os.Stat(bundled); err == nil {
			return filepath.Clean(bundled), nil
		}
		// Built in the repo: gui/build/bin/PortalGuard.app/Contents/MacOS.
		for d := filepath.Dir(exe); d != "/" && d != "."; d = filepath.Dir(d) {
			if p := filepath.Join(d, "bin", "portalguard"); isFile(p) && !strings.Contains(p, "/gui/build/") {
				return p, nil
			}
		}
	}
	if p, err := exec.LookPath("portalguard"); err == nil {
		return p, nil
	}
	return "", errors.New("cannot find the portalguard command; build it with `make build`")
}

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// shq quotes s for the shell.
func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// appleString quotes s as an AppleScript string literal.
func appleString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}
