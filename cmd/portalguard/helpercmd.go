package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"portalguard/internal/helper"
)

// ==== the helper: root, once, instead of a password every time =============
// See internal/helper for what it will and will not do.

const (
	helperLabel  = "dev.mredchristie.portalguard.helper"
	helperBinary = "/usr/local/libexec/portalguard"
	helperPlist  = "/Library/LaunchDaemons/" + helperLabel + ".plist"
	helperLog    = "/var/log/portalguard-helper.log"
)

// ttyEnv tells a command run by the helper that its user is at a terminal,
// so it talks in guided steps and offers the "type y" prompt, as it would
// under sudo.
const ttyEnv = "PORTALGUARD_TTY"

// rootCommands go through the helper when run without root.
var rootCommands = map[string]bool{
	"lockdown": true, "allow": true, "remember": true, "seal": true,
	"handoff": true, "release": true, "run": true, "arm": true,
	"trust": true, "untrust": true, "leave": true, "status": true,
	"doctor": true, "install-anchor": true, "uninstall-anchor": true,
}

// viaHelper reports whether this invocation should go to the helper: not
// root, a command that needs it, and a helper listening.
func viaHelper(args []string) bool {
	if os.Geteuid() == 0 || len(args) == 0 {
		return false
	}
	need := rootCommands[args[0]] || (args[0] == "vpn" && len(args) > 1 && (args[1] == "use" || args[1] == "clear"))
	if !need {
		return false
	}
	_, err := os.Stat(helper.SocketPath)
	return err == nil
}

// ---- the service -----------------------------------------------------------

func runHelper(ctx context.Context, args []string) int {
	if os.Geteuid() != 0 {
		return fail(errors.New("the helper runs as root, started by launchd; see install-helper"))
	}
	data, err := os.ReadFile(helper.ConfigPath)
	if err != nil {
		return fail(fmt.Errorf("no helper config (%v); run install-helper", err))
	}
	var cfg helper.Config
	if err := json.Unmarshal(data, &cfg); err != nil || cfg.UID <= 0 {
		return fail(fmt.Errorf("helper config %s does not name a user", helper.ConfigPath))
	}
	_ = os.Remove(helper.SocketPath)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: helper.SocketPath, Net: "unix"})
	if err != nil {
		return fail(err)
	}
	defer os.Remove(helper.SocketPath)
	// Anyone may connect; only the installing user (and root) is answered.
	// The check is the kernel's peer credential, per connection.
	if err := os.Chmod(helper.SocketPath, 0o666); err != nil {
		return fail(err)
	}
	logf("helper: listening on %s for uid %d", helper.SocketPath, cfg.UID)
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			return exitOK
		}
		go serveHelper(c, cfg)
	}
}

func serveHelper(c *net.UnixConn, cfg helper.Config) {
	defer c.Close()
	var mu sync.Mutex
	stdout := helper.FrameWriter{W: c, Kind: helper.Stdout, Mu: &mu}
	stderr := helper.FrameWriter{W: c, Kind: helper.Stderr, Mu: &mu}
	exit := func(code int) {
		mu.Lock()
		_ = helper.WriteFrame(c, helper.Exit, []byte(strconv.Itoa(code)))
		mu.Unlock()
	}
	refuse := func(err error) {
		fmt.Fprintf(stderr, "portalguard helper: %v\n", err)
		exit(exitError)
	}

	uid, err := helper.PeerUID(c)
	if err != nil || (uid != cfg.UID && uid != 0) {
		logf("helper: refused a connection from uid %d (%v)", uid, err)
		refuse(errors.New("this helper answers only the user who installed it"))
		return
	}
	kind, p, err := helper.ReadFrame(c)
	if err != nil || kind != helper.Meta {
		return
	}
	req, err := helper.UnmarshalRequest(p)
	if err != nil {
		refuse(err)
		return
	}
	if err := helper.Check(req.Args); err != nil {
		refuse(err)
		return
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		refuse(err)
		return
	}

	args := append([]string(nil), req.Args...)
	meta := map[string]any{"version": version}
	// run and arm leave their trace where the user keeps them, owned by the
	// user: the engine hands a trace to SUDO_UID, as under sudo.
	if args[0] == "run" || args[0] == "arm" {
		logs := filepath.Join(u.HomeDir, "Library", "Logs", "PortalGuard")
		if err := os.MkdirAll(logs, 0o700); err == nil {
			_ = os.Chown(logs, uid, cfg.GID)
			trace := filepath.Join(logs, time.Now().Format("2006-01-02 15.04.05")+".log")
			args = append(args, "-trace", trace)
			meta["trace"] = trace
		}
	}
	// A Wi-Fi password goes to a file only root can read, deleted by the
	// engine as soon as it has read it.
	if req.Password != "" {
		f, err := os.CreateTemp("/var/run", "portalguard-pw-")
		if err != nil {
			refuse(err)
			return
		}
		_ = f.Chmod(0o600)
		_, _ = f.WriteString(req.Password)
		f.Close()
		defer os.Remove(f.Name())
		args = append(args, "-join-password-file", f.Name())
	}
	mb, _ := json.Marshal(meta)
	mu.Lock()
	_ = helper.WriteFrame(c, helper.Meta, mb)
	mu.Unlock()

	self, _ := os.Executable()
	cmd := exec.Command(self, args...)
	cmd.Env = []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"HOME=/var/root",
		fmt.Sprintf("SUDO_UID=%d", uid),
		fmt.Sprintf("SUDO_GID=%d", cfg.GID),
	}
	if req.TTY {
		cmd.Env = append(cmd.Env, ttyEnv+"=1")
	}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		refuse(err)
		return
	}
	logf("helper: uid %d runs %s", uid, strings.Join(args, " "))
	if err := cmd.Start(); err != nil {
		refuse(err)
		return
	}

	// The client's input, Ctrl+C and going away. A client that disappears
	// is nobody watching: the command is interrupted, which releases.
	go func() {
		for {
			k, p, err := helper.ReadFrame(c)
			if err != nil {
				in.Close()
				_ = cmd.Process.Signal(os.Interrupt)
				return
			}
			switch k {
			case helper.Stdin:
				_, _ = in.Write(p)
			case helper.Close:
				in.Close()
			case helper.Signal:
				_ = cmd.Process.Signal(os.Interrupt)
			}
		}
	}()
	code := 0
	if err := cmd.Wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			code = exitError
		}
	}
	exit(code)
}

// ---- the client -------------------------------------------------------------

// forwardToHelper runs args through the helper, streaming its output here, and
// returns the command's exit code. -trace <file> is kept here: the helper
// writes the trace to the user's Logs folder, and it is copied to the file
// asked for once the command is done.
func forwardToHelper(args []string) int {
	var copyTo string
	var clean []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-trace" || a == "--trace":
			if i+1 < len(args) {
				copyTo = args[i+1]
				i++
			}
			continue
		case strings.HasPrefix(a, "-trace=") || strings.HasPrefix(a, "--trace="):
			_, copyTo, _ = strings.Cut(a, "=")
			continue
		}
		clean = append(clean, a)
	}

	c, err := net.Dial("unix", helper.SocketPath)
	if err != nil {
		return fail(fmt.Errorf("the helper is installed but not answering (%v); try: sudo %s install-helper", err, invokedAs()))
	}
	defer c.Close()
	req, _ := helper.MarshalRequest(helper.Request{Args: clean, TTY: isTerminal(os.Stdout)})
	var mu sync.Mutex
	if err := helper.WriteFrame(c, helper.Meta, req); err != nil {
		return fail(err)
	}

	// Input, only from a terminal: piped input to a command is a script's,
	// and the engine reads its own prompts.
	if isTerminal(os.Stdin) {
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := os.Stdin.Read(buf)
				if n > 0 {
					mu.Lock()
					_ = helper.WriteFrame(c, helper.Stdin, buf[:n])
					mu.Unlock()
				}
				if err != nil {
					mu.Lock()
					_ = helper.WriteFrame(c, helper.Close, nil)
					mu.Unlock()
					return
				}
			}
		}()
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		for range sig {
			mu.Lock()
			_ = helper.WriteFrame(c, helper.Signal, nil)
			mu.Unlock()
		}
	}()

	trace := ""
	for {
		k, p, err := helper.ReadFrame(c)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return fail(errors.New("the helper closed the connection"))
			}
			return fail(err)
		}
		switch k {
		case helper.Stdout:
			os.Stdout.Write(p)
		case helper.Stderr:
			os.Stderr.Write(p)
		case helper.Meta:
			var m struct{ Version, Trace string }
			if json.Unmarshal(p, &m) == nil {
				trace = m.Trace
				if m.Version != "" && m.Version != version {
					fmt.Fprintf(os.Stderr, "portalguard: the helper is %s and this is %s; update it: sudo %s install-helper\n", m.Version, version, invokedAs())
				}
			}
		case helper.Exit:
			code, _ := strconv.Atoi(string(p))
			if copyTo != "" && trace != "" {
				if data, err := os.ReadFile(trace); err == nil {
					_ = os.WriteFile(copyTo, data, 0o600)
				}
			}
			return code
		}
	}
}

// ---- installing it ----------------------------------------------------------

func runInstallHelper(ctx context.Context, args []string) int {
	if err := requireRoot("install-helper"); err != nil {
		return fail(err)
	}
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || uid <= 0 {
		return fail(errors.New("run it with sudo from your own account, so the helper knows whom to answer"))
	}

	// A root-owned copy in a root-owned folder: the helper must not run a
	// binary its user could replace.
	self, err := os.Executable()
	if err != nil {
		return fail(err)
	}
	if err := os.MkdirAll(filepath.Dir(helperBinary), 0o755); err != nil {
		return fail(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return fail(err)
	}
	tmp := helperBinary + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return fail(err)
	}
	_ = os.Chown(tmp, 0, 0)
	if err := os.Rename(tmp, helperBinary); err != nil {
		return fail(err)
	}

	cfg, _ := json.Marshal(helper.Config{UID: uid, GID: gid})
	if err := os.MkdirAll(filepath.Dir(helper.ConfigPath), 0o755); err != nil {
		return fail(err)
	}
	if err := os.WriteFile(helper.ConfigPath, cfg, 0o644); err != nil {
		return fail(err)
	}

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>%s</string>
	<key>ProgramArguments</key><array><string>%s</string><string>helper</string></array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>StandardErrorPath</key><string>%s</string>
	<key>StandardOutPath</key><string>%s</string>
</dict>
</plist>
`, helperLabel, helperBinary, helperLog, helperLog)
	if err := os.WriteFile(helperPlist, []byte(plist), 0o644); err != nil {
		return fail(err)
	}
	_ = exec.Command("/bin/launchctl", "bootout", "system/"+helperLabel).Run()
	if out, err := exec.Command("/bin/launchctl", "bootstrap", "system", helperPlist).CombinedOutput(); err != nil {
		return fail(fmt.Errorf("launchctl bootstrap: %v: %s", err, strings.TrimSpace(string(out))))
	}
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(helper.SocketPath); err == nil {
			fmt.Printf("Installed. PortalGuard runs as root in the background now, for your account only:\n")
			fmt.Printf("the app and `%s arm`, `run`, `status`... need no password or sudo.\n", filepath.Base(invokedAs()))
			fmt.Printf("After updating PortalGuard, run this again. To remove it: sudo %s uninstall-helper\n", invokedAs())
			return exitOK
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fail(fmt.Errorf("installed, but the helper did not start; see %s", helperLog))
}

func runUninstallHelper(ctx context.Context, args []string) int {
	if err := requireRoot("uninstall-helper"); err != nil {
		return fail(err)
	}
	_ = exec.Command("/bin/launchctl", "bootout", "system/"+helperLabel).Run()
	for _, p := range []string{helperPlist, helperBinary, helper.SocketPath, helper.ConfigPath} {
		_ = os.Remove(p)
	}
	fmt.Println("Removed. PortalGuard asks for a password again, as before.")
	return exitOK
}
