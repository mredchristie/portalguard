//go:build darwin

package pf

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ifconfigPath is the absolute path to ifconfig; we do not trust PATH for a
// privileged command.
const ifconfigPath = "/sbin/ifconfig"

// pflog is a pseudo-device. Nothing on macOS creates one: the only boot-time
// pf action is com.apple.pfctl.plist running `pfctl -f /etc/pf.conf`, which
// loads a ruleset and creates no interfaces, and enabling pf does not create
// one either. So we make our own.
//
// We use a dedicated pflog1 rather than the default pflog0 for the same reason
// the rules live in a dedicated anchor: nothing else owns it, so creating and
// destroying it cannot disturb another tool that is logging.

// ensureLogInterface brings up the log device, reporting whether this call
// created it. A device we did not create is never destroyed later.
func (b *Backend) ensureLogInterface(ctx context.Context) (created bool, err error) {
	if b.logExists(ctx) {
		// Someone else's, or ours from a previous run. Bring it up in case it
		// is down, but do not claim ownership.
		_, _ = b.ifconfig(ctx, LogInterface, "up")
		return false, nil
	}
	if _, err := b.ifconfig(ctx, LogInterface, "create"); err != nil {
		return false, fmt.Errorf("create %s: %w", LogInterface, err)
	}
	if _, err := b.ifconfig(ctx, LogInterface, "up"); err != nil {
		// Created but unusable: tidy up rather than leave a half-made device.
		_, _ = b.ifconfig(ctx, LogInterface, "destroy")
		return false, fmt.Errorf("bring %s up: %w", LogInterface, err)
	}
	return true, nil
}

// destroyLogInterface removes the log device, but only if we created it.
func (b *Backend) destroyLogInterface(ctx context.Context) error {
	if !b.logCreated {
		return nil
	}
	b.logCreated = false
	if _, err := b.ifconfig(ctx, LogInterface, "destroy"); err != nil {
		return fmt.Errorf("destroy %s: %w", LogInterface, err)
	}
	return nil
}

// logExists reports whether the pflog device is present.
func (b *Backend) logExists(ctx context.Context) bool {
	_, err := b.ifconfig(ctx, LogInterface)
	return err == nil
}

func (b *Backend) ifconfig(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, ifconfigPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("ifconfig %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// LogInterfaceReadable reports whether this process can read the pflog device
// without root. /dev/bpf* is group access_bpf on macOS, so a user in that
// group can run the reader unprivileged even though creating the interface
// needed root.
func LogInterfaceReadable() bool {
	f, err := os.Open("/dev/bpf0")
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}
