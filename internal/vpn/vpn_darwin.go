//go:build darwin

package vpn

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const scutil = "/usr/sbin/scutil"

// List returns the VPN configurations macOS knows about.
func List(ctx context.Context) ([]Service, error) {
	out, err := run(ctx, "--nc", "list")
	if err != nil {
		return nil, err
	}
	return parseList(out), nil
}

// Remote returns where a service connects to: its server's host, and port if
// the configuration names one.
func Remote(ctx context.Context, id string) (host string, port int, err error) {
	out, err := run(ctx, "--nc", "show", id)
	if err != nil {
		return "", 0, err
	}
	host, port = parseRemote(out)
	return host, port, nil
}

// Start asks macOS to connect a service. It returns once the request is made;
// the tunnel comes up, or does not, afterwards.
func Start(ctx context.Context, id string) error {
	out, err := run(ctx, "--nc", "start", id)
	if err != nil {
		return err
	}
	// scutil exits 0 and prints the reason when it cannot start a service.
	if s := strings.TrimSpace(out); s != "" {
		return fmt.Errorf("scutil: %s", s)
	}
	return nil
}

func run(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, scutil, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("scutil %s: %w: %s", strings.Join(args[:2], " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
