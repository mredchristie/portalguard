//go:build !darwin

package main

import (
	"context"
	"errors"
)

var errDarwinOnly = errors.New("this command is macOS-only; the pf backend does not exist on this platform")

func runInstallAnchor(context.Context, []string) int   { return fail(errDarwinOnly) }
func runUninstallAnchor(context.Context, []string) int { return fail(errDarwinOnly) }
func runPrintRules(context.Context, []string) int      { return fail(errDarwinOnly) }

func clearLoopbackSkipForRun(context.Context) (bool, error) { return false, nil }

func pfFindings(context.Context, bool) []finding {
	return []finding{{"fail", "no firewall backend on this platform", "portalguard runs on macOS for now"}}
}
