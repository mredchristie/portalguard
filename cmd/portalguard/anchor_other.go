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
