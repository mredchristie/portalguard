//go:build !darwin

package main

import "errors"

// pfNoAnchorHook has no meaning off macOS; a sentinel nothing matches.
func pfNoAnchorHook() error { return errors.New("no pf backend") }
