// Package backend selects the firewall driver for the host platform.
//
// It exists as its own package so that the per-OS drivers can import the
// firewall package for its types without the firewall package importing them
// back.
package backend
