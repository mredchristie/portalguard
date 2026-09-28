package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"portalguard/internal/firewall"
)

// ==== the session file ====================================================
// What one invocation leaves behind for the next one to pick up.

// SessionPath is where a session snapshot is written between invocations.
//
// /var/run for the same reason the pf enable token lives there: it is
// root-only, and it is cleared on reboot, which matches the lifetime of
// everything else portalguard installs. Nothing we do is meant to survive a
// restart.
const SessionPath = "/var/run/portalguard.session"

// snapshotVersion is bumped whenever the on-disk shape changes. A file written
// by a different version is discarded rather than guessed at: the kernel can
// rebuild everything that actually matters, so there is nothing to gain from
// being clever about an old file.
const snapshotVersion = 1

// ErrNoSnapshot means there is no session file, which is the normal case.
var ErrNoSnapshot = errors.New("state: no session snapshot")

// PortalRef is what detection worked out about the login page, kept in the
// smallest form a later invocation can use.
type PortalRef struct {
	URL   string   `json:"url,omitempty"`
	Host  string   `json:"host,omitempty"`
	Port  int      `json:"port,omitempty"`
	Addrs []string `json:"addrs,omitempty"`
}

// Snapshot is the part of a session that a later invocation cannot work out
// for itself.
//
// It deliberately does not carry the whole portal.Result. The per-probe detail
// includes response bodies served by an untrusted network, and none of it is
// needed to widen a gap or render a status line, so it is dropped rather than
// parked in a file on disk.
type Snapshot struct {
	Version int       `json:"version"`
	State   State     `json:"state"`
	Portal  PortalRef `json:"portal,omitzero"`
	// Allowed is the gap as the writing process understood it, carrying the
	// names, ports and reasons that pf tables cannot hold.
	Allowed []firewall.Host `json:"allowed,omitempty"`
	// PID is the invocation that wrote this. It is for display only: a live
	// pid proves nothing about the firewall, and a dead one does not mean the
	// rules went with it.
	PID       int          `json:"pid"`
	Since     time.Time    `json:"since,omitzero"`
	UpdatedAt time.Time    `json:"updated_at,omitzero"`
	History   []Transition `json:"history,omitempty"`
}

// SaveSnapshot writes a session snapshot, replacing any earlier one.
//
// The write is atomic: a temporary file in the same directory, then a rename.
// A snapshot half-written by a process that was killed mid-save would be
// discarded by LoadSnapshot anyway, but a torn file is the kind of thing that
// turns one bug into two.
func SaveSnapshot(path string, s Snapshot) error {
	s.Version = snapshotVersion
	s.UpdatedAt = time.Now()
	if s.PID == 0 {
		s.PID = os.Getpid()
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode session snapshot: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	// 0600: the snapshot is not a secret, but it records which hosts this
	// machine was told to trust, and nothing else should be editing that.
	f, err := os.CreateTemp(dir, filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create session snapshot: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once the rename has succeeded

	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return fmt.Errorf("chmod session snapshot: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write session snapshot: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close session snapshot: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("install session snapshot: %w", err)
	}
	return nil
}

// LoadSnapshot reads a snapshot left by an earlier invocation.
//
// Anything unreadable, unparseable or written by another version comes back as
// ErrNoSnapshot rather than as an error worth stopping for. The caller can
// always fall back to reading the kernel, which is the authority in any case:
// see Resume for why a lost or stale snapshot cannot make this process believe
// a gap is open when it is not.
func LoadSnapshot(path string) (Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, ErrNoSnapshot
	}
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return Snapshot{}, ErrNoSnapshot
	}
	if s.Version != snapshotVersion {
		return Snapshot{}, ErrNoSnapshot
	}
	if _, ok := transitions[s.State]; !ok {
		// A state this build does not have. Same treatment as a version skew.
		return Snapshot{}, ErrNoSnapshot
	}
	return s, nil
}

// ClearSnapshot removes the session file. A missing file is not an error:
// clearing is called on paths that must not fail, like release.
func ClearSnapshot(path string) {
	_ = os.Remove(path)
}
