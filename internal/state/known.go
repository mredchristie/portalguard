package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ==== known networks ========================================================
// A network this machine has been told about before, so the next visit does
// not repeat the same diagnosis. See docs/gap-scope.md, option E.

// KnownNetworksPath is where remembered networks are kept.
//
// /etc rather than /var/run: unlike the session file, this is meant to
// outlive a reboot and a single invocation - it is what makes the second
// visit to a network faster than the first.
const KnownNetworksPath = "/etc/portalguard/known-networks.json"

const knownNetworksVersion = 1

// KnownNetwork is one previously-handled portal, keyed by its registrable
// domain (see siteOf) rather than by the exact portal hostname: a chain's
// portal host can vary by branch or region while its CDN and login hosts stay
// put.
//
// Being remembered here is not the same as being trusted blindly. It only
// changes what OpenGap tries next time - see AutoOpenKnown, which still
// requires each host to prove itself with a valid TLS certificate before it
// is opened. Hosts is the list of things worth trying, not a list of things
// that will be let through regardless.
type KnownNetwork struct {
	Site  string   `json:"site"`
	Hosts []string `json:"hosts"` // "host" or "host:port", same form as `allow`

	AddedAt  time.Time `json:"added_at,omitzero"`
	LastSeen time.Time `json:"last_seen,omitzero"`
}

type knownNetworksFile struct {
	Version  int                     `json:"version"`
	Networks map[string]KnownNetwork `json:"networks"`
}

// seedKnownNetworks ships with exactly one entry. BT Wi-Fi is the only
// network this project has actually stood in front of, watched fail blank,
// and confirmed the fix for - see docs/gap-scope.md. Nothing else is seeded:
// a plausible-looking hostname for a provider nobody here has tested against
// is worse than no entry at all, because a wrong entry that never matches
// teaches nothing while looking like it should, and this whole mechanism
// exists to only ever hold names that were actually verified. Real entries
// accrue through Session.Remember, once a person has diagnosed a network by
// hand at least once - which is exactly what already has to happen today.
func seedKnownNetworks() map[string]KnownNetwork {
	return map[string]KnownNetwork{
		"btwifi.com": {
			Site:  "btwifi.com",
			Hosts: []string{"cdn.btwifi.com", "reg.btwifi.com", "info.btwifi.com:442"},
		},
	}
}

// LoadKnownNetworks reads the remembered-networks file, or the built-in seed
// if none exists yet or the file cannot be read.
//
// Same treatment as a stale session snapshot: a file this build cannot make
// sense of is worth less than the seed, not worth stopping for.
func LoadKnownNetworks(path string) map[string]KnownNetwork {
	data, err := os.ReadFile(path)
	if err != nil {
		return seedKnownNetworks()
	}
	var f knownNetworksFile
	if err := json.Unmarshal(data, &f); err != nil || f.Version != knownNetworksVersion || f.Networks == nil {
		return seedKnownNetworks()
	}
	// Drop anything that is not a hostname, so a file written before
	// Remember checked for that cannot keep sending a placeholder like
	// "portal" to be resolved - through the network's own DNS - and checked.
	for site, kn := range f.Networks {
		var hosts []string
		for _, spec := range kn.Hosts {
			if h, _ := splitHostPort(spec); rememberable(h) {
				hosts = append(hosts, spec)
			}
		}
		kn.Hosts = hosts
		f.Networks[site] = kn
	}
	return f.Networks
}

// rememberable reports whether name is something worth remembering: a
// hostname with at least one dot, or an address. What it screens out are the
// labels a host is given when it was recovered from the kernel with no name
// attached - "portal", "resolvers", "portalguard checks" - which name a
// table, not a host, and would resolve to whatever the network says.
func rememberable(name string) bool {
	if name == "" || strings.ContainsAny(name, " /") {
		return false
	}
	return strings.Contains(name, ".") || strings.Contains(name, ":")
}

// SaveKnownNetworks writes the remembered-networks file, replacing any
// earlier one. Atomic for the same reason SaveSnapshot is: a temporary file
// in the same directory, then a rename.
func SaveKnownNetworks(path string, networks map[string]KnownNetwork) error {
	data, err := json.MarshalIndent(knownNetworksFile{Version: knownNetworksVersion, Networks: networks}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode known networks: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create known networks directory: %w", err)
	}
	f, err := os.CreateTemp(dir, filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create known networks file: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once the rename below succeeds

	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return fmt.Errorf("chmod known networks file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write known networks file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close known networks file: %w", err)
	}
	return os.Rename(tmp, path)
}
