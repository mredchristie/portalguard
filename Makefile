BINARY   := portalguard
PKG      := ./cmd/portalguard
BIN_DIR  := bin
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -X main.version=$(VERSION)

.PHONY: app fuzz all build install uninstall test vet fmt clean detect rescue e2e e2e-redact demo demo-allow testenv-up testenv-down testenv-logs hotspot-up hotspot-down hotspot-demo hotspot-known hotspot-auto hotspot-hostile hotspot-armed preflight handoff-check dns-spike e2e-portal

all: vet test build

build:
	@mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(PKG)

# Copies the built binary to /usr/local/bin so `portalguard` and
# `sudo portalguard ...` work from anywhere, matching what the README shows.
# /usr/local/bin is root-owned on a stock Mac, so this usually needs sudo.
PREFIX ?= /usr/local

# Not `install: build`: under sudo that would compile as root, which may not
# find Go and leaves root-owned files in the repo. Build first, as yourself.
install:
	@test -x $(BIN_DIR)/$(BINARY) || { echo "build it first, without sudo: make build"; exit 1; }
	install -d $(PREFIX)/bin
	install -m 0755 $(BIN_DIR)/$(BINARY) $(PREFIX)/bin/$(BINARY)
	@echo "installed to $(PREFIX)/bin/$(BINARY) - try: sudo portalguard lockdown"

uninstall:
	rm -f $(PREFIX)/bin/$(BINARY)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

clean:
	rm -rf $(BIN_DIR)

# Convenience: run detection against the current network.
detect: build
	./$(BIN_DIR)/$(BINARY) detect -v

# --- Recovery -----------------------------------------------------------------
# If portalguard dies while the firewall is engaged, this is how you get your
# network back. It empties our pf anchor and touches nothing else on the
# system, needs no portalguard binary, and is safe to run at any time even if
# nothing is installed. Documented in README.md and docs/pf-design.md.
rescue:
	@echo "flushing the portalguard pf anchor (needs sudo)..."
	sudo pfctl -a portalguard -F all
	@echo "done - normal networking restored."

# --- Test captive portal (see testenv/README.md) -----------------------------
# COMPOSE can be overridden: make COMPOSE="podman compose" testenv-up
COMPOSE ?= docker compose

testenv-up:
	cd testenv && $(COMPOSE) up --build -d
	@echo "Portal up. Web: http://localhost:8080  DNS: localhost:5354 (udp)"

testenv-down:
	cd testenv && $(COMPOSE) down -v

testenv-logs:
	cd testenv && $(COMPOSE) logs -f

# End-to-end test against the real pf backend. Needs root, and CUTS THE
# NETWORK several times on purpose. See testenv/README.md for which half of
# the test covers what - a green run is not end-to-end proof on its own.
# Depends on build so the test can never run against a stale binary - which
# has already produced one full round of false failures.
#
# REDACT=1 becomes --redact on e2e.sh's own command line, not an
# environment variable passed through sudo: `sudo ... REDACT=1` (or any
# other env-var form) is silently dropped by sudo's default env_reset
# before the script ever sees it - confirmed directly, and it once produced
# a "redacted" recording that was not. Expanding REDACT into an argument
# here, before the `sudo` line runs, means make e2e REDACT=1 actually works
# rather than repeating that mistake with a friendlier-looking spelling.
# The fake portal e2e.sh talks to, without a container runtime: plain Go on
# 127.0.0.1:8080, redirecting to this network's gateway so the gap is pinned
# to a genuinely off-box address. Leave it running in a second terminal.
e2e-portal:
	@route -n get default | grep -qE 'interface: (utun|ipsec|ppp)' \
		&& { echo "a VPN owns the default route; disconnect it first"; exit 1; } || true
	go run ./testenv/portal-web -addr 127.0.0.1:8080 -login-url http://$$(route -n get default | awk '/gateway/{print $$2}')/

e2e: build
	@echo "this needs root and CUTS THE NETWORK several times on purpose."
	sudo ./testenv/e2e.sh $(if $(filter 1,$(REDACT)),--redact)

# Same as `e2e`, redacted - for recording a run somewhere other than your
# own reading. See testenv/README.md, "Running the end-to-end test", for
# what --redact actually guarantees and how it's verified.
e2e-redact: build
	@echo "this needs root and CUTS THE NETWORK several times on purpose."
	sudo ./testenv/e2e.sh --redact

# One command, nothing to type while it runs - for recording the actual
# product flow rather than the test harness. See testenv/demo.sh.
demo: build
	@echo "this needs root and CUTS THE NETWORK several times on purpose."
	sudo ./testenv/demo.sh

# The two-process flow: `run` waiting while a separate `allow` widens the gap
# under it, which is what a blank portal page actually needs. See
# testenv/README.md, "Recording the two-process demo".
demo-allow: build
	@echo "this needs root and CUTS THE NETWORK several times on purpose."
	sudo ./testenv/demo-allow.sh

# --- The app ---------------------------------------------------------------
# gui/ is its own Go module (Wails), so the engine stays dependency-free. The
# app carries the engine inside it, in Contents/Resources, and is signed
# ad hoc: it runs on this Mac, and is not yet for handing to anyone else.
APP := gui/build/bin/PortalGuard.app
#
# Wails signs the app itself, and that step fails when the files carry
# extended attributes (a Documents folder synced to iCloud adds them). So a
# failed build is accepted only if the app binary was built, and the bundle is
# stripped of attributes and signed here instead, with the engine inside.
# Wails from PATH, or where `go install` puts it.
WAILS ?= $(shell command -v wails 2>/dev/null || echo $(HOME)/go/bin/wails)

app: build
	@test -x "$(WAILS)" || { echo "needs the Wails CLI: go install github.com/wailsapp/wails/v2/cmd/wails@v2.16.0"; exit 1; }
	cd gui && ($(WAILS) build -clean || test -x build/bin/PortalGuard.app/Contents/MacOS/PortalGuard)
	cp $(BIN_DIR)/portalguard $(APP)/Contents/Resources/portalguard
	xattr -cr $(APP)
	codesign --force --deep --sign - $(APP)
	@echo "built $(APP)"

# --- Fuzzing the parsers that read untrusted input -------------------------
# Each target runs for FUZZTIME (default 30s). A crash is saved under the
# package's testdata/fuzz and from then on runs with every `make test`.
FUZZTIME ?= 30s
fuzz:
	go test -run '^$$' -fuzz '^FuzzHandle$$' -fuzztime $(FUZZTIME) ./internal/dnsfilter
	go test -run '^$$' -fuzz '^FuzzQuestionName$$' -fuzztime $(FUZZTIME) ./internal/dnsfilter
	go test -run '^$$' -fuzz '^FuzzAnswerAddrs$$' -fuzztime $(FUZZTIME) ./internal/dnsfilter
	go test -run '^$$' -fuzz '^FuzzSiteOf$$' -fuzztime $(FUZZTIME) ./internal/state
	go test -run '^$$' -fuzz '^FuzzMetaRefresh$$' -fuzztime $(FUZZTIME) ./internal/portal
	go test -run '^$$' -fuzz '^FuzzSplitURL$$' -fuzztime $(FUZZTIME) ./internal/portal

# --- The off-box hotspot (see testenv/README.md, "The off-box hotspot") ------
# A BT-shaped portal across four containers, each on its own address on
# bridge100, so pf genuinely filters it - unlike everything above, which runs
# on loopback. Needs Apple's container tool: brew install container.
# up and down run as you, not root: the container service is per-user.
hotspot-up:
	./testenv/hotspot.sh up

hotspot-down:
	./testenv/hotspot.sh down

# First visit: blank page, suggestion, allow from a second process, remember,
# login, seal. Points this Mac's DNS at the hotspot while it runs and puts it
# back on exit. Disconnect the VPN first.
hotspot-demo: build
	@echo "this needs root, CUTS THE NETWORK, and points DNS at the hotspot while it runs."
	sudo ./testenv/hotspot-demo.sh first

# Next visit: the remembered hosts open themselves after a TLS check. Needs
# hotspot-demo to have run first, and mkcert -install for the certificates.
hotspot-known: build
	@echo "this needs root, CUTS THE NETWORK, and points DNS at the hotspot while it runs."
	sudo ./testenv/hotspot-demo.sh known

# Auto-allow: the login page renders first time, with no allow and nothing
# remembered. hotspot-demo is its control: the same portal with it off.
hotspot-auto: build
	@echo "this needs root, CUTS THE NETWORK, and points DNS at the hotspot while it runs."
	sudo ./testenv/hotspot-demo.sh auto

# A portal that attacks. hostile-known needs remembered hosts, so run
# hotspot-demo first (preflight does both in the right order).
hotspot-hostile: build
	@echo "this needs root, CUTS THE NETWORK, and points DNS at the hotspot while it runs."
	sudo ./testenv/hotspot-demo.sh hostile-known
	sudo ./testenv/hotspot-demo.sh hostile

# Armed: lock down first, then join the hotspot. Nothing but detection and the
# login may reach its DNS during the join.
hotspot-armed: build
	@echo "this needs root, CUTS THE NETWORK, and points DNS at the hotspot while it runs."
	sudo ./testenv/hotspot-demo.sh armed

# Before a field test: unit tests, then every hotspot run back to back, with a
# verdict per suite. Brings the hotspot up and takes it down again.
preflight: build
	@echo "this needs root, CUTS THE NETWORK several times, and takes about three minutes."
	./testenv/preflight.sh

# --- The VPN handover ----------------------------------------------------------
# Proves the handover hole on the wire, with no VPN: during a handover a UDP
# packet to 51820 leaves the machine and one to port 9 does not, and 51820 is
# dropped again once the hole closes. Disconnect any VPN first.
handoff-check: build
	@echo "this needs root and CUTS THE NETWORK for about ten seconds."
	sudo ./testenv/handoff-rules-check.sh

# --- The v0.3 DNS filter ---------------------------------------------------------
# Proves pf can divert this Mac's DNS to a local resolver, the mechanism the
# DNS filter is built on. Needs the rdr hook: sudo ./bin/portalguard
# install-anchor. Disconnect any VPN first.
dns-spike: build
	go build -o $(BIN_DIR)/dnsspike ./testenv/dnsspike
	sudo ./testenv/dns-redirect-spike.sh
