BINARY   := portalguard
PKG      := ./cmd/portalguard
BIN_DIR  := bin
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -X main.version=$(VERSION)

.PHONY: all build install test vet fmt clean detect rescue e2e e2e-redact demo testenv-up testenv-down testenv-logs

all: vet test build

build:
	@mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(PKG)

install:
	go install -ldflags "$(LDFLAGS)" $(PKG)

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
