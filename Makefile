BINARY   := portalguard
PKG      := ./cmd/portalguard
BIN_DIR  := bin
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -X main.version=$(VERSION)

.PHONY: all build install test vet fmt clean detect rescue e2e testenv-up testenv-down testenv-logs

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
e2e: build
	@echo "this needs root and will cut the network. run:"
	@echo "    sudo ./testenv/e2e.sh"
