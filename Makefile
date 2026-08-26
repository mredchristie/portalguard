BINARY   := portalguard
PKG      := ./cmd/portalguard
BIN_DIR  := bin
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -X main.version=$(VERSION)

.PHONY: all build install test vet fmt clean detect testenv-up testenv-down testenv-logs panic-check

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

# --- Test captive portal (see testenv/README.md) -----------------------------
# COMPOSE can be overridden: make COMPOSE="podman compose" testenv-up
COMPOSE ?= docker compose

testenv-up:
	cd testenv && $(COMPOSE) up --build -d
	@echo "Portal up. Web: http://localhost:8080  DNS: localhost:5353 (udp)"

testenv-down:
	cd testenv && $(COMPOSE) down -v

testenv-logs:
	cd testenv && $(COMPOSE) logs -f
