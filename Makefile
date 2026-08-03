GO      ?= go
CLANG   ?= clang
# Everything ovpnmon owns lives here: binaries, config and recorded history.
PREFIX  ?= /opt/ovpnmon
BIN     := ovpnmon

# Prefer a git tag; fall back to a plain marker outside a checkout.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: all
all: build

## deps-check: report required tools and kernel features, changing nothing
.PHONY: deps-check
deps-check:
	@./deploy/install-deps.sh check

## deps: install the build toolchain, incl. the Go version go.mod needs (root)
.PHONY: deps
deps:
	sudo ./deploy/install-deps.sh build

## deps-openvpn: install packages needed to run 'make server' (root)
.PHONY: deps-openvpn
deps-openvpn:
	sudo ./deploy/install-deps.sh openvpn

## deps-dev: install test and benchmark tooling (root)
.PHONY: deps-dev
deps-dev:
	sudo ./deploy/install-deps.sh dev

## deps-all: build + openvpn + dev dependencies (root)
.PHONY: deps-all
deps-all:
	sudo ./deploy/install-deps.sh all

## generate: recompile the eBPF object and regenerate its Go bindings
.PHONY: generate
generate:
	$(GO) generate ./...

## build: build the ovpnmon binary (eBPF object is embedded)
.PHONY: build
build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/ovpnmon

## test: run every test; the eBPF load test needs root and a tun device
.PHONY: test
test:
	$(GO) test ./...

## test-root: run the full suite including the kernel verifier test
.PHONY: test-root
test-root:
	sudo -E env PATH=$$PATH $(GO) test ./...

## vet: static checks and formatting
.PHONY: vet
vet:
	$(GO) vet ./...
	@test -z "$$(gofmt -l ./cmd ./internal)" || { echo "gofmt needed:"; gofmt -l ./cmd ./internal; exit 1; }

## server: install and configure the OpenVPN server (root)
.PHONY: server
server:
	sudo ./deploy/setup-openvpn.sh

## install: install into $(PREFIX), keeping an existing config (root)
.PHONY: install
install: build
	sudo install -d -m 755 $(PREFIX)/bin $(PREFIX)/etc
	sudo install -d -m 700 $(PREFIX)/data
	sudo install -m 755 $(BIN) $(PREFIX)/bin/$(BIN)
	sudo install -m 755 deploy/ovpn-firewall.sh $(PREFIX)/bin/ovpn-firewall
	sudo install -m 644 README.md $(PREFIX)/README.md
	@# Never clobber a config the operator has edited.
	@if [ -f $(PREFIX)/etc/ovpnmon.conf ]; then \
		echo "keeping existing $(PREFIX)/etc/ovpnmon.conf"; \
		sudo install -m 640 deploy/ovpnmon.conf $(PREFIX)/etc/ovpnmon.conf.default; \
	else \
		sudo install -m 640 deploy/ovpnmon.conf $(PREFIX)/etc/ovpnmon.conf; \
	fi
	sudo install -m 644 deploy/ovpnmon.service /etc/systemd/system/ovpnmon.service
	sudo systemctl daemon-reload
	@echo "now run: sudo systemctl enable --now ovpnmon"

## uninstall: remove binaries, units and config, keeping recorded history (root)
.PHONY: uninstall
uninstall:
	-sudo systemctl disable --now ovpnmon 2>/dev/null
	-sudo systemctl disable --now ovpn-firewall 2>/dev/null
	sudo rm -f /etc/systemd/system/ovpnmon.service /etc/systemd/system/ovpn-firewall.service
	sudo systemctl daemon-reload
	sudo rm -rf $(PREFIX)/bin $(PREFIX)/etc $(PREFIX)/README.md
	@echo "removed. history kept at $(PREFIX)/data - 'make purge' deletes it too"

## purge: uninstall and delete recorded history as well (root)
.PHONY: purge
purge: uninstall
	sudo rm -rf $(PREFIX)
	@echo "$(PREFIX) removed entirely"

## client-up: connect a test client in an isolated namespace (root)
.PHONY: client-up
client-up:
	sudo ./deploy/test-client.sh up $(CLIENT)

## client-down: tear the test client down (root)
.PHONY: client-down
client-down:
	sudo ./deploy/test-client.sh down $(CLIENT)

CLIENT ?= alice

## clean: remove build output
.PHONY: clean
clean:
	rm -f $(BIN)

## help: list targets
.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
