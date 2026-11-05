# Static, reproducible stunmesh-cli: same commit, same bytes. Toolchain and
# codegen environment pinned as in stunmesh-avahi.
#
#   make build NODE=desk-cli CONFIG=~/mesh   # CONFIG: the dir of mesh.yaml
#
# builds the generic build/sm-ARCH and from it build/sm-NODE-ARCH,
# the same binary with CONFIG/NODE/node.json and the ssh_config beside
# it, as gen.py renders them, attached as a zip (sm config attach;
# unzip -p reads it back). Without NODE, only the generic binary, which
# takes its config from --config FILE.
# build/bin/ gets a symlink per applet, so PATH=build/bin:$PATH makes
# mosh, nc, ... the applets. Nothing is installed outside build/.
VERSION ?= $(shell git describe --tags --always --dirty)
GO_VERSION ?= 1.26.9
GOARCH ?= $(shell go env GOARCH)
GOHOSTARCH := $(shell go env GOHOSTARCH)
NODE ?=
CONFIG ?=
# SMALL=1 turns inlining off, about 9% smaller (arm64: 11.3 to 10.3 MB),
# for devices where space counts more than CPU per packet. gsa shows the
# rest is runtime, gvisor, crypto and net, all needed, plus pclntab.
SMALL ?=
GCFLAGS := $(if $(SMALL),-gcflags=all=-l)

BUILD := build
BASE := $(BUILD)/sm-$(GOARCH)
BIN := $(BUILD)/sm-$(if $(NODE),$(NODE)-)$(GOARCH)

export CGO_ENABLED := 0
export GOTOOLCHAIN := go$(GO_VERSION)
export GOFLAGS :=
export GOEXPERIMENT :=
export GOAMD64 := v1
export GOARM64 := v8.0

.PHONY: build check test vet tidy clean FORCE

# Always run go build: it is incremental itself, and restamps the version
# after a commit that changes no source.
$(BASE): FORCE
	GOOS=linux GOARCH=$(GOARCH) go build -trimpath $(GCFLAGS) -ldflags '-s -w -X main.version=$(VERSION)' -o $@ ./cmd/sm

# Attaching runs sm for this host, so it works for any GOARCH.
ifneq ($(NODE),)
$(BIN): $(BASE) FORCE
	@test -n "$(CONFIG)" || { echo "NODE=$(NODE) needs CONFIG=<dir of mesh.yaml>" >&2; exit 1; }
	GOARCH=$(GOHOSTARCH) go run ./cmd/sm config attach $(BASE) $(CONFIG)/$(NODE)/node.json $@
endif

# The applet links come from the binary's own --list, so only a binary for
# this host gets them.
build: $(BIN)
ifeq ($(GOARCH),$(GOHOSTARCH))
	rm -rf $(BUILD)/bin && mkdir -p $(BUILD)/bin
	for a in sm $$($(BIN) --list); do ln -s ../$(notdir $(BIN)) $(BUILD)/bin/$$a; done
endif

check: tidy vet test build
ifeq ($(GOARCH),$(GOHOSTARCH))
	$(BIN) --list > /dev/null
ifneq ($(NODE),)
	$(BIN) status > /dev/null
endif
endif

# go.mod and go.sum must be what go mod tidy makes them.
tidy:
	go mod tidy -diff

vet:
	go vet ./...

# The race detector needs cgo; only the shipped binary must be static.
test:
	CGO_ENABLED=1 go test -race ./...

clean:
	rm -rf $(BUILD)
