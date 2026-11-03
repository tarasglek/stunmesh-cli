# Static, reproducible stunmesh-cli: same commit, same bytes. Toolchain and
# codegen environment pinned as in stunmesh-avahi. The mobile tag selects
# stunmesh-go's embeddable node (mobile/), which also builds on linux.
#
#   make build NODE=desk-cli CONFIG=~/mesh   # CONFIG: the dir of mesh.yaml
#
# compiles in CONFIG/NODE/node.json, as gen.py renders it, and builds
# build/sm-NODE-ARCH; without NODE the binary has no node config.
# build/bin/ gets a symlink per applet, so PATH=build/bin:$PATH makes
# ssh, nc, ... the applets. Nothing is installed outside build/.
VERSION ?= $(shell git describe --tags --always --dirty)
GO_VERSION ?= 1.26.9
GOARCH ?= $(shell go env GOARCH)
GOHOSTARCH := $(shell go env GOHOSTARCH)
TAGS := mobile
NODE ?=
CONFIG ?=
# SMALL=1 turns inlining off, about 9% smaller (arm64: 11.3 to 10.3 MB),
# for devices where space counts more than CPU per packet. gsa shows the
# rest is runtime, gvisor, crypto and net, all needed, plus pclntab.
SMALL ?=
GCFLAGS := $(if $(SMALL),-gcflags=all=-l)

BUILD := build
EMBED := cmd/sm/config/node.json
BIN := $(BUILD)/sm-$(if $(NODE),$(NODE)-)$(GOARCH)

export CGO_ENABLED := 0
export GOTOOLCHAIN := go$(GO_VERSION)
export GOFLAGS :=
export GOEXPERIMENT :=
export GOAMD64 := v1
export GOARM64 := v8.0

.PHONY: build check test vet tidy clean FORCE
build: $(BIN)

# Always run go build: it is incremental itself, sees the replaced sibling
# modules, and restamps the version after a commit that changes no source.
# The applet links come from the binary's own --list, so only a binary for
# this host gets them.
$(BIN): FORCE
ifneq ($(NODE),)
	@test -n "$(CONFIG)" || { echo "NODE=$(NODE) needs CONFIG=<dir of mesh.yaml>" >&2; exit 1; }
	cp $(CONFIG)/$(NODE)/node.json $(EMBED)
else
	rm -f $(EMBED)
endif
	GOOS=linux GOARCH=$(GOARCH) go build -tags '$(TAGS)' -trimpath $(GCFLAGS) -ldflags '-s -w -X main.version=$(VERSION)' -o $@ ./cmd/sm
ifeq ($(GOARCH),$(GOHOSTARCH))
	rm -rf $(BUILD)/bin && mkdir -p $(BUILD)/bin
	for a in sm $$($@ --list); do ln -s ../$(notdir $@) $(BUILD)/bin/$$a; done
endif

check: tidy vet test build
	$(BIN) --list > /dev/null
ifneq ($(NODE),)
	$(BIN) status > /dev/null
endif

# go.mod and go.sum must be what go mod tidy makes them.
tidy:
	go mod tidy -diff

vet:
	go vet -tags '$(TAGS)' ./...

# The race detector needs cgo; only the shipped binary must be static.
test:
	CGO_ENABLED=1 go test -race -tags '$(TAGS)' ./...

clean:
	rm -rf $(BUILD)
