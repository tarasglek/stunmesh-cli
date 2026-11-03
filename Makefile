# Static, reproducible stunmesh-cli: same commit, same bytes. Toolchain and
# codegen environment pinned as in stunmesh-avahi. The mobile tag selects
# stunmesh-go's embeddable node (mobile/), which also builds on linux.
VERSION ?= $(shell git describe --tags --always --dirty)
GO_VERSION ?= 1.26.9
GOARCH ?= $(shell go env GOARCH)
TAGS := mobile

BUILD := build

export CGO_ENABLED := 0
export GOTOOLCHAIN := go$(GO_VERSION)
export GOFLAGS :=
export GOEXPERIMENT :=
export GOAMD64 := v1
export GOARM64 := v8.0

.PHONY: build check test vet tidy clean FORCE
build: $(BUILD)/stunmesh-cli-$(GOARCH)

# Always run go build: it is incremental itself, sees the replaced sibling
# modules, and restamps the version after a commit that changes no source.
$(BUILD)/stunmesh-cli-%: FORCE
	GOOS=linux GOARCH=$* go build -tags '$(TAGS)' -trimpath -ldflags '-s -w -X main.version=$(VERSION)' -o $@ ./cmd/stunmesh-cli

check: tidy vet test build
	$(BUILD)/stunmesh-cli-$(GOARCH) --list > /dev/null

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
