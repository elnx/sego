# sego -- a pure-Go reimplementation of the setools SELinux policy analysis
# tools. This file builds the sesearch command.
#
# Native build:      make            (or make build)
# Cross build:       GOOS=windows make         -> bin/sesearch.exe
#                    make GOOS=darwin GOARCH=arm64
# Distribution:      make dist        -> bin/dist/sesearch-<os>-<arch>[.exe]
#                                          for linux, windows and darwin
#                                          (darwin in both amd64 and arm64)

# The version reported by --version. Release builds set VERSION explicitly;
# otherwise it is derived from the closest git tag.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null)
ifeq ($(VERSION),)
VERSION := dev
endif

GO ?= go
PKG := ./cmd/sesearch
LDFLAGS := -X main.version=$(VERSION)

# GOOS/GOARCH default to the host, so `make build` is a native build and
# `GOOS=windows make build` (environment) or `make GOOS=windows build` (command
# line) both produce a cross build.
GOOS ?= $(shell $(GO) env GOOS)
GOARCH ?= $(shell $(GO) env GOARCH)

# Windows binaries carry the .exe suffix.
ifeq ($(GOOS),windows)
EXE := .exe
endif
BIN := bin/sesearch$(EXE)

# Cross compilation needs no toolchain beyond Go: the module has no cgo and no
# dependencies outside the standard library, so CGO is always disabled.
DIST_DIR ?= bin/dist
DIST_PLATFORMS ?= linux/amd64 windows/amd64 darwin/amd64 darwin/arm64

.DEFAULT_GOAL := build

.PHONY: build test lint fixtures dist clean help

# Build bin/sesearch (bin/sesearch.exe when GOOS is windows), with the version
# compiled in.
build:
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) $(PKG)

# Run the unit tests and, when testdata/queries.txt is present, the query
# matrix. Tests run on the host, not for GOOS/GOARCH. No network access and no
# installed SELinux policy are needed.
test:
	$(GO) test ./...

# Format, vet and (when available) type check.
lint:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt -l .:"; echo "$$unformatted"; exit 1; \
	fi
	$(GO) vet ./...
	@if command -v gopls >/dev/null 2>&1; then \
		gopls check $$(find . -name '*.go' -not -path './testdata/*'); \
	else \
		echo "gopls is not on PATH, skipping gopls check"; \
	fi

# Build the release binaries for every platform in DIST_PLATFORMS and write
# SHA256SUMS next to them. The host's own binary is run once as a smoke test.
dist:
	@rm -rf $(DIST_DIR)
	@mkdir -p $(DIST_DIR)
	@set -e; \
	hostos=$$($(GO) env GOOS); hostarch=$$($(GO) env GOARCH); \
	for platform in $(DIST_PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		ext=; [ "$$os" = windows ] && ext=.exe; \
		out=$(DIST_DIR)/sesearch-$$os-$$arch$$ext; \
		echo "  building $$out (GOOS=$$os GOARCH=$$arch)"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o "$$out" $(PKG); \
		if [ "$$os" = "$$hostos" ] && [ "$$arch" = "$$hostarch" ]; then \
			"$$out" --version >/dev/null || { echo "$$out does not run"; exit 1; }; \
		fi; \
	done
	@cd $(DIST_DIR) && sha256sum sesearch-* > SHA256SUMS
	@echo "version $(VERSION), $(words $(DIST_PLATFORMS)) platforms in $(DIST_DIR):"
	@ls -l $(DIST_DIR) | tail -n +2 | awk '{printf "  %8d  %s\n", $$5, $$9}'

# Regenerate the policy fixtures with testdata/gen.sh, which needs a
# checkpolicy build (see the script for CHECKPOLICY/LIBSEPOL_DIR).
fixtures:
	@if [ -x testdata/gen.sh ]; then \
		testdata/gen.sh; \
	else \
		echo "testdata/gen.sh is not present, nothing to regenerate"; \
	fi

clean:
	rm -rf bin

help:
	@echo "make build                     build $(BIN) (VERSION=$(VERSION))"
	@echo "GOOS=windows make              cross build bin/sesearch.exe"
	@echo "make dist                      build $(DIST_PLATFORMS) into $(DIST_DIR)"
	@echo "make test                      run go test ./... on the host"
	@echo "make lint                      gofmt -l, go vet, gopls check"
	@echo "make fixtures                  regenerate testdata/policies via testdata/gen.sh"
	@echo "make clean                     remove bin/"
