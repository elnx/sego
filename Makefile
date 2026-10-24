# sego -- a pure-Go reimplementation of the setools SELinux policy analysis
# tools. This file builds the sesearch, seinfo, sediff, sedta, seinfoflow and
# sechecker commands.
#
# Native build:      make            (or make build)
# Cross build:       GOOS=windows make         -> bin/*.exe
#                    make GOOS=darwin GOARCH=arm64
# Distribution:      make dist        -> bin/<os>_<arch>/<tool>[.exe]
#                                          for linux, windows and darwin
#                                          (darwin in both amd64 and arm64)

# The version reported by --version. Release builds set VERSION explicitly;
# otherwise it is derived from the closest git tag.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null)
ifeq ($(VERSION),)
VERSION := dev
endif

GO ?= go
TOOLS := sesearch seinfo sediff sedta seinfoflow sechecker
PKGS := $(foreach tool,$(TOOLS),./cmd/$(tool))

# Tests, vet and code intelligence always run for the host platform, even when
# GOOS/GOARCH are set on the command line for a cross build.
HOST_GOOS := $(shell $(GO) env GOHOSTOS)
HOST_GOARCH := $(shell $(GO) env GOHOSTARCH)
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

# Cross compilation needs no toolchain beyond Go: the module has no cgo and no
# dependencies outside the standard library, so CGO is always disabled.
DIST_ROOT ?= bin
DIST_PLATFORMS ?= linux/amd64 windows/amd64 darwin/amd64 darwin/arm64

.DEFAULT_GOAL := build

.PHONY: build test lint fixtures dist clean help

# Build every tool into bin/ (with the .exe suffix when GOOS is windows), with
# the version compiled in.
build:
	@for tool in $(TOOLS); do \
		echo "  building bin/$$tool$(EXE) ($(GOOS)/$(GOARCH))"; \
		GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 $(GO) build -trimpath \
			-ldflags '$(LDFLAGS)' -o bin/$$tool$(EXE) ./cmd/$$tool || exit 1; \
	done

# Run the unit tests and, when the query matrices are present, the golden
# replays. Tests run on the host, not for GOOS/GOARCH. No network access and
# no installed SELinux policy are needed; graphviz is only needed by the
# tools' graphical output and is not exercised by the tests.
test:
	GOOS=$(HOST_GOOS) GOARCH=$(HOST_GOARCH) $(GO) test ./...

# Format, vet and (when available) type check.
lint:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt -l .:"; echo "$$unformatted"; exit 1; \
	fi
	GOOS=$(HOST_GOOS) GOARCH=$(HOST_GOARCH) $(GO) vet ./...
	@if command -v gopls >/dev/null 2>&1; then \
		gopls check $$(find . -name '*.go' -not -path './testdata/*'); \
	else \
		echo "gopls is not on PATH, skipping gopls check"; \
	fi

# Build every tool for every platform in DIST_PLATFORMS into its own
# bin/<os>_<arch>/ directory (DIST_ROOT overrides bin) and write a SHA256SUMS
# in each. The host platform's own binaries are run once as a smoke test.
dist:
	@set -e; \
	hostos=$$($(GO) env GOOS); hostarch=$$($(GO) env GOARCH); \
	for platform in $(DIST_PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		dir=$(DIST_ROOT)/$${os}_$${arch}; \
		ext=; [ "$$os" = windows ] && ext=.exe; \
		rm -rf "$$dir"; \
		mkdir -p "$$dir"; \
		for tool in $(TOOLS); do \
			out=$$dir/$$tool$$ext; \
			echo "  building $$out (GOOS=$$os GOARCH=$$arch)"; \
			GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath \
				-ldflags '$(LDFLAGS)' -o "$$out" ./cmd/$$tool; \
			if [ "$$os" = "$$hostos" ] && [ "$$arch" = "$$hostarch" ]; then \
				"$$out" --version >/dev/null || { echo "$$out does not run"; exit 1; }; \
			fi; \
		done; \
		(cd "$$dir" && sha256sum * > SHA256SUMS); \
	done
	@echo "version $(VERSION), $(words $(DIST_PLATFORMS)) platforms in $(DIST_ROOT)/<os>_<arch>/:"
	@for platform in $(DIST_PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		dir=$(DIST_ROOT)/$${os}_$${arch}; \
		echo "  $$dir/"; \
		ls -l "$$dir" | tail -n +2 | awk '{printf "    %8d  %s\n", $$5, $$9}'; \
	done

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
	@echo "make build                     build $(TOOLS) into bin/ (VERSION=$(VERSION))"
	@echo "GOOS=windows make              cross build bin/*.exe"
	@echo "make dist                      build $(DIST_PLATFORMS) into $(DIST_ROOT)/<os>_<arch>/"
	@echo "make test                      run go test ./... on the host"
	@echo "make lint                      gofmt -l, go vet, gopls check"
	@echo "make fixtures                  regenerate testdata/policies via testdata/gen.sh"
	@echo "make clean                     remove bin/"
