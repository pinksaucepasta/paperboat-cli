BINARY      := pb
PKG         := ./cmd/pb
PREFIX      ?= /usr/local
BINDIR      := $(PREFIX)/bin
VERSION     ?= $(shell ./tools/release-version.sh current)
PROTOCOL_VERSION ?= 1
GO_VERSION  := 1.25.7
GO          := GOTOOLCHAIN=local go
GOFMT       := $(shell GOTOOLCHAIN=local go env GOROOT 2>/dev/null)/bin/gofmt
GO_FILES    := $(shell find . -path ./.git -prune -o -name '*.go' -print)
LDFLAGS     := -X github.com/pinksaucepasta/paperboat-cli/internal/buildinfo.Version=$(VERSION) -X github.com/pinksaucepasta/paperboat-cli/internal/buildinfo.ProtocolVersion=$(PROTOCOL_VERSION)

.PHONY: build check clean complete contracts cross-build fmt fmt-check generate install lint race release-metadata test tidy uninstall verify-toolchain vet

contracts:
	@./testdata/contracts/validate.sh

verify-toolchain:
	@test "$$(GOTOOLCHAIN=local go env GOVERSION)" = "go$(GO_VERSION)" || { echo "required Go $(GO_VERSION), found $$(GOTOOLCHAIN=local go env GOVERSION)" >&2; exit 1; }

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

cross-build: verify-toolchain
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64 $(PKG)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64 $(PKG)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 $(PKG)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 $(PKG)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe $(PKG)
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-arm64.exe $(PKG)

# Produce reviewable integrity metadata alongside a release binary. Signing,
# SBOM generation, and publishing are performed by the release pipeline.
release-metadata: build
	@mkdir -p dist
	@cp bin/$(BINARY) dist/$(BINARY)-$(VERSION)
	@shasum -a 256 dist/$(BINARY)-$(VERSION) > dist/$(BINARY)-$(VERSION).sha256
	@{ \
		printf '{"name":"paperboat-cli","version":"%s","protocol_version":"%s","commit":"%s","go_version":"%s"}\n' \
		"$(VERSION)" "$(PROTOCOL_VERSION)" \
		"$(shell git rev-parse HEAD 2>/dev/null || echo unknown)" "$(shell go version | awk '{print $$3}')"; \
	} > dist/$(BINARY)-$(VERSION).provenance.json

install: build
	install -d $(BINDIR)
	install -m 0755 bin/$(BINARY) $(BINDIR)/$(BINARY)

uninstall:
	rm -f $(BINDIR)/$(BINARY)

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	$(GOFMT) -w $(GO_FILES)

fmt-check:
	@test -z "$$($(GOFMT) -l $(GO_FILES))" || { $(GOFMT) -l $(GO_FILES); echo "Go files are not formatted" >&2; exit 1; }

generate:
	$(GO) generate ./...

lint: fmt-check vet

tidy:
	$(GO) mod tidy

check: verify-toolchain contracts fmt-check vet test build

complete: check race cross-build

clean:
	rm -rf bin dist coverage.out
