BINARY      := pb
ALIAS       := paperboat
PKG         := ./cmd/pb
PREFIX      ?= /usr/local
BINDIR      := $(PREFIX)/bin
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PROTOCOL_VERSION ?= 1
LDFLAGS     := -X github.com/pujan-modha/paperboat-cli/internal/buildinfo.Version=$(VERSION) -X github.com/pujan-modha/paperboat-cli/internal/buildinfo.ProtocolVersion=$(PROTOCOL_VERSION)

.PHONY: build release-metadata install uninstall test vet fmt lint tidy clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

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

# Install the binary and a `paperboat` alias symlink. urfave/cli derives the
# program name from argv[0], so both names behave identically.
install: build
	install -d $(BINDIR)
	install -m 0755 bin/$(BINARY) $(BINDIR)/$(BINARY)
	ln -sf $(BINDIR)/$(BINARY) $(BINDIR)/$(ALIAS)

uninstall:
	rm -f $(BINDIR)/$(BINARY) $(BINDIR)/$(ALIAS)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

lint: vet
	gofmt -l .

tidy:
	go mod tidy

clean:
	rm -rf bin
