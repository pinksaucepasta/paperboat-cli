BINARY      := pb
ALIAS       := paperboat
PKG         := ./cmd/pb
PREFIX      ?= /usr/local
BINDIR      := $(PREFIX)/bin
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -X github.com/pujan-modha/paperboat-cli/internal/buildinfo.Version=$(VERSION)

.PHONY: build install uninstall test vet fmt lint tidy clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

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
