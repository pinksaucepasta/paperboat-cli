BINARY      := pb
PKG         := ./cmd/pb
PREFIX      ?= /usr/local
BINDIR      := $(PREFIX)/bin
VERSION     ?= $(shell ./tools/release-version.sh current)
COMMIT      ?= $(shell git rev-parse --verify HEAD 2>/dev/null || echo unknown)
PROTOCOL_VERSION ?= 1
DEFAULT_SERVER_URL ?= https://api.pprbt.dev
# The configured control-plane origin also serves current.json and TUF.
DEFAULT_RELEASE_URL ?= $(DEFAULT_SERVER_URL)
GO_VERSION  := 1.26.6
SQLC_VERSION := v1.30.0
GO_ROOT     := $(shell GOTOOLCHAIN=go$(GO_VERSION) go env GOROOT)
export PATH := $(GO_ROOT)/bin:$(PATH)
GO          := GOTOOLCHAIN=local go
GOFMT       := $(GO_ROOT)/bin/gofmt
GO_FILES    := $(shell find . -path ./.git -prune -o -name '*.go' -print)
LDFLAGS     := -X github.com/pinksaucepasta/paperboat/internal/buildinfo.Version=$(VERSION) -X github.com/pinksaucepasta/paperboat/internal/buildinfo.Commit=$(COMMIT) -X github.com/pinksaucepasta/paperboat/internal/buildinfo.ProtocolVersion=$(PROTOCOL_VERSION) -X github.com/pinksaucepasta/paperboat/internal/buildinfo.DefaultServerURL=$(DEFAULT_SERVER_URL) -X github.com/pinksaucepasta/paperboat/internal/buildinfo.DefaultReleaseURL=$(DEFAULT_RELEASE_URL)

.PHONY: binary-size-check build check clean codex-path-manifest complete container-compose-check contracts cross-build dependencies fmt fmt-check fuzz generate generate-check hosted-image-check install license-check lint metrics-check metrics-generate preflight race release-assets release-binaries release-macos-pkg reproducible-builds source-policy static-analysis test tidy tidy-check uninstall verification verify-toolchain vet vulnerability-check

contracts:
	@./testdata/contracts/validate.sh

dependencies:
	@./tools/verify-peer-dependencies.sh

source-policy:
	@./tools/verify-source-policy.sh

metrics-generate:
	$(GO) run ./tools/metric-schema -write docs/metrics.json

metrics-check:
	$(GO) run ./tools/metric-schema docs/metrics.json

hosted-image-check:
	@./tools/verify-hosted-image.sh

container-compose-check:
	@./tools/verify-container-compose.sh

verify-toolchain:
	@test "$$(GOTOOLCHAIN=local go env GOVERSION)" = "go$(GO_VERSION)" || { echo "required Go $(GO_VERSION), found $$(GOTOOLCHAIN=local go env GOVERSION)" >&2; exit 1; }

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

cross-build: verify-toolchain
	@mkdir -p dist
	@rm -f dist/pb-darwin-arm64 dist/pb-linux-amd64 dist/pb-linux-arm64 dist/pb-windows-amd64.exe dist/pb-windows-arm64.exe
	VERSION="$(VERSION)" DEFAULT_SERVER_URL="$(DEFAULT_SERVER_URL)" DEFAULT_RELEASE_URL="$(DEFAULT_RELEASE_URL)" ./tools/build-release-asset.sh --platform darwin --architecture arm64 --output dist/pb-darwin-arm64 --version "$(VERSION)" --server-url "$(DEFAULT_SERVER_URL)" --release-url "$(DEFAULT_RELEASE_URL)"
	VERSION="$(VERSION)" DEFAULT_SERVER_URL="$(DEFAULT_SERVER_URL)" DEFAULT_RELEASE_URL="$(DEFAULT_RELEASE_URL)" ./tools/build-release-asset.sh --platform linux --architecture amd64 --output dist/pb-linux-amd64 --version "$(VERSION)" --server-url "$(DEFAULT_SERVER_URL)" --release-url "$(DEFAULT_RELEASE_URL)"
	VERSION="$(VERSION)" DEFAULT_SERVER_URL="$(DEFAULT_SERVER_URL)" DEFAULT_RELEASE_URL="$(DEFAULT_RELEASE_URL)" ./tools/build-release-asset.sh --platform linux --architecture arm64 --output dist/pb-linux-arm64 --version "$(VERSION)" --server-url "$(DEFAULT_SERVER_URL)" --release-url "$(DEFAULT_RELEASE_URL)"
	VERSION="$(VERSION)" DEFAULT_SERVER_URL="$(DEFAULT_SERVER_URL)" DEFAULT_RELEASE_URL="$(DEFAULT_RELEASE_URL)" ./tools/build-release-asset.sh --platform windows --architecture amd64 --output dist/pb-windows-amd64.exe --version "$(VERSION)" --server-url "$(DEFAULT_SERVER_URL)" --release-url "$(DEFAULT_RELEASE_URL)"
	VERSION="$(VERSION)" DEFAULT_SERVER_URL="$(DEFAULT_SERVER_URL)" DEFAULT_RELEASE_URL="$(DEFAULT_RELEASE_URL)" ./tools/build-release-asset.sh --platform windows --architecture arm64 --output dist/pb-windows-arm64.exe --version "$(VERSION)" --server-url "$(DEFAULT_SERVER_URL)" --release-url "$(DEFAULT_RELEASE_URL)"

release-binaries: verify-toolchain
	@mkdir -p dist
	@rm -f dist/pb-linux-amd64 dist/pb-linux-arm64 dist/pb-windows-amd64.exe dist/pb-windows-arm64.exe
	@./tools/build-release-asset.sh --platform linux --architecture amd64 --output dist/pb-linux-amd64 --version "$(VERSION)" --server-url "$(DEFAULT_SERVER_URL)" --release-url "$(DEFAULT_RELEASE_URL)"
	@./tools/build-release-asset.sh --platform linux --architecture arm64 --output dist/pb-linux-arm64 --version "$(VERSION)" --server-url "$(DEFAULT_SERVER_URL)" --release-url "$(DEFAULT_RELEASE_URL)"
	@./tools/build-release-asset.sh --platform windows --architecture amd64 --output dist/pb-windows-amd64.exe --version "$(VERSION)" --server-url "$(DEFAULT_SERVER_URL)" --release-url "$(DEFAULT_RELEASE_URL)"
	@./tools/build-release-asset.sh --platform windows --architecture arm64 --output dist/pb-windows-arm64.exe --version "$(VERSION)" --server-url "$(DEFAULT_SERVER_URL)" --release-url "$(DEFAULT_RELEASE_URL)"

release-macos-pkg: verify-toolchain
	@test "$$(uname -s)" = Darwin || { echo 'release-macos-pkg requires macOS' >&2; exit 1; }
	@test "$$(uname -m)" = arm64 || { echo 'release-macos-pkg requires an Apple Silicon runner' >&2; exit 1; }
	@mkdir -p dist
	@rm -f dist/pb-darwin-arm64.stage dist/pb-darwin-arm64.pkg
	@./tools/build-release-asset.sh --platform darwin --architecture arm64 --output dist/pb-darwin-arm64.stage --version "$(VERSION)" --server-url "$(DEFAULT_SERVER_URL)" --release-url "$(DEFAULT_RELEASE_URL)"
	@test -n "$(MACOS_INSTALLER_SIGNING_IDENTITY)" || { echo 'MACOS_INSTALLER_SIGNING_IDENTITY is required' >&2; exit 1; }
	@./tools/build-macos-pkg.sh --binary dist/pb-darwin-arm64.stage --output dist/pb-darwin-arm64.pkg --version "$(VERSION)" --signing-identity "$(MACOS_INSTALLER_SIGNING_IDENTITY)"
	@rm -f dist/pb-darwin-arm64.stage

release-assets: release-binaries release-macos-pkg

install: build
	install -d $(BINDIR)
	install -m 0755 bin/$(BINARY) $(BINDIR)/$(BINARY)

uninstall:
	rm -f $(BINDIR)/$(BINARY)

test:
	$(GO) test -count=1 -timeout 12m ./...

race:
	$(GO) test -race -count=1 -timeout 12m ./...

fuzz: verify-toolchain
	@./tools/run-fuzz-targets.sh

reproducible-builds: verify-toolchain
	@VERSION="$(VERSION)" COMMIT="$(COMMIT)" PROTOCOL_VERSION="$(PROTOCOL_VERSION)" ./tools/verify-reproducible-builds.sh

static-analysis: verify-toolchain source-policy
	@./tools/verify-static-analysis.sh

vulnerability-check: verify-toolchain
	@./tools/verify-vulnerabilities.sh

license-check: verify-toolchain
	@./tools/verify-licenses.sh

binary-size-check: verify-toolchain
	@LDFLAGS='$(LDFLAGS)' ./tools/verify-binary-sizes.sh

vet:
	$(GO) vet ./...

fmt:
	$(GOFMT) -w $(GO_FILES)

fmt-check:
	@test -z "$$($(GOFMT) -l $(GO_FILES))" || { $(GOFMT) -l $(GO_FILES); echo "Go files are not formatted" >&2; exit 1; }

generate:
	$(GO) run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION) generate
	$(GO) generate ./...

# This manifest is pinned to an official OpenAI Codex checkout and is not part
# of routine repository generation. Regenerate it only when intentionally
# updating the pinned Codex protocol version.
codex-path-manifest:
	@test -n "$(CODEX_SOURCE)" || { echo 'CODEX_SOURCE must point to the pinned official openai/codex checkout' >&2; exit 2; }
	$(GO) run ./tools/codex-path-manifest -source "$(CODEX_SOURCE)" -output internal/codexsession/codex_path_manifest_0_149_1.json

generate-check:
	@before="$$(git diff -- internal/hostruntime/store/storesqlc)"; $(MAKE) generate >/dev/null; test "$$(git diff -- internal/hostruntime/store/storesqlc)" = "$$before" || { echo "generated sqlc output is stale; run make generate" >&2; git diff -- internal/hostruntime/store/storesqlc; exit 1; }

lint: fmt-check vet

tidy:
	$(GO) mod tidy

tidy-check: verify-toolchain
	@./tools/verify-tidy.sh

check: verify-toolchain contracts dependencies source-policy metrics-check hosted-image-check fmt-check generate-check tidy-check vet test build

complete: check race cross-build

verification: complete fuzz reproducible-builds static-analysis vulnerability-check license-check binary-size-check

# Run the five local checks required before consuming hosted-runner time.
# Native platform execution, Victus E2E, release packaging, and publication
# remain separate workflow/integration gates.
preflight:
	@$(MAKE) check
	@$(MAKE) race
	@$(MAKE) cross-build
	@./packaging/windows/scripts/validate-release-pipeline.sh
	@command -v actionlint >/dev/null 2>&1 || { echo 'actionlint is required for preflight; install it before running make preflight' >&2; exit 1; }
	@actionlint .github/workflows/*.yml

clean:
	rm -rf bin dist coverage.out
