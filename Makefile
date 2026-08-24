BINARY      := pb
PKG         := ./cmd/pb
PREFIX      ?= /usr/local
BINDIR      := $(PREFIX)/bin
VERSION     ?= $(shell ./tools/release-version.sh current)
COMMIT      ?= $(shell git rev-parse --verify HEAD 2>/dev/null || echo unknown)
PROTOCOL_VERSION ?= 1
DEFAULT_RELEASE_URL ?=
GO_VERSION  := 1.26.6
SQLC_VERSION := v1.30.0
GO_ROOT     := $(shell GOTOOLCHAIN=go$(GO_VERSION) go env GOROOT)
export PATH := $(GO_ROOT)/bin:$(PATH)
GO          := GOTOOLCHAIN=local go
GOFMT       := $(GO_ROOT)/bin/gofmt
GO_FILES    := $(shell find . -path ./.git -prune -o -name '*.go' -print)
LDFLAGS     := -X github.com/pinksaucepasta/paperboat/internal/buildinfo.Version=$(VERSION) -X github.com/pinksaucepasta/paperboat/internal/buildinfo.Commit=$(COMMIT) -X github.com/pinksaucepasta/paperboat/internal/buildinfo.ProtocolVersion=$(PROTOCOL_VERSION) -X github.com/pinksaucepasta/paperboat/internal/buildinfo.DefaultReleaseURL=$(DEFAULT_RELEASE_URL)

.PHONY: binary-size-check build check clean codex-manifest-check codex-manifest-generate complete container-compose-check contracts cross-build dependencies fmt fmt-check fuzz generate generate-check hosted-image-check install license-check lint metrics-check metrics-generate preflight race release-metadata reproducible-builds source-policy static-analysis test tidy tidy-check uninstall verification verify-toolchain vet vulnerability-check

contracts:
	@./testdata/contracts/validate.sh
	@./tools/test-release-version.sh

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
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64 $(PKG)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 $(PKG)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 $(PKG)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe $(PKG)
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-arm64.exe $(PKG)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-launcher-windows-amd64.exe ./cmd/pb-launcher
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-launcher-windows-arm64.exe ./cmd/pb-launcher

# Produce reviewable integrity metadata alongside a release binary. Signing,
# SBOM generation, and publishing are performed by the release pipeline.
release-metadata: build
	@mkdir -p dist
	@cp bin/$(BINARY) dist/$(BINARY)-$(VERSION)
	@shasum -a 256 dist/$(BINARY)-$(VERSION) > dist/$(BINARY)-$(VERSION).sha256
	@{ \
		printf '{"name":"paperboat","version":"%s","protocol_version":"%s","commit":"%s","go_version":"%s"}\n' \
		"$(VERSION)" "$(PROTOCOL_VERSION)" \
		"$(COMMIT)" "$(shell go version | awk '{print $$3}')"; \
	} > dist/$(BINARY)-$(VERSION).provenance.json

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

codex-manifest-generate:
	@test -n "$(CODEX_SOURCE)" || { echo 'CODEX_SOURCE must point to the pinned official openai/codex checkout' >&2; exit 1; }
	$(GO) run ./tools/codex-path-manifest -source "$(CODEX_SOURCE)" -output internal/codexsession/codex_path_manifest_0_149_1.json

codex-manifest-check:
	@test -n "$(CODEX_SOURCE)" || { echo 'CODEX_SOURCE must point to the pinned official openai/codex checkout' >&2; exit 1; }
	@temporary="$$(mktemp "$${TMPDIR:-/tmp}/paperboat-codex-manifest.XXXXXX")"; \
		trap 'rm -f "$$temporary"' EXIT; \
		$(GO) run ./tools/codex-path-manifest -source "$(CODEX_SOURCE)" -output "$$temporary"; \
		cmp -s "$$temporary" internal/codexsession/codex_path_manifest_0_149_1.json || { \
			echo 'Codex path manifest is stale; run make codex-manifest-generate CODEX_SOURCE=/path/to/openai/codex' >&2; \
			diff -u internal/codexsession/codex_path_manifest_0_149_1.json "$$temporary"; \
			exit 1; \
		}

generate-check:
	@before="$$(git diff -- internal/hostruntime/store/storesqlc)"; \
		$(MAKE) generate >/dev/null || exit $$?; \
		test "$$(git diff -- internal/hostruntime/store/storesqlc)" = "$$before" || { echo "generated sqlc output is stale; run make generate" >&2; git diff -- internal/hostruntime/store/storesqlc; exit 1; }
	@$(GO) test ./internal/codexsession -run '^TestCodexPathManifestHasPinnedCompleteCoverage$$' -count=1

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
	@$(MAKE) codex-manifest-check
	@$(MAKE) race
	@$(MAKE) cross-build
	@./packaging/windows/scripts/validate-release-pipeline.sh
	@command -v actionlint >/dev/null 2>&1 || { echo 'actionlint is required for preflight; install it before running make preflight' >&2; exit 1; }
	@actionlint .github/workflows/*.yml

clean:
	rm -rf bin dist coverage.out
