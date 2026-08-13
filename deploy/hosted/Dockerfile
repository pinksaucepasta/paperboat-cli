ARG PAPERBOAT_VERSION

FROM golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS build
ARG PAPERBOAT_VERSION

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN printf '%s\n' "${PAPERBOAT_VERSION}" | grep -Eq '^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.(0|[1-9][0-9]*)$' \
  && CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/pinksaucepasta/paperboat/internal/buildinfo.Version=${PAPERBOAT_VERSION} -X github.com/pinksaucepasta/paperboat/internal/buildinfo.ProtocolVersion=1" \
    -o /out/pb ./cmd/pb

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
ARG PAPERBOAT_VERSION

LABEL org.opencontainers.image.version="${PAPERBOAT_VERSION}"

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates git openssh-server tini \
  && rm -rf /var/lib/apt/lists/* \
  && rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub

COPY --from=build /out/pb /usr/local/bin/pb
COPY deploy/hosted/entrypoint.sh /usr/local/libexec/paperboat-hosted-entrypoint

RUN chmod 0755 /usr/local/bin/pb /usr/local/libexec/paperboat-hosted-entrypoint

WORKDIR /workspace
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/libexec/paperboat-hosted-entrypoint"]
CMD ["/usr/local/bin/pb", "__runtime-host"]
