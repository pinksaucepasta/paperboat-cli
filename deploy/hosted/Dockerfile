ARG PAPERBOAT_VERSION

FROM golang:1.27.1-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b AS build
ARG PAPERBOAT_VERSION

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN printf '%s\n' "${PAPERBOAT_VERSION}" | grep -Eq '^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.(0|[1-9][0-9]*)$' \
  && CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/pinksaucepasta/paperboat/internal/buildinfo.Version=${PAPERBOAT_VERSION} -X github.com/pinksaucepasta/paperboat/internal/buildinfo.ProtocolVersion=1" \
    -o /out/paperboat ./cmd/pb \
  && cp /out/paperboat /out/paperboat-hostd \
  && cp /out/paperboat /out/paperboat-updated \
  && cp /out/paperboat /out/paperboat-runtime.bootstrap \
  && cp /out/paperboat /out/pb.bootstrap

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
ARG PAPERBOAT_VERSION

LABEL org.opencontainers.image.version="${PAPERBOAT_VERSION}"

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates git openssh-server tini util-linux \
  && rm -rf /var/lib/apt/lists/* \
  && rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub \
  && groupadd --gid 10001 paperboat \
  && useradd --uid 10001 --gid 10001 --create-home --shell /bin/bash paperboat \
  && install -d -m 0755 -o root -g root /usr/local/libexec/paperboat/components \
  && install -d -m 0755 -o root -g root /usr/local/libexec/paperboat/bootstrap

COPY --from=build /out/paperboat-hostd /usr/local/libexec/paperboat/components/paperboat-hostd
COPY --from=build /out/paperboat-updated /usr/local/libexec/paperboat/components/paperboat-updated
COPY --from=build /out/paperboat-runtime.bootstrap /usr/local/libexec/paperboat/bootstrap/paperboat-runtime
COPY --from=build /out/pb.bootstrap /usr/local/libexec/paperboat/bootstrap/pb
COPY deploy/hosted/entrypoint.sh /usr/local/libexec/paperboat-hosted-entrypoint
COPY deploy/hosted/pb-launcher.sh /usr/local/bin/pb

RUN chmod 0755 /usr/local/libexec/paperboat/components/paperboat-hostd \
    /usr/local/libexec/paperboat/components/paperboat-updated \
    /usr/local/libexec/paperboat/bootstrap/paperboat-runtime \
    /usr/local/libexec/paperboat/bootstrap/pb \
    /usr/local/bin/pb \
    /usr/local/libexec/paperboat-hosted-entrypoint

WORKDIR /workspace
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/libexec/paperboat-hosted-entrypoint"]
