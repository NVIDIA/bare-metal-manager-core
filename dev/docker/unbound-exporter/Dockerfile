# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Site-controlled build of `unbound_exporter`, the Prometheus exporter
# sidecar that ships alongside unbound in the chart's Deployment.
#
# Replaces the upstream `nvcr.io/nvidian/nvforge/unbound_exporter:<tag>`
# image so the supply chain for this dependency is owned by the site.
#
# Build:
#   docker build -f dev/docker/unbound-exporter/Dockerfile \
#     --build-arg EXPORTER_REF=v0.4.6 \
#     -t forge/unbound_exporter:0.4.6-$(git rev-parse --short HEAD) \
#     dev/docker/unbound-exporter
#
# `EXPORTER_REF` is any git ref (tag or sha) of the upstream
# letsencrypt/unbound_exporter repository.

ARG GOLANG_VERSION=1.22

FROM golang:${GOLANG_VERSION}-bookworm AS builder

ARG EXPORTER_REF=v0.4.6
ARG SQUID_PROXY

ENV CGO_ENABLED=0 \
    GO111MODULE=on \
    GOFLAGS="-mod=mod"

RUN http_proxy=${SQUID_PROXY} https_proxy=${SQUID_PROXY} \
    apt-get update && \
    http_proxy=${SQUID_PROXY} https_proxy=${SQUID_PROXY} \
    apt-get install -y --no-install-recommends ca-certificates git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src

RUN http_proxy=${SQUID_PROXY} https_proxy=${SQUID_PROXY} \
    git clone --depth=1 --branch "${EXPORTER_REF}" \
      https://github.com/letsencrypt/unbound_exporter.git . && \
    http_proxy=${SQUID_PROXY} https_proxy=${SQUID_PROXY} \
    go build -trimpath -ldflags="-s -w" -o /out/unbound_exporter .

# ---------------------------------------------------------------------------
# Runtime — distroless static; the binary is fully static (CGO disabled).
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static:nonroot

ARG EXPORTER_REF=v0.4.6

LABEL org.opencontainers.image.title="forge-unbound-exporter" \
      org.opencontainers.image.description="Prometheus exporter for unbound — site-built" \
      org.opencontainers.image.source="https://github.com/letsencrypt/unbound_exporter" \
      org.opencontainers.image.licenses="Apache-2.0" \
      forge.unbound-exporter.upstream-ref="${EXPORTER_REF}"

COPY --from=builder /out/unbound_exporter /unbound_exporter

# Defaults match the chart's expectation: read TLS keys from
# /etc/unbound/keys (shared emptyDir with the unbound container) and
# expose metrics on :9167.
ENV KEYS_DIR=/etc/unbound/keys

EXPOSE 9167
# Must match the `unbound` UID/GID in dev/docker/unbound/Dockerfile so the
# shared `control-keys` emptyDir (populated by unbound on boot) is readable
# here.  The chart's podSecurityContext.fsGroup is also set to 1001 so the
# volume is group-owned correctly by the kubelet.
USER 1001:1001

ENTRYPOINT ["/unbound_exporter"]
CMD [ \
    "-unbound.host", "tcp://127.0.0.1:8953", \
    "-unbound.cert", "/etc/unbound/keys/unbound_control.pem", \
    "-unbound.key",  "/etc/unbound/keys/unbound_control.key", \
    "-unbound.ca",   "/etc/unbound/keys/unbound_server.pem", \
    "-web.listen-address", ":9167" \
]
