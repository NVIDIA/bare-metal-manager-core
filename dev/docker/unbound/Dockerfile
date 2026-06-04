# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Site-controlled build of the Unbound recursive DNS resolver used by NICo
# to serve the `.forge` zone to BMCs/DPUs on the OOB management network.
#
# Replaces the upstream `nvcr.io/nvidian/nvforge/unbound:<tag>` image so that
# the supply chain for this dependency is owned by the deploying site:
# unbound is rebuilt on a cadence YOU control (CVE response, quarterly,
# matching upstream NLnetLabs releases).
#
# The runtime image honours the same env-var contract the helm chart expects:
#   LOCAL_CONFIG_DIR     — directory mounted from the `unbound-local-config`
#                          ConfigMap; every `*.conf` file is included by
#                          unbound's `server:` section at startup.
#   BROKEN_DNSSEC        — when `1`, DNSSEC validation is disabled (the chart
#                          sets this so the synthetic `.forge` zone validates).
#   UNBOUND_CONTROL_DIR  — directory shared with the `unbound_exporter`
#                          sidecar; holds the auto-generated `unbound_control`
#                          TLS keypair.
#
# Build:
#   docker build -f dev/docker/unbound/Dockerfile \
#     --build-arg UNBOUND_VERSION=1.20.0 \
#     -t forge/unbound:1.20.0-$(git rev-parse --short HEAD) \
#     dev/docker/unbound
#
# Pin a specific upstream release by passing `UNBOUND_VERSION=<x.y.z>`. The
# upstream tarball is fetched over HTTPS from nlnetlabs.nl with its published
# SHA256 verified — bump both `UNBOUND_VERSION` and `UNBOUND_SHA256` together.

ARG UBUNTU_VERSION=24.04

# ---------------------------------------------------------------------------
# Stage 1 — build unbound from source
# ---------------------------------------------------------------------------
FROM ubuntu:${UBUNTU_VERSION} AS builder

ARG UNBOUND_VERSION=1.20.0
# sha256 published by NLnetLabs for unbound-1.20.0.tar.gz
# (https://nlnetlabs.nl/downloads/unbound/unbound-1.20.0.tar.gz.sha256)
ARG UNBOUND_SHA256=56b4ceed33639522000fd96775576ddf8782bb3617610715d7f1e777c5ec1dbf
# Optional: route apt + curl through a site proxy (lab: 172.16.0.50:3128).
ARG SQUID_PROXY

ENV DEBIAN_FRONTEND=noninteractive

RUN http_proxy=${SQUID_PROXY} https_proxy=${SQUID_PROXY} \
    apt-get update && \
    http_proxy=${SQUID_PROXY} https_proxy=${SQUID_PROXY} \
    apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      curl \
      libssl-dev \
      libexpat1-dev \
      libevent-dev \
      libhiredis-dev \
      libnghttp2-dev \
      libsystemd-dev \
      pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

RUN http_proxy=${SQUID_PROXY} https_proxy=${SQUID_PROXY} \
    curl -fsSL -o unbound.tar.gz \
      "https://nlnetlabs.nl/downloads/unbound/unbound-${UNBOUND_VERSION}.tar.gz" && \
    echo "${UNBOUND_SHA256}  unbound.tar.gz" | sha256sum -c - && \
    tar -xzf unbound.tar.gz && \
    cd "unbound-${UNBOUND_VERSION}" && \
    ./configure \
      --prefix=/opt/unbound \
      --sysconfdir=/etc \
      --with-pthreads \
      --with-libevent \
      --with-libhiredis \
      --with-libnghttp2 \
      --enable-event-api \
      --enable-tfo-client \
      --enable-tfo-server \
      --with-username= && \
    make -j"$(nproc)" && \
    make install

# Fetch the DNSSEC root trust anchor at build time so a sealed-network
# runtime image doesn't need to reach iana.org at startup.
RUN http_proxy=${SQUID_PROXY} https_proxy=${SQUID_PROXY} \
    /opt/unbound/sbin/unbound-anchor -a /opt/unbound/etc/unbound/root.key || true

# ---------------------------------------------------------------------------
# Stage 2 — minimal runtime
# ---------------------------------------------------------------------------
FROM ubuntu:${UBUNTU_VERSION}

ARG SQUID_PROXY
ARG UNBOUND_VERSION=1.20.0

# Embed provenance into the image so `docker inspect` / image scanners can
# attribute it back to the source.
LABEL org.opencontainers.image.title="forge-unbound" \
      org.opencontainers.image.description="NICo .forge zone resolver (site-built unbound)" \
      org.opencontainers.image.source="https://github.com/nurametal/ncx-infra-controller-core" \
      org.opencontainers.image.licenses="BSD-3-Clause" \
      org.opencontainers.image.base.name="ubuntu:24.04" \
      forge.unbound.upstream-version="${UNBOUND_VERSION}"

ENV DEBIAN_FRONTEND=noninteractive

RUN http_proxy=${SQUID_PROXY} https_proxy=${SQUID_PROXY} \
    apt-get update && \
    http_proxy=${SQUID_PROXY} https_proxy=${SQUID_PROXY} \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      libcap2-bin \
      libssl3 \
      libexpat1 \
      libevent-2.1-7t64 \
      libhiredis1.1.0 \
      libnghttp2-14 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r -g 1001 unbound \
    && useradd -r -u 1001 -g 1001 -d /opt/unbound -s /usr/sbin/nologin unbound

COPY --from=builder /opt/unbound /opt/unbound

# Chart-expected paths:
#   /etc/unbound/local.conf.d/  — ConfigMap mount (LOCAL_CONFIG_DIR)
#   /etc/unbound/keys/          — emptyDir shared with exporter (UNBOUND_CONTROL_DIR)
RUN mkdir -p /etc/unbound/local.conf.d /etc/unbound/keys \
    && chown -R unbound:unbound /opt/unbound /etc/unbound

COPY unbound.base.conf /etc/unbound/unbound.conf
COPY entrypoint.sh /opt/unbound/entrypoint.sh
RUN chmod +x /opt/unbound/entrypoint.sh \
    && chown unbound:unbound /opt/unbound/entrypoint.sh /etc/unbound/unbound.conf

# Bind port 53 without needing root in the container.  cap_net_bind_service
# lets the `unbound` user open privileged ports.
RUN setcap 'cap_net_bind_service=+ep' /opt/unbound/sbin/unbound

ENV PATH="/opt/unbound/sbin:${PATH}" \
    LOCAL_CONFIG_DIR=/etc/unbound/local.conf.d \
    UNBOUND_CONTROL_DIR=/etc/unbound/keys \
    BROKEN_DNSSEC=0

# Numeric USER lets Kubernetes evaluate `runAsNonRoot` without resolving
# /etc/passwd inside the container.  UID/GID 1001 matches the `unbound`
# user/group created above and must match the chart's
# podSecurityContext.fsGroup so the shared `control-keys` emptyDir is
# writable by unbound and readable by the unbound_exporter sidecar.
# (1000 is reserved for the default `ubuntu` user in ubuntu:24.04.)
USER 1001:1001
EXPOSE 53/udp 53/tcp

ENTRYPOINT ["/opt/unbound/entrypoint.sh"]
# `-dd` runs in the foreground AND logs to stderr (which kubelet captures).
# `-d` alone still daemonizes in unbound 1.20, causing the container PID 1
# to exit immediately and triggering CrashLoopBackOff.
CMD ["unbound", "-dd", "-c", "/etc/unbound/unbound.conf"]
