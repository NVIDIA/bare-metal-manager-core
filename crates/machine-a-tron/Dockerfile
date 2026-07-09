# syntax=docker/dockerfile:1.7
#
# Cross-compilation: the BUILDER always runs NATIVE on the build host
# ($BUILDPLATFORM) and cross-compiles to x86_64-unknown-linux-gnu. This is not
# a Mac convenience: building the amd64 stage the naive way on an Apple
# Silicon host runs rustc under QEMU emulation, and QEMU SEGFAULTs assembling
# aws-lc-sys's hand-written x86-64 assembly (s2n-bignum) — even though the
# resulting binary runs fine on real x86_64. On an x86_64 build host the
# builder is simply native and the "cross" compile is a no-op.
#
# Build from the repo root:
#
#   docker buildx build \
#     --platform linux/amd64 \
#     -f crates/machine-a-tron/Dockerfile \
#     --build-arg VERSION=0.1.0 \
#     -t machine-a-tron:latest \
#     .
#
ARG RUST_VERSION=1.96.0

FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-slim-bookworm AS builder

ARG VERSION
ARG CI_COMMIT_SHORT_SHA
ENV VERSION=${VERSION}
ENV CI_COMMIT_SHORT_SHA=${CI_COMMIT_SHORT_SHA}

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    pkg-config \
    protobuf-compiler \
    libprotobuf-dev \
    && if [ "$(uname -m)" != "x86_64" ]; then \
         apt-get install -y --no-install-recommends \
           gcc-x86-64-linux-gnu libc6-dev-amd64-cross; \
       else \
         apt-get install -y --no-install-recommends gcc libc6-dev; \
       fi \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-gnu

ENV CARGO_HOME=/cargo-home
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
ENV CARGO_TARGET_DIR=/cargo-target
ENV RUST_BACKTRACE=1

WORKDIR /workspace
COPY . .

# Build release binary with cross-compilation
RUN --mount=type=cache,id=nico-mat-cross-cargo-home,target=/cargo-home,sharing=locked \
    --mount=type=cache,id=nico-mat-cross-cargo-target,target=/cargo-target,sharing=locked \
    if [ "$(uname -m)" != "x86_64" ]; then \
      export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
             CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc; \
    fi && \
    cargo build -p carbide-machine-a-tron --bin machine-a-tron --locked --release \
      --target x86_64-unknown-linux-gnu && \
    mkdir -p /artifacts && \
    cp /cargo-target/x86_64-unknown-linux-gnu/release/machine-a-tron /artifacts/machine-a-tron

# Runtime image
FROM --platform=linux/amd64 debian:bookworm-slim

ARG VERSION
ARG CI_COMMIT_SHORT_SHA
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${CI_COMMIT_SHORT_SHA}"
LABEL org.opencontainers.image.title="machine-a-tron"
LABEL org.opencontainers.image.description="NICo Hardware Simulation Tool"
LABEL org.opencontainers.image.vendor="NVIDIA"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    iproute2 \
    iputils-ping \
    libssl3 \
    libudev1 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/machine-a-tron/bin /opt/machine-a-tron/templates /tmp/machine-a-tron-data

COPY --from=builder /artifacts/machine-a-tron /opt/machine-a-tron/bin/machine-a-tron
COPY crates/machine-a-tron/templates /opt/machine-a-tron/templates

WORKDIR /opt/machine-a-tron
ENTRYPOINT ["/opt/machine-a-tron/bin/machine-a-tron"]
