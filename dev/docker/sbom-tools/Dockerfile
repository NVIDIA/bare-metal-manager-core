ARG RUST_VERSION=1.90
ARG CC_VERSION=v3.2.1 # NVIDIA DistrolessContainer version
ARG TAG=${CC_VERSION}
ARG IMG=nvcr.io/nvidia/distroless/cc
ARG DEBUG_DISTROLESS=true
ARG DISTROLESS_DEBUG_TAG=${DEBUG_DISTROLESS:+"dev"} # 'dev' provides a busybox shell

FROM rust:1.90.0-slim-bookworm AS builder

WORKDIR /build

# Copy workspace files
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/sbom ./crates/sbom

# Build release binary
RUN cargo build --release --bin sbom

# NVIDIA Distroless Container
FROM ${IMG}:${TAG}-${DISTROLESS_DEBUG_TAG}

COPY --from=builder /build/target/release/sbom /app/sbom

