# Runtime image for forge-dpu-agent on arm64 DPUs.
#
# The binary is cross-compiled externally using the
# build-artifacts-container-cross-aarch64 image and copied into this
# minimal runtime container.

ARG CC_VERSION=v3.2.1 # NVIDIA Distroless Container version
ARG TAG=${CC_VERSION}
ARG IMG=nvcr.io/nvidia/distroless/cc
ARG DEBUG_DISTROLESS=true
ARG DISTROLESS_DEBUG_TAG=${DEBUG_DISTROLESS:+"dev"} # 'dev' provides a busybox shell

# NVIDIA Distroless Container

# Stage 1

# Get libudev1 for arm64
FROM --platform=linux/arm64 debian:bookworm-slim AS builder
RUN apt-get update && apt-get install -y libudev1

# Stage 2
FROM --platform=linux/arm64 ${IMG}:${TAG}-${DISTROLESS_DEBUG_TAG}

# Copy the library from builder and forge-dpu-agent
COPY --from=builder /lib/aarch64-linux-gnu/libudev.so.1 /lib/aarch64-linux-gnu/libudev.so.1
COPY target/aarch64-unknown-linux-gnu/release/forge-dpu-agent /usr/bin/forge-dpu-agent

ENTRYPOINT ["/usr/bin/forge-dpu-agent"]
