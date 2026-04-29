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

FROM --platform=linux/arm64 debian:bookworm-slim AS builder

# Get libraries and install MFT (provides flint for DPU firmware enumeration)
RUN apt-get update && apt-get install -y \
     libudev1 \
     bash

# Working flint extraction
COPY mft-4.35.0-159-aarch64-deb/DEBS/mft_4.35.0-159_arm64.deb /tmp/mstflint.deb
RUN mkdir -p /extract && dpkg-deb -x /tmp/mstflint.deb /extract
RUN mkdir -p /deps && \
    # Locate the binary (usually in /usr/bin/ inside the extraction folder)
    BINARY_PATH=$(find /extract -name flint -o -name mstflint | head -n 1) && \
    # Use ldd to find dependencies, but point it to the libraries in the extraction folder if needed
    ldd $BINARY_PATH | grep "=> /" | awk '{print $3}' | xargs -I '{}' cp -v '{}' /deps/

# Setup directory to collect all shared libraries
RUN mkdir -p /deps && \
    cp $(ldd /bin/bash | grep "=> /" | awk '{print $3}') /deps/

# Stage 2
FROM --platform=linux/arm64 ${IMG}:${TAG}-${DISTROLESS_DEBUG_TAG}

# Copy bash binary, libraries, and mft from builder
COPY --from=builder /lib/aarch64-linux-gnu/libudev.so.1 /lib/aarch64-linux-gnu/libudev.so.1
COPY --from=builder --chmod=755 /bin/bash /bin/bash
COPY --from=builder --chmod=755 /extract/usr/bin/ /usr/bin/
COPY --from=builder /deps/* /lib/

# Copy forge-dpu-agent and set entry point
COPY --chmod=755 target/aarch64-unknown-linux-gnu/release/forge-dpu-agent /usr/bin/forge-dpu-agent

ENTRYPOINT ["/usr/bin/forge-dpu-agent"]
