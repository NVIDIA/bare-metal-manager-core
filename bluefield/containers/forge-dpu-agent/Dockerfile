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
     bash \
     curl
COPY mft-4.35.0-159-aarch64-deb /tmp/mft
RUN dpkg -i /tmp/mft/DEBS/mft_4.35.0-159_arm64.deb && rm -rf /tmp/mft

# Setup directory to collect all shared libraries
RUN mkdir -p /deps && \
    cp $(ldd /bin/bash | grep "=> /" | awk '{print $3}') /deps/

# Stage 2
FROM --platform=linux/arm64 ${IMG}:${TAG}-${DISTROLESS_DEBUG_TAG}

# Copy bash binary, libraries, mft, and curl from builder
COPY --from=builder /lib/aarch64-linux-gnu/libudev.so.1 /lib/aarch64-linux-gnu/libudev.so.1
COPY --from=builder --chmod=755 /bin/bash /bin/bash
COPY --from=builder --chmod=755 /usr/bin/flint /usr/bin/flint
COPY --from=builder /deps/* /lib/
COPY --from=builder --chmod=755 /usr/bin/curl /usr/bin/curl
COPY --from=builder /usr/lib/aarch64-linux-gnu/libcurl.so.4 /lib/aarch64-linux-gnu/libcurl.so.4

# Copy forge-dpu-agent and set entry point
COPY --chmod=755 target/aarch64-unknown-linux-gnu/release/forge-dpu-agent /usr/bin/forge-dpu-agent

ENTRYPOINT ["/usr/bin/forge-dpu-agent"]
