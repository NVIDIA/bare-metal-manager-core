# Runtime image for carbide-fmds on arm64 DPUs.
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
FROM --platform=linux/arm64 ${IMG}:${TAG}-${DISTROLESS_DEBUG_TAG}

COPY --chmod=755 target/aarch64-unknown-linux-gnu/release/carbide-fmds /usr/bin/carbide-fmds

ENTRYPOINT ["/usr/bin/carbide-fmds"]
