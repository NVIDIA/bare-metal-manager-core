# Multi-stage build for custom OpenTelemetry Collector targeting arm64 DPUs.
#
# Stage 1: Build the custom otelcol-contrib binary with fileresourceprocessor
# and telemetrystatsprocessor using the OpenTelemetry Collector Builder (ocb).
# Runs on the host platform and cross-compiles to arm64 via GOOS/GOARCH.
#
# Stage 2: Assemble the runtime image with the binary, wrapper scripts, and
# default configuration.
#
# NOTE: This image uses debian:12-slim instead of NVIDIA distroless because the
# otelcol-wrapper entrypoint is a bash script that requires a full shell.

ARG GO_VERSION=1.22.0
ARG OTELCOL_VERSION=0.101.0

# ---------------------------------------------------------------------------
# Builder (host-native Go, cross-compiles to arm64)
# ---------------------------------------------------------------------------
FROM golang:${GO_VERSION} AS builder

ARG OTELCOL_VERSION

WORKDIR /build

# Install ocb
RUN CGO_ENABLED=0 go install \
    go.opentelemetry.io/collector/cmd/builder@v${OTELCOL_VERSION} \
    && mv "$(go env GOPATH)/bin/builder" /usr/local/bin/ocb

# Copy custom processors, receiver, and builder config template
COPY bluefield/otel/fileresourceprocessor /build/fileresourceprocessor
COPY bluefield/otel/telemetrystatsprocessor /build/telemetrystatsprocessor
COPY bluefield/otel/puntstatsreceiver /build/puntstatsreceiver
COPY bluefield/otel/otelcol_builder_config_yaml.txt /build/
COPY bluefield/otel/get_module_version.sh /build/

# Generate the builder config with resolved versions
RUN FILERESOURCE_VERSION=$(bash /build/get_module_version.sh /build/fileresourceprocessor) && \
    TELEMETRYSTATS_VERSION=$(bash /build/get_module_version.sh /build/telemetrystatsprocessor) && \
    PUNTSTATS_VERSION=$(bash /build/get_module_version.sh /build/puntstatsreceiver) && \
    sed -e "s/\${VERSION}/${OTELCOL_VERSION}/g" \
        -e "s/\${FILERESOURCE_VERSION}/${FILERESOURCE_VERSION}/g" \
        -e "s/\${TELEMETRYSTATS_VERSION}/${TELEMETRYSTATS_VERSION}/g" \
        -e "s/\${PUNTSTATS_VERSION}/${PUNTSTATS_VERSION}/g" \
        otelcol_builder_config_yaml.txt > ocb_config.yaml

# Cross-compile the collector binary for arm64
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 ocb --config ocb_config.yaml

# ---------------------------------------------------------------------------
# Runtime (arm64)
# ---------------------------------------------------------------------------
FROM --platform=linux/arm64 debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Collector binary
COPY --from=builder /build/ocb-build/otelcol-contrib /usr/bin/otelcol-contrib

# Wrapper scripts
COPY bluefield/otel/otelcol-wrapper /etc/otelcol-contrib/otelcol-wrapper
COPY bluefield/otel/otelcol-wrapper-imports /etc/otelcol-contrib/otelcol-wrapper-imports
COPY bluefield/otel/otelcol-wrapper-validate /etc/otelcol-contrib/otelcol-wrapper-validate
RUN chmod +x /etc/otelcol-contrib/otelcol-wrapper \
             /etc/otelcol-contrib/otelcol-wrapper-imports \
             /etc/otelcol-contrib/otelcol-wrapper-validate

# Config fragments directory
RUN mkdir -p /etc/otelcol-contrib/config-fragments \
             /var/lib/otelcol-contrib/cursors \
             /run/otelcol-contrib

# Default config is mounted via ConfigMap at runtime
ENTRYPOINT ["/etc/otelcol-contrib/otelcol-wrapper"]
