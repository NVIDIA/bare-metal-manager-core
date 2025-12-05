ARG CC_VERSION=v3.2.1 # NVIDIA DistrolessContainer version
ARG TAG=${CC_VERSION}
ARG IMG=nvcr.io/nvidia/distroless/cc
ARG DEBUG_DISTROLESS=true
ARG DISTROLESS_DEBUG_TAG=${DEBUG_DISTROLESS:+"dev"} # 'dev' provides a busybox shell
ARG SYFT_VERSION=v1.38.0

# Import sbom-tools
FROM nvcr.io/nvidian/nvforge/sbom-tools:latest AS sbom-tools

# Import syft
FROM anchore/syft:v1.38.0 AS syft

FROM debian:12-slim AS builder

ARG PDNS_TAG=4.9.11
ENV DEBIAN_FRONTEND=noninteractive
ENV OPENSSL_CONF=/etc/ssl/openssl-fips.cnf 

RUN apt-get update && \
  apt-get install -y --no-install-recommends \
  build-essential \
  ca-certificates \
  curl \
  git \
  gnupg \
  file \
  pkg-config \
  libtool \
  autoconf \
  automake \
  libboost-all-dev \
  flex \
  bison \
  libcurl4-openssl-dev \
  libyaml-cpp-dev \
  ragel \
  gawk \
  libluajit-5.1-dev \
  lua-yaml-dev \
  libtolua-dev \
  libssl-dev \
  python3-venv \
  wget \
  jq \
  && rm -rf /var/lib/apt/lists/*

# Install sbom and syft tools for SBOM generation
COPY --from=sbom-tools /app/sbom /usr/local/bin/sbom
COPY --from=syft /syft /usr/local/bin/syft

WORKDIR /build
COPY dev/docker/powerdns/deps.json deps.json
RUN sbom --log-dir /var/log/sbom install-packages -f /build/deps.json 

# --------------------------
# Build PowerDNS with FIPS-enabled OpenSSL (DNS-over-TLS capable)
# --------------------------
# Import PowerDNS GPG signing keys
# Key IDs: 0xFD380FBB (releases), 0xCBC8B383 (master)
RUN gpg --batch --keyserver keyserver.ubuntu.com --recv-keys \
  0x9FAAA5577E8FCF62093D036C1B0C6205FD380FBB \
  0x16E12866B7738C73976A57436FFC33439B0D04DF || \
  gpg --batch --keyserver keys.openpgp.org --recv-keys \
  0x9FAAA5577E8FCF62093D036C1B0C6205FD380FBB \
  0x16E12866B7738C73976A57436FFC33439B0D04DF

# Download PowerDNS Authoritative Server source and signature
RUN curl -sSLf "https://downloads.powerdns.com/releases/pdns-${PDNS_TAG}.tar.bz2" \
  -o "pdns-${PDNS_TAG}.tar.bz2" && \
  curl -sSLf "https://downloads.powerdns.com/releases/pdns-${PDNS_TAG}.tar.bz2.asc" \
  -o "pdns-${PDNS_TAG}.tar.bz2.asc"

# Verify GPG signature
RUN gpg --batch --verify "pdns-${PDNS_TAG}.tar.bz2.asc" "pdns-${PDNS_TAG}.tar.bz2" && \
  tar xf "pdns-${PDNS_TAG}.tar.bz2"

# Build PowerDNS with distroless FIPS OpenSSL (dynamically linked)
WORKDIR /build/pdns-${PDNS_TAG}

ENV CXXFLAGS="-O2 -pipe"

RUN autoreconf -vi
RUN ./configure \
  --with-modules="remote" \
  --bindir=/app \
  --sbindir=/app \
  --sysconfdir=/etc/powerdns \
  --localstatedir=/var \
  --enable-dns-over-tls \
  --disable-lua-records \
  --disable-systemd \
  --enable-static-boost=yes \
  --enable-verbose-logging=yes \
  --disable-dependency-tracking && \
  make -j"$(nproc)" && \
  make install

# Create package metadata for SBOM tools (Syft will detect this)
RUN mkdir -p /var/lib/dpkg/status.d && \
  INSTALL_SIZE=$(du -sk /app | cut -f1) && \
  BUILD_DATE=$(date -u +"%Y-%m-%d %H:%M:%S UTC") && \
  cat > /var/lib/dpkg/status.d/powerdns <<-EOF
	Package: powerdns
	Source: pdns
	Version: ${PDNS_TAG}
	Architecture: amd64
	Status: install ok installed
	Priority: optional
	Section: net
	Installed-Size: ${INSTALL_SIZE}
	Maintainer: PowerDNS.COM BV <powerdns.support@powerdns.com>
	Homepage: https://www.powerdns.com/
	Description: PowerDNS Authoritative Server (source build)
	 Authoritative DNS server with DNSSEC and DNS-over-TLS support.
	 .
	 Built from source: https://downloads.powerdns.com/releases/pdns-${PDNS_TAG}.tar.bz2
	 Build date: ${BUILD_DATE}
	 Configure flags: --with-modules=remote --enable-dns-over-tls --disable-lua-records --enable-static-boost=yes
	 License: GPL-2.0-only
	EOF

# Generate MD5 checksums for all PowerDNS files (relative paths, no leading slash)
RUN cd / && \
  find app -type f -exec md5sum {} \; 2>/dev/null | sort -k2 > /var/lib/dpkg/status.d/powerdns.md5sums

# --------------------------
# Install runtime dependencies and prepare distroless structure
# --------------------------
# Download source packages for compliance (excludes base container packages)
RUN sbom --log-dir /var/log/sbom download-sources -f /build/deps.json -o /distroless/src

# Copy package files to distroless structure (excludes base container packages)
RUN sbom --log-dir /var/log/sbom copy-files -f /build/deps.json  -d /distroless

# --------------------------
# Prepare rootfs for final image
# --------------------------
# Create directory structure for PowerDNS and compliance files
RUN mkdir -p /rootfs/etc/powerdns \
  /rootfs/var/run \
  /rootfs/var/log \
  /rootfs/var/lib/powerdns \
  /rootfs/app/packages \
  /rootfs/usr/share/doc/pdns-${PDNS_TAG} \
  /rootfs/bin \
  /rootfs/var/lib/dpkg/status.d 


# GPL v2 Compliance - copy source tarball and README
RUN cp /build/pdns-${PDNS_TAG}.tar.bz2 /rootfs/app/packages/

RUN cat > /rootfs/app/README.txt <<EOF
Container Licensing Information
================================

This container image is a collection of components with different licenses:

1. Container Base Image & Assembly
   License: NVIDIA Proprietary
   Vendor: NVIDIA Corporation
   Note: Source code not provided (proprietary)

2. PowerDNS Authoritative Server
   License: GPL v2
   Version: ${PDNS_TAG}
   Source: /app/packages/pdns-${PDNS_TAG}.tar.bz2
   License File: /usr/share/licenses/PowerDNS-LICENSE
   Homepage: https://www.powerdns.com/

3. Third-Party Dependencies
   Licenses: Various open-source licenses
   Complete Attribution: /app/ATTRIBUTION.txt
   Package Documentation: /usr/share/doc/<package>/
   Source Code: /app/packages/ (includes PowerDNS and all dependencies)
   
GPL v2 Source Code Compliance
==============================

All source code (PowerDNS and dependencies) is in: /app/packages/

To access PowerDNS source code:
1. Extract from container:
   docker cp <container-id>:/app/packages/pdns-${PDNS_TAG}.tar.bz2 .

2. Unpack and build:
   tar xjf pdns-${PDNS_TAG}.tar.bz2
   cd pdns-${PDNS_TAG}
   
   See the INSTALL file for complete build instructions.

Configure options used in this container:
   ./configure \\
     --with-modules="remote" \\
     --prefix=/app \\
     --bindir=/app \\
     --sbindir=/app \\
     --sysconfdir=/app/etc/powerdns \\
     --localstatedir=/app/var \\
     --enable-dns-over-tls \\
     --disable-lua-records \\
     --disable-systemd \\
     --enable-static-boost=yes \\
     --enable-tools=yes \\
     --enable-verbose-logging=yes \\
     --disable-dependency-tracking

Legal Attribution & Compliance
===============================
All legal information is consolidated in ONE file:

  /app/ATTRIBUTION.txt

This file contains complete attribution information:
  - Full license texts for all third-party packages
  - Deduplicated licenses (no redundancy)
  - Package copyright information

Additional references:
  - PowerDNS GPL v2 license: /usr/share/licenses/PowerDNS-LICENSE
  - Package documentation: /usr/share/doc/<package>/
  - Copyright files: /usr/share/doc/<package>/copyright

Software Bill of Materials (SBOM)
==================================
A machine-readable inventory of all components is available:

  /sbom/sbom-runtime.json (SPDX JSON format)

  To extract SBOM from container:
  docker cp <container-id>:/sbom/sbom-runtime.json .

Important Notes
===============
- All source code consolidated in /app/packages/
  - PowerDNS: /app/packages/pdns-${PDNS_TAG}.tar.bz2
  - Third-party dependencies: /app/packages/*.dsc, *.tar.gz, etc.
- Container base image is NVIDIA proprietary (source not provided)
- Each component retains its own license
- GPL obligations apply only to GPL-licensed components
- SBOM available in SPDX JSON format at /sbom/sbom-runtime.json
EOF


# Copy PowerDNS license file (GPL v2)
RUN cp /build/pdns-${PDNS_TAG}/COPYING /rootfs/usr/share/doc/pdns-${PDNS_TAG}/PowerDNS-LICENSE

# --------------------------
# Generate SBOM (Software Bill of Materials)
# --------------------------
# Copy Syft configuration
COPY dev/docker/common/syft.yaml /build/.syft.yaml

# Create staging directory that mirrors final runtime filesystem
RUN sbom --log-dir /var/log/sbom stage \
  --rootfs /rootfs \
  --app-dir /app \
  --distroless-dir /distroless \
  --include /build/pdns-${PDNS_TAG}.tar.bz2:app/packages/pdns-${PDNS_TAG}.tar.bz2 \
  --include /var/lib/dpkg/status.d/powerdns:var/lib/dpkg/status.d/powerdns \
  --include /var/lib/dpkg/status.d/powerdns.md5sums:var/lib/dpkg/status.d/powerdns.md5sums \
  --include /var/log/sbom/sbom.log:app/install.log \
  --syft-config /build/.syft.yaml \
  -o /sbom-staging

# Generate SBOM in SPDX JSON format
RUN mkdir -p /sbom-staging/sbom && \
  syft scan dir:/sbom-staging \
  --output spdx-json=/sbom-staging/sbom/sbom-runtime.json \
  --config /sbom-staging/.syft.yaml \
  --quiet && \
  rm /sbom-staging/.syft.yaml

# Generate ATTRIBUTION file from SBOM
RUN sbom --log-dir /var/log/sbom attribution /sbom-staging/sbom/sbom-runtime.json \
  -o /sbom-staging/app/ATTRIBUTION.txt

# --------------------------
# Final Runtime Image
# --------------------------
FROM ${IMG}:${TAG}-${DISTROLESS_DEBUG_TAG}

WORKDIR /app

# This single COPY ensures the final image matches EXACTLY what was scanned for the SBOM,
# eliminating the risk of inconsistencies between SBOM generation and final image assembly.
COPY --from=builder /sbom-staging /

# Environment variables for PowerDNS
# Note: OpenSSL FIPS provided by distroless at standard Debian paths
ENV PATH=/app:$PATH
ENV LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu
ENV OPENSSL_CONF=/etc/ssl/openssl-fips.cnf

# Labels for compliance and documentation
ARG PDNS_TAG
ARG IMG
ARG TAG
ARG DISTROLESS_DEBUG_TAG
ARG SYFT_VERSION=v1.18.1
LABEL org.opencontainers.image.title="PowerDNS Authoritative Server"
LABEL org.opencontainers.image.description="PowerDNS Authoritative Server"
LABEL org.opencontainers.image.version="${PDNS_TAG}"
LABEL org.opencontainers.image.base.name="${IMG}:${TAG}-${DISTROLESS_DEBUG_TAG}"
LABEL org.opencontainers.image.vendor="NVIDIA Corporation"
LABEL org.opencontainers.image.licenses="Mixed: NVIDIA-Proprietary (base image) AND GPL-2.0 (PowerDNS)"
LABEL org.opencontainers.image.documentation="See /app/README.txt for license details"

# Expose DNS ports
EXPOSE 53/udp 53/tcp

# Expose DNS-over-TLS port
EXPOSE 853/tcp

# Expose PowerDNS webserver port
EXPOSE 8081/tcp

# For PowerDNS with DNS-over-TLS (FIPS-enabled):
#   Default entrypoint runs pdns_server
#   For shell access (dev mode only): docker run --entrypoint /busybox/busybox <image> sh
#
ENTRYPOINT ["/app/pdns_server", "--config-dir=/app/etc/powerdns", "--daemon=no"]
#ENTRYPOINT ["/busybox/busybox", "sh"]
