# SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.
FROM rust:1.70.0

ENV HOME /app
ENV CARGO_HOME /app/.cargo
WORKDIR /app

COPY dev/deployment/pgdg.gpg /etc/apt/trusted.gpg.d/apt.postgresql.org.gpg
COPY dev/deployment/pgdg.list /etc/apt/sources.list.d/pgdg.list
COPY dev/docker/isc-kea-2-0.gpg /etc/apt/trusted.gpg.d/apt.isc-kea-2.0.gpg
COPY dev/docker/isc-kea-2-0.list /etc/apt/sources.list.d/isc-kea-2.0.list
COPY dev/docker/hashicorp.gpg /etc/apt/trusted.gpg.d/apt.hashicorp.gpg
COPY dev/docker/hashicorp.list /etc/apt/sources.list.d/hashicorp.list

RUN apt-get update && apt-get install -y --no-install-recommends \
  binutils-aarch64-linux-gnu \
  build-essential \
  ca-certificates \
  curl \
  gcc-aarch64-linux-gnu \
  iproute2 \
  isc-kea-dev \
  isc-kea-dhcp4-server \
  isc-kea-dhcp6-server \
  libboost-dev \
  libudev-dev \
  postgresql-client-14 \
  postgresql-client-14-dbgsym \
  vault \
  pkg-config \
  libfreeipmi-dev \
  libfreeipmi17 \
  libipmiconsole-dev \
  libipmiconsole2 \
  cmake \
  unzip \
  iputils-ping \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/protobuf && \
  rm -rf /tmp/protobuf && \
  mkdir -p /tmp/protobuf && \
  curl -L https://github.com/protocolbuffers/protobuf/releases/download/v21.5/protoc-21.5-linux-x86_64.zip -o /tmp/protobuf/protobuf.zip && \
  unzip -d /tmp/protobuf /tmp/protobuf/protobuf.zip && \
  mv /tmp/protobuf/bin/protoc /opt/protobuf/ && \
  mv /tmp/protobuf/include /opt/protobuf/ && \
  rm -rf /tmp/protobuf
ENV PATH "$PATH:/opt/protobuf"
ENV PROTOC "/opt/protobuf/protoc"
ENV PROTOC_INCLUDE "/opt/protobuf/include"
RUN rustup component add rustfmt rust-src

RUN --mount=type=cache,target=/app/.cargo/registry/index \
  --mount=type=cache,target=/app/.cargo/registry/cache \
  --mount=type=cache,target=/app/.cargo/git/db \
  cargo install --force cargo-make cargo-watch sqlx-cli sccache
