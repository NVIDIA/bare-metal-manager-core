FROM rust:latest

ENV HOME /app
ENV CARGO_HOME /app/.cargo
WORKDIR /app

COPY dev/deployment/pgdg.gpg /etc/apt/trusted.gpg.d/apt.postgresql.org.gpg
COPY dev/deployment/pgdg.list /etc/apt/sources.list.d/pgdg.list
COPY dev/docker/isc-kea-2-0.gpg /etc/apt/trusted.gpg.d/apt.isc-kea-2.0.gpg
COPY dev/docker/isc-kea-2-0.list /etc/apt/sources.list.d/isc-kea-2.0.list

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
  postgresql-client-14 \
  postgresql-client-14-dbgsym \
  && rm -rf /var/lib/apt/lists/*

RUN rustup component add rustfmt rust-src

RUN --mount=type=cache,target=/app/.cargo/registry/index \
    --mount=type=cache,target=/app/.cargo/registry/cache \
    --mount=type=cache,target=/app/.cargo/git/db \
    cargo install --force cargo-make cargo-watch sqlx-cli
