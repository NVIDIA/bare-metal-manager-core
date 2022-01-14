FROM rust:latest as builder

#COPY pgdg.gpg /etc/apt/trusted.gpg.d/apt.postgresql.org.gpg
#COPY pgdg.list /etc/apt/sources.list.d/pgdg.list
COPY dev/docker/isc-kea-2-0.gpg /etc/apt/trusted.gpg.d/apt.isc-kea-2.0.gpg
COPY dev/docker/isc-kea-2-0.list /etc/apt/sources.list.d/isc-kea-2.0.list
RUN apt update && apt-get install -y build-essential isc-kea-dev libboost-dev gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu && rm -rf /var/lib/apt/lists/*
ENV KEA_INCLUDE_PATH /usr/include/kea
ENV KEA_BIN_PATH /usr/bin
ENV KEA_LIB_PATH /usr/lib/kea
RUN rustup component add rustfmt
RUN cargo install cargo-make mdbook mdbook-mermaid
RUN USER=root cargo new --bin carbide
WORKDIR ./carbide
COPY . ./

RUN cargo build

FROM ubuntu:latest as carbide
RUN ln -snf /usr/share/zoneinfo/UTC /etc/localtime && echo UTC > /etc/timezone
RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates curl iproute2
COPY dev/deployment/carbide-api/pgdg.gpg /etc/apt/trusted.gpg.d/apt.postgresql.org.gpg
COPY dev/deployment/carbide-api/pgdg.list /etc/apt/sources.list.d/pgdg.list
COPY dev/deployment/carbide-dhcp/isc-kea-2-0.gpg /etc/apt/trusted.gpg.d/apt.isc-kea-2.0.gpg
COPY dev/deployment/carbide-dhcp/isc-kea-2-0.list /etc/apt/sources.list.d/isc-kea-2.0.list
COPY dev/deployment/carbide-dhcp/kea-dhcp4.conf /etc/kea/kea-dhcp4-carbide.conf
RUN apt-get update && apt-get install -y --no-install-recommends \
  postgresql-client-14 postgresql-client-14-dbgsym \
  ca-certificates curl iproute2 \
  isc-kea-dhcp4-server isc-kea-dhcp6-server \
  && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /opt/carbide/migrations && \
  mkdir -p /opt/carbide/pxe/templates && \
  mkdir -p /opt/carbide/static
COPY --from=builder ["/carbide/target/debug/carbide-api", "/carbide/target/debug/carbide","/opt/carbide/"]
COPY --from=builder /carbide/target/debug/libdhcp.so /usr/lib/x86_64-linux-gnu/kea/hooks
COPY api/migrations/ /opt/carbide/migrations/
COPY pxe/templates/*  /opt/carbide/pxe/templates/
COPY pxe/Rocket.toml /opt/carbide/
