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
#RUN bash -c 'mkdir -p {api,dhcp,pxe,rpc,api}'
#api  book  Cargo.lock  Cargo.toml  dev  dhcp  Makefile.toml  pxe  README.md  rpc  target
#ARG GITROOT
#COPY ./Cargo.toml ./Cargo.toml
#COPY ./dhcp/Cargo.toml ./dhcp/Cargo.toml
#COPY ./rpc/ ./rpc
#COPY ./api/Cargo.toml ./api/Cargo.toml
#COPY ./pxe/Cargo.toml ./pxe/Cargo.toml
#RUN cargo build-deps
#RUN cargo build --release
COPY . ./
#RUN cargo build-deps
#RUN rm ./target/release/depds/carbide*

RUN cargo build --release
#ADD ../../target/release/carbide-api 

FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl ca-certificates iproute2
COPY dev/deployment/isc-kea-2-0.gpg /etc/apt/trusted.gpg.d/apt.isc-kea-2.0.gpg
COPY dev/deployment/isc-kea-2-0.list /etc/apt/sources.list.d/isc-kea-2.0.list
RUN apt-get update && apt-get install -y isc-kea-dhcp4-server isc-kea-dhcp6-server && rm -rf /var/lib/apt/lists/*
COPY --from=builder /carbide/target/release/carbide-api /carbide/target/release/carbide /usr/sbin/
COPY --from=builder /carbide/target/release/libdhcp.so /usr/lib/kea/hooks
#RUN apt-get update && apt-get install -y locales && rm -rf /var/lig/apt/lists/* \
#  && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
#ENV LAN en_US.utf8
#
#RUN apt-get install --no-install-recommends -y \
#  ca-certificates \
#  curl \
#  build-essential \ 
#  git \
#  autoconf automake autotools-dev libtool xutils-dev && \
#  rm -rf /var/lib/apt/lists/*
#
#RUN curl https://sh.rustup.rs -sSf | \
#  sh -s -- --default-toolchain stable -y
#
#ENV PATH=/root/.cargo/bin:$PATH
#
