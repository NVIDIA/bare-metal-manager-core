FROM rust:latest

COPY pgdg.gpg /etc/apt/trusted.gpg.d/apt.postgresql.org.gpg
COPY pgdg.list /etc/apt/sources.list.d/pgdg.list
COPY isc-kea-2-0.gpg /etc/apt/trusted.gpg.d/apt.isc-kea-2.0.gpg
COPY isc-kea-2-0.list /etc/apt/sources.list.d/isc-kea-2.0.list

RUN apt update && apt-get install -y postgresql-14 build-essential isc-kea-dhcp4-server isc-kea-dhcp6-server isc-kea-dev libboost-dev && rm -rf /var/lib/apt/lists/*
