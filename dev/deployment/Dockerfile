FROM urm.nvidia.com/swngc-ngcc-docker-local/forge/carbide/x86-64/build-container:v0.0.1-206-gf23904ca as builder

RUN USER=root cargo new --bin carbide
WORKDIR ./carbide
COPY . ./
RUN export CARGO_MAKE_SKIP_CODECOV="true" && \
    export DATABASE_URL="postgresql://%2Fvar%2Frun%2Fpostgresql" && \
    export SCCACHE_DIR=/sccache && \
    /etc/init.d/postgresql start && \
    sudo -u postgres psql -c "ALTER USER root WITH SUPERUSER;" && \
    createdb root && \
    cargo make --env CARGO_MAKE_RUN_CLIPPY=true workspace-ci-flow

FROM ubuntu:focal as carbide
#RUN ln -snf /usr/share/zoneinfo/UTC /etc/localtime && echo UTC > /etc/timezone
RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates curl iproute2
COPY dev/deployment/pgdg.gpg /etc/apt/trusted.gpg.d/apt.postgresql.org.gpg
COPY dev/deployment/pgdg.list /etc/apt/sources.list.d/pgdg.list
COPY dev/deployment/isc-kea-2-0.gpg /etc/apt/trusted.gpg.d/apt.isc-kea-2.0.gpg
COPY dev/deployment/isc-kea-2-0.list /etc/apt/sources.list.d/isc-kea-2.0.list
COPY dev/deployment/kea-dhcp4-carbide.conf /etc/kea/kea-dhcp4-carbide.conf
COPY dev/deployment/wait-for-pg /usr/local/bin
COPY dev/deployment/wait-for-carbide-migrations /usr/local/bin
RUN apt-get update && apt-get install -y --no-install-recommends \
  postgresql-client-14 postgresql-client-14-dbgsym \
  ca-certificates curl iproute2 \
  isc-kea-dhcp4-server isc-kea-dhcp6-server libfreeipmi17 libipmiconsole2 libudev1 \
  && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /opt/carbide/migrations && \
  mkdir -p /opt/carbide/pxe/templates && \
  mkdir -p /opt/carbide/static
COPY --from=builder ["/carbide/target/debug/carbide-api", "/carbide/target/debug/carbide","/carbide/target/debug/carbide-dns", "/opt/carbide/"]
COPY --from=builder /carbide/target/debug/libdhcp.so /usr/lib/x86_64-linux-gnu/kea/hooks
COPY api/migrations/ /opt/carbide/migrations/
COPY pxe/templates/*  /opt/carbide/pxe/templates/
COPY pxe/Rocket.toml /opt/carbide/
COPY pxe/artifacts.json /opt/carbide/
