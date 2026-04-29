#!/usr/bin/env bash
set -euo pipefail

LOCAL_CONFIG_DIR="${LOCAL_CONFIG_DIR:-/etc/unbound/local.conf.d}"
UNBOUND_CONTROL_DIR="${UNBOUND_CONTROL_DIR:-/etc/unbound/keys}"
UNBOUND_CONFIG="${UNBOUND_CONFIG:-/tmp/unbound.conf}"

mkdir -p "${LOCAL_CONFIG_DIR}" "${UNBOUND_CONTROL_DIR}"

if [ ! -f "${UNBOUND_CONTROL_DIR}/unbound_server.key" ]; then
  unbound-control-setup -d "${UNBOUND_CONTROL_DIR}" >/dev/null
fi

chown -R unbound:unbound "${UNBOUND_CONTROL_DIR}"

cat >"${UNBOUND_CONFIG}" <<EOF
server:
    interface: 0.0.0.0
    interface: ::0
    port: 53
    access-control: 0.0.0.0/0 allow
    access-control: ::0/0 allow
    directory: "/etc/unbound"
    username: "unbound"
EOF

if [ "${BROKEN_DNSSEC:-}" = "1" ]; then
  cat >>"${UNBOUND_CONFIG}" <<EOF
    val-permissive-mode: yes
EOF
fi

cat >>"${UNBOUND_CONFIG}" <<EOF

include: "${LOCAL_CONFIG_DIR}/*.conf"

remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-port: 8953
    server-key-file: "${UNBOUND_CONTROL_DIR}/unbound_server.key"
    server-cert-file: "${UNBOUND_CONTROL_DIR}/unbound_server.pem"
    control-key-file: "${UNBOUND_CONTROL_DIR}/unbound_control.key"
    control-cert-file: "${UNBOUND_CONTROL_DIR}/unbound_control.pem"
EOF

exec unbound -d -c "${UNBOUND_CONFIG}"
