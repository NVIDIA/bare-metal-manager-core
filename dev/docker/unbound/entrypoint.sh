#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Entrypoint for the site-built unbound runtime image.
#
# Honours the same env-var contract as the upstream
# `nvcr.io/nvidian/nvforge/unbound` image so the helm chart in
# `helm/charts/unbound/` works without any changes:
#
#   LOCAL_CONFIG_DIR      Directory containing `*.conf` files included by the
#                         main unbound.conf at startup.  Mounted by the chart
#                         from the `unbound-local-config` ConfigMap.
#   BROKEN_DNSSEC         When `1`, disables DNSSEC validation (the chart
#                         sets this so the synthetic `.forge` zone validates).
#   UNBOUND_CONTROL_DIR   Directory for the auto-generated unbound_control
#                         TLS keypair shared with the unbound_exporter
#                         sidecar via an emptyDir volume.
set -eu

LOCAL_CONFIG_DIR="${LOCAL_CONFIG_DIR:-/etc/unbound/local.conf.d}"
UNBOUND_CONTROL_DIR="${UNBOUND_CONTROL_DIR:-/etc/unbound/keys}"
BROKEN_DNSSEC="${BROKEN_DNSSEC:-0}"

# Generate the unbound-control TLS keypair on first boot.  The chart's
# unbound_exporter sidecar mounts UNBOUND_CONTROL_DIR read-only and uses
# `unbound_control.pem` + `unbound_control.key` to query stats over the
# control channel.  Skip generation if the keys are already present
# (deployment was restarted with the same emptyDir volume).
if [ ! -f "${UNBOUND_CONTROL_DIR}/unbound_control.key" ]; then
  /opt/unbound/sbin/unbound-control-setup -d "${UNBOUND_CONTROL_DIR}" >/dev/null 2>&1 || \
    echo "warning: unbound-control-setup failed; metrics sidecar may not connect" >&2
fi

# Disable DNSSEC validation if requested.  unbound itself doesn't have a
# single "disable DNSSEC" toggle, but if `auto-trust-anchor-file` points
# at a missing/empty file, unbound 1.20 refuses to start.  When the
# operator opts out of DNSSEC, drop both the trust anchor file AND the
# config line that references it.
if [ "${BROKEN_DNSSEC}" = "1" ]; then
  rm -f /opt/unbound/etc/unbound/root.key
  # Strip the auto-trust-anchor-file directive (sed in-place is safe
  # since the file is owned by the unbound user, see Dockerfile).
  sed -i '/auto-trust-anchor-file/d' /etc/unbound/unbound.conf
fi

exec "$@"
