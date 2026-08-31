#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -eEuo pipefail

# Optional: enable verbose debug
[[ -n "${DEBUG:-}" ]] && set -xv

banner() {
  printf '\n\033[1;36m%s\033[0m\n' "$*"
}

# ------------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------------

# Optional: set KUBECTL_CONTEXT env if you want a specific context:
#   KUBECTL_CONTEXT=my-context ./create-postgres-extensions.sh
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-}"

# Build kubectl command with optional context
KUBECTL=(kubectl)
if [[ -n "$KUBECTL_CONTEXT" ]]; then
  KUBECTL+=(--context "$KUBECTL_CONTEXT")
fi

DB_NAME="${DB_NAME:-nico_rest}"

banner "📦 Using database name: ${DB_NAME}"

# ------------------------------------------------------------------------------
# Wait for the CloudNativePG Cluster to be Ready
# ------------------------------------------------------------------------------

banner "⏳  Waiting for CloudNativePG Cluster postgres/nico-pg-cluster to be Ready…"

if ! "${KUBECTL[@]}" -n postgres wait \
  --for=condition=Ready \
  cluster.postgresql.cnpg.io/nico-pg-cluster \
  --timeout=10m; then
  echo "❌  CloudNativePG Cluster not Ready after 10 minutes"
  exit 2
fi

banner "✅  CloudNativePG Cluster is Ready"

# ------------------------------------------------------------------------------
# Find the primary pod and run CREATE EXTENSION inside it
# ------------------------------------------------------------------------------

MASTER_POD="$("${KUBECTL[@]}" -n postgres get pods \
  -l cnpg.io/cluster=nico-pg-cluster,cnpg.io/instanceRole=primary \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"

if [[ -z "$MASTER_POD" ]]; then
  echo "❌  Could not locate primary pod (labels cnpg.io/cluster=nico-pg-cluster,cnpg.io/instanceRole=primary)"
  exit 2
fi

echo "🔑  Running extension SQL inside pod ${MASTER_POD}"

"${KUBECTL[@]}" -n postgres exec "${MASTER_POD}" -c postgres -- \
  psql -U postgres -d "${DB_NAME}" \
    -c 'CREATE EXTENSION IF NOT EXISTS btree_gin;' \
    -c 'CREATE EXTENSION IF NOT EXISTS pg_trgm;'

echo "✅  Postgres extensions ensured."
