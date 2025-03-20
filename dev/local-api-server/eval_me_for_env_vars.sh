#!/bin/bash

set -euo pipefail

function fail() {
    echo "Note: This script requires that a k3s cluster is deployed via forged, and that typical kubectl commands work as expected." 1>&2
}

trap fail ERR

# Construct a DATABASE_URL from kubernetes info
DB_SECRET_JSON="$(kubectl -n forge-system get secret forge-system.carbide.forge-pg-cluster.credentials -o json)"
DB_CONFIG_JSON="$(kubectl -n forge-system get configmaps forge-system-carbide-database-config -o json)"
# Get the IP from the postgres-operator pod, which has nslookup installed.
DB_IP="$(kubectl -n postgres exec deployments/postgres-operator -- nslookup forge-pg-cluster.postgres.svc.cluster.local | grep 'Address:' | tail -1 | awk '{print $NF}' | sed 's/\r//;')"
DB_USERNAME="$(echo "${DB_SECRET_JSON}" | jq -r .data.username | base64 -d)"
DB_PASSWORD="$(echo "${DB_SECRET_JSON}" | jq -r .data.password | base64 -d)"
DB_NAME="$(echo "${DB_CONFIG_JSON}" | jq -r .data.DB_NAME)"
DB_PORT="$(echo "${DB_CONFIG_JSON}" | jq -r .data.DB_PORT)"

cat <<EOF
export CARBIDE_API_DATABASE_URL="postgres://${DB_USERNAME}:${DB_PASSWORD}@${DB_IP}:${DB_PORT}/${DB_NAME}"
export DISABLE_TLS_ENFORCEMENT=true
EOF


# Carbide needs these set or it'll panic. They don't need to be valid, since
# the point here is to get a minimal API server running against the database.
cat <<EOF
export VAULT_TOKEN=invalid
export VAULT_PKI_ROLE_NAME=invalid
export VAULT_PKI_MOUNT_LOCATION=invalid
export VAULT_KV_MOUNT_LOCATION=invalid
EOF
