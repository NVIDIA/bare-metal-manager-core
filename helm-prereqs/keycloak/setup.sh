#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS="${KEYCLOAK_NS:-carbide-rest}"

kubectl create namespace "${NS}" 2>/dev/null || true

echo "  Ensuring keycloak database..."
_PG_POD="$(kubectl get pods -n postgres -l app=postgres \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"

if [[ -n "${_PG_POD}" ]]; then
    kubectl exec -n postgres "${_PG_POD}" -- \
        psql -U postgres -c "CREATE DATABASE keycloak;" 2>/dev/null || true
    kubectl exec -n postgres "${_PG_POD}" -- \
        psql -U postgres -c "CREATE USER keycloak WITH ENCRYPTED PASSWORD 'keycloak';" 2>/dev/null || true
    kubectl exec -n postgres "${_PG_POD}" -- \
        psql -U postgres -c "ALTER USER keycloak WITH ENCRYPTED PASSWORD 'keycloak';"
    kubectl exec -n postgres "${_PG_POD}" -- \
        psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;"
    kubectl exec -n postgres "${_PG_POD}" -- \
        psql -U postgres -d keycloak -c "GRANT ALL ON SCHEMA public TO keycloak;"
else
    echo "  WARNING: no postgres pod found — ensure keycloak DB exists"
fi

echo "  Deploying Keycloak (quay.io/keycloak/keycloak:24.0)..."
kubectl apply -n "${NS}" \
    -f "${SCRIPT_DIR}/realm-configmap.yaml" \
    -f "${SCRIPT_DIR}/deployment.yaml" \
    -f "${SCRIPT_DIR}/service.yaml"

echo "  Waiting for Keycloak to be ready..."
kubectl rollout status deployment/keycloak -n "${NS}" --timeout=180s

echo "  Keycloak ready (realm: carbide, client: carbide-rest)"
