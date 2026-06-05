#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS="${KEYCLOAK_NS:-nico-rest}"

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

echo "  Keycloak ready (realm: nico, client: nico-rest)"
