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

# Fetches a Keycloak access token for the ncx-service client (client_credentials
# grant) and prints it to stdout. Nothing else.
#
# Usage:
#   ./get-token.sh
#   TOKEN=$(./get-token.sh)
set -euo pipefail

NS="${KEYCLOAK_NS:-nico-rest}"
KC_URL="http://keycloak.${NS}:8082"
TOKEN_URL="${KC_URL}/realms/nico/protocol/openid-connect/token"
CLIENT_ID="ncx-service"
CLIENT_SECRET="nico-local-secret"

# Runs curl from inside the cluster via a one-shot pod.
# This ensures JWT issuer matches the internal Keycloak URL.
_cluster_curl() {
    kubectl run -i --rm --restart=Never --image=curlimages/curl "curl-$$" \
        -n "${NS}" --quiet -- "$@" 2>/dev/null
}

CURL_DATA="grant_type=client_credentials&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}"

TOKEN="$(_cluster_curl \
    -sf -X POST "${TOKEN_URL}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "${CURL_DATA}")" || { echo "ERROR: token request failed" >&2; exit 1; }

ACCESS_TOKEN="$(echo "${TOKEN}" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null \
    || echo "${TOKEN}" | jq -r '.access_token' 2>/dev/null)" || true

if [[ -z "${ACCESS_TOKEN}" || "${ACCESS_TOKEN}" == "null" ]]; then
    echo "ERROR: failed to extract access_token" >&2
    echo "${TOKEN}" >&2
    exit 1
fi

echo "${ACCESS_TOKEN}"
