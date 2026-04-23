#!/usr/bin/env bash
# Fetches a Keycloak access token for the ncx-service client (client_credentials
# grant) and prints it to stdout. Nothing else.
#
# Usage:
#   ./get-token.sh
#   TOKEN=$(./get-token.sh)
set -euo pipefail

NS="${KEYCLOAK_NS:-carbide-rest}"
KC_URL="http://keycloak.${NS}:8082"
TOKEN_URL="${KC_URL}/realms/carbide/protocol/openid-connect/token"
CLIENT_ID="ncx-service"
CLIENT_SECRET="carbide-local-secret"

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
