#!/usr/bin/env bash
# Fetches an ncx-service token and exercises the carbide-rest-api with it:
#   1. GET  /healthz
#   2. GET  /v2/org/ncx/carbide/user/current   (with the token)
# Then dumps the forge.user table so you can see the auto-created row.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GET_TOKEN="${SCRIPT_DIR}/get-token.sh"
NS="${KEYCLOAK_NS:-carbide-rest}"
API_URL="http://carbide-rest-api.${NS}:8388"

_cluster_curl() {
    kubectl run -i --rm --restart=Never --image=curlimages/curl "curl-$$-$RANDOM" \
        -n "${NS}" --quiet -- "$@" 2>/dev/null
}

_decode_jwt() {
    local payload="$1"
    local pad=$(( 4 - ${#payload} % 4 ))
    [[ ${pad} -ne 4 ]] && payload="${payload}$(printf '%*s' ${pad} '' | tr ' ' '=')"
    echo "${payload}" | base64 --decode 2>/dev/null || echo "${payload}" | base64 -d 2>/dev/null
}

echo "================================================================="
echo "  ncx-service"
echo "================================================================="
TOKEN="$(bash "${GET_TOKEN}")"
if [[ -z "${TOKEN}" ]]; then
    echo "  FAILED: could not obtain ncx-service token" >&2
    exit 1
fi
echo "${TOKEN}"

echo ""
echo "--- JWT payload ---"
_decode_jwt "$(echo "${TOKEN}" | cut -d. -f2)" | python3 -m json.tool 2>/dev/null \
    || _decode_jwt "$(echo "${TOKEN}" | cut -d. -f2)" | jq . 2>/dev/null \
    || _decode_jwt "$(echo "${TOKEN}" | cut -d. -f2)"

echo ""
echo "--- API test: healthz ---"
_cluster_curl -sf "${API_URL}/healthz" | python3 -m json.tool 2>/dev/null \
    || _cluster_curl -sf "${API_URL}/healthz" | jq . 2>/dev/null \
    || echo "  healthz: not reachable"

echo ""
echo "--- API test: GET /v2/org/ncx/carbide/user/current ---"
_API_RESP="$(_cluster_curl -s -w '\nHTTP_STATUS:%{http_code}' \
    "${API_URL}/v2/org/ncx/carbide/user/current" \
    -H "Authorization: Bearer ${TOKEN}")" || true
_API_STATUS="$(echo "${_API_RESP}" | grep 'HTTP_STATUS:' | cut -d: -f2)"
_API_BODY="$(echo "${_API_RESP}" | sed '/HTTP_STATUS:/d')"
echo "  HTTP ${_API_STATUS}"
echo "${_API_BODY}" | python3 -m json.tool 2>/dev/null \
    || echo "${_API_BODY}" | jq . 2>/dev/null \
    || echo "${_API_BODY}"

echo ""
echo "=== postgres user table (forge) ==="
if [[ -z "${PG_POD:-}" ]]; then
    PG_POD="$(kubectl get pods -n postgres -l app=postgres \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
fi
if [[ -z "${PG_POD}" ]]; then
    echo "  FAILED: set PG_POD or ensure a postgres pod exists (ns postgres, label app=postgres)" >&2
    exit 1
fi
kubectl exec -n postgres "$PG_POD" -- psql -U forge -d forge -c 'SELECT * FROM "user" LIMIT 20;'
