#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../.." && pwd)"

CORE_NAMESPACE="${LOCAL_DEV_NAMESPACE:-nico-system}"
REST_NAMESPACE="nico-rest"
API_FORWARD_PORT="${LOCAL_DEV_REST_API_FORWARD_PORT:-18388}"
KEYCLOAK_FORWARD_PORT="${LOCAL_DEV_KEYCLOAK_FORWARD_PORT:-18082}"
WORK_DIR="${LOCAL_DEV_REST_WORK_DIR:-${HOME}/Developer/_agent-tmp/devspace-rest}"

api_forward_pid=""
keycloak_forward_pid=""

cleanup() {
  if [[ -n "${api_forward_pid}" ]]; then
    kill "${api_forward_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${keycloak_forward_pid}" ]]; then
    kill "${keycloak_forward_pid}" >/dev/null 2>&1 || true
  fi
}

require_bin() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'missing required binary: %s\n' "$1" >&2
    exit 1
  }
}

trap cleanup EXIT INT TERM

require_bin curl
require_bin jq
require_bin kubectl
require_bin base64

mkdir -p "${WORK_DIR}"

kubectl rollout status deployment/nico-api -n "${CORE_NAMESPACE}" --timeout=300s >/dev/null
kubectl rollout status deployment/machine-a-tron -n "${CORE_NAMESPACE}" --timeout=300s >/dev/null
kubectl rollout status deployment/nico-rest-api -n "${REST_NAMESPACE}" --timeout=300s >/dev/null
kubectl rollout status deployment/nico-rest-cert-manager -n "${REST_NAMESPACE}" --timeout=300s >/dev/null
kubectl rollout status deployment/nico-rest-cloud-worker -n "${REST_NAMESPACE}" --timeout=300s >/dev/null
kubectl rollout status deployment/nico-rest-site-worker -n "${REST_NAMESPACE}" --timeout=300s >/dev/null
kubectl rollout status deployment/nico-rest-site-manager -n "${REST_NAMESPACE}" --timeout=300s >/dev/null
kubectl rollout status deployment/nico-mcp -n "${REST_NAMESPACE}" --timeout=300s >/dev/null
kubectl wait --for=condition=Ready certificate/core-grpc-client-site-agent-certs \
  -n "${REST_NAMESPACE}" --timeout=240s >/dev/null

kubectl port-forward --address 127.0.0.1 -n "${REST_NAMESPACE}" \
  service/nico-rest-api "${API_FORWARD_PORT}:8388" \
  >"${WORK_DIR}/api-port-forward.log" 2>&1 &
api_forward_pid=$!

kubectl port-forward --address 127.0.0.1 -n "${REST_NAMESPACE}" \
  service/keycloak "${KEYCLOAK_FORWARD_PORT}:8082" \
  >"${WORK_DIR}/keycloak-port-forward.log" 2>&1 &
keycloak_forward_pid=$!

curl --fail --silent --show-error --retry 120 --retry-connrefused --retry-delay 1 \
  --max-time 5 "http://localhost:${KEYCLOAK_FORWARD_PORT}/realms/nico-dev" >/dev/null
curl --fail --silent --show-error --retry 120 --retry-connrefused --retry-delay 1 \
  --max-time 5 "http://localhost:${API_FORWARD_PORT}/healthz" >/dev/null

api_forward_log="$(<"${WORK_DIR}/api-port-forward.log")"
keycloak_forward_log="$(<"${WORK_DIR}/keycloak-port-forward.log")"
if ! kill -0 "${api_forward_pid}" >/dev/null 2>&1 || \
  [[ "${api_forward_log}" != *"Forwarding from 127.0.0.1:${API_FORWARD_PORT}"* ]]; then
  printf 'REST API port-forward failed; port %s may already be in use\n' \
    "${API_FORWARD_PORT}" >&2
  sed -n '1,120p' "${WORK_DIR}/api-port-forward.log" >&2
  exit 1
fi
if ! kill -0 "${keycloak_forward_pid}" >/dev/null 2>&1 || \
  [[ "${keycloak_forward_log}" != *"Forwarding from 127.0.0.1:${KEYCLOAK_FORWARD_PORT}"* ]]; then
  printf 'Keycloak port-forward failed; port %s may already be in use\n' \
    "${KEYCLOAK_FORWARD_PORT}" >&2
  sed -n '1,120p' "${WORK_DIR}/keycloak-port-forward.log" >&2
  exit 1
fi

setup_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

NAMESPACE="${REST_NAMESPACE}" \
API_URL="http://localhost:${API_FORWARD_PORT}" \
KEYCLOAK_URL="http://localhost:${KEYCLOAK_FORWARD_PORT}" \
RESTART_API=0 \
  "${REPO_ROOT}/rest-api/scripts/setup-local.sh" site-agent

kubectl rollout status statefulset/nico-rest-site-agent \
  -n "${REST_NAMESPACE}" --timeout=300s >/dev/null

site_agent_logs=""
core_connected=0
for attempt in {1..60}; do
  site_agent_logs="$(kubectl logs statefulset/nico-rest-site-agent \
    -n "${REST_NAMESPACE}" --since-time="${setup_started_at}" 2>/dev/null || true)"
  case "${site_agent_logs}" in
    *"CoreGrpcClient: Successfully connected to server"*)
      core_connected=1
      break
      ;;
  esac
  sleep 5
done
if [[ "${core_connected}" != "1" ]]; then
  printf 'site-agent did not establish a Core gRPC connection\n' >&2
  printf '%s\n' "${site_agent_logs}" >&2
  exit 1
fi

site_id="$(kubectl get configmap nico-rest-site-agent-config -n "${REST_NAMESPACE}" \
  -o jsonpath='{.data.CLUSTER_ID}')"
secret_site_id="$(kubectl get secret site-registration -n "${REST_NAMESPACE}" \
  -o jsonpath='{.data.site-uuid}' 2>/dev/null | base64 -d 2>/dev/null || true)"
if [[ -z "${site_id}" || "${site_id}" == "00000000-0000-4000-8000-000000000001" || \
  "${secret_site_id}" != "${site_id}" ]]; then
  printf 'site-agent ConfigMap and registration Secret do not contain the same registered site ID\n' >&2
  exit 1
fi

inventory_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

machine_status="$(kubectl exec deployment/nico-api -n "${CORE_NAMESPACE}" -- \
  curl --fail --insecure --silent --max-time 5 \
  https://machine-a-tron-bmc-mock:1266/machines/status 2>/dev/null || true)"
expected_host_count="$(jq -r \
  'if (.machines | type) == "array" then .machines | length else 0 end' \
  <<<"${machine_status}" 2>/dev/null || printf '0')"
if [[ "${expected_host_count}" == "0" ]]; then
  printf 'machine-a-tron did not report any expected hosts\n' >&2
  exit 1
fi

site_ready=false
machines_ready=false
machine_count=0
core_hosts_ready=false
core_host_count=0
core_ready_count=0
fresh_cycle=false
# A clean cluster may need a second three-minute inventory cycle after Core discovers machines.
for attempt in {1..90}; do
  site_ready=false
  machines_ready=false
  machine_count=0
  core_hosts_ready=false
  core_host_count=0
  core_ready_count=0
  token="$(curl --fail --silent --max-time 5 -X POST \
    "http://localhost:${KEYCLOAK_FORWARD_PORT}/realms/nico-dev/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=nico-api" \
    -d "client_secret=nico-local-secret" \
    -d "grant_type=password" \
    -d "username=admin@example.com" \
    -d "password=adminpassword" 2>/dev/null | jq -er '.access_token' 2>/dev/null || true)"
  if [[ -n "${token}" ]]; then
    site="$(curl --fail --silent --max-time 5 \
      "http://localhost:${API_FORWARD_PORT}/v2/org/test-org/nico/site/${site_id}" \
      -H "Authorization: Bearer ${token}" 2>/dev/null || true)"
    machines="$(curl --fail --silent --max-time 5 \
      "http://localhost:${API_FORWARD_PORT}/v2/org/test-org/nico/machine?siteId=${site_id}&isMissingOnSite=false&pageSize=100" \
      -H "Authorization: Bearer ${token}" 2>/dev/null || true)"
    site_ready="$(jq -r --arg site_id "${site_id}" \
      '.id == $site_id and .isOnline == true and .status == "Registered"' \
      <<<"${site}" 2>/dev/null || printf 'false')"
    machines_ready="$(jq -r --arg site_id "${site_id}" \
      --argjson expected_host_count "${expected_host_count}" \
      'type == "array" and length == $expected_host_count and all(.[]; .siteId == $site_id)' \
      <<<"${machines}" 2>/dev/null || printf 'false')"
    machine_count="$(jq -r 'if type == "array" then length else 0 end' \
      <<<"${machines}" 2>/dev/null || printf '0')"
  fi

  core_hosts="$(kubectl exec deployment/nico-api -n "${CORE_NAMESPACE}" -- \
    /opt/carbide/nico-admin-cli -f json machine show --hosts 2>/dev/null || true)"
  core_host_count="$(jq -r \
    'if (.machines | type) == "array" then .machines | length else 0 end' \
    <<<"${core_hosts}" 2>/dev/null || printf '0')"
  core_ready_count="$(jq -r \
    'if (.machines | type) == "array" then [.machines[] | select(.state == "Ready")] | length else 0 end' \
    <<<"${core_hosts}" 2>/dev/null || printf '0')"
  if [[ "${core_host_count}" == "${expected_host_count}" && \
    "${core_ready_count}" == "${expected_host_count}" ]]; then
    core_hosts_ready=true
  fi

  site_worker_logs="$(kubectl logs deployment/nico-rest-site-worker \
    -n "${REST_NAMESPACE}" --since-time="${inventory_started_at}" 2>/dev/null || true)"
  fresh_cycle="$(jq -Rrs --arg site_id "${site_id}" '
    [splits("\n") | fromjson?
     | select(.Activity == "UpdateMachinesInDB" and .["Site ID"] == $site_id)
     | .msg] |
    reduce .[] as $msg (
      {saw_last_nonempty_page: false, complete: false};
      if ($msg | startswith("Received Machine inventory page:")) then
        ($msg | capture("^Received Machine inventory page: (?<current>[0-9]+) of (?<pages>[0-9]+), page size: [0-9]+, total count: (?<items>[0-9]+)$")) as $page |
        .saw_last_nonempty_page = (
          ($page.current | tonumber) == ($page.pages | tonumber) and
          ($page.items | tonumber) > 0
        )
      elif .saw_last_nonempty_page and $msg == "completed activity" then
        .complete = true
      else . end
    ) | .complete
  ' <<<"${site_worker_logs}" 2>/dev/null || printf 'false')"

  if [[ "${site_ready}" == "true" && "${machines_ready}" == "true" && \
    "${core_hosts_ready}" == "true" && \
    "${fresh_cycle}" == "true" ]]; then
    printf 'REST API reports site %s online with all %s Core hosts Ready and synced from a current inventory\n' \
      "${site_id}" "${expected_host_count}"
    break
  fi
  if [[ "${attempt}" == "90" ]]; then
    printf 'REST integration verification failed: site_ready=%s machines_ready=%s rest_machines=%s core_ready=%s core_hosts=%s expected_hosts=%s fresh_cycle=%s\n' \
      "${site_ready}" "${machines_ready}" "${machine_count}" "${core_ready_count}" \
      "${core_host_count}" "${expected_host_count}" "${fresh_cycle}" >&2
    exit 1
  fi
  sleep 5
done

printf 'REST integration setup complete\n'
