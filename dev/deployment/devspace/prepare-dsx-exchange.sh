#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../.." && pwd)"

DSX_EXCHANGE_VERSION="v2.9.1"
DSX_EXCHANGE_COMMIT="909f21c722b3f4eb6954a63ffbc3cb894685e3cd"
DSX_EXCHANGE_URL="https://github.com/NVIDIA/dsx-exchange.git"
DSX_EXCHANGE_DIR="${REPO_ROOT}/.devspace/dsx-exchange-${DSX_EXCHANGE_VERSION}"
DSX_GATEWAY_CHART="${DSX_EXCHANGE_DIR}/deploy/dsx-agent-gateway"
HELM_REPOSITORY_CONFIG="${REPO_ROOT}/.devspace/dsx-helm-repositories.yaml"
HELM_REPOSITORY_CACHE="${REPO_ROOT}/.devspace/dsx-helm-cache"
GATEWAY_API_VERSION="v1.5.1"
GATEWAY_API_SHA256="751002b3b91a87f7ae3bd2517c79a47a8d7ed6702901808a1cf9bd97d284f9b8"
GATEWAY_API_MANIFEST="${REPO_ROOT}/.devspace/gateway-api-standard-${GATEWAY_API_VERSION}.yaml"
GATEWAY_API_URL="https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml"

require_bin() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'missing required binary: %s\n' "$1" >&2
    exit 1
  }
}

require_bin git
require_bin helm
require_bin curl
require_bin shasum

mkdir -p "${REPO_ROOT}/.devspace"

if [[ ! -d "${DSX_EXCHANGE_DIR}/.git" ]]; then
  if [[ -e "${DSX_EXCHANGE_DIR}" ]]; then
    printf 'refusing to replace incomplete DSX Exchange checkout: %s\n' \
      "${DSX_EXCHANGE_DIR}" >&2
    exit 1
  fi
  git clone --filter=blob:none --depth 1 --branch "${DSX_EXCHANGE_VERSION}" \
    "${DSX_EXCHANGE_URL}" "${DSX_EXCHANGE_DIR}"
fi

actual_commit="$(git -C "${DSX_EXCHANGE_DIR}" rev-parse HEAD)"
if [[ "${actual_commit}" != "${DSX_EXCHANGE_COMMIT}" ]]; then
  printf 'DSX Exchange %s resolved to %s, expected %s\n' \
    "${DSX_EXCHANGE_VERSION}" "${actual_commit}" "${DSX_EXCHANGE_COMMIT}" >&2
  exit 1
fi

if ! git -C "${DSX_EXCHANGE_DIR}" diff --quiet --ignore-submodules -- || \
  ! git -C "${DSX_EXCHANGE_DIR}" diff --cached --quiet --ignore-submodules --; then
  printf 'refusing to use modified DSX Exchange checkout: %s\n' \
    "${DSX_EXCHANGE_DIR}" >&2
  exit 1
fi

mkdir -p "${HELM_REPOSITORY_CACHE}"
helm repo add valkey https://valkey-io.github.io/valkey-helm \
  --force-update \
  --repository-config "${HELM_REPOSITORY_CONFIG}" \
  --repository-cache "${HELM_REPOSITORY_CACHE}" >/dev/null
helm dependency build "${DSX_GATEWAY_CHART}" \
  --repository-config "${HELM_REPOSITORY_CONFIG}" \
  --repository-cache "${HELM_REPOSITORY_CACHE}" >/dev/null

if [[ ! -f "${GATEWAY_API_MANIFEST}" ]]; then
  gateway_api_download="${GATEWAY_API_MANIFEST}.download"
  curl -fsSL -o "${gateway_api_download}" "${GATEWAY_API_URL}"
  actual_gateway_api_sha="$(shasum -a 256 "${gateway_api_download}" | awk '{print $1}')"
  if [[ "${actual_gateway_api_sha}" != "${GATEWAY_API_SHA256}" ]]; then
    printf 'Gateway API %s checksum %s does not match %s\n' \
      "${GATEWAY_API_VERSION}" "${actual_gateway_api_sha}" "${GATEWAY_API_SHA256}" >&2
    exit 1
  fi
  mv "${gateway_api_download}" "${GATEWAY_API_MANIFEST}"
fi

actual_gateway_api_sha="$(shasum -a 256 "${GATEWAY_API_MANIFEST}" | awk '{print $1}')"
if [[ "${actual_gateway_api_sha}" != "${GATEWAY_API_SHA256}" ]]; then
  printf 'cached Gateway API %s checksum %s does not match %s\n' \
    "${GATEWAY_API_VERSION}" "${actual_gateway_api_sha}" "${GATEWAY_API_SHA256}" >&2
  exit 1
fi

case "${1:-}" in
  "")
    printf '%s\n' "${DSX_EXCHANGE_DIR}"
    ;;
  --gateway-api-manifest)
    printf '%s\n' "${GATEWAY_API_MANIFEST}"
    ;;
  *)
    printf 'unknown argument: %s\n' "$1" >&2
    exit 2
    ;;
esac
