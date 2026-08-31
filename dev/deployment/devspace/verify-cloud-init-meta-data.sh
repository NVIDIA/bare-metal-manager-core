#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ "$#" != "2" ]]; then
  printf 'usage: %s <assigned-instance-ip> <expected-local-hostname>\n' "$0" >&2
  exit 2
fi

instance_ip="$1"
expected_hostname="$2"
namespace="${LOCAL_DEV_NAMESPACE:-nico-system}"
forward_port="${LOCAL_DEV_PXE_FORWARD_PORT:-18081}"
work_dir="$(mktemp -d)"
forward_pid=""

cleanup() {
  if [[ -n "${forward_pid}" ]]; then
    kill "${forward_pid}" >/dev/null 2>&1 || true
  fi
  rm -rf -- "${work_dir}"
}
trap cleanup EXIT INT TERM

for binary in curl grep kubectl; do
  command -v "${binary}" >/dev/null 2>&1 || {
    printf 'missing required binary: %s\n' "${binary}" >&2
    exit 1
  }
done

kubectl rollout status deployment/nico-pxe -n "${namespace}" --timeout=300s >/dev/null
kubectl port-forward --address 127.0.0.1 -n "${namespace}" \
  service/nico-pxe "${forward_port}:8080" >"${work_dir}/port-forward.log" 2>&1 &
forward_pid=$!

for _ in {1..60}; do
  if grep -Fq "Forwarding from 127.0.0.1:${forward_port}" "${work_dir}/port-forward.log"; then
    break
  fi
  if ! kill -0 "${forward_pid}" >/dev/null 2>&1; then
    printf 'PXE port-forward exited before it became ready\n' >&2
    sed -n '1,120p' "${work_dir}/port-forward.log" >&2
    exit 1
  fi
  sleep 1
done

if ! grep -Fq "Forwarding from 127.0.0.1:${forward_port}" "${work_dir}/port-forward.log"; then
  printf 'PXE port-forward did not become ready\n' >&2
  exit 1
fi

metadata="$(curl --fail --silent --show-error --max-time 10 \
  -H "X-Forwarded-For: ${instance_ip}" \
  "http://127.0.0.1:${forward_port}/api/v0/cloud-init/meta-data")"

if ! grep -Fxq "local-hostname: \"${expected_hostname}\"" <<<"${metadata}"; then
  printf 'expected local-hostname %q was not present in meta-data:\n%s\n' \
    "${expected_hostname}" "${metadata}" >&2
  exit 1
fi

printf '%s\n' "${metadata}"
printf 'cloud-init meta-data local-hostname verified for %s\n' "${instance_ip}"
