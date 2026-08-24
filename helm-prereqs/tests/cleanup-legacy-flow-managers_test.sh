#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TEST_TMP_DIR}"' EXIT
TEST_LOG="${TEST_TMP_DIR}/kubectl.log"
export TEST_LOG

mkdir -p "${TEST_TMP_DIR}/bin"
cat > "${TEST_TMP_DIR}/bin/kubectl" <<'FAKE_KUBECTL'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${TEST_LOG}"
if [[ "$*" == *"get secret vaultroottoken"* ]]; then
    printf 'cm9vdC10b2tlbg=='
elif [[ "$*" == *"exec -i vault-0"* ]]; then
    IFS= read -r token
    printf 'vault-stdin-bytes=%s\n' "${#token}" >> "${TEST_LOG}"
fi
FAKE_KUBECTL
chmod +x "${TEST_TMP_DIR}/bin/kubectl"

PATH="${TEST_TMP_DIR}/bin:${PATH}" \
    "${SCRIPT_DIR}/../cleanup-legacy-flow-managers.sh"
PATH="${TEST_TMP_DIR}/bin:${PATH}" \
    "${SCRIPT_DIR}/../cleanup-legacy-flow-managers.sh"

assert_logged() {
    if ! grep -Fq -- "$1" "${TEST_LOG}"; then
        echo "missing expected kubectl invocation: $1" >&2
        exit 1
    fi
}

assert_logged "delete job flow-vault-tokens -n nico-system --ignore-not-found"
assert_logged "delete clusterrolebinding flow-vault-tokens-writer --ignore-not-found"
assert_logged 'accessors_json="$(vault list -format=json auth/token/accessors)"'
assert_logged "psm-vault-token|nsm-vault-token|token-psm-vault-token|token-nsm-vault-token"
assert_logged "vault token revoke -accessor"
assert_logged "vault policy delete psm-vault-policy"
assert_logged "delete secret psm-vault-token nsm-vault-token -n flow --ignore-not-found"
assert_logged "delete serviceaccount flow-vault-tokens-sa -n nico-system --ignore-not-found"
assert_logged "delete clusterrole flow-vault-tokens-writer --ignore-not-found"

if grep -Fq -- "root-token" "${TEST_LOG}"; then
    echo "Vault root token leaked into kubectl arguments or logs" >&2
    exit 1
fi

if [[ "$(grep -Fc -- "delete job flow-vault-tokens" "${TEST_LOG}")" -ne 2 ]]; then
    echo "cleanup was not exercised twice" >&2
    exit 1
fi

first_line() {
    grep -Fn -- "$1" "${TEST_LOG}" | head -1 | cut -d: -f1
}

job_line="$(first_line "delete job flow-vault-tokens")"
binding_line="$(first_line "delete clusterrolebinding flow-vault-tokens-writer")"
exec_line="$(first_line "exec -i vault-0")"
secret_line="$(first_line "delete secret psm-vault-token nsm-vault-token")"
if ! (( job_line < binding_line && binding_line < exec_line && exec_line < secret_line )); then
    echo "legacy credential cleanup ran in an unsafe order" >&2
    exit 1
fi

# A missing root token must stop after authorization removal and before deleting
# the workload token Secrets; this leaves the predecessor workload recoverable.
cat > "${TEST_TMP_DIR}/bin/kubectl" <<'FAKE_EMPTY_ROOT_KUBECTL'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${TEST_LOG}"
FAKE_EMPTY_ROOT_KUBECTL
chmod +x "${TEST_TMP_DIR}/bin/kubectl"
: > "${TEST_LOG}"
if PATH="${TEST_TMP_DIR}/bin:${PATH}" \
    "${SCRIPT_DIR}/../cleanup-legacy-flow-managers.sh"; then
    echo "cleanup accepted an empty Vault root token" >&2
    exit 1
fi
assert_logged "delete clusterrolebinding flow-vault-tokens-writer --ignore-not-found"
if grep -Fq -- "delete secret psm-vault-token nsm-vault-token" "${TEST_LOG}"; then
    echo "workload token Secrets were deleted after Vault cleanup failed" >&2
    exit 1
fi

echo "cleanup-legacy-flow-managers tests passed"
