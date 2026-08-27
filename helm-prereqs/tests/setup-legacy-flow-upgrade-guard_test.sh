#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETUP_SH="${SCRIPT_DIR}/../setup.sh"
TEST_TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TEST_TMP_DIR}"' EXIT
TEST_LOG="${TEST_TMP_DIR}/kubectl.log"
export TEST_LOG

guard_definition="$(
    sed -n '/^_reject_bundled_flow_manager_upgrade()/,/^}/p' "${SETUP_SH}"
)"
if [[ -z "${guard_definition}" ]]; then
    echo "could not extract bundled manager upgrade guard" >&2
    exit 1
fi
eval "${guard_definition}"

mkdir -p "${TEST_TMP_DIR}/bin"
cat > "${TEST_TMP_DIR}/bin/kubectl" <<'FAKE_KUBECTL'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${TEST_LOG}"

case "${TEST_SCENARIO}" in
    error)
        exit 1
        ;;
    absent)
        ;;
    flow)
        printf 'flow\n'
        ;;
    psm)
        printf 'flow\npsm\n'
        ;;
    nsm)
        printf 'flow\nnsm\n'
        ;;
    both)
        printf 'flow\npsm\nnsm\n'
        ;;
esac
FAKE_KUBECTL
chmod +x "${TEST_TMP_DIR}/bin/kubectl"

run_guard() {
    TEST_SCENARIO="$1" PATH="${TEST_TMP_DIR}/bin:${PATH}" \
        _reject_bundled_flow_manager_upgrade
}

for supported in absent flow; do
    : > "${TEST_LOG}"
    run_guard "${supported}"
    grep -Fqx -- \
        'get deployment flow -n flow --ignore-not-found -o jsonpath={range .spec.template.spec.containers[*]}{.name}{"\n"}{end}' \
        "${TEST_LOG}"
done

for unsupported in psm nsm both; do
    : > "${TEST_LOG}"
    if guard_output="$(run_guard "${unsupported}" 2>&1)"; then
        echo "guard accepted bundled manager scenario: ${unsupported}" >&2
        exit 1
    fi
    if ! grep -Fq -- \
        'upgrade only the flow Helm release to the Flow-only chart' \
        <<< "${guard_output}"; then
        echo "guard did not provide the staged Flow upgrade action" >&2
        exit 1
    fi
done

if (run_guard error); then
    echo "guard accepted a Deployment inspection failure" >&2
    exit 1
fi

preflight_line="$(grep -nF 'source "${SCRIPT_DIR}/preflight.sh"' "${SETUP_SH}" | cut -d: -f1)"
guard_line="$(grep -nF '_reject_bundled_flow_manager_upgrade' "${SETUP_SH}" | tail -1 | cut -d: -f1)"
first_install_line="$(grep -nF 'helmfile sync -l name=postgres-operator' "${SETUP_SH}" | cut -d: -f1)"
if ! (( guard_line < preflight_line && preflight_line < first_install_line )); then
    echo "bundled manager guard must run before preflight and installation phases" >&2
    exit 1
fi

echo "setup legacy Flow upgrade guard tests passed"
