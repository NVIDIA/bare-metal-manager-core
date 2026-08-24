#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETUP_SH="${SCRIPT_DIR}/../setup.sh"

if [[ "$(grep -Fc '"${SCRIPT_DIR}/cleanup-legacy-flow-managers.sh"' "${SETUP_SH}")" -ne 1 ]]; then
    echo "setup.sh must invoke legacy manager cleanup exactly once" >&2
    exit 1
fi

skip_line="$(grep -nF 'if "${SKIP_FLOW}"; then' "${SETUP_SH}" | head -1 | cut -d: -f1)"
else_line="$(awk -v start="${skip_line}" 'NR > start && /^else$/ { print NR; exit }' "${SETUP_SH}")"
upgrade_line="$(grep -nF 'helm upgrade --install flow "${NICO_FLOW_CHART}"' "${SETUP_SH}" | cut -d: -f1)"
cleanup_line="$(grep -nF '"${SCRIPT_DIR}/cleanup-legacy-flow-managers.sh"' "${SETUP_SH}" | cut -d: -f1)"
branch_end_line="$(awk -v start="${cleanup_line}" 'NR > start && /^fi$/ { print NR; exit }' "${SETUP_SH}")"

if ! (( skip_line < else_line && else_line < upgrade_line && \
        upgrade_line < cleanup_line && cleanup_line < branch_end_line )); then
    echo "legacy cleanup must run only in the non-skip branch after Flow upgrade" >&2
    exit 1
fi

echo "setup Flow cleanup ordering test passed"
