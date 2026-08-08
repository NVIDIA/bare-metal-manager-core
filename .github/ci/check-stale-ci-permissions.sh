#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
	echo "Usage: check-stale-ci-permissions.sh [workflow-path]"
}

if (( $# > 1 )); then
	usage >&2
	exit 2
fi

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
	usage
	exit 0
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
workflow_path="${1:-${repo_root}/.github/workflows/stale-check.yml}"

# The `stale` block replaces `contents: read`; it does not extend it. Keep the
# two writes as the complete job policy unless the action's contract changes.
bash "${script_dir}/check-ci-permissions.sh" \
	--workflow-name "Stale PRs" \
	--workflow-path "${workflow_path}" \
	--workflow-permissions "contents=read" \
	--job-permissions "stale=issues=write,pull-requests=write"
