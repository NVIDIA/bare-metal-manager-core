#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
	echo "Usage: check-core-ci-permissions.sh [workflow-path]"
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
workflow_path="${1:-${repo_root}/.github/workflows/ci.yaml}"

# A job-level block replaces the workflow default. Keep each complete
# exception here so a new scope cannot hide beside one that was already
# reviewed.
bash "${script_dir}/check-ci-permissions.sh" \
	--workflow-name "Core CI" \
	--workflow-path "${workflow_path}" \
	--workflow-permissions "contents=read" \
	--job-permissions "lint-police=contents=read,pull-requests=read" \
	--job-permissions "security-codeql-scan=actions=read,contents=read"
