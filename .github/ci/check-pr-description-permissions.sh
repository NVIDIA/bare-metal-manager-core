#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
	echo "Usage: check-pr-description-permissions.sh [workflow-path]"
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
workflow_path="${1:-${repo_root}/.github/workflows/pr-description.yml}"

# `GET /pulls/{number}` accepts either pull-request or contents read access.
# The base template already requires `contents: read`, so that one scope covers
# both reads. Only this job publishes the status used by branch protection.
bash "${script_dir}/check-ci-permissions.sh" \
	--workflow-name "Pull Request Description" \
	--workflow-path "${workflow_path}" \
	--workflow-permissions "contents=read" \
	--job-permissions "validate=contents=read,statuses=write"
