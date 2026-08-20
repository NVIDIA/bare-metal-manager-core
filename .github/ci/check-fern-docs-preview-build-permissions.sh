#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
	echo "Usage: check-fern-docs-preview-build-permissions.sh [workflow-path]"
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
workflow_path="${1:-${repo_root}/.github/workflows/fern-docs-preview-build.yml}"

# The build workflow only reads sources and uploads an artifact. The privileged
# pull request comment lives in the companion workflow.
bash "${script_dir}/check-ci-permissions.sh" \
	--workflow-name "Preview Fern Docs: Build" \
	--workflow-path "${workflow_path}" \
	--workflow-permissions "contents=read"
