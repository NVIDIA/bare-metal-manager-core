#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
	echo "Usage: check-docs-pages-permissions.sh [workflow-path]"
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
workflow_path="${1:-${repo_root}/.github/workflows/docs.yml}"

# Building reads the Pages site configuration. Only deployment publishes the
# artifact and requests the OIDC token used by GitHub Pages.
bash "${script_dir}/check-ci-permissions.sh" \
	--workflow-name "GitHub Pages" \
	--workflow-path "${workflow_path}" \
	--workflow-permissions "pages=read" \
	--job-permissions "deploy=id-token=write,pages=write"
