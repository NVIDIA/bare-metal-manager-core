#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

context="${1:-Repository check}"

if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
	git config --global --add safe.directory "$(pwd -P)"
fi

untracked="$(git ls-files --others --exclude-standard)"

if git diff --quiet --exit-code && [[ -z "${untracked}" ]]; then
	echo "OK: ${context} left the repository clean."
	exit 0
fi

echo "::error::${context} left uncommitted changes. Regenerate and commit the results."
echo
echo "Changed files:"
git status --porcelain
echo
echo "Diff:"
git -P diff

if [[ -n "${untracked}" ]]; then
	echo
	echo "Untracked files:"
	echo "${untracked}"
fi

exit 1
