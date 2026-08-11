#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# The copy PR bot rewrites its synthetic branch after rebases and force-pushes,
# so that branch's previous SHA is not a durable scan boundary. Resolve the
# current PR base and emit nothing unless it and this workflow's commit form a
# non-empty range in the checkout. Otherwise, fail before the scanner can
# report a clean result.

fail() {
	printf '::error::Could not resolve PR secret-scan range: %s\n' "$1" >&2
	exit 1
}

for variable_name in \
	GH_TOKEN \
	GITHUB_REF \
	GITHUB_REPOSITORY \
	GITHUB_SHA \
	GITHUB_WORKSPACE; do
	[[ -n "${!variable_name:-}" ]] || fail "\`${variable_name}\` is not set"
done

if [[ "$GITHUB_REF" =~ ^refs/heads/pull-request/([1-9][0-9]*)$ ]]; then
	pull_request_number="${BASH_REMATCH[1]}"
else
	fail "\`GITHUB_REF\` is not a pull request ref: ${GITHUB_REF}"
fi

commit_pattern='^[0-9a-fA-F]{40}$'
[[ "$GITHUB_SHA" =~ $commit_pattern ]] \
	|| fail "\`GITHUB_SHA\` is not a full commit SHA"

if ! pull_request_json=$(curl --disable --fail --silent --show-error \
	--connect-timeout 10 \
	--max-time 30 \
	-H "Authorization: Bearer ${GH_TOKEN}" \
	-H 'Accept: application/vnd.github+json' \
	-H 'X-GitHub-Api-Version: 2022-11-28' \
	"https://api.github.com/repos/${GITHUB_REPOSITORY}/pulls/${pull_request_number}"); then
	fail "could not load pull request #${pull_request_number} from GitHub"
fi

if ! base_sha=$(jq --exit-status --raw-output \
	'.base.sha | select(type == "string")' \
	<<< "$pull_request_json"); then
	fail "GitHub returned incomplete data for pull request #${pull_request_number}"
fi

[[ "$base_sha" =~ $commit_pattern ]] \
	|| fail "GitHub returned an invalid pull request base"

if ! merge_base=$(git -C "$GITHUB_WORKSPACE" merge-base "$base_sha" "$GITHUB_SHA"); then
	fail "could not compute a merge base for the pull request base and workflow commit"
fi
[[ "${merge_base,,}" != "${GITHUB_SHA,,}" ]] \
	|| fail "the pull request scan range is empty"

printf 'base=%s\nhead=%s\n' "${merge_base,,}" "${GITHUB_SHA,,}"
