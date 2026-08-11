#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
resolver="${script_dir}/resolve-pr-scan-range.sh"
fixture_dir=$(mktemp -d)
trap 'rm -rf -- "$fixture_dir"' EXIT

repository="${fixture_dir}/repository"
mock_bin="${fixture_dir}/bin"
mkdir -p "$repository" "$mock_bin"

cat > "${mock_bin}/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

[[ "${MOCK_CURL_FAIL:-false}" != true ]] || exit 22
[[ "$*" == *'/repos/NVIDIA/infra-controller/pulls/4786'* ]] || exit 64
printf '%s' "$MOCK_PULL_REQUEST_JSON"
EOF
chmod +x "${mock_bin}/curl"

git -C "$repository" init --quiet --initial-branch=main
git -C "$repository" config user.email ci-test@nvidia.com
git -C "$repository" config user.name 'CI Test'
git -C "$repository" config commit.gpgsign false
git -C "$repository" config core.hooksPath /dev/null

printf 'shared\n' > "${repository}/shared.txt"
git -C "$repository" add shared.txt
git -C "$repository" commit --quiet -m 'shared base'
merge_base=$(git -C "$repository" rev-parse HEAD)

git -C "$repository" switch --quiet -c pull-request
printf 'pull request\n' > "${repository}/pull-request.txt"
git -C "$repository" add pull-request.txt
git -C "$repository" commit --quiet -m 'pull request change'
head_sha=$(git -C "$repository" rev-parse HEAD)

git -C "$repository" switch --quiet main
printf 'main\n' > "${repository}/main.txt"
git -C "$repository" add main.txt
git -C "$repository" commit --quiet -m 'main change'
base_sha=$(git -C "$repository" rev-parse HEAD)
git -C "$repository" switch --quiet pull-request

missing_sha=ffffffffffffffffffffffffffffffffffffffff

pull_request_json() {
	local base=$1

	jq --null-input --compact-output \
		--arg base "$base" \
		'{base: {sha: $base}}'
}

run_resolver() {
	local payload=$1
	local ref=$2
	local event_head=$3
	local curl_fail=${4:-false}

	PATH="${mock_bin}:${PATH}" \
	GH_TOKEN='not-a-real-token' \
	GITHUB_REF="$ref" \
	GITHUB_REPOSITORY='NVIDIA/infra-controller' \
	GITHUB_SHA="$event_head" \
	GITHUB_WORKSPACE="$repository" \
	MOCK_PULL_REQUEST_JSON="$payload" \
	MOCK_CURL_FAIL="$curl_fail" \
		bash "$resolver"
}

expect_failure() {
	local name=$1
	local expected_error=$2
	local payload=$3
	local ref=$4
	local event_head=$5
	local curl_fail=${6:-false}
	local output

	if output=$(run_resolver "$payload" "$ref" "$event_head" "$curl_fail" \
		2> "${fixture_dir}/error"); then
		printf 'Expected failure for %s\n' "$name" >&2
		exit 1
	fi
	[[ -z "$output" ]] || {
		printf 'Failure %s wrote step outputs: %s\n' "$name" "$output" >&2
		exit 1
	}
	if ! grep -Fq "::error::Could not resolve PR secret-scan range: ${expected_error}" \
		"${fixture_dir}/error"; then
		printf 'Failure %s did not report the expected error: %s\nActual error:\n' \
			"$name" "$expected_error" >&2
		cat "${fixture_dir}/error" >&2
		exit 1
	fi
}

valid_payload=$(pull_request_json "$base_sha")
expected_output=$(printf 'base=%s\nhead=%s' "$merge_base" "$head_sha")
actual_output=$(run_resolver \
	"$valid_payload" \
	refs/heads/pull-request/4786 \
	"$head_sha")
[[ "$actual_output" == "$expected_output" ]] || {
	printf 'Expected:\n%s\nActual:\n%s\n' "$expected_output" "$actual_output" >&2
	exit 1
}

expect_failure \
	'malformed PR ref' \
	'`GITHUB_REF` is not a pull request ref' \
	"$valid_payload" \
	refs/heads/main \
	"$head_sha"
expect_failure \
	'invalid workflow commit' \
	'`GITHUB_SHA` is not a full commit SHA' \
	"$valid_payload" \
	refs/heads/pull-request/4786 \
	invalid
expect_failure \
	'missing base commit' \
	'could not compute a merge base for the pull request base and workflow commit' \
	"$(pull_request_json "$missing_sha")" \
	refs/heads/pull-request/4786 \
	"$head_sha"
expect_failure \
	'invalid API base' \
	'GitHub returned an invalid pull request base' \
	"$(pull_request_json invalid)" \
	refs/heads/pull-request/4786 \
	"$head_sha"
expect_failure \
	'empty scan range' \
	'the pull request scan range is empty' \
	"$(pull_request_json "$head_sha")" \
	refs/heads/pull-request/4786 \
	"$head_sha"
expect_failure \
	'incomplete API response' \
	'GitHub returned incomplete data for pull request #4786' \
	'{}' \
	refs/heads/pull-request/4786 \
	"$head_sha"
expect_failure \
	'API request failure' \
	'could not load pull request #4786 from GitHub' \
	"$valid_payload" \
	refs/heads/pull-request/4786 \
	"$head_sha" \
	true

printf 'Checked the PR secret-scan range resolver.\n'
