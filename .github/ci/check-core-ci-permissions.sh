#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if (( BASH_VERSINFO[0] < 4 )); then
	printf 'check-core-ci-permissions.sh requires Bash 4 or newer.\n' >&2
	exit 2
fi

# This checker treats `ci.yaml` as a small permission contract, not arbitrary
# YAML. AWK reads the workflow and job permission mappings we support and emits
# tab-delimited records; Bash compares those records with the exact reviewed
# inventory below. Anything unfamiliar fails closed so a workflow rewrite
# cannot quietly put a token scope outside the policy.
#
# Root and job-property keys use canonical plain YAML syntax. Rejecting anchors,
# escapes, merge keys, and other decorated forms prevents them from hiding a
# semantic `permissions` key from this deliberately small parser.

readonly EXPECTED_WORKFLOW_PERMISSIONS="contents=read"
readonly WORKFLOW_OWNER="::workflow::"

# Each job-level block replaces the workflow default instead of extending it.
# Keep each complete exception here so a new scope cannot hide beside one that
# was already reviewed.
declare -Ar EXPECTED_JOB_PERMISSIONS=(
	[lint-police]="contents=read,pull-requests=read"
	[security-codeql-scan]="actions=read,contents=read"
)

usage() {
	echo "Usage: check-core-ci-permissions.sh [workflow-path]"
}

normalize_permissions() {
	local permissions="$1"
	local permission
	local -a entries

	if [[ -z "${permissions}" ]]; then
		return
	fi

	IFS=',' read -r -a entries <<< "${permissions}"
	for permission in "${entries[@]}"; do
		if [[ ! "${permission}" =~ ^[a-z][a-z-]*=(read|write|none)$ ]]; then
			printf 'Invalid permission inventory entry: %s.\n' "${permission}" >&2
			return 1
		fi
	done

	printf '%s\n' "${permissions}" |
		tr ',' '\n' |
		LC_ALL=C sort |
		paste -sd, -
}

permission_is_expected() {
	local expected_permissions="$1"
	local permission="$2"

	[[ ",${expected_permissions}," == *",${permission},"* ]]
}

# `extract_permission_records` emits `job`, `blocks`, and `permission` records
# for supported input. Anything else becomes an `inline`, `invalid`, `misplaced`,
# or `unparsed` record for the Bash pass to reject.
extract_permission_records() {
	local workflow_path="$1"

	awk -v workflow_owner="${WORKFLOW_OWNER}" '
		function without_comment(value) {
			sub(/[[:space:]]+#.*$/, "", value)
			sub(/[[:space:]]+$/, "", value)
			return value
		}

		function emit_permission(owner, line, scope, access) {
			line = without_comment(line)
			scope = line
			sub(/:.*/, "", scope)
			access = line
			sub(/^[^:]+:[[:space:]]*/, "", access)

			if (scope !~ /^[a-z][a-z-]*$/ || access !~ /^(read|write|none)$/) {
				printf "invalid\t%s\t%s\n", owner, line
				return
			}

			printf "permission\t%s\t%s\t%s\n", owner, scope, access
		}

		function is_job_key(value) {
			return value ~ /^[A-Za-z_][A-Za-z0-9_-]*:[[:space:]]*$/ ||
				value ~ /^"[A-Za-z_][A-Za-z0-9_-]*":[[:space:]]*$/ ||
				value ~ /^\047[A-Za-z_][A-Za-z0-9_-]*\047:[[:space:]]*$/
		}

		function is_canonical_property(value) {
			return value ~ /^[A-Za-z_][A-Za-z0-9_-]*:[[:space:]]*/
		}

		function normalize_job_key(value, first, last) {
			sub(/:[[:space:]]*$/, "", value)
			first = substr(value, 1, 1)
			last = substr(value, length(value), 1)
			if ((first == "\"" && last == "\"") ||
				(first == "\047" && last == "\047")) {
				return substr(value, 2, length(value) - 2)
			}
			return value
		}

		function is_permissions_key(value) {
			return value ~ /^(permissions|"permissions"|\047permissions\047)[[:space:]]*:/
		}

		function permissions_remainder(value) {
			sub(/^(permissions|"permissions"|\047permissions\047)[[:space:]]*:[[:space:]]*/, "", value)
			return value
		}

		{
			raw = $0
			content = raw
			sub(/^ */, "", content)
			if (content == "" || content ~ /^#/) {
				next
			}

			indent = length(raw) - length(content)
			content = without_comment(content)
			if (content == "") {
				next
			}

			if (in_root_permissions && indent == 0 && !is_permissions_key(content)) {
				in_root_permissions = 0
			}
			if (in_job_permissions && indent <= 4 && !is_permissions_key(content)) {
				in_job_permissions = 0
			}

			if (in_jobs && indent == 0 && content != "jobs:") {
				in_jobs = 0
				current_job = ""
			}

			if (indent == 0 && content == "jobs:") {
				in_jobs = 1
				next
			}

			if (indent == 0 && is_permissions_key(content)) {
				root_blocks++
				remainder = permissions_remainder(content)
				if (remainder != "") {
					printf "inline\t%s\t%s\n", workflow_owner, remainder
				} else {
					in_root_permissions = 1
				}
				next
			}
			if (indent == 0 && !is_canonical_property(content)) {
				printf "unparsed-root\t%s\n", content
				next
			}

			if (in_jobs && indent == 2 && is_job_key(content)) {
				current_job = normalize_job_key(content)
				printf "job\t%s\n", current_job
				next
			}
			if (in_jobs && indent == 2) {
				printf "unparsed\t%s\n", content
				current_job = ""
				next
			}

			if (in_jobs && current_job != "" && indent > 2 &&
				!(current_job in job_property_seen)) {
				job_property_seen[current_job] = 1
				if (indent != 4) {
					printf "misplaced\t%s\t%d\n", current_job, indent
					next
				}
			}

			if (in_jobs && current_job != "" && indent == 4 && is_permissions_key(content)) {
				job_blocks[current_job]++
				remainder = permissions_remainder(content)
				if (remainder != "") {
					printf "inline\t%s\t%s\n", current_job, remainder
				} else {
					in_job_permissions = 1
				}
				next
			}
			if (in_jobs && current_job != "" && indent == 4 &&
				!is_canonical_property(content)) {
				printf "unparsed-property\t%s\t%s\n", current_job, content
				next
			}

			if (in_jobs && current_job != "" && indent == 6 &&
				is_permissions_key(content)) {
				printf "misplaced\t%s\t%d\n", current_job, indent
				in_job_permissions = 0
				next
			}

			if (in_root_permissions && indent == 2) {
				emit_permission(workflow_owner, content)
				next
			}
			if (in_job_permissions && indent == 6) {
				emit_permission(current_job, content)
			}
		}

		END {
			printf "blocks\t%s\t%d\n", workflow_owner, root_blocks
			for (job in job_blocks) {
				printf "blocks\t%s\t%d\n", job, job_blocks[job]
			}
		}
	' "${workflow_path}"
}

# `validate_permissions` returns success only when the workflow default and
# every job override exactly matches the reviewed inventories. It reports every
# mismatch it finds before returning failure so CI shows what needs review.
validate_permissions() {
	local workflow_path="$1"
	local record
	local owner
	local scope
	local access
	local display_owner
	local expected
	local actual
	local job
	local records
	local job_count=0
	local failed=0
	local -A actual_permissions=()
	local -A permission_blocks=()
	local -A seen_jobs=()

	if ! records="$(extract_permission_records "${workflow_path}")"; then
		printf 'Failed to parse permissions from %s.\n' "${workflow_path}" >&2
		return 1
	fi

	while IFS=$'\t' read -r record owner scope access; do
		display_owner="${owner}"
		if [[ "${owner}" == "${WORKFLOW_OWNER}" ]]; then
			display_owner="workflow"
		fi

		case "${record}" in
		job)
			seen_jobs["${owner}"]=1
			job_count=$((job_count + 1))
			;;
		blocks)
			permission_blocks["${owner}"]="${scope}"
			;;
		permission)
			if [[ -n "${actual_permissions[${owner}]:-}" ]]; then
				actual_permissions["${owner}"]+=","
			fi
			actual_permissions["${owner}"]+="${scope}=${access}"

			if [[ "${access}" == "write" ]]; then
				if [[ "${owner}" == "${WORKFLOW_OWNER}" ]]; then
					printf 'Workflow-wide write permission %s:write is not allowed.\n' "${scope}" >&2
					failed=1
				elif ! permission_is_expected "${EXPECTED_JOB_PERMISSIONS[${owner}]:-}" "${scope}=write"; then
					printf 'Unreviewed write permission %s:write on job %s.\n' "${scope}" "${owner}" >&2
					failed=1
				fi
			fi
			;;
		inline)
			printf 'Inline permissions value %s on %s is not allowed.\n' \
				"${scope}" "${display_owner}" >&2
			failed=1
			;;
		invalid)
			printf 'Invalid permission entry %s on %s.\n' \
				"${scope}" "${display_owner}" >&2
			failed=1
			;;
		misplaced)
			printf 'Job properties on job %s must use four-space indentation; found %s spaces.\n' \
				"${owner}" "${scope}" >&2
			failed=1
			;;
		unparsed)
			printf 'Unrecognized jobs entry: %s.\n' "${owner}" >&2
			failed=1
			;;
		unparsed-root)
			printf 'Top-level workflow properties must use canonical unquoted keys; found %s.\n' \
				"${owner}" >&2
			failed=1
			;;
		unparsed-property)
			printf 'Job properties on job %s must use canonical unquoted keys; found %s.\n' \
				"${owner}" "${scope}" >&2
			failed=1
			;;
		esac
	done <<< "${records}"

	if [[ "${permission_blocks[${WORKFLOW_OWNER}]:-0}" != "1" ]]; then
		printf 'Expected exactly one workflow permissions block in %s; found %s.\n' \
			"${workflow_path}" "${permission_blocks[${WORKFLOW_OWNER}]:-0}" >&2
		failed=1
	fi

	expected="$(normalize_permissions "${EXPECTED_WORKFLOW_PERMISSIONS}")"
	actual="$(normalize_permissions "${actual_permissions[${WORKFLOW_OWNER}]:-}")"
	if [[ "${actual}" != "${expected}" ]]; then
		printf 'Workflow permissions must be %s; found %s.\n' \
			"${expected}" "${actual:-none}" >&2
		failed=1
	fi

	for job in "${!EXPECTED_JOB_PERMISSIONS[@]}"; do
		if [[ -z "${seen_jobs[${job}]+present}" ]]; then
			printf 'Permission inventory names missing job %s.\n' "${job}" >&2
			failed=1
			continue
		fi

		if [[ "${permission_blocks[${job}]:-0}" != "1" ]]; then
			printf 'Expected exactly one permissions block on job %s; found %s.\n' \
				"${job}" "${permission_blocks[${job}]:-0}" >&2
			failed=1
			continue
		fi

		expected="$(normalize_permissions "${EXPECTED_JOB_PERMISSIONS[${job}]}")"
		actual="$(normalize_permissions "${actual_permissions[${job}]:-}")"
		if [[ "${actual}" != "${expected}" ]]; then
			printf 'Permissions for job %s must be %s; found %s.\n' \
				"${job}" "${expected}" "${actual:-none}" >&2
			failed=1
		fi
	done

	for job in "${!permission_blocks[@]}"; do
		if [[ "${job}" == "${WORKFLOW_OWNER}" ]]; then
			continue
		fi
		if [[ -z "${EXPECTED_JOB_PERMISSIONS[${job}]+reviewed}" ]]; then
			printf 'Job %s has a permissions block that is not in the inventory.\n' "${job}" >&2
			failed=1
		fi
	done

	if (( job_count == 0 )); then
		printf 'No Core CI jobs found in %s.\n' "${workflow_path}" >&2
		failed=1
	fi

	if (( failed )); then
		return 1
	fi

	printf 'Checked %d Core CI jobs: %d use the workflow default and %d use reviewed job permissions.\n' \
		"${job_count}" "$((job_count - ${#EXPECTED_JOB_PERMISSIONS[@]}))" \
		"${#EXPECTED_JOB_PERMISSIONS[@]}"
}

run_fixture() {
	local fixture_dir="$1"
	local fixture_name="$2"
	local expected_result="$3"
	local expected_message="$4"
	local fixture="$5"
	local fixture_path="${fixture_dir}/${fixture_name}.yaml"
	local output
	local actual_result

	printf '%s' "${fixture}" > "${fixture_path}"
	if output="$(validate_permissions "${fixture_path}" 2>&1)"; then
		actual_result="pass"
	else
		actual_result="fail"
	fi

	if [[ "${actual_result}" != "${expected_result}" ]]; then
		printf 'Fixture %s expected %s, got %s:\n%s\n' \
			"${fixture_name}" "${expected_result}" "${actual_result}" "${output}" >&2
		return 1
	fi

	if [[ -n "${expected_message}" && "${output}" != *"${expected_message}"* ]]; then
		printf 'Fixture %s did not report %s:\n%s\n' \
			"${fixture_name}" "${expected_message}" "${output}" >&2
		return 1
	fi
}

run_fixture_tests() (
	local fixture_dir
	local valid_fixture
	local missing_default
	local workflow_write
	local unreviewed_read
	local unreviewed_write
	local broadened_exception
	local quoted_jobs
	local quoted_lint_job
	local double_quoted_job_write
	local single_quoted_job_write
	local escaped_job_write
	local anchored_job_write
	local escaped_workflow_write
	local missing_inventory_job
	local off_indent
	local deep_off_indent
	local job_write_all
	local spaced_job_write_all
	local invalid_access
	local duplicate_workflow_block
	local over_indent_entries
	local trailing_root_permissions
	local step_input_permissions
	local workflow_mapping_write
	local workflow_owner_collision
	local flow_style_job
	local -r expected_fixture_count=25
	local fixture_count=0
	local failed=0

	fixture_dir="$(mktemp -d)"
	trap 'rm -rf -- "${fixture_dir}"' EXIT

	# Start with one valid workflow and mutate one policy rule or supported form
	# at a time. That keeps each failure tied to the boundary named by its case.
	printf -v valid_fixture '%s\n' \
		'name: Permission fixture' \
		'permissions:' \
		'  contents: read' \
		'jobs:' \
		'  ordinary:' \
		'    runs-on: ubuntu-latest' \
		'  lint-police:' \
		'    permissions:' \
		'      contents: read' \
		'      pull-requests: read' \
		'    runs-on: ubuntu-latest' \
		'  security-codeql-scan:' \
		'    permissions:' \
		'      actions: read' \
		'      contents: read' \
		'    runs-on: ubuntu-latest'

	missing_default="${valid_fixture/$'permissions:\n  contents: read\n'/}"
	workflow_write="${valid_fixture/$'permissions:\n  contents: read'/'permissions: write-all'}"
	unreviewed_read="${valid_fixture/$'  ordinary:\n    runs-on: ubuntu-latest'/$'  ordinary:\n    permissions:\n      contents: read\n    runs-on: ubuntu-latest'}"
	unreviewed_write="${valid_fixture/$'  ordinary:\n    runs-on: ubuntu-latest'/$'  ordinary:\n    permissions:\n      contents: read\n      issues: write\n    runs-on: ubuntu-latest'}"
	double_quoted_job_write="${unreviewed_write/$'    permissions:'/$'    "permissions":'}"
	single_quoted_job_write="${unreviewed_write/$'    permissions:'/$'    \047permissions\047:'}"
	escaped_job_write="${unreviewed_write/$'    permissions:'/$'    "permis\\x73ions":'}"
	anchored_job_write="${unreviewed_write/$'    permissions:'/$'    &permission_key permissions:'}"
	broadened_exception="${valid_fixture/$'      pull-requests: read'/$'      pull-requests: write'}"
	quoted_lint_job="${valid_fixture/$'  lint-police:'/$'  "lint-police":'}"
	if [[ "${quoted_lint_job}" == "${valid_fixture}" ]]; then
		printf 'Fixture quoted-job-keys could not quote lint-police.\n' >&2
		return 1
	fi
	quoted_jobs="${quoted_lint_job/$'  security-codeql-scan:'/$'  \047security-codeql-scan\047:'}"
	if [[ "${quoted_jobs}" == "${quoted_lint_job}" ]]; then
		printf 'Fixture quoted-job-keys could not quote security-codeql-scan.\n' >&2
		return 1
	fi
	missing_inventory_job="${valid_fixture/$'  lint-police:'/$'  renamed-lint-police:'}"
	off_indent="${valid_fixture/$'  ordinary:\n    runs-on: ubuntu-latest'/$'  ordinary:\n      permissions:\n        contents: read\n      runs-on: ubuntu-latest'}"
	deep_off_indent="${valid_fixture/$'  ordinary:\n    runs-on: ubuntu-latest'/$'  ordinary:\n        permissions:\n          contents: read\n        runs-on: ubuntu-latest'}"
	job_write_all="${valid_fixture/$'  ordinary:\n    runs-on: ubuntu-latest'/$'  ordinary:\n    permissions: write-all\n    runs-on: ubuntu-latest'}"
	spaced_job_write_all="${job_write_all/$'    permissions: write-all'/$'    permissions : write-all'}"
	invalid_access="${valid_fixture/$'permissions:\n  contents: read'/$'permissions:\n  contents: readonly'}"
	workflow_mapping_write="${valid_fixture/$'permissions:\n  contents: read'/$'permissions:\n  contents: write'}"
	escaped_workflow_write="${workflow_mapping_write/$'permissions:'/$'"permis\\x73ions":'}"
	workflow_owner_collision="${missing_default/$'  ordinary:\n    runs-on: ubuntu-latest'/$'  workflow:\n    permissions:\n      contents: read\n    runs-on: ubuntu-latest'}"
	flow_style_job="${valid_fixture/$'  ordinary:\n    runs-on: ubuntu-latest'/$'  ordinary: {permissions: write-all}'}"
	duplicate_workflow_block="${valid_fixture/$'permissions:\n  contents: read'/$'permissions:\n  contents: read\npermissions:\n  contents: read'}"
	over_indent_entries="${valid_fixture/$'      pull-requests: read'/$'        pull-requests: read'}"
	trailing_root_permissions="${valid_fixture/$'permissions:\n  contents: read\n'/}"
	trailing_root_permissions+=$'permissions:\n  contents: read\n'
	step_input_permissions="${valid_fixture/$'  ordinary:\n    runs-on: ubuntu-latest'/$'  ordinary:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: fixture/action@v1\n        with:\n          permissions: read-all'}"
	if [[ "${step_input_permissions}" == "${valid_fixture}" ]]; then
		printf 'Fixture step-input-permissions could not add the step input.\n' >&2
		return 1
	fi

	run_counted_fixture() {
		fixture_count=$((fixture_count + 1))
		run_fixture "$@" || failed=1
	}

	run_counted_fixture "${fixture_dir}" "complete" "pass" "" "${valid_fixture}"
	run_counted_fixture "${fixture_dir}" "quoted-job-keys" "pass" "" "${quoted_jobs}"
	run_counted_fixture "${fixture_dir}" "trailing-root-permissions" "pass" "" \
		"${trailing_root_permissions}"
	run_counted_fixture "${fixture_dir}" "step-input-permissions" "pass" "" \
		"${step_input_permissions}"
	run_counted_fixture "${fixture_dir}" "implicit-default" "fail" \
		"Expected exactly one workflow permissions block" "${missing_default}"
	run_counted_fixture "${fixture_dir}" "workflow-write-all" "fail" \
		"Inline permissions value write-all on workflow is not allowed" "${workflow_write}"
	run_counted_fixture "${fixture_dir}" "workflow-mapping-write" "fail" \
		"Workflow-wide write permission contents:write is not allowed" \
		"${workflow_mapping_write}"
	run_counted_fixture "${fixture_dir}" "workflow-owner-collision" "fail" \
		"Job workflow has a permissions block that is not in the inventory" \
		"${workflow_owner_collision}"
	run_counted_fixture "${fixture_dir}" "flow-style-job" "fail" \
		"Unrecognized jobs entry: ordinary: {permissions: write-all}" \
		"${flow_style_job}"
	run_counted_fixture "${fixture_dir}" "unreviewed-job-read" "fail" \
		"Job ordinary has a permissions block that is not in the inventory" "${unreviewed_read}"
	run_counted_fixture "${fixture_dir}" "unreviewed-job-write" "fail" \
		"Unreviewed write permission issues:write on job ordinary" "${unreviewed_write}"
	run_counted_fixture "${fixture_dir}" "double-quoted-job-write" "fail" \
		"Unreviewed write permission issues:write on job ordinary" \
		"${double_quoted_job_write}"
	run_counted_fixture "${fixture_dir}" "single-quoted-job-write" "fail" \
		"Unreviewed write permission issues:write on job ordinary" \
		"${single_quoted_job_write}"
	run_counted_fixture "${fixture_dir}" "escaped-job-write" "fail" \
		"Job properties on job ordinary must use canonical unquoted keys" \
		"${escaped_job_write}"
	run_counted_fixture "${fixture_dir}" "anchored-job-write" "fail" \
		"Job properties on job ordinary must use canonical unquoted keys" \
		"${anchored_job_write}"
	run_counted_fixture "${fixture_dir}" "escaped-workflow-write" "fail" \
		"Top-level workflow properties must use canonical unquoted keys" \
		"${escaped_workflow_write}"
	run_counted_fixture "${fixture_dir}" "broadened-exception" "fail" \
		"Unreviewed write permission pull-requests:write on job lint-police" "${broadened_exception}"
	run_counted_fixture "${fixture_dir}" "missing-inventory-job" "fail" \
		"Permission inventory names missing job lint-police" "${missing_inventory_job}"
	run_counted_fixture "${fixture_dir}" "off-indent-permissions" "fail" \
		"Job properties on job ordinary must use four-space indentation" "${off_indent}"
	run_counted_fixture "${fixture_dir}" "deep-off-indent-permissions" "fail" \
		"Job properties on job ordinary must use four-space indentation; found 8 spaces" \
		"${deep_off_indent}"
	run_counted_fixture "${fixture_dir}" "over-indent-entries" "fail" \
		"Permissions for job lint-police must be" "${over_indent_entries}"
	run_counted_fixture "${fixture_dir}" "job-write-all" "fail" \
		"Inline permissions value write-all on ordinary is not allowed" "${job_write_all}"
	run_counted_fixture "${fixture_dir}" "spaced-job-write-all" "fail" \
		"Inline permissions value write-all on ordinary is not allowed" \
		"${spaced_job_write_all}"
	run_counted_fixture "${fixture_dir}" "invalid-access" "fail" \
		"Invalid permission entry contents: readonly on workflow" "${invalid_access}"
	run_counted_fixture "${fixture_dir}" "duplicate-workflow-block" "fail" \
		"Expected exactly one workflow permissions block" "${duplicate_workflow_block}"

	if (( fixture_count != expected_fixture_count )); then
		printf 'Expected %d Core CI permission fixtures; ran %d.\n' \
			"${expected_fixture_count}" "${fixture_count}" >&2
		failed=1
	fi

	if (( failed )); then
		return 1
	fi

	printf 'Checked %d Core CI permission fixtures.\n' "${fixture_count}"
)

if (( $# > 1 )); then
	usage >&2
	exit 2
fi

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
	usage
	exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workflow_path="${1:-${repo_root}/.github/workflows/ci.yaml}"

if [[ ! -f "${workflow_path}" ]]; then
	printf 'Workflow not found: %s\n' "${workflow_path}" >&2
	exit 2
fi

run_fixture_tests
validate_permissions "${workflow_path}"
