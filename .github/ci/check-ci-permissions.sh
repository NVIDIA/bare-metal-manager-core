#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
	printf 'check-ci-permissions.sh requires Bash 4.4 or newer.\n' >&2
	exit 2
fi

# This checker treats one selected workflow as a small permission contract, not
# arbitrary YAML. AWK reads the workflow and job permission mappings we support
# and emits tab-delimited records; Bash compares those records with the exact
# policy supplied by a workflow-specific wrapper. Anything unfamiliar fails
# closed so a workflow rewrite cannot quietly put a token scope outside its
# reviewed policy.
#
# Workflow-wide write access is never an accepted policy. A workflow must move
# each write into the exact job that needs it before this checker can adopt it.
#
# Root and job-property keys use canonical plain YAML syntax. Rejecting anchors,
# escapes, merge keys, and other decorated forms prevents them from hiding a
# semantic `permissions` key from this deliberately small parser.

readonly WORKFLOW_OWNER="::workflow::"
WORKFLOW_NAME=""
EXPECTED_WORKFLOW_PERMISSIONS=""
declare -A EXPECTED_JOB_PERMISSIONS=()

usage() {
	printf '%s\n' \
		'Usage: check-ci-permissions.sh --workflow-name NAME --workflow-path PATH' \
		'       --workflow-permissions INVENTORY' \
		'       [--job-permissions JOB=INVENTORY]...' \
		'   or: check-ci-permissions.sh --self-test' \
		'   or: check-ci-permissions.sh (-h | --help)'
}

normalize_permissions() {
	local permissions="$1"
	local context="${2:-}"
	local permission
	local scope
	local -a entries
	local -A seen_scopes=()

	if [[ -z "${permissions}" ]]; then
		return
	fi

	IFS=',' read -r -a entries <<< "${permissions}"
	for permission in "${entries[@]}"; do
		if [[ ! "${permission}" =~ ^[a-z][a-z-]*=(read|write|none)$ ]]; then
			printf 'Invalid permission inventory entry: %s.\n' "${permission}" >&2
			return 1
		fi
		scope="${permission%%=*}"
		if [[ -n "${seen_scopes[${scope}]+present}" ]]; then
			if [[ -n "${context}" ]]; then
				printf 'Duplicate permission scope %s in %s.\n' \
					"${scope}" "${context}" >&2
			else
				printf 'Duplicate permission inventory scope: %s.\n' "${scope}" >&2
			fi
			return 1
		fi
		seen_scopes["${scope}"]=1
	done

	printf '%s\n' "${permissions}" |
		tr ',' '\n' |
		LC_ALL=C sort |
		paste -sd, -
}

configure_policy() {
	local workflow_name="$1"
	local workflow_permissions="$2"
	shift 2

	local job_policy
	local job
	local permissions
	local normalized_permissions

	if [[ -z "${workflow_name}" ]]; then
		printf 'Workflow name must not be empty.\n' >&2
		return 1
	fi
	if [[ "${workflow_name}" =~ [[:cntrl:]] ]]; then
		printf 'Workflow name must not contain control characters.\n' >&2
		return 1
	fi

	if [[ -z "${workflow_permissions}" ]]; then
		printf 'Workflow permission inventory must not be empty.\n' >&2
		return 1
	fi
	if ! normalized_permissions="$(normalize_permissions "${workflow_permissions}")"; then
		return 1
	fi
	if [[ "${normalized_permissions}" =~ (^|,)[a-z][a-z-]*=write(,|$) ]]; then
		printf 'Workflow permission policy must not allow write access.\n' >&2
		return 1
	fi

	WORKFLOW_NAME="${workflow_name}"
	EXPECTED_WORKFLOW_PERMISSIONS="${normalized_permissions}"
	EXPECTED_JOB_PERMISSIONS=()

	for job_policy in "$@"; do
		if [[ "${job_policy}" != *=* ]]; then
			printf 'Job permission policy must use JOB=INVENTORY: %s.\n' \
				"${job_policy}" >&2
			return 1
		fi

		job="${job_policy%%=*}"
		permissions="${job_policy#*=}"
		if [[ ! "${job}" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]]; then
			printf 'Invalid job name in permission policy: %s.\n' "${job}" >&2
			return 1
		fi
		if [[ -n "${EXPECTED_JOB_PERMISSIONS[${job}]+present}" ]]; then
			printf 'Permission policy names job %s more than once.\n' "${job}" >&2
			return 1
		fi
		if [[ -z "${permissions}" ]]; then
			printf 'Permission inventory for job %s must not be empty.\n' "${job}" >&2
			return 1
		fi
		if ! normalized_permissions="$(normalize_permissions "${permissions}")"; then
			printf 'Invalid permission policy for job %s.\n' "${job}" >&2
			return 1
		fi
		EXPECTED_JOB_PERMISSIONS["${job}"]="${normalized_permissions}"
	done
}

permission_is_expected() {
	local expected_permissions="$1"
	local permission="$2"

	[[ ",${expected_permissions}," == *",${permission},"* ]]
}

# `extract_permission_records` emits `job`, `jobs-blocks`, `blocks`, and
# `permission` records for supported input. Anything else becomes an `inline`,
# `invalid`, `misplaced`, or `unparsed` record for the Bash pass to reject.
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
			if (indent == 0 && content == "---" &&
				!seen_document_start && !seen_content) {
				seen_document_start = 1
				next
			}
			seen_content = 1

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
				jobs_blocks++
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
			printf "jobs-blocks\t%d\n", jobs_blocks
			printf "blocks\t%s\t%d\n", workflow_owner, root_blocks
			for (job in job_blocks) {
				printf "blocks\t%s\t%d\n", job, job_blocks[job]
			}
		}
	' < "${workflow_path}"
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
	local job_word="jobs"
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
			if [[ -n "${seen_jobs[${owner}]+present}" ]]; then
				printf 'Job %s appears more than once.\n' "${owner}" >&2
				failed=1
			else
				seen_jobs["${owner}"]=1
			fi
			job_count=$((job_count + 1))
			;;
		jobs-blocks)
			if [[ "${owner}" != "1" ]]; then
				printf 'Expected exactly one jobs block; found %s.\n' "${owner}" >&2
				failed=1
			fi
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

	expected="${EXPECTED_WORKFLOW_PERMISSIONS}"
	if ! actual="$(normalize_permissions \
		"${actual_permissions[${WORKFLOW_OWNER}]:-}" "workflow")"; then
		actual="invalid"
		failed=1
	fi
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

		expected="${EXPECTED_JOB_PERMISSIONS[${job}]}"
		if ! actual="$(normalize_permissions \
			"${actual_permissions[${job}]:-}" "job ${job}")"; then
			actual="invalid"
			failed=1
		fi
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
		printf 'No %s jobs found in %s.\n' "${WORKFLOW_NAME}" "${workflow_path}" >&2
		failed=1
	fi

	if (( failed )); then
		return 1
	fi
	if (( job_count == 1 )); then
		job_word="job"
	fi

	printf 'Checked %d %s %s: %d use the workflow default and %d use reviewed job permissions.\n' \
		"${job_count}" "${WORKFLOW_NAME}" "${job_word}" \
		"$((job_count - ${#EXPECTED_JOB_PERMISSIONS[@]}))" \
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
	if output="$(
		cd "${fixture_dir}"
		validate_permissions "${fixture_name}.yaml" </dev/null 2>&1
	)"; then
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

run_policy_fixture() (
	local fixture_name="$1"
	local expected_result="$2"
	local expected_message="$3"
	shift 3

	local output
	local actual_result

	if output="$(configure_policy "$@" 2>&1)"; then
		actual_result="pass"
	else
		actual_result="fail"
	fi

	if [[ "${actual_result}" != "${expected_result}" ]]; then
		printf 'Policy fixture %s expected %s, got %s:\n%s\n' \
			"${fixture_name}" "${expected_result}" "${actual_result}" "${output}" >&2
		return 1
	fi

	if [[ -n "${expected_message}" && "${output}" != *"${expected_message}"* ]]; then
		printf 'Policy fixture %s did not report %s:\n%s\n' \
			"${fixture_name}" "${expected_message}" "${output}" >&2
		return 1
	fi
)

run_cli_fixture() {
	local checker_path="$1"
	local fixture_name="$2"
	local expected_status="$3"
	local expected_message="$4"
	shift 4

	local output
	local actual_status

	if output="$(bash "${checker_path}" "$@" 2>&1)"; then
		actual_status=0
	else
		actual_status=$?
	fi

	if (( actual_status != expected_status )); then
		printf 'CLI fixture %s expected status %d, got %d:\n%s\n' \
			"${fixture_name}" "${expected_status}" "${actual_status}" "${output}" >&2
		return 1
	fi

	if [[ -n "${expected_message}" && "${output}" != *"${expected_message}"* ]]; then
		printf 'CLI fixture %s did not report %s:\n%s\n' \
			"${fixture_name}" "${expected_message}" "${output}" >&2
		return 1
	fi
}

run_fixture_tests() (
	local checker_path
	local fixture_dir
	local valid_fixture
	local stale_fixture
	local stale_broadened
	local read_only_fixture
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
	local duplicate_workflow_scope
	local duplicate_jobs_block
	local duplicate_job
	local duplicate_job_scope
	local over_indent_entries
	local trailing_root_permissions
	local step_input_permissions
	local workflow_mapping_write
	local workflow_owner_collision
	local flow_style_job
	local leading_document_start
	local duplicate_document_start
	local mid_document_start
	local -r expected_fixture_count=60
	local fixture_count=0
	local failed=0

	checker_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
	fixture_dir="$(mktemp -d)"
	trap 'rm -rf -- "${fixture_dir}"' EXIT
	configure_policy \
		"Core CI fixture" \
		"contents=read" \
		"lint-police=contents=read,pull-requests=read" \
		"security-codeql-scan=actions=read,contents=read"

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
	duplicate_workflow_scope="${valid_fixture/$'permissions:\n  contents: read'/$'permissions:\n  contents: read\n  contents: read'}"
	duplicate_jobs_block="${valid_fixture}"$'jobs:\n  another:\n    runs-on: ubuntu-latest\n'
	duplicate_job="${valid_fixture/$'  ordinary:\n    runs-on: ubuntu-latest'/$'  ordinary:\n    runs-on: ubuntu-latest\n  ordinary:\n    runs-on: ubuntu-latest'}"
	duplicate_job_scope="${valid_fixture/$'      pull-requests: read'/$'      pull-requests: read\n      contents: read'}"
	over_indent_entries="${valid_fixture/$'      pull-requests: read'/$'        pull-requests: read'}"
	trailing_root_permissions="${valid_fixture/$'permissions:\n  contents: read\n'/}"
	trailing_root_permissions+=$'permissions:\n  contents: read\n'
	step_input_permissions="${valid_fixture/$'  ordinary:\n    runs-on: ubuntu-latest'/$'  ordinary:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: fixture/action@v1\n        with:\n          permissions: read-all'}"
	if [[ "${step_input_permissions}" == "${valid_fixture}" ]]; then
		printf 'Fixture step-input-permissions could not add the step input.\n' >&2
		return 1
	fi
	leading_document_start=$'---\n'"${valid_fixture}"
	duplicate_document_start=$'---\n---\n'"${valid_fixture}"
	mid_document_start="${valid_fixture/$'permissions:'/$'---\npermissions:'}"

	run_counted_fixture() {
		fixture_count=$((fixture_count + 1))
		run_fixture "$@" || failed=1
	}
	run_counted_policy_fixture() {
		fixture_count=$((fixture_count + 1))
		run_policy_fixture "$@" || failed=1
	}
	run_counted_cli_fixture() {
		fixture_count=$((fixture_count + 1))
		run_cli_fixture "${checker_path}" "$@" || failed=1
	}

	run_counted_fixture "${fixture_dir}" "complete" "pass" "" "${valid_fixture}"
	run_counted_fixture "${fixture_dir}" "complete=fixture" "pass" "" "${valid_fixture}"
	run_counted_fixture "${fixture_dir}" "leading-document-start" "pass" "" \
		"${leading_document_start}"
	run_counted_fixture "${fixture_dir}" "duplicate-document-start" "fail" \
		"Top-level workflow properties must use canonical unquoted keys; found ---" \
		"${duplicate_document_start}"
	run_counted_fixture "${fixture_dir}" "mid-document-start" "fail" \
		"Top-level workflow properties must use canonical unquoted keys; found ---" \
		"${mid_document_start}"
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
	run_counted_fixture "${fixture_dir}" "duplicate-workflow-scope" "fail" \
		"Duplicate permission scope contents in workflow" "${duplicate_workflow_scope}"
	run_counted_fixture "${fixture_dir}" "duplicate-jobs-block" "fail" \
		"Expected exactly one jobs block; found 2" "${duplicate_jobs_block}"
	run_counted_fixture "${fixture_dir}" "duplicate-job" "fail" \
		"Job ordinary appears more than once" "${duplicate_job}"
	run_counted_fixture "${fixture_dir}" "duplicate-job-scope" "fail" \
		"Duplicate permission scope contents in job lint-police" "${duplicate_job_scope}"

	printf -v stale_fixture '%s\n' \
		'name: Stale fixture' \
		'permissions:' \
		'  contents: read' \
		'jobs:' \
		'  stale:' \
		'    permissions:' \
		'      issues: write' \
		'      pull-requests: write' \
		'    runs-on: ubuntu-latest'
	stale_broadened="${stale_fixture/$'      pull-requests: write'/$'      pull-requests: write\n      contents: read'}"
	printf -v read_only_fixture '%s\n' \
		'name: Read-only fixture' \
		'permissions:' \
		'  contents: read' \
		'jobs:' \
		'  ordinary:' \
		'    runs-on: ubuntu-latest'

	configure_policy \
		"Stale PR fixture" \
		"contents=read" \
		"stale=issues=write,pull-requests=write"
	run_counted_fixture "${fixture_dir}" "stale-policy" "pass" "" "${stale_fixture}"
	configure_policy "Stale PR fixture" "contents=read"
	run_counted_fixture "${fixture_dir}" "stale-missing-exception" "fail" \
		"Unreviewed write permission issues:write on job stale" "${stale_fixture}"
	configure_policy \
		"Stale PR fixture" \
		"contents=read" \
		"stale=issues=write,pull-requests=write"
	run_counted_fixture "${fixture_dir}" "stale-broadened-exception" "fail" \
		"Permissions for job stale must be" "${stale_broadened}"
	configure_policy "Read-only fixture" "contents=read"
	run_counted_fixture "${fixture_dir}" "read-only-policy" "pass" "" \
		"${read_only_fixture}"

	run_counted_policy_fixture "malformed-job-policy" "fail" \
		"Job permission policy must use JOB=INVENTORY" \
		"Policy fixture" "contents=read" "stale"
	run_counted_policy_fixture "invalid-job-name" "fail" \
		"Invalid job name in permission policy" \
		"Policy fixture" "contents=read" "stale job=issues=write"
	run_counted_policy_fixture "duplicate-job-policy" "fail" \
		"Permission policy names job stale more than once" \
		"Policy fixture" "contents=read" \
		"stale=issues=write" "stale=pull-requests=write"
	run_counted_policy_fixture "empty-job-policy" "fail" \
		"Permission inventory for job stale must not be empty" \
		"Policy fixture" "contents=read" "stale="
	run_counted_policy_fixture "invalid-policy-access" "fail" \
		"Invalid permission inventory entry: issues=admin" \
		"Policy fixture" "contents=read" "stale=issues=admin"
	run_counted_policy_fixture "duplicate-policy-scope" "fail" \
		"Duplicate permission inventory scope: issues" \
		"Policy fixture" "contents=read" "stale=issues=write,issues=write"
	run_counted_policy_fixture "conflicting-policy-scope" "fail" \
		"Duplicate permission inventory scope: issues" \
		"Policy fixture" "contents=read" "stale=issues=read,issues=write"
	run_counted_policy_fixture "workflow-write-policy" "fail" \
		"Workflow permission policy must not allow write access" \
		"Policy fixture" "contents=write"
	run_counted_policy_fixture "control-character-name" "fail" \
		"Workflow name must not contain control characters" \
		$'Policy\nfixture' "contents=read"

	run_counted_cli_fixture "missing-required-options" 2 \
		"Workflow name, path, and permissions are required"
	run_counted_cli_fixture "unknown-option" 2 \
		"Unknown argument: --unknown" "--unknown"
	run_counted_cli_fixture "missing-option-value" 2 \
		"Option --workflow-name requires a value" "--workflow-name"
	run_counted_cli_fixture "duplicate-workflow-name" 2 \
		"Option --workflow-name may be specified only once" \
		"--workflow-name" "one" "--workflow-name" "two"
	run_counted_cli_fixture "duplicate-workflow-path" 2 \
		"Option --workflow-path may be specified only once" \
		"--workflow-path" "one" "--workflow-path" "two"
	run_counted_cli_fixture "duplicate-workflow-permissions" 2 \
		"Option --workflow-permissions may be specified only once" \
		"--workflow-permissions" "contents=read" \
		"--workflow-permissions" "actions=read"
	run_counted_cli_fixture "self-test-with-other-options" 2 \
		"Option --self-test does not accept other arguments" \
		"--self-test" "--workflow-name" "fixture"
	run_counted_cli_fixture "help" 0 \
		"or: check-ci-permissions.sh --self-test" "--help"
	run_counted_cli_fixture "short-help" 0 \
		"or: check-ci-permissions.sh (-h | --help)" "-h"
	run_counted_cli_fixture "help-with-other-options" 2 \
		"Option --help does not accept other arguments" "--help" "extra"
	run_counted_cli_fixture "missing-workflow" 2 \
		"Workflow not found" \
		"--workflow-name" "Missing fixture" \
		"--workflow-path" "${fixture_dir}/missing.yaml" \
		"--workflow-permissions" "contents=read"
	run_counted_cli_fixture "valid-workflow" 0 "Checked 1 Read-only fixture job" \
		"--workflow-name" "Read-only fixture" \
		"--workflow-path" "${fixture_dir}/read-only-policy.yaml" \
		"--workflow-permissions" "contents=read"
	run_counted_cli_fixture "repeated-job-permissions" 0 \
		"Checked 3 Core CI fixture jobs: 1 use the workflow default and 2 use reviewed job permissions" \
		"--workflow-name" "Core CI fixture" \
		"--workflow-path" "${fixture_dir}/complete.yaml" \
		"--workflow-permissions" "contents=read" \
		"--job-permissions" "lint-police=contents=read,pull-requests=read" \
		"--job-permissions" "security-codeql-scan=actions=read,contents=read"
	run_counted_cli_fixture "policy-mismatch" 1 \
		"Workflow permissions must be actions=read; found contents=read" \
		"--workflow-name" "Read-only fixture" \
		"--workflow-path" "${fixture_dir}/read-only-policy.yaml" \
		"--workflow-permissions" "actions=read"

	if (( fixture_count != expected_fixture_count )); then
		printf 'Expected %d CI permission fixtures; ran %d.\n' \
			"${expected_fixture_count}" "${fixture_count}" >&2
		failed=1
	fi

	if (( failed )); then
		return 1
	fi

	printf 'Checked %d CI permission fixtures.\n' "${fixture_count}"
)

validate_from_arguments() {
	local workflow_name=""
	local workflow_path=""
	local workflow_permissions=""
	local option
	local -a job_policies=()
	local workflow_name_seen=0
	local workflow_path_seen=0
	local workflow_permissions_seen=0

	while (( $# > 0 )); do
		option="$1"
		case "${option}" in
		--workflow-name | --workflow-path | --workflow-permissions | --job-permissions)
			if (( $# < 2 )) || [[ "$2" == --* ]]; then
				printf 'Option %s requires a value.\n' "${option}" >&2
				usage >&2
				return 2
			fi
			;;
		*)
			printf 'Unknown argument: %s.\n' "${option}" >&2
			usage >&2
			return 2
			;;
		esac

		case "${option}" in
		--workflow-name)
			if (( workflow_name_seen )); then
				printf 'Option --workflow-name may be specified only once.\n' >&2
				return 2
			fi
			workflow_name="$2"
			workflow_name_seen=1
			;;
		--workflow-path)
			if (( workflow_path_seen )); then
				printf 'Option --workflow-path may be specified only once.\n' >&2
				return 2
			fi
			workflow_path="$2"
			workflow_path_seen=1
			;;
		--workflow-permissions)
			if (( workflow_permissions_seen )); then
				printf 'Option --workflow-permissions may be specified only once.\n' >&2
				return 2
			fi
			workflow_permissions="$2"
			workflow_permissions_seen=1
			;;
		--job-permissions)
			job_policies+=("$2")
			;;
		esac
		shift 2
	done

	if (( ! workflow_name_seen || ! workflow_path_seen || ! workflow_permissions_seen )); then
		printf 'Workflow name, path, and permissions are required.\n' >&2
		usage >&2
		return 2
	fi

	if ! configure_policy \
		"${workflow_name}" \
		"${workflow_permissions}" \
		"${job_policies[@]}"; then
		return 2
	fi

	if [[ ! -f "${workflow_path}" ]]; then
		printf 'Workflow not found: %s\n' "${workflow_path}" >&2
		return 2
	fi
	if [[ ! -r "${workflow_path}" ]]; then
		printf 'Workflow is not readable: %s\n' "${workflow_path}" >&2
		return 2
	fi

	validate_permissions "${workflow_path}"
}

main() {
	if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
		if (( $# != 1 )); then
			printf 'Option %s does not accept other arguments.\n' "$1" >&2
			return 2
		fi
		usage
		return 0
	fi

	if [[ "${1:-}" == "--self-test" ]]; then
		if (( $# != 1 )); then
			printf 'Option --self-test does not accept other arguments.\n' >&2
			return 2
		fi
		run_fixture_tests
		return
	fi

	validate_from_arguments "$@"
}

main "$@"
