#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Cache-backend selection for the Rust builder stages.
#
# Sourced rather than executed, so that the variables sccache_setup exports
# reach the cargo invocation that follows it:
#
#   . /carbide/dev/docker/sccache-cache.sh && \
#     sccache_setup && \
#     cargo build ... && \
#     sccache_report
#
# POSIX sh only -- a Dockerfile RUN is interpreted by /bin/sh.

# Number of backend writes sccache has failed so far, or 0 when it cannot be
# determined. The text output is parsed as a fallback because --stats-format is
# the newer of the two interfaces.
sccache_write_errors() {
	_errors="$(sccache --show-stats --stats-format=json 2>/dev/null |
		grep -oE '"cache_write_errors" *: *[0-9]+' |
		head -n 1 |
		grep -oE '[0-9]+$')"
	if [ -z "${_errors}" ]; then
		_errors="$(sccache --show-stats 2>/dev/null |
			awk '/^Cache write errors/ { print $NF; exit }')"
	fi
	case "${_errors}" in
	'' | *[!0-9]*) echo 0 ;;
	*) echo "${_errors}" ;;
	esac
}

sccache_dump_log() {
	[ -n "${SCCACHE_ERROR_LOG}" ] && [ -s "${SCCACHE_ERROR_LOG}" ] || return 0
	echo "--- sccache server log (deduplicated, last 40 lines) ---"
	# A failing backend produces one near-identical line per compilation, so
	# thousands of them collapse to a handful of distinct messages.
	sort -u "${SCCACHE_ERROR_LOG}" | tail -n 40
	echo "--- end sccache server log ---"
	# Truncated so that a later dump reports only what happened since, rather
	# than reprinting the setup-time failure.
	: >"${SCCACHE_ERROR_LOG}"
	return 0
}

# A single greppable marker for both the "never worked" and the "stopped
# working partway through" case.
sccache_degraded_banner() {
	echo "=============================================================="
	echo "SCCACHE_BACKEND_DEGRADED: $1"
	echo "Compiled output is not being shared with the next build."
	echo "=============================================================="
	return 0
}

# Whether the configured backend actually stores anything. `sccache
# --start-server` only proves the local daemon came up: sccache latches into
# read-only mode for the life of the process once a backend write fails, so a
# server that starts cleanly can still silently discard every artifact for the
# rest of the build. The only reliable check is to compile something and look
# at the resulting write-error count.
sccache_backend_writable() {
	_probe_dir="$(mktemp -d)" || return 1
	echo 'pub fn probe() {}' >"${_probe_dir}/probe.rs"
	# Deliberately an ordinary rlib compile. sccache only writes to the
	# backend for invocations it considers cacheable, so a probe using an
	# exotic --emit would pass without exercising a write.
	sccache rustc --crate-name sccache_probe --crate-type lib \
		"${_probe_dir}/probe.rs" --out-dir "${_probe_dir}" >/dev/null 2>&1
	_probe_rc=$?
	rm -rf "${_probe_dir}"
	[ "${_probe_rc}" -eq 0 ] || return 1
	# The server stores the result after answering the client, so the
	# counter is not necessarily up to date the instant the compile returns.
	sleep 3
	SCCACHE_PROBE_WRITE_ERRORS="$(sccache_write_errors)"
	[ "${SCCACHE_PROBE_WRITE_ERRORS}" -eq 0 ]
}

sccache_setup() {
	SCCACHE_ERROR_LOG=/tmp/sccache-server.log
	SCCACHE_LOG=warn
	SCCACHE_PROBE_WRITE_ERRORS=unknown
	export SCCACHE_ERROR_LOG SCCACHE_LOG

	# No credentials: a plain local `docker build`, where the BuildKit cache
	# mount is the only backend available.
	if ! grep -qE "^https?://" /run/secrets/actions_results_url 2>/dev/null; then
		echo "sccache: using local cache mount at ${SCCACHE_DIR}"
		sccache --start-server >/dev/null 2>&1 || true
		return 0
	fi

	SCCACHE_GHA_ENABLED=true
	ACTIONS_RESULTS_URL="$(cat /run/secrets/actions_results_url)"
	ACTIONS_RUNTIME_TOKEN="$(cat /run/secrets/actions_runtime_token)"
	export SCCACHE_GHA_ENABLED ACTIONS_RESULTS_URL ACTIONS_RUNTIME_TOKEN

	if ! sccache --start-server >/dev/null 2>&1; then
		_reason="the sccache server would not start"
	elif ! sccache_backend_writable; then
		_reason="the Actions cache rejected the write probe (${SCCACHE_PROBE_WRITE_ERRORS} write errors)"
	else
		echo "sccache: using GitHub Actions cache backend"
		return 0
	fi

	sccache_dump_log
	sccache_degraded_banner "${_reason}; falling back to the local cache mount"
	# A restart is required, not just a reconfigure: read-only mode is held
	# by the running server and survives any change to the environment.
	sccache --stop-server >/dev/null 2>&1 || true
	unset SCCACHE_GHA_ENABLED ACTIONS_RESULTS_URL ACTIONS_RUNTIME_TOKEN
	sccache --start-server >/dev/null 2>&1 || true
	return 0
}

sccache_report() {
	sccache --show-stats || true
	sccache_dump_log
	_errors="$(sccache_write_errors)"
	if [ "${_errors}" -gt 0 ]; then
		sccache_degraded_banner "${_errors} cache write errors during the build"
	fi
	return 0
}
