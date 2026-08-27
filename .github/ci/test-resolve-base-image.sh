#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Tests for resolve-base-image.sh:
#   1. the $GITHUB_OUTPUT contract (only key=value, four keys per image);
#   2. the build / reuse / forced-rebuild decision;
#   3. that changing any file a base Dockerfile COPYs changes that image's tag,
#      i.e. the auto-derived hash inputs really include the COPYd files;
#   4. that a transient registry error is retried and then fails open to a build.
#
# `docker` and `sleep` are stubbed so there is no network and no real backoff.

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${here}/../.." && pwd)"
script="${here}/resolve-base-image.sh"

fail() {
	printf '::error::resolve-base-image test failed: %s\n' "$1" >&2
	exit 1
}

stub_dir="$(mktemp -d)"
trap 'rm -rf "${stub_dir}"' EXIT

# docker stub for `manifest inspect <ref>`:
#   - present if <ref> is listed in $EXISTING;
#   - a retryable 503 if <ref> == $TRANSIENT_REF (logging each attempt to $CALL_LOG);
#   - otherwise a genuine "no such manifest" (absent, must not be retried).
cat > "${stub_dir}/docker" <<'STUB'
#!/usr/bin/env bash
if [[ "$1 $2" == "manifest inspect" ]]; then
	if [[ -n "${TRANSIENT_REF:-}" && "$3" == "${TRANSIENT_REF}" ]]; then
		[[ -n "${CALL_LOG:-}" ]] && echo "$3" >> "${CALL_LOG}"
		echo "received unexpected HTTP status: 503 Service Unavailable" >&2
		exit 1
	fi
	for e in ${EXISTING:-}; do [[ "$e" == "$3" ]] && exit 0; done
	echo "no such manifest: $3" >&2
	exit 1
fi
exit 0
STUB
# no-op sleep so retry backoff does not slow the test down
printf '#!/usr/bin/env bash\nexit 0\n' > "${stub_dir}/sleep"
chmod +x "${stub_dir}/docker" "${stub_dir}/sleep"

run_gate() { # <dir> <existing> <target> <source> <version> <commit>
	(
		cd "$1" \
			&& EXISTING="$2" TARGET_REGISTRY="$3" SOURCE_REGISTRY="$4" VERSION="$5" COMMIT_MESSAGE="$6" \
				PATH="${stub_dir}:${PATH}" bash "${script}"
	)
}

# 1. Nothing exists -> every image builds; output is only key=value, 4 per image.
absent="$(run_gate "${repo_root}" "" reg reg 2.1.0 "")"
while IFS= read -r line; do
	[[ "${line}" =~ ^[a-z0-9_]+= ]] || fail "output line is not key=value: '${line}'"
done <<< "${absent}"
count="$(grep -c '=' <<< "${absent}")"
[[ "${count}" -eq 24 ]] || fail "expected 24 output lines (6 images x 4), got ${count}"
grep -q '^build_container_x86_64_run=true$' <<< "${absent}" || fail "expected build when tag absent"

# 2. Present in the source registry -> reuse in place (run=false, ref=source).
tag="$(sed -n 's/^build_container_x86_64_version=//p' <<< "${absent}")"
reuse="$(run_gate "${repo_root}" "reg/build-container-x86_64:${tag}" reg reg 2.1.0 "")"
grep -q '^build_container_x86_64_run=false$' <<< "${reuse}" || fail "expected reuse when tag exists"
grep -q "^build_container_x86_64_ref=reg/build-container-x86_64:${tag}$" <<< "${reuse}" \
	|| fail "expected reuse ref to be the existing content tag"

# 3. `ci-rebuild-base-containers` forces a rebuild even if the image exists.
forced="$(run_gate "${repo_root}" "reg/build-container-x86_64:${tag}" reg reg 2.1.0 "chore: ci-rebuild-base-containers")"
grep -q '^build_container_x86_64_run=true$' <<< "${forced}" || fail "expected forced rebuild"

# 4. Auto-derived inputs: changing any file a base Dockerfile COPYs must change
#    that image's tag. Runs against a throwaway copy of the build context.
work="$(mktemp -d)"
mkdir -p "${work}/dev"
cp -R "${repo_root}/dev/docker" "${work}/dev/docker"
baseline="$(run_gate "${work}" "" reg reg 2.1.0 "")"
dockerfiles=(
	Dockerfile.build-container-x86_64
	Dockerfile.build-container-aarch64
	Dockerfile.runtime-container-x86_64
	Dockerfile.runtime-container-aarch64
	Dockerfile.build-artifacts-container-x86_64
	Dockerfile.build-artifacts-container-aarch64
)
for dfname in "${dockerfiles[@]}"; do
	prefix="$(sed 's/^Dockerfile\.//; s/-/_/g' <<< "${dfname}")"
	base_ver="$(sed -n "s/^${prefix}_version=//p" <<< "${baseline}")"
	while IFS= read -r copied; do
		printf '\n# resolve-base-image test mutation\n' >> "${work}/${copied}"
		new_ver="$(run_gate "${work}" "" reg reg 2.1.0 "" | sed -n "s/^${prefix}_version=//p")"
		[[ "${base_ver}" != "${new_ver}" ]] \
			|| fail "${prefix}: changing COPYd '${copied}' did not change the tag; it is not a hash input"
		cp "${repo_root}/${copied}" "${work}/${copied}"
	done < <(awk '/^COPY / && !/--from=/ { for (i = 2; i < NF; i++) if ($i !~ /^--/) print $i }' "${work}/dev/docker/${dfname}")
done
rm -rf "${work}"

# 5. A transient registry error is retried (3 attempts) and then fails open. The
#    503 below is simulated by the docker stub; the resolver's real retry
#    diagnostics are left visible and framed so a log reader knows they are
#    expected. The retry itself is verified via the call counter.
echo "[test] simulating a transient registry failure; the following 503 errors are EXPECTED and not a real outage:" >&2
call_log="$(mktemp)"
export TRANSIENT_REF="reg/build-container-x86_64:${tag}" CALL_LOG="${call_log}"
retry_out="$(run_gate "${repo_root}" "" reg reg 2.1.0 "")"
unset TRANSIENT_REF CALL_LOG
echo "[test] end of expected 503 errors" >&2
grep -q '^build_container_x86_64_run=true$' <<< "${retry_out}" || fail "transient error should fail open to a build"
attempts="$(grep -c . "${call_log}")"
[[ "${attempts}" -eq 3 ]] || fail "expected 3 inspect attempts on transient error, got ${attempts}"
rm -f "${call_log}"

echo "resolve-base-image test: OK (contract, decision, COPY-derivation, retry)"
