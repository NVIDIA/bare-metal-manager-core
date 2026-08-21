#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Tag each base/builder image by a hash of its build inputs so an identical
# definition maps to a single image that is reused across runs instead of rebuilt.
# Prints `<image>_{run,version,ref,version_latest}` to stdout for the build gate.
#
# Requires TARGET_REGISTRY, SOURCE_REGISTRY and VERSION; a
# `ci-rebuild-base-containers` mention in COMMIT_MESSAGE forces a rebuild.

major_minor="$(cut -d. -f1,2 <<< "${VERSION}")"

forced_base=false
if [[ "${COMMIT_MESSAGE:-}" =~ ci-rebuild-base-containers ]]; then
	forced_base=true
fi

# image_exists <ref>: is the image present in its registry?
#   present            -> return 0
#   definitively absent (registry says the manifest/name is unknown) -> return 1
#   transient failure (network, 5xx, rate limit) -> retry with backoff, then
#     fail open and return 1 so a registry blip triggers a rebuild rather than a
#     hard pipeline failure.
image_exists() {
	local ref="$1" attempt out
	for attempt in 1 2 3; do
		if out="$(docker manifest inspect "${ref}" 2>&1)"; then
			return 0
		fi
		case "${out}" in
		*"no such manifest"* | *"manifest unknown"* | *"not found"* | *MANIFEST_UNKNOWN* | *NAME_UNKNOWN*)
			return 1
			;;
		esac
		echo "image_exists: transient lookup failure for ${ref} (attempt ${attempt}/3): ${out}" >&2
		if [[ "${attempt}" -lt 3 ]]; then
			sleep "$((attempt * 2))"
		fi
	done
	return 1
}

# copy_inputs <dockerfile>: print each file the Dockerfile COPYs from the build
# context, one per line. Skips flags (`--chown`, ...) and multi-stage
# `COPY --from=` copies, which come from an earlier build stage, not the context.
copy_inputs() {
	awk '/^COPY / && !/--from=/ { for (i = 2; i < NF; i++) if ($i !~ /^--/) print $i }' "$1"
}

# resolve <output_prefix> <image_short_name> <dockerfile>
resolve() {
	local prefix="$1" name="$2" dockerfile="$3"
	local tag tgt src ref run copied
	local inputs=("${dockerfile}")

	# Hash the Dockerfile plus every file it COPYs from the context, so any change
	# to a build input yields a new tag. The COPY list is derived from the
	# Dockerfile itself, so it can never drift from the actual COPY statements.
	# TODO: pin all references within the files so this catches all content changes.
	while IFS= read -r copied; do
		inputs+=("${copied}")
	done < <(copy_inputs "${dockerfile}")

	tag="src-$(sha256sum "${inputs[@]}" | sha256sum | cut -c1-16)"
	tgt="${TARGET_REGISTRY}/${name}:${tag}"
	src="${SOURCE_REGISTRY}/${name}:${tag}"

	# Default to building and pushing to the target registry; reuse an existing
	# image instead (from the source, or the target for a fork) unless forced.
	run=true
	ref="${tgt}"
	if [[ "${forced_base}" != "true" ]]; then
		if image_exists "${src}"; then
			run=false
			ref="${src}"
		elif [[ "${TARGET_REGISTRY}" != "${SOURCE_REGISTRY}" ]] && image_exists "${tgt}"; then
			run=false
			ref="${tgt}"
		fi
	fi

	echo "${prefix}_run=${run}"
	echo "${prefix}_version=${tag}"
	echo "${prefix}_ref=${ref}"
	# TODO: nothing reads the `<major.minor>-latest` alias now that consumers use
	# the content-addressed ref. It is kept only for parity with the previous gate
	# and can be dropped (along with `tag_latest` on the build jobs) once we confirm
	# no external puller depends on it. It is published only on a build, so it is
	# empty on reuse.
	if [[ "${run}" == "true" ]]; then
		echo "${prefix}_version_latest=${TARGET_REGISTRY}/${name}:${major_minor}-latest"
	else
		echo "${prefix}_version_latest="
	fi
}

d=dev/docker
resolve build_container_x86_64            build-container-x86_64            "${d}/Dockerfile.build-container-x86_64"
resolve build_container_aarch64           build-container-aarch64           "${d}/Dockerfile.build-container-aarch64"
resolve runtime_container_x86_64          runtime-container-x86_64          "${d}/Dockerfile.runtime-container-x86_64"
resolve runtime_container_aarch64         runtime-container-aarch64         "${d}/Dockerfile.runtime-container-aarch64"
resolve build_artifacts_container_x86_64  build-artifacts-container-x86_64  "${d}/Dockerfile.build-artifacts-container-x86_64"
resolve build_artifacts_container_aarch64 build-artifacts-container-aarch64 "${d}/Dockerfile.build-artifacts-container-aarch64"
