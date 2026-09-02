#!/usr/bin/env bash
# Write `.git-describe` from `git describe` and run nix with that file as the
# `git-describe` flake input. Gitignored files are not in the flake source, so
# `nix build .#…` cannot see the file unless it is passed as an input.
#
# Usage: scripts/nix-with-git-describe.sh build .#carbide-api
set -euo pipefail

repo=$(cd "$(dirname -- "$0")/.." && pwd)
file="${repo}/.git-describe"
extra=()

if git -C "${repo}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	git -C "${repo}" describe --tags --first-parent --always >"${file}"
	extra+=(--override-input git-describe "path:${file}" --no-write-lock-file)
fi

exec nix "$@" "${extra[@]}"
