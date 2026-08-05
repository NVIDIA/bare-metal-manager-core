#!/bin/bash
# Tests for the BFB glob-array discovery pattern in
# on-server/dpuinstall.sh (copy_files function).

set -euo pipefail
UNIT_TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$UNIT_TEST_DIR/lib.sh"

# Run each case in a temp dir so globs don't pick up unrelated files.
with_tmpdir() {
    local fn="$1"; shift
    local dir; dir=$(mktemp -d)
    ( cd "$dir" && "$fn" "$@" )
    local rc=$?
    rm -rf "$dir"
    return $rc
}

# Returns exit 0 + bfb name if exactly one BFB found, non-zero otherwise.
discover_bfb() {
    local -a _bfbs=(bf-bundle*.bfb)
    if [ ! -f "${_bfbs[0]}" ]; then
        echo "ERROR: BFB file not found" >&2
        return 1
    fi
    if [ "${#_bfbs[@]}" -gt 1 ]; then
        echo "ERROR: multiple BFB files staged: ${_bfbs[*]}" >&2
        return 1
    fi
    echo "${_bfbs[0]}"
}

echo "=== BFB discovery ==="

assert_eq "single BFB found" "bf-bundle-3.2.2.bfb" "$(
    with_tmpdir bash -c '
        touch bf-bundle-3.2.2.bfb
        discover_bfb() {
            local -a _bfbs=(bf-bundle*.bfb)
            [ ! -f "${_bfbs[0]}" ] && { echo "ERROR: not found" >&2; return 1; }
            [ "${#_bfbs[@]}" -gt 1 ] && { echo "ERROR: multiple: ${_bfbs[*]}" >&2; return 1; }
            echo "${_bfbs[0]}"
        }
        discover_bfb
    '
)"

assert_false "no BFB returns error" "
    with_tmpdir bash -c '
        discover_bfb() {
            local -a _bfbs=(bf-bundle*.bfb)
            [ ! -f \"\${_bfbs[0]}\" ] && return 1
            echo \"\${_bfbs[0]}\"
        }
        discover_bfb >/dev/null 2>&1
    '
"

assert_false "multiple BFBs returns error" "
    with_tmpdir bash -c '
        touch bf-bundle-3.2.2.bfb bf-bundle-3.2.3.bfb
        discover_bfb() {
            local -a _bfbs=(bf-bundle*.bfb)
            [ ! -f \"\${_bfbs[0]}\" ] && return 1
            [ \"\${#_bfbs[@]}\" -gt 1 ] && return 1
            echo \"\${_bfbs[0]}\"
        }
        discover_bfb >/dev/null 2>&1
    '
"

assert_true "glob does not match .bfb.gz" "
    with_tmpdir bash -c '
        touch bf-bundle-3.2.2.bfb.gz
        local -a _bfbs=(bf-bundle*.bfb)
        [ ! -f \"\${_bfbs[0]:-}\" ]
    '
"

summary
