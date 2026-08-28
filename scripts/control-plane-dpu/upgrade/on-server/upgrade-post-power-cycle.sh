#!/bin/bash
# upgrade-post-power-cycle.sh
# Run after the host power cycles during a DPU firmware upgrade.
# Sources dpuinstall.sh from the working directory to reuse SSH helpers and
# check_hbn_container without re-running the install steps.
#
# Unlike the initial-provisioning post-power-cycle.sh, this script does NOT
# write or apply netplan. It verifies that the BlueField p0 MAC address is
# unchanged from before the upgrade, so the existing host netplan stays valid.
#
# Usage:
#   ./upgrade-post-power-cycle.sh
#
# Options:
#   --help   Show this help message
#
# Must be run as root.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# fd 3 initially = terminal (for early die() before log ready);
# reassigned below to tee so it writes to both log and terminal.
exec 3>&2
die() { echo "ERROR: $*" >&3; exit 1; }

usage() {
    grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,1\}//'
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h) usage ;;
        *) die "Unknown option: $1" ;;
    esac
done

[[ "$(id -u)" -ne 0 ]] && die "must be run as root"
LOG_FILE="$SCRIPT_DIR/upgrade-post-power-cycle.log"
# Keep the original stderr on fd 4: when there is no usable /dev/tty (e.g. a
# session without a controlling terminal), tee dies and the first write to
# fd 3 would kill the script silently with SIGPIPE.
exec 4>&3
exec 2>>"$LOG_FILE"
if { : > /dev/tty; } 2>/dev/null; then
    exec 3> >(tee -a "$LOG_FILE" >/dev/tty)
else
    exec 3> >(tee -a "$LOG_FILE" >&4)
fi
echo "============================================================" >&3
echo "  Logging to: $LOG_FILE" >&3
echo "============================================================" >&3

# ── Validate the working directory ─────────────────────────────────────────────

VERSION_CFG="$SCRIPT_DIR/dpu_fw_version.cfg"
[[ -f "$VERSION_CFG" ]] || die "dpu_fw_version.cfg not found at $VERSION_CFG"
# shellcheck source=/dev/null
source "$VERSION_CFG"
[[ -z "${DOCA_VERSION:-}" ]] && die "DOCA_VERSION not set in $VERSION_CFG"
[[ -z "${HBN_VERSION:-}" ]]  && die "HBN_VERSION not set in $VERSION_CFG"

BACKUP_P0_MAC="$SCRIPT_DIR/backup/p0_mac"
[[ -s "$BACKUP_P0_MAC" ]] \
    || die "saved p0 MAC not found at $BACKUP_P0_MAC — did upgrade-dpu-fw.sh complete its backup phase?"
EXPECTED_MAC="$(cat "$BACKUP_P0_MAC")"

# ── Source helpers and the (unchanged) provisioning functions ─────────────────
# The BASH_SOURCE guard in dpuinstall.sh prevents the main install block
# from executing when sourced.

# shellcheck source=upgrade-lib.sh
source "$SCRIPT_DIR/upgrade-lib.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/dpuinstall.sh"

[[ -f "$TOUCHFILE_HBN_DEPLOYED" ]] \
    || die "HBN deployment touchfile not found — power cycle may have happened before upgrade-dpu-fw.sh completed. Re-run upgrade-dpu-fw.sh."

trap cleanup EXIT
set -eux

update_progress 11
check_hbn_container
# check_hbn_container re-runs start_rshim/setup_tmfifo, which rewind CUR_STEP.
update_progress 11

# ── Validate the BlueField p0 MAC instead of writing netplan ──────────────────

echo "Validating that the BlueField p0 MAC address is unchanged..." >&3
ACTUAL_MAC="$(detect_bluefield_p0_mac 3 10)" \
    || die "could not detect the BlueField p0 MAC after the upgrade (see $LOG_FILE)"

if macs_equal "$EXPECTED_MAC" "$ACTUAL_MAC"; then
    echo "BlueField p0 MAC unchanged: $ACTUAL_MAC — existing netplan remains valid." >&3
else
    echo "ERROR: BlueField p0 MAC changed during the upgrade!" >&3
    echo "  before: $EXPECTED_MAC" >&3
    echo "  after:  $ACTUAL_MAC" >&3
    echo "The existing host netplan matches the old MAC, so host networking will" >&3
    echo "not come up through the DPU. If the DPU hardware was replaced, update" >&3
    echo "the MAC in your netplan config (e.g. /etc/netplan/99_config.yaml)," >&3
    echo "run 'netplan generate && netplan apply', then record the new MAC with" >&3
    echo "  echo '$ACTUAL_MAC' > $BACKUP_P0_MAC" >&3
    echo "and re-run this script to complete verification." >&3
    exit 1
fi

CUR_STEP=$FINAL_STEP
echo "DPU firmware upgrade complete"
