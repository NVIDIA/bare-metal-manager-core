#!/bin/bash
# install.sh
# Installs DPU provisioning scripts and artifacts from the ISO to a persistent
# working directory on the host. Run once per host before provisioning.
#
# After this script completes, run provision-dpu.sh from the working directory:
#   /var/lib/dpu-install/<version>/provision-dpu.sh --server-name <hostname>
#
# Usage:
#   ./install.sh [--skip-os-check]
#
# Options:
#   --skip-os-check   Skip OS version check and DOCA host package installation.
#                     Use only if the host has already been validated.
#   --help            Show this help message

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Save terminal as fd 3 so die() always writes to screen even after log redirect
exec 3>&2
die() { echo "ERROR: $*" >&3; exit 1; }
log() { echo "[$(date '+%H:%M:%S')] $*" >&3; }

usage() {
    grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,1\}//'
    exit 1
}

# ── Load version ───────────────────────────────────────────────────────────────

VERSION_CFG="$SCRIPT_DIR/dpu_fw_version.cfg"
[[ -f "$VERSION_CFG" ]] || die "dpu_fw_version.cfg not found at $VERSION_CFG"
# shellcheck source=/dev/null
source "$VERSION_CFG"
[[ -z "${DOCA_VERSION:-}" ]] && die "DOCA_VERSION not set in $VERSION_CFG"
[[ -z "${HBN_VERSION:-}" ]]  && die "HBN_VERSION not set in $VERSION_CFG"

VERSION_TAG="${DOCA_VERSION}_${HBN_VERSION}"
WORK_DIR="/var/lib/dpu-install/${VERSION_TAG}"
_work_dir_existed=false
[[ -d "$WORK_DIR" ]] && _work_dir_existed=true

# ── Argument parsing ───────────────────────────────────────────────────────────

SKIP_OS_CHECK=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-os-check) SKIP_OS_CHECK=true; shift ;;
        --help|-h) usage ;;
        *) die "Unknown option: $1" ;;
    esac
done

[[ "$(id -u)" -ne 0 ]] && die "must be run as root"

# Redirect trace output (set -x) to log file; terminal stays on fd 3
mkdir -p "$WORK_DIR"
LOG_FILE="$WORK_DIR/install.log"
exec 2>>"$LOG_FILE"
exec 3> >(tee -a "$LOG_FILE" >/dev/tty)
echo "============================================================" >&3
echo "  Logging to: $LOG_FILE" >&3
echo "============================================================" >&3

# ── OS version check ──────────────────────────────────────────────────────────

if [[ "$SKIP_OS_CHECK" == false ]]; then
    log "Checking OS version..."
    os_id=""
    os_version=""
    if [[ -f /etc/os-release ]]; then
        os_id=$(. /etc/os-release && echo "${ID:-}")
        os_version=$(. /etc/os-release && echo "${VERSION_ID:-}")
    fi
    if [[ "$os_id" != "ubuntu" ]] || [[ "$os_version" != "24.04" ]]; then
        die "Unsupported OS: ${os_id} ${os_version}. Ubuntu 24.04 is required. Use --skip-os-check to override."
    fi
    log "OS: Ubuntu ${os_version} — OK"

    # ── libfuse2t64 package check / install (rshim dependency) ───────────────

    log "Checking libfuse2t64 package..."
    if dpkg -s libfuse2t64 &>/dev/null && dpkg -s libfuse2t64 | grep -q "Status: install ok installed"; then
        installed_ver=$(dpkg -s libfuse2t64 | awk '/^Version:/{print $2}')
        log "libfuse2t64 ${installed_ver} already installed — skipping"
    else
        log "libfuse2t64 not installed — locating package in ISO..."
        libfuse2_deb=""
        for f in "$SCRIPT_DIR"/libfuse2t64_*.deb; do
            [[ -e "$f" ]] && libfuse2_deb="$f" && break
        done
        [[ -z "$libfuse2_deb" ]] && die "libfuse2t64 .deb not found in $SCRIPT_DIR — ISO may be incomplete"

        log "Installing $(basename "$libfuse2_deb")..."
        dpkg -i "$libfuse2_deb" || die "Failed to install libfuse2t64 — check dpkg output above"

        dpkg -s libfuse2t64 | grep -q "Status: install ok installed" \
            || die "libfuse2t64 installation verification failed"
        log "libfuse2t64 installed and verified"
    fi

    # ── rshim package check / install ────────────────────────────────────────

    log "Checking rshim package..."
    if dpkg -s rshim &>/dev/null && dpkg -s rshim | grep -q "Status: install ok installed"; then
        installed_ver=$(dpkg -s rshim | awk '/^Version:/{print $2}')
        log "rshim ${installed_ver} already installed — skipping"
    else
        log "rshim not installed — locating package in ISO..."
        rshim_deb=""
        for f in "$SCRIPT_DIR"/rshim_*.deb; do
            [[ -e "$f" ]] && rshim_deb="$f" && break
        done
        [[ -z "$rshim_deb" ]] && die "rshim .deb not found in $SCRIPT_DIR — ISO may be incomplete"

        log "Installing $(basename "$rshim_deb")..."
        dpkg -i "$rshim_deb" || die "Failed to install rshim — check dpkg output above"

        dpkg -s rshim | grep -q "Status: install ok installed" \
            || die "rshim installation verification failed"
        log "rshim installed and verified"
    fi

    # ── DOCA host package check / install ─────────────────────────────────────

    log "Checking DOCA host package..."
    if dpkg -s doca-host &>/dev/null && dpkg -s doca-host | grep -q "Status: install ok installed"; then
        installed_ver=$(dpkg -s doca-host | awk '/^Version:/{print $2}')
        log "doca-host ${installed_ver} already installed — skipping"
    else
        log "doca-host not installed — locating package in ISO..."
        doca_host_deb=""
        for f in "$SCRIPT_DIR"/doca-host_*.deb; do
            [[ -e "$f" ]] && doca_host_deb="$f" && break
        done
        [[ -z "$doca_host_deb" ]] && die "doca-host .deb not found in $SCRIPT_DIR — ISO may be incomplete"

        log "Installing $(basename "$doca_host_deb")..."
        dpkg -i "$doca_host_deb" || die "Failed to install doca-host — check dpkg output above"

        log "Verifying installation..."
        dpkg -s doca-host | grep -q "Status: install ok installed" \
            || die "doca-host installation verification failed"
        command -v bfb-install &>/dev/null \
            || die "bfb-install not found after doca-host install — package may be incomplete"
        systemctl list-unit-files rshim.service &>/dev/null && systemctl list-unit-files rshim.service | grep -q rshim \
            || die "rshim service not found after doca-host install — package may be incomplete"
        log "doca-host installed and verified (bfb-install: $(command -v bfb-install), rshim: OK)"
    fi
fi

# ── Set up working directory ───────────────────────────────────────────────────

if [[ "$_work_dir_existed" == true ]]; then
    echo "WARNING: working directory already exists: $WORK_DIR"
    echo "Re-installing will overwrite scripts and artifacts but preserve touchfiles."
    read -r -p "Continue? [y/N] " _confirm
    [[ "$(echo "$_confirm" | tr '[:upper:]' '[:lower:]')" == "y" ]] || die "Aborted."
fi
log "Creating working directory: $WORK_DIR"
mkdir -p "$WORK_DIR/touchfiles"

# ── Copy scripts ───────────────────────────────────────────────────────────────

log "Copying scripts..."
cp "$SCRIPT_DIR/provision-dpu.sh"     "$WORK_DIR/"
cp "$SCRIPT_DIR/dpuinstall.sh"        "$WORK_DIR/"
cp "$SCRIPT_DIR/post-power-cycle.sh"  "$WORK_DIR/"
cp "$SCRIPT_DIR/setup_netplan.sh"     "$WORK_DIR/"
cp "$SCRIPT_DIR/doca_hbn_versions.cfg" "$WORK_DIR/"
cp "$SCRIPT_DIR/dpu_fw_version.cfg"   "$WORK_DIR/"
# dpuinstall.sh looks for bf.cfg (not bf.cfg.template) in its own SCRIPTS_DIR
cp "$SCRIPT_DIR/bf.cfg.template"      "$WORK_DIR/bf.cfg"
chmod 755 "$WORK_DIR/provision-dpu.sh" \
          "$WORK_DIR/dpuinstall.sh" \
          "$WORK_DIR/post-power-cycle.sh" \
          "$WORK_DIR/setup_netplan.sh"

# ── Copy per-node server configs ───────────────────────────────────────────────

if [[ -d "$SCRIPT_DIR/servers" ]]; then
    log "Copying per-node server configs..."
    rm -rf "$WORK_DIR/servers"
    cp -r "$SCRIPT_DIR/servers" "$WORK_DIR/"
    log "  $(ls "$SCRIPT_DIR/servers" | wc -l | tr -d ' ') node(s) copied"
else
    die "servers/ directory not found in $SCRIPT_DIR — ISO may be incomplete"
fi

# ── Copy artifacts ─────────────────────────────────────────────────────────────

log "Copying artifacts..."
_needed_kb=$(du -sk "$SCRIPT_DIR" | cut -f1)
_avail_kb=$(df -Pk "$WORK_DIR" | awk 'NR==2{print $4}')
(( _avail_kb > _needed_kb )) \
    || die "Insufficient space in $WORK_DIR: need ~$(( _needed_kb / 1024 ))MiB, have $(( _avail_kb / 1024 ))MiB"
_copied=0
for pattern in "*.bfb" "*.bfb.gz" "*.deb" "*.deb.gz" "*.tar.gz" "*.zip.gz"; do
    for f in "$SCRIPT_DIR"/$pattern; do
        [[ -e "$f" ]] || continue
        # Skip the full ISO zip — it is not needed at runtime
        [[ "$(basename "$f")" == dpu_install_*.zip* ]] && continue
        cp -f "$f" "$WORK_DIR/"
        log "  $(basename "$f")  ($(du -h "$f" | cut -f1))"
        _copied=$(( _copied + 1 ))
    done
done
[[ "$_copied" -eq 0 ]] && die "No artifacts found in $SCRIPT_DIR — ISO may be incomplete"

# ── Done ───────────────────────────────────────────────────────────────────────

echo
echo "============================================================"
echo "  Install complete."
echo "  Working directory: $WORK_DIR"
echo ""
echo "  To provision a node, run:"
echo "    $WORK_DIR/provision-dpu.sh --server-name <hostname>"
echo ""
echo "  Available nodes:"
for d in "$WORK_DIR/servers"/*/; do
    echo "    $(basename "$d")"
done
echo "============================================================"
