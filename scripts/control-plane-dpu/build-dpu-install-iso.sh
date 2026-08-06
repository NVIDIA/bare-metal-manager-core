#!/usr/bin/env bash
# build-dpu-install-iso.sh
# Generates per-node DPU startup configs and builds a DPU install ISO and ZIP
# in a single run.
#
# Usage:
#   ./build-dpu-install-iso.sh --control-plane-config site-sample.yaml \
#                              --download-artifacts --doca-version 3.2.2 \
#                              --bfb-build 125 --bfb-release 26.02
#
# Required (always):
#   --control-plane-config <path>  Path to site config YAML
#
# Required (one of):
#   --download-artifacts           Download artifacts; also requires --doca-version,
#                                  --hbn-version, --bfb-build, --bfb-release,
#                                  --doca-host-url
#   --artifacts-dir DIR            Use pre-downloaded artifacts; DOCA_VERSION and
#                                  HBN_VERSION are read from dpu_fw_version.cfg
#                                  inside the directory (written by
#                                  download-build-dpu-artifacts.sh)
#
# Required with --download-artifacts:
#   --doca-version VERSION         DOCA platform version (e.g. 3.2.2)
#   --hbn-version VERSION          HBN version (e.g. 3.2.2)
#   --hbn-container-tag TAG        Exact NGC container tag for the HBN image, e.g.
#                                  3.2.2-doca3.2.2 or 2.4.2-doca2.9.2-32
#                                  (check https://catalog.ngc.nvidia.com for the tag)
#   --bfb-build NUMBER             BFB build number (e.g. 125)
#   --bfb-release VERSION          BFB release string (e.g. 26.02)
#   --doca-host-url URL            Full URL to DOCA host .deb package
#   --rshim-url URL                Full URL to rshim .deb package (from GitHub releases)
#   --libfuse2-url URL             Full URL to libfuse2t64 .deb package (rshim dependency)
#                                  e.g. http://archive.ubuntu.com/ubuntu/pool/universe/f/fuse/libfuse2t64_2.9.9-8.1build1_amd64.deb
#
# Optional with --download-artifacts:
#   --bfb-url URL            Base CDN URL for BFB download
#                            (default: https://content.mellanox.com/BlueField/BFBs/Ubuntu22.04)
#   --hbn-config-url URL     Full NGC files API URL for HBN config bundle
#                            (default: https://api.ngc.nvidia.com/v2/resources/org/nvidia/team/doca/doca_hbn/<hbn-version>/files)
#
# Optional:
#   --output-dir DIR         Output directory (default: current directory)
#   --no-fnn                 FOR TESTING ONLY: ignore fnn: in site config and use
#                            startup.template instead of startupSMN.template.
#                            Requires interactive confirmation. Do NOT use in production.
#   --help                   Show this help
#
# Dependencies: yq (mikefarah/yq v4), gomplate, wget, docker, curl, jq,
#               base64, gzip, zip, sha256sum (Linux) or shasum (macOS),
#               mkisofs (Linux) or xorrisofs (macOS)
#
# Output (all under --output-dir):
#   <hostname>/startup.yaml      HBN DPU configuration per node
#   <hostname>/99_config.yaml    Host netplan per node
#   dpu_install_<ver>.iso        DPU install ISO
#   dpu_install_<ver>.zip        DPU install ZIP

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ON_SERVER_DIR="$SCRIPT_DIR/on-server"
TEMPLATES_DIR="$ON_SERVER_DIR/templates"

die()  { echo "ERROR: $*" >&2; exit 1; }
log()  { echo "[$(date '+%H:%M:%S')] $*"; }
step() { echo; echo "------------------------------------------------------------"; \
         echo "[$(date '+%H:%M:%S')] $*"; \
         echo "------------------------------------------------------------"; }

usage() {
    grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,1\}//'
    exit 1
}

# ── Argument parsing ──────────────────────────────────────────────────────────

CONTROL_PLANE_CONFIG=""
DOCA_VERSION=""
HBN_VERSION=""
HBN_CONTAINER_TAG=""
BFB_BUILD=""
BFB_RELEASE=""
BFB_URL=""
HBN_CONFIG_URL=""
DOCA_HOST_URL=""
RSHIM_URL=""
LIBFUSE2_URL=""
OUTPUT_DIR=""
ARTIFACTS_DIR=""
DOWNLOAD_ARTIFACTS=false
NO_FNN=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --control-plane-config) [[ -z "${2:-}" ]] && die "$1 requires a value"; CONTROL_PLANE_CONFIG="$2"; shift 2 ;;
        --doca-version)         [[ -z "${2:-}" ]] && die "$1 requires a value"; DOCA_VERSION="$2";         shift 2 ;;
        --hbn-version)          [[ -z "${2:-}" ]] && die "$1 requires a value"; HBN_VERSION="$2";          shift 2 ;;
        --hbn-container-tag)    [[ -z "${2:-}" ]] && die "$1 requires a value"; HBN_CONTAINER_TAG="$2";    shift 2 ;;
        --bfb-build)            [[ -z "${2:-}" ]] && die "$1 requires a value"; BFB_BUILD="$2";            shift 2 ;;
        --bfb-release)          [[ -z "${2:-}" ]] && die "$1 requires a value"; BFB_RELEASE="$2";          shift 2 ;;
        --bfb-url)              [[ -z "${2:-}" ]] && die "$1 requires a value"; BFB_URL="$2";              shift 2 ;;
        --hbn-config-url)       [[ -z "${2:-}" ]] && die "$1 requires a value"; HBN_CONFIG_URL="$2";       shift 2 ;;
        --doca-host-url)        [[ -z "${2:-}" ]] && die "$1 requires a value"; DOCA_HOST_URL="$2";        shift 2 ;;
        --rshim-url)            [[ -z "${2:-}" ]] && die "$1 requires a value"; RSHIM_URL="$2";            shift 2 ;;
        --libfuse2-url)         [[ -z "${2:-}" ]] && die "$1 requires a value"; LIBFUSE2_URL="$2";         shift 2 ;;
        --output-dir)           [[ -z "${2:-}" ]] && die "$1 requires a value"; OUTPUT_DIR="$2";           shift 2 ;;
        --artifacts-dir)        [[ -z "${2:-}" ]] && die "$1 requires a value"; ARTIFACTS_DIR="$2";        shift 2 ;;
        --download-artifacts)   DOWNLOAD_ARTIFACTS=true;       shift ;;
        --no-fnn)               NO_FNN=true;                   shift ;;
        --help|-h) usage ;;
        *) die "Unknown option: $1" ;;
    esac
done

[[ -z "$CONTROL_PLANE_CONFIG" ]] && die "--control-plane-config is required"
[[ -f "$CONTROL_PLANE_CONFIG" ]] || die "Config file not found: $CONTROL_PLANE_CONFIG"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="./output"
if [[ -d "$OUTPUT_DIR" ]] && [[ -n "$(ls -A "$OUTPUT_DIR" 2>/dev/null)" ]]; then
    die "Output directory $OUTPUT_DIR already exists and is non-empty. Remove it manually or choose a different --output-dir."
fi
OUTPUT_DIR="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)"

if [[ -z "$ARTIFACTS_DIR" ]] && [[ "$DOWNLOAD_ARTIFACTS" == false ]]; then
    die "either --download-artifacts or --artifacts-dir is required"
fi

if [[ "$DOWNLOAD_ARTIFACTS" == true ]]; then
    [[ -z "$DOCA_VERSION" ]]      && die "--doca-version is required with --download-artifacts"
    [[ -z "$HBN_VERSION" ]]       && die "--hbn-version is required with --download-artifacts"
    [[ -z "$HBN_CONTAINER_TAG" ]] && die "--hbn-container-tag is required with --download-artifacts"
    [[ -z "$BFB_BUILD" ]]         && die "--bfb-build is required with --download-artifacts"
    [[ -z "$BFB_RELEASE" ]]       && die "--bfb-release is required with --download-artifacts"
    [[ -z "$DOCA_HOST_URL" ]]     && die "--doca-host-url is required with --download-artifacts"
    [[ -z "$RSHIM_URL" ]]         && die "--rshim-url is required with --download-artifacts"
    [[ -z "$LIBFUSE2_URL" ]]      && die "--libfuse2-url is required with --download-artifacts"
else
    [[ -d "$ARTIFACTS_DIR" ]] || die "--artifacts-dir not found: $ARTIFACTS_DIR"
    _ver_cfg="$ARTIFACTS_DIR/dpu_fw_version.cfg"
    [[ -f "$_ver_cfg" ]] || die "dpu_fw_version.cfg not found in $ARTIFACTS_DIR — was it created by download-build-dpu-artifacts.sh?"
    # shellcheck source=/dev/null
    source "$_ver_cfg"
    [[ -z "${DOCA_VERSION:-}" ]] && die "DOCA_VERSION not set in $_ver_cfg"
    [[ -z "${HBN_VERSION:-}" ]]  && die "HBN_VERSION not set in $_ver_cfg"
    log "Versions from artifacts dir: DOCA=${DOCA_VERSION} HBN=${HBN_VERSION}"
fi

ISO_BASE="dpu_install_${DOCA_VERSION}_${HBN_VERSION}"
ISO_OUT="$OUTPUT_DIR/${ISO_BASE}.iso"
ZIP_OUT="$OUTPUT_DIR/${ISO_BASE}.zip"

# ── Preflight ─────────────────────────────────────────────────────────────────

step "Preflight checks"

for f in \
    "$SCRIPT_DIR/download-build-dpu-artifacts.sh" \
    "$ON_SERVER_DIR/dpuinstall.sh" \
    "$ON_SERVER_DIR/install.sh" \
    "$ON_SERVER_DIR/provision-dpu.sh" \
    "$ON_SERVER_DIR/post-power-cycle.sh" \
    "$ON_SERVER_DIR/setup_netplan.sh" \
    "$TEMPLATES_DIR/bf.cfg.template" \
    "$TEMPLATES_DIR/startup.template" \
    "$TEMPLATES_DIR/startupSMN.template" \
    "$TEMPLATES_DIR/netplan.template"; do
    [[ -f "$f" ]] || die "Required file not found: $f"
done
log "Script and template files: OK"

command -v yq       &>/dev/null || die "yq (mikefarah/yq v4) is required"
command -v gomplate &>/dev/null || die "gomplate is required — https://docs.gomplate.ca/installing/"
command -v zip      &>/dev/null || die "zip is required"
command -v unzip    &>/dev/null || die "unzip is required"
command -v gunzip   &>/dev/null || die "gunzip is required"

if [[ "$(uname)" == "Darwin" ]]; then
    ISO_TOOL="xorrisofs"
else
    ISO_TOOL="mkisofs"
fi
command -v "$ISO_TOOL" &>/dev/null || die "$ISO_TOOL not found — install genisoimage (Linux) or xorriso (macOS)"
log "Tools: OK (ISO tool: $ISO_TOOL)"

# ── IP arithmetic helpers ─────────────────────────────────────────────────────

ip_to_int() {
    local ip="$1"
    IFS='.' read -r a b c d <<< "$ip"
    echo $(( (a << 24) | (b << 16) | (c << 8) | d ))
}

int_to_ip() {
    local n=$1
    echo "$(( (n >> 24) & 255 )).$(( (n >> 16) & 255 )).$(( (n >> 8) & 255 )).$(( n & 255 ))"
}

get_nth_addr() {
    local cidr="$1" n="$2"
    local ip="${cidr%/*}" prefix="${cidr#*/}"
    local net_int
    net_int=$(( $(ip_to_int "$ip") & ( 0xFFFFFFFF << (32 - prefix) & 0xFFFFFFFF ) ))
    int_to_ip $(( net_int + n ))
}

split_in_half() {
    local cidr="$1"
    local ip="${cidr%/*}" prefix="${cidr#*/}"
    local new_prefix=$(( prefix + 1 ))
    local net_int
    net_int=$(( $(ip_to_int "$ip") & ( 0xFFFFFFFF << (32 - prefix) & 0xFFFFFFFF ) ))
    local half_size=$(( 1 << (32 - new_prefix) ))
    echo "$(int_to_ip "$net_int")/$new_prefix $(int_to_ip $(( net_int + half_size )))/$new_prefix"
}

# ── Template renderer (gomplate) ──────────────────────────────────────────────

render_template() {
    local tmpl_file="$1"
    shift
    local vars_file
    vars_file="$(mktemp "$OUTPUT_DIR/gomplate_vars_XXXXXX")"

    while [[ $# -gt 0 ]]; do
        local key="${1%%=*}"
        local val="${1#*=}"
        printf '%s: "%s"\n' "$key" "$val" >> "$vars_file"
        shift
    done

    gomplate --file "$tmpl_file" --context ".=${vars_file}?type=application/yaml" --datasource "site=$CONTROL_PLANE_CONFIG"
    local rc=$?
    rm -f "$vars_file"
    return $rc
}

# ── Read required fields from control plane config ────────────────────────────

yq_get() { yq ".$1" "$CONTROL_PLANE_CONFIG" 2>/dev/null | grep -v '^null$' || true; }

require_field() {
    local val
    val=$(yq_get "$1")
    if [ -z "$val" ]; then
        echo "ERROR: '$1' is required in $CONTROL_PLANE_CONFIG" >&2
        exit 1
    fi
    echo "$val"
}

validate_asn() {
    local field="$1" val="$2"
    [[ "$val" =~ ^[0-9]+$ ]] && (( val >= 1 && val <= 4294967295 )) || \
        die "'$field' must be a valid ASN (1-4294967295), got: $val"
}

validate_integer() {
    local field="$1" val="$2"
    [[ "$val" =~ ^[0-9]+$ ]] || die "'$field' must be an integer, got: $val"
}

validate_cidr() {
    local field="$1" val="$2"
    [[ "$val" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/([0-9]{1,2})$ ]] || \
        die "'$field' must be a valid CIDR prefix (e.g. 10.0.0.0/24), got: $val"
    local o1="${BASH_REMATCH[1]}" o2="${BASH_REMATCH[2]}" \
          o3="${BASH_REMATCH[3]}" o4="${BASH_REMATCH[4]}" \
          prefix="${BASH_REMATCH[5]}"
    for octet in "$o1" "$o2" "$o3" "$o4"; do
        (( octet <= 255 )) || die "'$field': octet $octet is out of range (0-255), got: $val"
    done
    (( prefix <= 32 )) || die "'$field': prefix length $prefix is out of range (0-32), got: $val"
}

# ── Validate site config fields ───────────────────────────────────────────────

_check_unknown_keys() {
    local context="$1" yq_expr="$2"; shift 2
    local known=("$@") key ok
    while IFS= read -r key; do
        ok=false
        for k in "${known[@]}"; do [[ "$key" == "$k" ]] && ok=true && break; done
        $ok || die "Unsupported field in site config ${context}: '$key'"
    done < <(yq "$yq_expr" "$CONTROL_PLANE_CONFIG" 2>/dev/null | grep -v '^null$' || true)
}

step "Validating site config fields"

_check_unknown_keys "(top level)" 'keys | .[]' \
    bgpAsnStart forgeDpuLoopbackPrefix forgeControlPlanePrefix \
    forgeServiceVipPrefix siteControllerMtuSize nameServer \
    ubuntuPasswordHash siteControllerNodes datacenterAsn \
    siteControllerRoutesAsn fnn

if [[ "$(yq '.fnn' "$CONTROL_PLANE_CONFIG")" != "null" ]]; then
    _check_unknown_keys "fnn" '.fnn | keys | .[]' \
        controlPlaneVni vpcVrfLoopbackPrefix \
        commonManagedNodeBmcRouteTarget commonSiteControllerRouteTarget \
        commonAdminNetworkTarget routeTargetsToImport
fi

_nc=$(yq '.siteControllerNodes | length' "$CONTROL_PLANE_CONFIG")
for (( _i=0; _i<_nc; _i++ )); do
    _hn=$(yq ".siteControllerNodes[$_i].hostName // \"node $_i\"" "$CONTROL_PLANE_CONFIG")
    _check_unknown_keys "siteControllerNodes[$_i] ($_hn)" ".siteControllerNodes[$_i] | keys | .[]" \
        hostName mac nodeId
done

log "Site config fields: OK"

# ── Step 1: Generate per-node DPU servers ────────────────────────────────────

step "Generating per-node DPU servers"

BGP_ASN_START=$(require_field bgpAsnStart)
validate_asn bgpAsnStart "$BGP_ASN_START"
DPU_LOOPBACK_PREFIX=$(require_field forgeDpuLoopbackPrefix)
validate_cidr forgeDpuLoopbackPrefix "$DPU_LOOPBACK_PREFIX"
CONTROL_PLANE_PREFIX=$(require_field forgeControlPlanePrefix)
validate_cidr forgeControlPlanePrefix "$CONTROL_PLANE_PREFIX"
SERVICE_VIP_PREFIX=$(require_field forgeServiceVipPrefix)
validate_cidr forgeServiceVipPrefix "$SERVICE_VIP_PREFIX"
MTU=$(require_field siteControllerMtuSize)
validate_integer siteControllerMtuSize "$MTU"
NODE_COUNT=$(yq '.siteControllerNodes | length' "$CONTROL_PLANE_CONFIG")

[ "$NODE_COUNT" -gt 0 ] || die "siteControllerNodes is empty in $CONTROL_PLANE_CONFIG"
actual_ids=$(yq '[.siteControllerNodes[].nodeId] | sort | .[]' "$CONTROL_PLANE_CONFIG" | tr '\n' ' ')
expected_ids=$(seq 1 "$NODE_COUNT" | tr '\n' ' ')
[[ "$actual_ids" == "$expected_ids" ]] || \
    die "siteControllerNodes: nodeId values must be unique integers from 1 to $NODE_COUNT, got: ${actual_ids% }"

loopback_prefix="${DPU_LOOPBACK_PREFIX#*/}"
loopback_capacity=$(( 1 << (32 - loopback_prefix) ))
[ "$loopback_capacity" -gt "$NODE_COUNT" ] || \
    die "forgeDpuLoopbackPrefix $DPU_LOOPBACK_PREFIX is too small for $NODE_COUNT node(s) (capacity $loopback_capacity addresses, need > $NODE_COUNT)"

cp_prefix="${CONTROL_PLANE_PREFIX#*/}"
cp_capacity=$(( 1 << (32 - cp_prefix) ))
[ "$cp_capacity" -ge $(( NODE_COUNT * 2 )) ] || \
    die "forgeControlPlanePrefix $CONTROL_PLANE_PREFIX is too small for $NODE_COUNT node(s) (capacity $cp_capacity addresses, need >= $((NODE_COUNT * 2)))"

NAMESERVER=$(require_field nameServer)
UBUNTU_PASSWORD_HASH=$(require_field ubuntuPasswordHash)

if [[ "$NO_FNN" == "true" ]]; then
    echo
    echo "WARNING: --no-fnn is for testing only. The generated ISO must NOT be used in production."
    read -r -p "Confirm non-FNN test build? [y/N] " _confirm
    [[ "$(echo "$_confirm" | tr '[:upper:]' '[:lower:]')" == "y" ]] || die "Aborted."
    HAS_FNN="false"
else
    HAS_FNN=$(yq 'has("fnn")' "$CONTROL_PLANE_CONFIG")
fi

if [[ "$HAS_FNN" == "true" ]]; then
    log "fnn: present in config — using startupSMN.template"
    SMN_SC_ROUTES_ASN=$(require_field siteControllerRoutesAsn)
    validate_asn siteControllerRoutesAsn "$SMN_SC_ROUTES_ASN"
    SMN_DATACENTER_ASN=$(require_field datacenterAsn)
    validate_asn datacenterAsn "$SMN_DATACENTER_ASN"
    FNN_CTRL_PLANE_VNI=$(require_field 'fnn.controlPlaneVni')
    validate_integer 'fnn.controlPlaneVni' "$FNN_CTRL_PLANE_VNI"
    FNN_VPC_VRF_PREFIX=$(yq_get 'fnn.vpcVrfLoopbackPrefix')
    if [[ -n "$FNN_VPC_VRF_PREFIX" ]]; then
        validate_cidr 'fnn.vpcVrfLoopbackPrefix' "$FNN_VPC_VRF_PREFIX"
        _vpc_prefix="${FNN_VPC_VRF_PREFIX#*/}"
        _vpc_capacity=$(( 1 << (32 - _vpc_prefix) ))
        [ "$_vpc_capacity" -ge "$NODE_COUNT" ] || \
            die "fnn.vpcVrfLoopbackPrefix $FNN_VPC_VRF_PREFIX is too small for $NODE_COUNT node(s) (capacity $_vpc_capacity addresses, need >= $NODE_COUNT)"
    fi
    FNN_COMMON_MANAGED_NODE_BMC=$(require_field 'fnn.commonManagedNodeBmcRouteTarget')
    validate_integer 'fnn.commonManagedNodeBmcRouteTarget' "$FNN_COMMON_MANAGED_NODE_BMC"
    FNN_COMMON_SC_RT=$(require_field 'fnn.commonSiteControllerRouteTarget')
    validate_integer 'fnn.commonSiteControllerRouteTarget' "$FNN_COMMON_SC_RT"
    FNN_COMMON_ADMIN=$(require_field 'fnn.commonAdminNetworkTarget')
    validate_integer 'fnn.commonAdminNetworkTarget' "$FNN_COMMON_ADMIN"
    # Normalize to the network address so a host-bit-set CIDR (e.g. 10.0.0.5/24)
    # doesn't offset all node addresses by the host bits.
    FNN_VPC_VRF_BASE_IP=$(get_nth_addr "${FNN_VPC_VRF_PREFIX:-0.0.0.0/32}" 0)
else
    log "fnn: not present in config — using startup.template (non-FNN mode)"
fi

read -r INT_VIP EXT_VIP <<< "$(split_in_half "$SERVICE_VIP_PREFIX")"

log "Generating servers for $NODE_COUNT node(s)..."

SORTED_INDICES=()
while IFS= read -r idx; do
    SORTED_INDICES+=("$idx")
done < <(
    for i in $(seq 0 $(( NODE_COUNT - 1 ))); do
        node_id=$(yq ".siteControllerNodes[$i].nodeId" "$CONTROL_PLANE_CONFIG")
        echo "$node_id $i"
    done | sort -n | awk '{print $2}'
)

declare -A _SEEN_HOSTNAMES=()

for pos in "${!SORTED_INDICES[@]}"; do
    idx="${SORTED_INDICES[$pos]}"

    HOSTNAME=$(yq ".siteControllerNodes[$idx].hostName // \"\"" "$CONTROL_PLANE_CONFIG")
    [ -z "$HOSTNAME" ] && die "siteControllerNodes[$idx]: hostName is required"
    [ "${_SEEN_HOSTNAMES["$HOSTNAME"]+set}" ] && die "siteControllerNodes[$idx]: hostName '$HOSTNAME' is not unique"
    _SEEN_HOSTNAMES["$HOSTNAME"]=1
    DPU_MAC=$(yq ".siteControllerNodes[$idx].mac // \"\"" "$CONTROL_PLANE_CONFIG")
    [ -z "$DPU_MAC" ] && die "$HOSTNAME: mac is required"
    [[ "$DPU_MAC" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]] || die "$HOSTNAME: mac '$DPU_MAC' is not a valid MAC address"

    ASN=$(( BGP_ASN_START + pos + 1 ))
    REMOTE_AS="$BGP_ASN_START"
    LOOPBACK_IP=$(get_nth_addr "$DPU_LOOPBACK_PREFIX" $(( pos + 1 )))
    LOOPBACK="${LOOPBACK_IP}/32"
    HOSTNET_IP=$(get_nth_addr "$CONTROL_PLANE_PREFIX" $(( pos * 2 )))
    HOSTNET="${HOSTNET_IP}/31"
    BGP_NEIGHBOR=$(get_nth_addr "$CONTROL_PLANE_PREFIX" $(( pos * 2 + 1 )))
    HOST_IP="${BGP_NEIGHBOR}/31"
    HOST_GATEWAY="$HOSTNET_IP"
    NODE_DIR="$OUTPUT_DIR/$HOSTNAME"
    mkdir -p "$NODE_DIR"

    if [[ "$HAS_FNN" == "true" ]]; then
        VPC_VRF_LOOPBACK=""
        [[ -n "$FNN_VPC_VRF_PREFIX" ]] && VPC_VRF_LOOPBACK="$(int_to_ip $(( $(ip_to_int "$FNN_VPC_VRF_BASE_IP") + pos )))/32"
        render_template "$TEMPLATES_DIR/startupSMN.template" \
            "ASN=$ASN" \
            "LoopbackIP=$LOOPBACK_IP" \
            "Loopback=$LOOPBACK" \
            "Hostnet=$HOSTNET" \
            "RemoteAS=$REMOTE_AS" \
            "BGPNeighbor=$BGP_NEIGHBOR" \
            "Rule30=$INT_VIP" \
            "Rule40=$EXT_VIP" \
            "ControlPlaneVNI=$FNN_CTRL_PLANE_VNI" \
            "SiteControllerRoutesASN=$SMN_SC_ROUTES_ASN" \
            "DatacenterASN=$SMN_DATACENTER_ASN" \
            "VpcVrfLoopback=$VPC_VRF_LOOPBACK" \
            "FnnCommonManagedNodeBmcRouteTarget=$FNN_COMMON_MANAGED_NODE_BMC" \
            "FnnCommonSiteControllerRouteTarget=$FNN_COMMON_SC_RT" \
            "FnnCommonAdminNetworkTarget=$FNN_COMMON_ADMIN" \
            > "$NODE_DIR/startup.yaml"
    else
        render_template "$TEMPLATES_DIR/startup.template" \
            "ASN=$ASN" \
            "LoopbackIP=$LOOPBACK_IP" \
            "Loopback=$LOOPBACK" \
            "Hostnet=$HOSTNET" \
            "RemoteAS=$REMOTE_AS" \
            "BGPNeighbor=$BGP_NEIGHBOR" \
            "Rule30=$INT_VIP" \
            "Rule40=$EXT_VIP" \
            > "$NODE_DIR/startup.yaml"
    fi

    render_template "$TEMPLATES_DIR/netplan.template" \
        "MTU=$MTU" \
        "MAC=$DPU_MAC" \
        "IP=$HOST_IP" \
        "NameServer=$NAMESERVER" \
        "RouteVia=$HOST_GATEWAY" \
        > "$NODE_DIR/99_config.yaml"

    log "  $HOSTNAME/startup.yaml  (ASN=$ASN, loopback=$LOOPBACK, hostnet=$HOSTNET)"
    log "  $HOSTNAME/99_config.yaml (host_ip=$HOST_IP, gateway=$HOST_GATEWAY)"
done

# ── Step 2: Download artifacts ───────────────────────────────────────────────

CLEANUP_ARTIFACTS_DIR=""

if [[ "$DOWNLOAD_ARTIFACTS" == false ]]; then
    step "Using pre-built artifacts from $ARTIFACTS_DIR"
else
    step "Downloading artifacts"
    ARTIFACTS_DIR="$(mktemp -d)"
    CLEANUP_ARTIFACTS_DIR="$ARTIFACTS_DIR"
    trap 'rm -rf ${STAGE_DIR:-} ${CLEANUP_ARTIFACTS_DIR:-}' EXIT

    BUILD_ARGS=(
        --doca-version "$DOCA_VERSION"
        --bfb-build    "$BFB_BUILD"
        --bfb-release  "$BFB_RELEASE"
    )
    [[ "$HBN_VERSION" != "$DOCA_VERSION" ]] && BUILD_ARGS+=(--doca-hbn-version "$HBN_VERSION")
    BUILD_ARGS+=(--hbn-container-tag "$HBN_CONTAINER_TAG")
    [[ -n "$BFB_URL" ]]        && BUILD_ARGS+=(--bfb-url "$BFB_URL")
    [[ -n "$HBN_CONFIG_URL" ]] && BUILD_ARGS+=(--hbn-config-url "$HBN_CONFIG_URL")
    BUILD_ARGS+=(--doca-host-url "$DOCA_HOST_URL")
    BUILD_ARGS+=(--rshim-url     "$RSHIM_URL")
    BUILD_ARGS+=(--libfuse2-url  "$LIBFUSE2_URL")

    log "Running download-build-dpu-artifacts.sh — output dir: $ARTIFACTS_DIR"
    (cd "$ARTIFACTS_DIR" && bash "$SCRIPT_DIR/download-build-dpu-artifacts.sh" "${BUILD_ARGS[@]}")
fi

# ── Step 2b: Validate HBN config bundle ─────────────────────────────────────

step "Validating HBN config bundle"

_hbn_ver_cfg="$ARTIFACTS_DIR/doca_hbn_versions.cfg"
[[ -f "$_hbn_ver_cfg" ]] || die "doca_hbn_versions.cfg not found in $ARTIFACTS_DIR"

# shellcheck source=/dev/null
source "$_hbn_ver_cfg"
[[ -z "${HBN_SCRIPT_DIR:-}" ]]    && die "HBN_SCRIPT_DIR not set in doca_hbn_versions.cfg"
[[ -z "${HBN_CONFIG_SRC_DIR:-}" ]] && die "HBN_CONFIG_SRC_DIR not set in doca_hbn_versions.cfg"
log "HBN_SCRIPT_DIR:    $HBN_SCRIPT_DIR"
log "HBN_CONFIG_SRC_DIR: $HBN_CONFIG_SRC_DIR"

# Strip leading ./ for zip path matching
_script_dir="${HBN_SCRIPT_DIR#./}"
_config_dir="${HBN_CONFIG_SRC_DIR#./}"

_zip=""
for f in "$ARTIFACTS_DIR"/doca_container_configs.zip "$ARTIFACTS_DIR"/doca_container_configs.zip.gz; do
    [[ -f "$f" ]] && _zip="$f" && break
done
[[ -z "$_zip" ]] && die "doca_container_configs.zip(.gz) not found in $ARTIFACTS_DIR"

if [[ "$_zip" == *.gz ]]; then
    _tmp_zip=$(mktemp /tmp/hbn_cfg_XXXXXX)
    gunzip -c "$_zip" > "$_tmp_zip"
    _zip_list=$(unzip -l "$_tmp_zip" | awk '{print $4}')
    rm -f "$_tmp_zip"
else
    _zip_list=$(unzip -l "$_zip" | awk '{print $4}')
fi

# Check HBN_SCRIPT_DIR exists in zip
if ! echo "$_zip_list" | grep -q "^${_script_dir}/"; then
    die "HBN_SCRIPT_DIR '${_script_dir}/' not found in doca_container_configs.zip — check doca_hbn_versions.cfg"
fi
log "HBN_SCRIPT_DIR found in zip: OK"

# Check hbn-dpu-setup.sh exists in HBN_SCRIPT_DIR
if ! echo "$_zip_list" | grep -q "^${_script_dir}/hbn-dpu-setup.sh$"; then
    die "hbn-dpu-setup.sh not found at '${_script_dir}/hbn-dpu-setup.sh' in zip"
fi
log "hbn-dpu-setup.sh found in zip: OK"

# Check HBN_CONFIG_SRC_DIR exists in zip
if ! echo "$_zip_list" | grep -q "^${_config_dir}/"; then
    die "HBN_CONFIG_SRC_DIR '${_config_dir}/' not found in doca_container_configs.zip — check doca_hbn_versions.cfg"
fi
log "HBN_CONFIG_SRC_DIR found in zip: OK"

# Check doca_hbn.yaml exists in HBN_CONFIG_SRC_DIR
if ! echo "$_zip_list" | grep -q "^${_config_dir}/doca_hbn.yaml$"; then
    die "doca_hbn.yaml not found at '${_config_dir}/doca_hbn.yaml' in zip — was it included in the artifact download?"
fi
log "doca_hbn.yaml found in zip: OK"

# ── Step 3: Assemble ISO staging directory ───────────────────────────────────

step "Assembling ISO contents"

STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGE_DIR" ${CLEANUP_ARTIFACTS_DIR:-}' EXIT

mkdir -p "$STAGE_DIR/servers"

cp "$ON_SERVER_DIR/install.sh"           "$STAGE_DIR/"
cp "$ON_SERVER_DIR/provision-dpu.sh"    "$STAGE_DIR/"
cp "$ON_SERVER_DIR/post-power-cycle.sh" "$STAGE_DIR/"
cp "$ON_SERVER_DIR/setup_netplan.sh"    "$STAGE_DIR/"
render_template "$TEMPLATES_DIR/bf.cfg.template" \
    "UbuntuPasswordHash=$UBUNTU_PASSWORD_HASH" \
    > "$STAGE_DIR/bf.cfg.template"
chmod 755 "$STAGE_DIR/install.sh" \
          "$STAGE_DIR/provision-dpu.sh" \
          "$STAGE_DIR/post-power-cycle.sh" \
          "$STAGE_DIR/setup_netplan.sh"

cp "$ON_SERVER_DIR/dpuinstall.sh" "$STAGE_DIR/"
chmod 755 "$STAGE_DIR/dpuinstall.sh"

cat > "$STAGE_DIR/dpu_fw_version.cfg" <<EOF
DOCA_VERSION="${DOCA_VERSION}"
HBN_VERSION="${HBN_VERSION}"
EOF

cat > "$STAGE_DIR/doca_hbn_versions.cfg" <<EOF
HBN_SCRIPT_DIR="${HBN_SCRIPT_DIR}"
HBN_CONFIG_SRC_DIR="${HBN_CONFIG_SRC_DIR}"
EOF

# Per-node DPU servers generated in step 1
log "Copying per-node servers..."
for i in "${!SORTED_INDICES[@]}"; do
    idx="${SORTED_INDICES[$i]}"
    hn=$(yq ".siteControllerNodes[$idx].hostName" "$CONTROL_PLANE_CONFIG")
    cp -r "$OUTPUT_DIR/$hn" "$STAGE_DIR/servers/$hn"
    log "  servers/$hn/"
done

log "Copying artifacts..."
copied=0
for pattern in "*.bfb" "*.bfb.gz" "*.deb" "*.deb.gz" "*.tar" "*.tar.gz" "*.zip" "*.zip.gz"; do
    for f in "$ARTIFACTS_DIR"/$pattern; do
        [[ -e "$f" ]] || continue
        cp "$f" "$STAGE_DIR/"
        log "  $(basename "$f")  ($(du -h "$f" | cut -f1))"
        copied=$(( copied + 1 ))
    done
done
[[ "$copied" -eq 0 ]] && die "No artifacts found in $ARTIFACTS_DIR — download may have failed"

log "Staging layout:"
find "$STAGE_DIR" -type f | sort | sed "s|$STAGE_DIR/||" | while read -r f; do
    log "  $f"
done

# ── Step 4: Build ISO ─────────────────────────────────────────────────────────

step "Building ISO: $(basename "$ISO_OUT")"
"$ISO_TOOL" -quiet -J -r -V "dpu-install" -o "$ISO_OUT" "$STAGE_DIR"
log "Created: $ISO_OUT  ($(du -h "$ISO_OUT" | cut -f1))"

# ── Step 5: Build ZIP ─────────────────────────────────────────────────────────

step "Building ZIP: $(basename "$ZIP_OUT")"
(cd "$STAGE_DIR" && zip -qr "$ZIP_OUT" .)
log "Created: $ZIP_OUT  ($(du -h "$ZIP_OUT" | cut -f1))"

# ── Cleanup: remove per-node config dirs from output (they are in ISO/ZIP) ───

for i in "${!SORTED_INDICES[@]}"; do
    idx="${SORTED_INDICES[$i]}"
    hn=$(yq ".siteControllerNodes[$idx].hostName // \"\"" "$CONTROL_PLANE_CONFIG")
    [ -n "$hn" ] && rm -rf "${OUTPUT_DIR:?}/$hn"
done

# ── Summary ───────────────────────────────────────────────────────────────────

echo
echo "============================================================"
echo "  Done. Output: $OUTPUT_DIR"
echo "============================================================"
echo "  $(du -h "$ISO_OUT")"
echo "  $(du -h "$ZIP_OUT")"
echo "============================================================"
echo
echo "To provision a site controller:"
echo "  mount -o ro,loop $(basename "$ISO_OUT") /mnt/dpu-install"
echo "  /mnt/dpu-install/install.sh"
echo "  /var/lib/dpu-install/${DOCA_VERSION}_${HBN_VERSION}/provision-dpu.sh --server-name <hostname>"
echo "  (power cycle)"
echo "  /var/lib/dpu-install/${DOCA_VERSION}_${HBN_VERSION}/post-power-cycle.sh --server-name <hostname>"
