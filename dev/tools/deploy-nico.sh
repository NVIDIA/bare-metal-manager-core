#!/usr/bin/env bash
# =============================================================================
# deploy-nico.sh
# -----------------------------------------------------------------------------
# Comprehensive, idempotent end-to-end automation for deploying NICo
# (NCX Infra Controller) on any Linux host(s).
#
# Capabilities
# ------------
#   * Collects deployment topology either interactively or non-interactively
#     (env vars / config file / --yes) — suitable for CircleCI.
#   * Generic IP & subnet handling — works for any /24 lab network, any
#     range of MetalLB VIPs, any DHCP pool, any number of worker nodes.
#   * Provisions a local Docker registry on the control-plane host and
#     rewrites devspace/helm value files so the cluster pulls images from
#     <registry-host>:<registry-port> instead of relying on per-node
#     `ctr images import`.
#   * Runs (or generates) every phase of DEPLOYMENT.md:
#       Phase 1 — OS prereqs (kernel, swap, containerd, kubeadm tools)
#       Phase 2 — kubeadm cluster bring-up + Calico
#       Phase 3 — dev tools (helm, helmfile, devspace, docker)
#       Phase 4 — MetalLB install + IPAddressPool/L2Advertisement
#       Phase 5 — Generate site-specific values.* files
#       Phase 6 — Bootstrap prereqs (cert-manager, vault, postgres)
#       Phase 7 — Build images via devspace + push to local registry +
#                 deploy helm chart
#
# Usage
# -----
#   # Interactive (asks every question, suitable for first run on a lab host)
#   ./dev/tools/deploy-nico.sh
#
#   # Non-interactive via config file (CircleCI / repeat runs)
#   ./dev/tools/deploy-nico.sh --config ./my-site.env --yes
#
#   # Non-interactive via env vars
#   NICO_SUBNET_CIDR=172.16.0.0/24 NICO_GATEWAY=172.16.0.1 \
#   NICO_CP_IP=172.16.0.80 NICO_WORKER_IPS=172.16.0.81,172.16.0.82 \
#   NICO_METALLB_RANGE=172.16.0.85-172.16.0.95 \
#   NICO_DHCP_POOL=172.16.0.20-172.16.0.76 \
#   NICO_LOOPBACK_POOL=172.16.0.100-172.16.0.121 \
#   ./dev/tools/deploy-nico.sh --yes
#
#   # Just generate values files + print summary (no cluster changes)
#   ./dev/tools/deploy-nico.sh --phases values --yes
#
#   # Run a subset of phases (comma-separated)
#   ./dev/tools/deploy-nico.sh --phases prereqs,registry,values,deploy --yes
#
# Phase names
# -----------
#   prereqs   — Phase 1 (OS / kernel / containerd / kubeadm packages)
#   cluster   — Phase 2 (kubeadm init + Calico + join workers)
#   tools     — Phase 3 (helm, helmfile, devspace, docker, kubectl)
#   metallb   — Phase 4 (MetalLB install + L2 advertisement)
#   values    — Phase 5 (render values.base.yaml / ncx-core.yaml from template)
#   registry  — Provision local Docker registry on CP node + rewrite values
#   bootstrap — Phase 6 (cert-manager, vault, postgres via bootstrap-prereqs.sh)
#   deploy    — Phase 7 (devspace build/push + helm deploy)
#   cli       — Configure carbide-admin-cli (`ncli`) on the control-plane host:
#               extract TLS certs, add the carbide-api /etc/hosts entry, write
#               ~/.config/carbide_api_cli.json and the `ncli` alias in ~/.bashrc
#   verify    — Verify pods/services and print useful URLs
#   all       — All of the above, in order (default)
#
# Environment variables (overridable; defaults will be prompted in interactive)
# ----------------------------------------------------------------------------
#   NICO_REPO_ROOT          Path to ncx-infra-controller-core checkout
#                           (default: auto-detect via script location)
#   NICO_NAMESPACE          K8s namespace for NICo  (default: forge-system)
#   NICO_SITE_NAME          Site name in carbide-api siteConfig (default: nico-lab)
#   NICO_DOMAIN             initial_domain_name              (default: lab.local)
#
#   NICO_SUBNET_CIDR        Management/OOB subnet            (e.g. 172.16.0.0/24)
#   NICO_GATEWAY            Gateway for subnet               (e.g. 172.16.0.1)
#   NICO_MTU                MTU                              (default: 1500)
#
#   NICO_CP_IP              Control-plane host IP            (e.g. 172.16.0.80)
#   NICO_WORKER_IPS         Comma-separated worker IPs       (e.g. 172.16.0.81,172.16.0.82)
#   NICO_NIC_NAME           Primary NIC name on each host    (default: eth0)
#
#   NICO_METALLB_RANGE      VIP pool start-end               (e.g. 172.16.0.85-172.16.0.95)
#   NICO_DHCP_POOL          BMC DHCP pool start-end          (e.g. 172.16.0.20-172.16.0.76)
#                           Used to compute reserve_first.
#   NICO_LOOPBACK_POOL      NICo loopback IP pool start-end  (e.g. 172.16.0.100-172.16.0.121)
#
#   NICO_VLAN_ID_POOL       integer pool start-end           (default: 100-501)
#   NICO_VNI_POOL           integer pool start-end           (default: 1024000-1099999)
#
#   NICO_VIP_DHCP           VIP for carbide-dhcp             (default: first of NICO_METALLB_RANGE)
#   NICO_VIP_PXE            VIP for carbide-pxe              (default: NICO_VIP_DHCP + 1)
#   NICO_VIP_DNS_0          VIP for carbide-dns-0            (default: NICO_VIP_DHCP + 2)
#   NICO_VIP_DNS_1          VIP for carbide-dns-1            (default: NICO_VIP_DHCP + 3)
#   NICO_VIP_API            VIP for carbide-api              (default: NICO_VIP_DHCP + 4)
#   NICO_VIP_SSH            VIP for carbide-ssh-console      (default: NICO_VIP_DHCP + 5)
#   NICO_VIP_UNBOUND        VIP for forge-unbound            (default: NICO_VIP_DHCP + 6)
#
#   NICO_REGISTRY_HOST      Hostname/IP of local registry    (default: NICO_CP_IP)
#   NICO_REGISTRY_PORT      Port of local registry           (default: 5000)
#   NICO_REGISTRY_NAME      docker container name            (default: nico-registry)
#   NICO_REGISTRY_DATA      Host directory for registry data (default: /var/lib/nico-registry)
#   NICO_USE_REGISTRY       0 to skip registry + fall back to ctr-import workflow
#                           (default: 1 — use registry)
#
#   NICO_SQUID_PROXY        HTTP proxy for air-gapped builds (optional)
#   NICO_SSH_USER           SSH user used to reach worker nodes (default: $USER)
#   NICO_SSH_KEY            Identity file for ssh to workers (default: ~/.ssh/id_rsa)
#
#   NICO_KUBE_VERSION       Kubernetes version               (default: 1.30.4-1.1)
#   NICO_CALICO_VERSION     Calico manifest version          (default: v3.28.1)
#   NICO_METALLB_VERSION    MetalLB helm chart version       (default: 0.14.5)
#   NICO_POD_CIDR           Pod CIDR for kubeadm             (default: 10.244.0.0/16)
#
#   NICO_CLI_BIN            Path to the carbide-admin-cli binary used by the
#                           `ncli` alias    (default: <repo>/target/release/carbide-admin-cli)
#   NICO_CLI_CERT_DIR       Persistent dir for the extracted CLI TLS certs
#                           (default: ~/.config/carbide-certs)
#
#   NICO_NON_INTERACTIVE    1 to skip prompts (same as --yes)
#   NICO_LOG_DIR            Where to write logs              (default: /tmp/nico-deploy)
#
# Exit codes
# ----------
#   0   success
#   1   user aborted / missing required input
#   2   prerequisite missing on host
#   3   a phase failed (see log for details)
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Bootstrap: locate repo root, set defaults
# -----------------------------------------------------------------------------
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "${SCRIPT_PATH}")"
DEFAULT_REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

NICO_REPO_ROOT="${NICO_REPO_ROOT:-${DEFAULT_REPO_ROOT}}"
NICO_NAMESPACE="${NICO_NAMESPACE:-forge-system}"
NICO_SITE_NAME="${NICO_SITE_NAME:-nico-lab}"
NICO_DOMAIN="${NICO_DOMAIN:-lab.local}"
NICO_MTU="${NICO_MTU:-1500}"
NICO_NIC_NAME="${NICO_NIC_NAME:-eth0}"
NICO_VLAN_ID_POOL="${NICO_VLAN_ID_POOL:-100-501}"
NICO_VNI_POOL="${NICO_VNI_POOL:-1024000-1099999}"
NICO_REGISTRY_PORT="${NICO_REGISTRY_PORT:-5000}"
NICO_REGISTRY_NAME="${NICO_REGISTRY_NAME:-nico-registry}"
NICO_REGISTRY_DATA="${NICO_REGISTRY_DATA:-/var/lib/nico-registry}"
NICO_USE_REGISTRY="${NICO_USE_REGISTRY:-1}"
NICO_KUBE_VERSION="${NICO_KUBE_VERSION:-1.30.4-1.1}"
NICO_CALICO_VERSION="${NICO_CALICO_VERSION:-v3.28.1}"
NICO_METALLB_VERSION="${NICO_METALLB_VERSION:-0.14.5}"
NICO_POD_CIDR="${NICO_POD_CIDR:-10.244.0.0/16}"
NICO_SSH_USER="${NICO_SSH_USER:-${USER}}"
NICO_SSH_KEY="${NICO_SSH_KEY:-${HOME}/.ssh/id_rsa}"
NICO_LOG_DIR="${NICO_LOG_DIR:-/tmp/nico-deploy}"
NICO_NON_INTERACTIVE="${NICO_NON_INTERACTIVE:-0}"
NICO_SQUID_PROXY="${NICO_SQUID_PROXY:-}"

# ---- carbide-admin-cli (`ncli`) --------------------------------------------
# Binary built by `cargo build --release -p carbide-admin-cli`. Override
# NICO_CLI_BIN if you keep the binary somewhere else (e.g. copied to ~/).
NICO_CLI_BIN="${NICO_CLI_BIN:-${NICO_REPO_ROOT}/target/release/carbide-admin-cli}"
NICO_CLI_CERT_DIR="${NICO_CLI_CERT_DIR:-${HOME}/.config/carbide-certs}"

# ---- Unbound (site-built) images -------------------------------------------
# The `unbound` + `unbound_exporter` images are NOT built by devspace; they are
# built here so a deploy produces every image NICo runs. Tags must match the
# values pinned in phase_values (`unbound.image.tag` / `unbound.exporterImage.tag`).
NICO_BUILD_UNBOUND="${NICO_BUILD_UNBOUND:-1}"
NICO_UNBOUND_VERSION="${NICO_UNBOUND_VERSION:-1.20.0}"
NICO_EXPORTER_REF="${NICO_EXPORTER_REF:-v0.4.6}"
NICO_UNBOUND_TAG="${NICO_UNBOUND_TAG:-1.20.0-local}"
NICO_EXPORTER_TAG="${NICO_EXPORTER_TAG:-0.4.6-local}"

PHASES="all"
CONFIG_FILE=""

mkdir -p "${NICO_LOG_DIR}"
LOG_FILE="${NICO_LOG_DIR}/deploy-$(date +%Y%m%d-%H%M%S).log"

# -----------------------------------------------------------------------------
# Logging helpers
# -----------------------------------------------------------------------------
C_RESET=$'\e[0m'; C_RED=$'\e[31m'; C_GREEN=$'\e[32m'
C_YELLOW=$'\e[33m'; C_BLUE=$'\e[34m'; C_BOLD=$'\e[1m'

log()  { printf '%s[INFO]%s  %s\n'  "${C_BLUE}"   "${C_RESET}" "$*" | tee -a "${LOG_FILE}"; }
warn() { printf '%s[WARN]%s  %s\n'  "${C_YELLOW}" "${C_RESET}" "$*" | tee -a "${LOG_FILE}"; }
err()  { printf '%s[ERR ]%s  %s\n'  "${C_RED}"    "${C_RESET}" "$*" | tee -a "${LOG_FILE}" >&2; }
ok()   { printf '%s[ OK ]%s  %s\n'  "${C_GREEN}"  "${C_RESET}" "$*" | tee -a "${LOG_FILE}"; }
hdr()  { printf '\n%s========== %s ==========%s\n' "${C_BOLD}" "$*" "${C_RESET}" | tee -a "${LOG_FILE}"; }

die()  { err "$*"; exit 3; }

run() {
  log "+ $*"
  if ! "$@" 2>&1 | tee -a "${LOG_FILE}"; then
    die "command failed: $*"
  fi
}

# -----------------------------------------------------------------------------
# CLI parsing
# -----------------------------------------------------------------------------
usage() {
  sed -n '/^# =\{10,\}/,/^# =\{10,\}/p' "${SCRIPT_PATH}" | sed 's/^# \{0,1\}//' | head -90
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)  CONFIG_FILE="$2"; shift 2 ;;
    --phases)  PHASES="$2"; shift 2 ;;
    --yes|-y)  NICO_NON_INTERACTIVE=1; shift ;;
    --help|-h) usage ;;
    *) err "Unknown argument: $1"; usage ;;
  esac
done

if [[ -n "${CONFIG_FILE}" ]]; then
  if [[ ! -r "${CONFIG_FILE}" ]]; then
    die "config file not readable: ${CONFIG_FILE}"
  fi
  log "Loading config from ${CONFIG_FILE}"
  # shellcheck disable=SC1090
  set -a; source "${CONFIG_FILE}"; set +a
fi

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
prompt() {
  # prompt VAR_NAME "Question text" "default"
  local var="$1" question="$2" default="${3:-}" current
  current="${!var:-${default}}"
  if [[ "${NICO_NON_INTERACTIVE}" == "1" ]]; then
    if [[ -z "${current}" ]]; then
      die "missing required value: ${var} (run interactively or set in env/config)"
    fi
    printf -v "${var}" '%s' "${current}"
    return 0
  fi
  local input
  if [[ -n "${current}" ]]; then
    read -r -p "$(printf '%s [%s]: ' "${question}" "${current}")" input || true
    input="${input:-${current}}"
  else
    read -r -p "$(printf '%s: ' "${question}")" input || true
    while [[ -z "${input}" ]]; do
      read -r -p "$(printf '%s (required): ' "${question}")" input || true
    done
  fi
  printf -v "${var}" '%s' "${input}"
}

confirm() {
  # confirm "Question" — returns 0 if yes
  [[ "${NICO_NON_INTERACTIVE}" == "1" ]] && return 0
  local ans
  read -r -p "$(printf '%s [y/N]: ' "$1")" ans || true
  [[ "${ans:-}" =~ ^[Yy] ]]
}

ip_to_int() {
  local a b c d
  IFS=. read -r a b c d <<<"$1"
  printf '%d' "$(( (a<<24) + (b<<16) + (c<<8) + d ))"
}
int_to_ip() {
  local n="$1"
  printf '%d.%d.%d.%d' \
    "$(( (n>>24) & 0xff ))" \
    "$(( (n>>16) & 0xff ))" \
    "$(( (n>> 8) & 0xff ))" \
    "$(( n & 0xff ))"
}
ip_add() {
  local base="$1" offset="$2"
  int_to_ip "$(( $(ip_to_int "${base}") + offset ))"
}
range_start() { echo "${1%%-*}"; }
range_end()   { echo "${1##*-}"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command missing: $1"
}

ssh_run() {
  local host="$1"; shift
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -i "${NICO_SSH_KEY}" "${NICO_SSH_USER}@${host}" "$@"
}

# Run on local host and (if multi-node) on each worker via ssh.
on_all_nodes() {
  local script="$1"
  log "Running on local host (control-plane)"
  bash -c "${script}" 2>&1 | tee -a "${LOG_FILE}"
  for w in "${WORKER_IPS_ARR[@]}"; do
    log "Running on worker ${w}"
    # shellcheck disable=SC2029
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -i "${NICO_SSH_KEY}" "${NICO_SSH_USER}@${w}" "bash -s" <<< "${script}" 2>&1 \
      | tee -a "${LOG_FILE}"
  done
}

# -----------------------------------------------------------------------------
# Phase 0 — collect inputs
# -----------------------------------------------------------------------------
phase_inputs() {
  hdr "Collecting deployment inputs"

  prompt NICO_REPO_ROOT       "Path to ncx-infra-controller-core checkout"  "${NICO_REPO_ROOT}"
  prompt NICO_NAMESPACE       "Kubernetes namespace for NICo"               "${NICO_NAMESPACE}"
  prompt NICO_SITE_NAME       "Site name (carbide-api sitename)"            "${NICO_SITE_NAME}"
  prompt NICO_DOMAIN          "Initial domain name"                         "${NICO_DOMAIN}"

  prompt NICO_SUBNET_CIDR     "Management/OOB subnet CIDR (e.g. 172.16.0.0/24)"  "${NICO_SUBNET_CIDR:-}"
  prompt NICO_GATEWAY         "Gateway IP for that subnet"                       "${NICO_GATEWAY:-}"
  prompt NICO_NIC_NAME        "Primary NIC name on each VM (must be uniform)"    "${NICO_NIC_NAME}"
  prompt NICO_MTU             "MTU"                                              "${NICO_MTU}"

  prompt NICO_CP_IP           "Control-plane host IP"                            "${NICO_CP_IP:-}"
  prompt NICO_WORKER_IPS      "Comma-separated worker host IPs (empty = single-node)"  "${NICO_WORKER_IPS:-}"

  prompt NICO_METALLB_RANGE   "MetalLB VIP pool (start-end, ≥7 IPs)"             "${NICO_METALLB_RANGE:-}"
  prompt NICO_DHCP_POOL       "BMC DHCP pool (start-end)"                        "${NICO_DHCP_POOL:-}"
  prompt NICO_LOOPBACK_POOL   "NICo loopback IP pool (start-end)"                "${NICO_LOOPBACK_POOL:-}"
  prompt NICO_VLAN_ID_POOL    "VLAN-ID integer pool (start-end)"                 "${NICO_VLAN_ID_POOL}"
  prompt NICO_VNI_POOL        "VNI integer pool (start-end)"                     "${NICO_VNI_POOL}"

  prompt NICO_USE_REGISTRY    "Provision local Docker registry & use it? (1/0)" "${NICO_USE_REGISTRY}"
  if [[ "${NICO_USE_REGISTRY}" == "1" ]]; then
    NICO_REGISTRY_HOST="${NICO_REGISTRY_HOST:-${NICO_CP_IP}}"
    prompt NICO_REGISTRY_HOST "Registry hostname or IP (reachable from all nodes)" "${NICO_REGISTRY_HOST}"
    prompt NICO_REGISTRY_PORT "Registry port"                                       "${NICO_REGISTRY_PORT}"
    prompt NICO_REGISTRY_DATA "Host directory to persist registry data"             "${NICO_REGISTRY_DATA}"
  fi

  prompt NICO_SQUID_PROXY     "HTTP proxy for builds (empty = none)"            "${NICO_SQUID_PROXY}"

  # ------- derive per-service VIPs (configurable, defaults = sequential) -----
  local mb_start; mb_start="$(range_start "${NICO_METALLB_RANGE}")"
  NICO_VIP_DHCP="${NICO_VIP_DHCP:-$(ip_add "${mb_start}" 0)}"
  NICO_VIP_PXE="${NICO_VIP_PXE:-$(ip_add "${mb_start}" 1)}"
  NICO_VIP_DNS_0="${NICO_VIP_DNS_0:-$(ip_add "${mb_start}" 2)}"
  NICO_VIP_DNS_1="${NICO_VIP_DNS_1:-$(ip_add "${mb_start}" 3)}"
  NICO_VIP_API="${NICO_VIP_API:-$(ip_add "${mb_start}" 4)}"
  NICO_VIP_SSH="${NICO_VIP_SSH:-$(ip_add "${mb_start}" 5)}"
  NICO_VIP_UNBOUND="${NICO_VIP_UNBOUND:-$(ip_add "${mb_start}" 6)}"

  # Parse worker IPs into array; empty = none.
  WORKER_IPS_ARR=()
  if [[ -n "${NICO_WORKER_IPS:-}" ]]; then
    IFS=',' read -r -a WORKER_IPS_ARR <<<"${NICO_WORKER_IPS}"
  fi

  # Derive reserve_first from DHCP-pool start relative to subnet base.
  local subnet_base="${NICO_SUBNET_CIDR%/*}"
  local dhcp_start; dhcp_start="$(range_start "${NICO_DHCP_POOL}")"
  local subnet_base_no_last="${subnet_base%.*}"
  local dhcp_start_no_last="${dhcp_start%.*}"
  if [[ "${subnet_base_no_last}" != "${dhcp_start_no_last}" ]]; then
    warn "DHCP pool ${NICO_DHCP_POOL} is outside subnet base ${subnet_base} — reserve_first set to 2"
    RESERVE_FIRST=2
  else
    RESERVE_FIRST="${dhcp_start##*.}"
  fi
  export RESERVE_FIRST

  hdr "Deployment plan"
  cat <<EOF | tee -a "${LOG_FILE}"
Repo root        : ${NICO_REPO_ROOT}
Namespace        : ${NICO_NAMESPACE}
Site name        : ${NICO_SITE_NAME}
Domain           : ${NICO_DOMAIN}
Subnet           : ${NICO_SUBNET_CIDR}  gw=${NICO_GATEWAY}  mtu=${NICO_MTU}
Primary NIC      : ${NICO_NIC_NAME}
Control-plane    : ${NICO_CP_IP}
Workers          : ${WORKER_IPS_ARR[*]:-<none>}
MetalLB pool     : ${NICO_METALLB_RANGE}
DHCP pool        : ${NICO_DHCP_POOL}  (reserve_first=${RESERVE_FIRST})
Loopback pool    : ${NICO_LOOPBACK_POOL}
VLAN-ID pool     : ${NICO_VLAN_ID_POOL}
VNI pool         : ${NICO_VNI_POOL}
VIPs             : dhcp=${NICO_VIP_DHCP} pxe=${NICO_VIP_PXE}
                   dns0=${NICO_VIP_DNS_0} dns1=${NICO_VIP_DNS_1}
                   api=${NICO_VIP_API} ssh=${NICO_VIP_SSH} unbound=${NICO_VIP_UNBOUND}
Use registry     : ${NICO_USE_REGISTRY}
EOF
  if [[ "${NICO_USE_REGISTRY}" == "1" ]]; then
    echo "Registry         : ${NICO_REGISTRY_HOST}:${NICO_REGISTRY_PORT}  data=${NICO_REGISTRY_DATA}" \
      | tee -a "${LOG_FILE}"
  fi
  echo "Log file         : ${LOG_FILE}" | tee -a "${LOG_FILE}"

  if ! confirm "Proceed with these settings?"; then
    die "aborted by user"
  fi
}

# -----------------------------------------------------------------------------
# Phase 1 — OS prereqs (kernel, swap, containerd, kubeadm packages)
# -----------------------------------------------------------------------------
phase_prereqs() {
  hdr "Phase 1: OS prereqs (kernel, swap, containerd, kubeadm)"

  local kver="${NICO_KUBE_VERSION}"
  local script
  script=$(cat <<EOF
set -euxo pipefail
sudo swapoff -a
sudo sed -i '/\\bswap\\b/d' /etc/fstab

cat <<KSYSCTL | sudo tee /etc/sysctl.d/99-kubernetes.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
KSYSCTL
sudo modprobe br_netfilter || true
echo br_netfilter | sudo tee /etc/modules-load.d/br_netfilter.conf
sudo sysctl --system >/dev/null

# /etc/hosts entries for kubeadm + Calico Felix DNS resolution
sudo sed -i '/# nico-managed-hosts/,/# end-nico-managed-hosts/d' /etc/hosts
sudo tee -a /etc/hosts <<HOSTS
# nico-managed-hosts
${NICO_CP_IP}  nico-cp-1
HOSTS

# kernel modules
sudo apt-get update -y
sudo apt-get install -y ca-certificates curl gnupg lsb-release apt-transport-https

# Docker repo (for containerd.io)
if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg
fi
echo "deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \$(lsb_release -cs) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list

# Kubernetes repo
if [[ ! -f /etc/apt/keyrings/kubernetes-apt-keyring.gpg ]]; then
  curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.30/deb/Release.key \
    | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
fi
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.30/deb/ /' \
  | sudo tee /etc/apt/sources.list.d/kubernetes.list

sudo apt-get update -y
sudo apt-get install -y containerd.io kubelet=${kver} kubeadm=${kver} kubectl=${kver}
sudo apt-mark hold kubelet kubeadm kubectl

sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml >/dev/null
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
sudo systemctl restart containerd
sudo systemctl enable containerd kubelet

sudo ufw disable 2>/dev/null || true
EOF
)
  on_all_nodes "${script}"
  ok "OS prereqs installed on all nodes"
}

# -----------------------------------------------------------------------------
# Phase 2 — kubeadm cluster bring-up + Calico
# -----------------------------------------------------------------------------
phase_cluster() {
  hdr "Phase 2: kubeadm init + Calico + worker join"

  if kubectl cluster-info >/dev/null 2>&1; then
    warn "Cluster already initialised — skipping kubeadm init"
  else
    run sudo kubeadm init \
      --kubernetes-version="v${NICO_KUBE_VERSION%-*}" \
      --pod-network-cidr="${NICO_POD_CIDR}" \
      --apiserver-advertise-address="${NICO_CP_IP}" \
      --control-plane-endpoint="${NICO_CP_IP}"

    mkdir -p "${HOME}/.kube"
    sudo cp /etc/kubernetes/admin.conf "${HOME}/.kube/config"
    sudo chown "$(id -u):$(id -g)" "${HOME}/.kube/config"
    export KUBECONFIG="${HOME}/.kube/config"
  fi
  export KUBECONFIG="${HOME}/.kube/config"

  # Install Calico
  local calico_yaml="${NICO_LOG_DIR}/calico-${NICO_CALICO_VERSION}.yaml"
  if [[ ! -f "${calico_yaml}" ]]; then
    run curl -fsSL -o "${calico_yaml}" \
      "https://raw.githubusercontent.com/projectcalico/calico/${NICO_CALICO_VERSION}/manifests/calico.yaml"
  fi
  run kubectl apply -f "${calico_yaml}"
  run kubectl set env daemonset/calico-node -n kube-system \
    IP_AUTODETECTION_METHOD="interface=${NICO_NIC_NAME}" \
    IP6_AUTODETECTION_METHOD=none

  if (( ${#WORKER_IPS_ARR[@]} > 0 )); then
    log "Generating kubeadm join command"
    local join_cmd
    join_cmd="$(sudo kubeadm token create --print-join-command)"
    for w in "${WORKER_IPS_ARR[@]}"; do
      log "Joining worker ${w}"
      ssh_run "${w}" "sudo ${join_cmd}" || warn "join may already be done on ${w}"
    done
  fi

  log "Waiting for nodes to become Ready (up to 5 min)"
  for _ in $(seq 1 60); do
    if kubectl get nodes 2>/dev/null | tail -n +2 | awk '{print $2}' | grep -vq Ready; then
      sleep 5
    else
      break
    fi
  done
  kubectl get nodes -o wide | tee -a "${LOG_FILE}"
  ok "Cluster up"
}

# -----------------------------------------------------------------------------
# Phase 3 — Dev tools (helm, helmfile, devspace, docker)
# -----------------------------------------------------------------------------
phase_tools() {
  hdr "Phase 3: install helm, helmfile, devspace, docker (control-plane host only)"

  if ! command -v helm >/dev/null 2>&1; then
    run bash -c 'curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash'
  fi
  if ! command -v devspace >/dev/null 2>&1; then
    run bash -c 'curl -fsSL https://github.com/loft-sh/devspace/releases/latest/download/devspace-linux-amd64 -o /tmp/devspace && sudo install -m 0755 /tmp/devspace /usr/local/bin/devspace'
  fi
  if ! helm plugin list 2>/dev/null | grep -q '^diff'; then
    run helm plugin install https://github.com/databus23/helm-diff
  fi
  if ! command -v docker >/dev/null 2>&1; then
    run sudo apt-get install -y docker-ce docker-ce-cli docker-buildx-plugin docker-compose-plugin
    run sudo usermod -aG docker "${USER}"
    warn "User added to docker group — you may need to log out/in for non-sudo docker access"
  fi
  ok "Dev tools installed"
}

# -----------------------------------------------------------------------------
# Phase 4 — MetalLB
# -----------------------------------------------------------------------------
phase_metallb() {
  hdr "Phase 4: install MetalLB + apply IPAddressPool/L2Advertisement"

  if ! helm status metallb -n metallb-system >/dev/null 2>&1; then
    run helm repo add metallb https://metallb.github.io/metallb
    run helm repo update
    run helm install metallb metallb/metallb \
      --version "${NICO_METALLB_VERSION}" \
      --namespace metallb-system --create-namespace --wait
  else
    log "MetalLB already installed"
  fi

  log "Waiting for MetalLB webhook to be ready..."
  kubectl rollout status deployment/metallb-controller -n metallb-system --timeout=180s || true

  cat <<EOF | kubectl apply -f - | tee -a "${LOG_FILE}"
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: nico-vips
  namespace: metallb-system
spec:
  addresses:
    - ${NICO_METALLB_RANGE}
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: nico-vips-l2
  namespace: metallb-system
spec:
  ipAddressPools:
    - nico-vips
  interfaces:
    - ${NICO_NIC_NAME}
EOF
  ok "MetalLB configured with pool ${NICO_METALLB_RANGE}"
}

# -----------------------------------------------------------------------------
# Phase 5 — render site-specific values files
# -----------------------------------------------------------------------------
phase_values() {
  hdr "Phase 5: render values.base.yaml and helm-prereqs/ncx-core.yaml"

  local out_dir="${NICO_REPO_ROOT}/dev/deployment/devspace"
  local values_base="${out_dir}/values.base.yaml"
  local backup="${values_base}.bak.$(date +%s)"

  if [[ -f "${values_base}" ]]; then
    cp "${values_base}" "${backup}"
    log "Backed up existing values.base.yaml → ${backup}"
  fi

  local image_repo="carbide-api"
  local bmc_repo="carbide-bmc-proxy"
  if [[ "${NICO_USE_REGISTRY}" == "1" ]]; then
    image_repo="${NICO_REGISTRY_HOST}:${NICO_REGISTRY_PORT}/carbide-api"
    bmc_repo="${NICO_REGISTRY_HOST}:${NICO_REGISTRY_PORT}/carbide-bmc-proxy"
  fi

  cat >"${values_base}" <<EOF
# AUTO-GENERATED by dev/tools/deploy-nico.sh
# Site: ${NICO_SITE_NAME}  Domain: ${NICO_DOMAIN}
# Subnet: ${NICO_SUBNET_CIDR}  Gateway: ${NICO_GATEWAY}
# MetalLB pool: ${NICO_METALLB_RANGE}  DHCP pool: ${NICO_DHCP_POOL}
# Loopback pool: ${NICO_LOOPBACK_POOL}
# Generated: $(date -Iseconds)

global:
  image:
    repository: "${image_repo}"
    pullPolicy: IfNotPresent

carbide-api:
  image:
    repository: "${image_repo}"
    pullPolicy: IfNotPresent
  resources:
    limits:   { cpu: "16", memory: "16Gi" }
    requests: { cpu: "1",  memory: "1Gi" }
  siteConfig:
    enabled: true
    carbideApiSiteConfig: |
      sitename             = "${NICO_SITE_NAME}"
      initial_domain_name  = "${NICO_DOMAIN}"
      attestation_enabled  = false
      dpu_ipmi_tool_impl   = "ipmi"
      max_database_connections = 64
      dhcp_servers = ["${NICO_VIP_DHCP}"]

      [pools.lo-ip]
      type   = "ipv4"
      ranges = [{ start = "$(range_start "${NICO_LOOPBACK_POOL}")", end = "$(range_end "${NICO_LOOPBACK_POOL}")" }]

      [pools.vlan-id]
      type   = "integer"
      ranges = [{ start = "$(range_start "${NICO_VLAN_ID_POOL}")", end = "$(range_end "${NICO_VLAN_ID_POOL}")" }]

      [pools.vni]
      type   = "integer"
      ranges = [{ start = "$(range_start "${NICO_VNI_POOL}")", end = "$(range_end "${NICO_VNI_POOL}")" }]

      [networks.admin]
      type          = "underlay"
      prefix        = "${NICO_SUBNET_CIDR}"
      gateway       = "${NICO_GATEWAY}"
      mtu           = ${NICO_MTU}
      reserve_first = ${RESERVE_FIRST}

      [site_explorer]
      enabled              = true
      create_machines      = true
      allow_zero_dpu_hosts = true
      explore_mode         = "nv-redfish"
      run_interval         = "30s"

      [machine_state_controller]
      failure_retry_time = "90m"

      [machine_validation_config]
      enabled = false

  externalService:
    enabled: true
    annotations:
      metallb.universe.tf/loadBalancerIPs: "${NICO_VIP_API}"

carbide-bmc-proxy:
  enabled: true
  image:
    repository: "${bmc_repo}"
    pullPolicy: IfNotPresent

carbide-dhcp:
  enabled: true
  externalService:
    enabled: true
    annotations:
      metallb.universe.tf/loadBalancerIPs: "${NICO_VIP_DHCP}"
  config:
    enabled: true
    keaConfigJson: |
      {
        "Dhcp4": {
          "interfaces-config": { "interfaces": ["${NICO_NIC_NAME}"], "dhcp-socket-type": "udp" },
          "lease-database": { "type": "memfile", "lfc-interval": 3600 },
          "match-client-id": false,
          "authoritative": true,
          "renew-timer": 900,
          "rebind-timer": 1800,
          "valid-lifetime": 3600,
          "hooks-libraries": [
            {
              "library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp.so",
              "parameters": {
                "carbide-api-url": "https://carbide-api.__NAMESPACE__.svc.cluster.local:1079",
                "carbide-metrics-endpoint": "[::]:1089",
                "carbide-nameservers": "${NICO_VIP_UNBOUND}",
                "carbide-ntpserver": "${NICO_CP_IP}",
                "carbide-provisioning-server-ipv4": "${NICO_VIP_PXE}"
              }
            }
          ],
          "subnet4": [
            { "subnet": "0.0.0.0/0", "pools": [{ "pool": "0.0.0.0-255.255.255.255" }] }
          ]
        }
      }

carbide-pxe:
  enabled: true
  externalService:
    enabled: true
    annotations:
      metallb.universe.tf/loadBalancerIPs: "${NICO_VIP_PXE}"

carbide-dns:
  enabled: true
  externalService:
    enabled: true
    perPodAnnotations:
      - metallb.universe.tf/loadBalancerIPs: "${NICO_VIP_DNS_0}"
      - metallb.universe.tf/loadBalancerIPs: "${NICO_VIP_DNS_1}"

carbide-dsx-exchange-consumer:
  enabled: false

carbide-hardware-health:
  enabled: true

carbide-ssh-console-rs:
  enabled: false

unbound:
  enabled: true
  image:
    repository: "forge/unbound"
    tag: "1.20.0-local"
    pullPolicy: IfNotPresent
  exporterImage:
    repository: "forge/unbound_exporter"
    tag: "0.4.6-local"
    pullPolicy: IfNotPresent
  externalService:
    enabled: true
    type: LoadBalancer
    annotations:
      metallb.universe.tf/loadBalancerIPs: "${NICO_VIP_UNBOUND}"
  localConfig:
    forwarders.conf: |
      forward-zone:
        name: "."
        forward-addr: 8.8.8.8
        forward-addr: 1.1.1.1
    local_data.conf: |
      server:
        local-zone: "forge." static
        local-data: "carbide-api.forge.        300 IN A ${NICO_VIP_API}"
        local-data: "carbide-pxe.forge.        300 IN A ${NICO_VIP_PXE}"
        local-data: "carbide-static-pxe.forge. 300 IN A ${NICO_VIP_PXE}"
        local-data: "carbide-ntp.forge.        300 IN A ${NICO_CP_IP}"
        local-data: "unbound.forge.            300 IN A ${NICO_VIP_UNBOUND}"
EOF
  ok "Wrote ${values_base}"

  # Render helm-prereqs/values/ncx-core.yaml if the directory exists.
  local ncx_core="${NICO_REPO_ROOT}/helm-prereqs/values/ncx-core.yaml"
  if [[ -d "$(dirname "${ncx_core}")" ]]; then
    [[ -f "${ncx_core}" ]] && cp "${ncx_core}" "${ncx_core}.bak.$(date +%s)"
    cat >"${ncx_core}" <<EOF
# AUTO-GENERATED by dev/tools/deploy-nico.sh
carbide-api:
  hostname: "carbide-api.${NICO_DOMAIN}"
  externalService:
    enabled: true
    annotations:
      metallb.universe.tf/loadBalancerIPs: "${NICO_VIP_API}"
carbide-dhcp:
  externalService:
    enabled: true
    annotations:
      metallb.universe.tf/loadBalancerIPs: "${NICO_VIP_DHCP}"
carbide-pxe:
  externalService:
    enabled: true
    annotations:
      metallb.universe.tf/loadBalancerIPs: "${NICO_VIP_PXE}"
carbide-dns:
  externalService:
    enabled: true
  perPodAnnotations:
    - metallb.universe.tf/loadBalancerIPs: "${NICO_VIP_DNS_0}"
    - metallb.universe.tf/loadBalancerIPs: "${NICO_VIP_DNS_1}"
EOF
    ok "Wrote ${ncx_core}"
  fi
}

# -----------------------------------------------------------------------------
# Registry — stand up local registry + tell containerd to trust it
# -----------------------------------------------------------------------------
phase_registry() {
  hdr "Registry: provision local Docker registry (${NICO_REGISTRY_HOST}:${NICO_REGISTRY_PORT})"
  if [[ "${NICO_USE_REGISTRY}" != "1" ]]; then
    warn "NICO_USE_REGISTRY=0 — skipping registry provisioning"
    return 0
  fi

  require_cmd docker

  if docker ps --format '{{.Names}}' | grep -qx "${NICO_REGISTRY_NAME}"; then
    log "Registry container '${NICO_REGISTRY_NAME}' already running"
  elif docker ps -a --format '{{.Names}}' | grep -qx "${NICO_REGISTRY_NAME}"; then
    run docker start "${NICO_REGISTRY_NAME}"
  else
    run sudo mkdir -p "${NICO_REGISTRY_DATA}"
    run docker run -d --restart=always --name "${NICO_REGISTRY_NAME}" \
      -p "${NICO_REGISTRY_PORT}:5000" \
      -v "${NICO_REGISTRY_DATA}:/var/lib/registry" \
      registry:2
  fi

  # Configure containerd on every node to treat this registry as insecure
  # (http) since we did not provision TLS.
  local registry="${NICO_REGISTRY_HOST}:${NICO_REGISTRY_PORT}"
  local conf
  conf=$(cat <<EOF
set -euxo pipefail
sudo mkdir -p /etc/containerd/certs.d/${registry}
sudo tee /etc/containerd/certs.d/${registry}/hosts.toml <<HOSTS
server = "http://${registry}"

[host."http://${registry}"]
  capabilities = ["pull", "resolve", "push"]
  skip_verify  = true
HOSTS

# Ensure containerd loads from /etc/containerd/certs.d (modern config).
sudo sed -i 's|config_path = ".*"|config_path = "/etc/containerd/certs.d"|' /etc/containerd/config.toml
if ! grep -q 'config_path' /etc/containerd/config.toml; then
  sudo sed -i '/\[plugins."io.containerd.grpc.v1.cri".registry\]/a\    config_path = "/etc/containerd/certs.d"' /etc/containerd/config.toml
fi
sudo systemctl restart containerd

# Allow Docker daemon to push to this insecure registry (control-plane node only).
sudo mkdir -p /etc/docker
if [[ -f /etc/docker/daemon.json ]]; then
  python3 - <<PY
import json, sys
p = "/etc/docker/daemon.json"
d = {}
try:
  with open(p) as f: d = json.load(f)
except Exception:
  d = {}
insecure = set(d.get("insecure-registries", []))
insecure.add("${registry}")
d["insecure-registries"] = sorted(insecure)
with open(p, "w") as f: json.dump(d, f, indent=2)
PY
else
  echo '{ "insecure-registries": ["${registry}"] }' | sudo tee /etc/docker/daemon.json
fi
sudo systemctl restart docker 2>/dev/null || true
EOF
)
  on_all_nodes "${conf}"

  # Smoke-test registry from each node.
  log "Smoke-testing registry from each node"
  for h in "${NICO_CP_IP}" "${WORKER_IPS_ARR[@]:-}"; do
    [[ -z "${h}" ]] && continue
    if [[ "${h}" == "${NICO_CP_IP}" ]]; then
      curl -fsS "http://${registry}/v2/" >/dev/null \
        && ok "registry reachable from ${h}" \
        || die "registry NOT reachable from ${h}"
    else
      ssh_run "${h}" "curl -fsS http://${registry}/v2/" >/dev/null \
        && ok "registry reachable from ${h}" \
        || die "registry NOT reachable from ${h}"
    fi
  done
}

# -----------------------------------------------------------------------------
# Bootstrap — cert-manager, vault, postgres
# -----------------------------------------------------------------------------
phase_bootstrap() {
  hdr "Phase 6: bootstrap prereqs (cert-manager, vault, postgres)"

  if ! helm status cert-manager -n cert-manager >/dev/null 2>&1; then
    run helm repo add jetstack https://charts.jetstack.io
    run helm repo update
    run helm install cert-manager jetstack/cert-manager \
      --namespace cert-manager --create-namespace \
      --version v1.15.3 --set crds.enabled=true
  fi
  run kubectl rollout status deployment/cert-manager-webhook -n cert-manager --timeout=180s

  # local-path-provisioner storage class
  if ! kubectl get sc local-path >/dev/null 2>&1; then
    run kubectl apply -f "${NICO_REPO_ROOT}/helm-prereqs/operators/local-path-provisioner.yaml"
    run kubectl apply -f "${NICO_REPO_ROOT}/helm-prereqs/operators/storageclass-local-path-persistent.yaml"
    run kubectl annotate storageclass local-path \
      storageclass.kubernetes.io/is-default-class=true --overwrite
  fi

  # bootstrap-prereqs.sh (vault + postgres + cert issuer)
  pushd "${NICO_REPO_ROOT}" >/dev/null
  LOCAL_DEV_INSTALL_CERT_MANAGER=0 LOCAL_DEV_NAMESPACE="${NICO_NAMESPACE}" \
    bash dev/deployment/devspace/bootstrap-prereqs.sh
  popd >/dev/null
  ok "Bootstrap prereqs ready"
}

# -----------------------------------------------------------------------------
# Build the site-controlled unbound + unbound_exporter images.
#
# devspace only builds carbide-api (all-services) and carbide-bmc-proxy, so the
# remaining images NICo deploys (forge/unbound, forge/unbound_exporter) are
# built here. They are tagged with the exact tags pinned in phase_values so the
# registry-push / ctr-import loop below distributes them like every other image.
# -----------------------------------------------------------------------------
build_unbound_images() {
  local unbound_image="forge/unbound:${NICO_UNBOUND_TAG}"
  local exporter_image="forge/unbound_exporter:${NICO_EXPORTER_TAG}"

  log "Building ${unbound_image}"
  run docker build \
    ${NICO_SQUID_PROXY:+--build-arg SQUID_PROXY=${NICO_SQUID_PROXY}} \
    --build-arg UNBOUND_VERSION="${NICO_UNBOUND_VERSION}" \
    -f "${NICO_REPO_ROOT}/dev/docker/unbound/Dockerfile" \
    -t "${unbound_image}" \
    "${NICO_REPO_ROOT}/dev/docker/unbound"

  log "Building ${exporter_image}"
  run docker build \
    ${NICO_SQUID_PROXY:+--build-arg SQUID_PROXY=${NICO_SQUID_PROXY}} \
    --build-arg EXPORTER_REF="${NICO_EXPORTER_REF}" \
    -f "${NICO_REPO_ROOT}/dev/docker/unbound-exporter/Dockerfile" \
    -t "${exporter_image}" \
    "${NICO_REPO_ROOT}/dev/docker/unbound-exporter"

  ok "Built unbound images (${NICO_UNBOUND_TAG}, ${NICO_EXPORTER_TAG})"
}

# -----------------------------------------------------------------------------
# Deploy — build all images + push to registry + helm deploy
# -----------------------------------------------------------------------------
phase_deploy() {
  hdr "Phase 7: build all images + deploy"

  pushd "${NICO_REPO_ROOT}" >/dev/null

  if [[ -n "${NICO_SQUID_PROXY}" ]]; then
    export SQUID_PROXY="${NICO_SQUID_PROXY}"
    log "Using SQUID_PROXY=${SQUID_PROXY} for image builds"
  fi

  log "Building images with devspace (this can take ~30–45 min on first run)"
  run devspace build -n "${NICO_NAMESPACE}"

  # Images to distribute to the cluster. devspace builds carbide-api +
  # carbide-bmc-proxy; the unbound images (if enabled) are appended below.
  local push_images=(carbide-api carbide-bmc-proxy)
  if [[ "${NICO_BUILD_UNBOUND}" == "1" ]]; then
    build_unbound_images
    push_images+=("forge/unbound" "forge/unbound_exporter")
  else
    log "NICO_BUILD_UNBOUND=0 — skipping unbound image build"
  fi

  if [[ "${NICO_USE_REGISTRY}" == "1" ]]; then
    local registry="${NICO_REGISTRY_HOST}:${NICO_REGISTRY_PORT}"
    log "Tagging & pushing images to ${registry}"
    for img in "${push_images[@]}"; do
      local tag
      tag=$(docker images --format '{{.Tag}}' "${img}" | head -1)
      [[ -z "${tag}" ]] && { warn "no local image ${img} — skipping"; continue; }
      run docker tag  "${img}:${tag}" "${registry}/${img}:${tag}"
      run docker tag  "${img}:${tag}" "${registry}/${img}:latest"
      run docker push "${registry}/${img}:${tag}"
      run docker push "${registry}/${img}:latest"
    done
  else
    log "Skipping registry push — importing images into containerd on every node"
    for img in "${push_images[@]}"; do
      local tag tarname
      tag=$(docker images --format '{{.Tag}}' "${img}" | head -1)
      [[ -z "${tag}" ]] && continue
      # forge/unbound -> unbound (avoid '/' in tar filenames)
      tarname="${img##*/}"
      docker save "${img}:${tag}" -o "/tmp/${tarname}.tar"
      sudo ctr -n k8s.io images import "/tmp/${tarname}.tar"
      for w in "${WORKER_IPS_ARR[@]}"; do
        scp -i "${NICO_SSH_KEY}" "/tmp/${tarname}.tar" "${NICO_SSH_USER}@${w}:/tmp/"
        ssh_run "${w}" "sudo ctr -n k8s.io images import /tmp/${tarname}.tar"
      done
    done
  fi

  log "Running devspace deploy"
  run devspace deploy -n "${NICO_NAMESPACE}"

  popd >/dev/null
  ok "devspace deploy complete"
}

# -----------------------------------------------------------------------------
# CLI — configure carbide-admin-cli (`ncli`) on the control-plane host
#
# Without this, a bare `carbide-admin-cli --carbide-api <url>` cannot reach
# carbide-api: the server speaks mTLS and is reachable only by its DNS name.
# This phase fixes both by (1) extracting the client cert/key + CA from the
# machine-a-tron-certificate secret, (2) pinning carbide-api's DNS name to its
# VIP in /etc/hosts, (3) writing ~/.config/carbide_api_cli.json, and
# (4) installing an `ncli` alias in ~/.bashrc that passes the certs explicitly
# and strips http(s) proxies (the CLI only accepts socks5:// proxies).
# -----------------------------------------------------------------------------
phase_cli() {
  hdr "CLI: configure carbide-admin-cli (ncli) on control-plane host"

  export KUBECONFIG="${HOME}/.kube/config"

  if [[ ! -x "${NICO_CLI_BIN}" ]]; then
    warn "carbide-admin-cli not found at ${NICO_CLI_BIN}"
    warn "Build it with: (cd '${NICO_REPO_ROOT}' && cargo build --release -p carbide-admin-cli)"
    warn "or set NICO_CLI_BIN to the binary location and re-run --phases cli"
  fi

  # Certs go in a persistent dir — unlike /tmp, this survives a reboot.
  mkdir -p "${NICO_CLI_CERT_DIR}"

  if kubectl get secret machine-a-tron-certificate -n "${NICO_NAMESPACE}" >/dev/null 2>&1; then
    log "Extracting carbide-api TLS credentials from machine-a-tron-certificate secret"
    kubectl get secret machine-a-tron-certificate -n "${NICO_NAMESPACE}" \
      -o jsonpath='{.data.ca\.crt}'  | base64 -d > "${NICO_CLI_CERT_DIR}/forge-ca.crt"
    kubectl get secret machine-a-tron-certificate -n "${NICO_NAMESPACE}" \
      -o jsonpath='{.data.tls\.crt}' | base64 -d > "${NICO_CLI_CERT_DIR}/client.crt"
    kubectl get secret machine-a-tron-certificate -n "${NICO_NAMESPACE}" \
      -o jsonpath='{.data.tls\.key}' | base64 -d > "${NICO_CLI_CERT_DIR}/client.key"
    chmod 600 "${NICO_CLI_CERT_DIR}/client.key"
    ok "Wrote TLS certs to ${NICO_CLI_CERT_DIR}"
  else
    warn "Secret machine-a-tron-certificate not found in '${NICO_NAMESPACE}' — run the 'deploy' phase first, then re-run --phases cli"
  fi

  # carbide-api's TLS cert is issued for its DNS name, not its VIP. nico-cp-1 is
  # a host (not a pod), so cluster DNS (.svc.cluster.local) does not resolve —
  # pin the name to the API VIP in /etc/hosts so the cert's SAN matches.
  local api_dns="carbide-api.${NICO_NAMESPACE}.svc.cluster.local"
  local carbide_api_url="https://${api_dns}:443"
  sudo sed -i '/# nico-carbide-api/d' /etc/hosts 2>/dev/null || true
  echo "${NICO_VIP_API} ${api_dns}  # nico-carbide-api" | sudo tee -a /etc/hosts >/dev/null
  log "Mapped ${api_dns} -> ${NICO_VIP_API} in /etc/hosts"

  # Config file so a bare `ncli` (no flags) also works.
  mkdir -p "${HOME}/.config"
  cat > "${HOME}/.config/carbide_api_cli.json" <<EOF
{
  "carbide_api": "${carbide_api_url}",
  "forge_root_ca_path": "${NICO_CLI_CERT_DIR}/forge-ca.crt",
  "client_cert_path": "${NICO_CLI_CERT_DIR}/client.crt",
  "client_key_path": "${NICO_CLI_CERT_DIR}/client.key"
}
EOF
  ok "Wrote ${HOME}/.config/carbide_api_cli.json"

  # `ncli` alias — managed inside a # nico-ncli block so re-runs don't duplicate.
  # \$CARBIDE_API stays literal in ~/.bashrc and is expanded when ncli is run.
  local bashrc="${HOME}/.bashrc"
  touch "${bashrc}"
  sed -i '/# nico-ncli/d' "${bashrc}"
  cat >> "${bashrc}" <<EOF
export CARBIDE_API="${carbide_api_url}"  # nico-ncli
alias ncli='env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY ${NICO_CLI_BIN} --carbide-api \$CARBIDE_API --forge-root-ca-path ${NICO_CLI_CERT_DIR}/forge-ca.crt --client-cert-path ${NICO_CLI_CERT_DIR}/client.crt --client-key-path ${NICO_CLI_CERT_DIR}/client.key'  # nico-ncli
EOF
  ok "Installed 'ncli' alias in ${bashrc}"
  log "Activate it with:  source ${bashrc}  &&  ncli machine show"
}

# -----------------------------------------------------------------------------
# Verify
# -----------------------------------------------------------------------------
phase_verify() {
  hdr "Verification"
  kubectl get nodes -o wide                                | tee -a "${LOG_FILE}"
  kubectl get pods -n "${NICO_NAMESPACE}" -o wide          | tee -a "${LOG_FILE}"
  kubectl get svc  -n "${NICO_NAMESPACE}"                  | tee -a "${LOG_FILE}"
  kubectl get ipaddresspool,l2advertisement -A             | tee -a "${LOG_FILE}"

  cat <<EOF | tee -a "${LOG_FILE}"

${C_BOLD}Useful endpoints:${C_RESET}
  carbide-api    https://${NICO_VIP_API}
  carbide-pxe    http://${NICO_VIP_PXE}
  carbide-dhcp   udp://${NICO_VIP_DHCP}:67
  carbide-dns    udp://${NICO_VIP_DNS_0}:53 , udp://${NICO_VIP_DNS_1}:53
  unbound        udp://${NICO_VIP_UNBOUND}:53

OOB switch — point the BMC VLAN at carbide-dhcp:
  ip helper-address ${NICO_VIP_DHCP}

Admin CLI (configured by the 'cli' phase):
  source ~/.bashrc        # load the 'ncli' alias + \$CARBIDE_API
  ncli machine show       # should return a (possibly empty) machine list
  Binary : ${NICO_CLI_BIN}
  Certs  : ${NICO_CLI_CERT_DIR}

Log: ${LOG_FILE}
EOF
}

# -----------------------------------------------------------------------------
# Phase dispatcher
# -----------------------------------------------------------------------------
run_phase() {
  case "$1" in
    inputs)    phase_inputs ;;
    prereqs)   phase_prereqs ;;
    cluster)   phase_cluster ;;
    tools)     phase_tools ;;
    metallb)   phase_metallb ;;
    values)    phase_values ;;
    registry)  phase_registry ;;
    bootstrap) phase_bootstrap ;;
    deploy)    phase_deploy ;;
    cli)       phase_cli ;;
    verify)    phase_verify ;;
    *) die "unknown phase: $1" ;;
  esac
}

main() {
  log "deploy-nico.sh starting — log: ${LOG_FILE}"
  log "Phases requested: ${PHASES}"

  # Inputs are always collected (interactive prompt or env).
  phase_inputs

  local list
  if [[ "${PHASES}" == "all" ]]; then
    list=(prereqs tools cluster metallb registry values bootstrap deploy cli verify)
  else
    IFS=',' read -r -a list <<<"${PHASES}"
  fi

  for ph in "${list[@]}"; do
    run_phase "${ph}"
  done

  ok "All requested phases complete"
}

main "$@"
