#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# =============================================================================
# setup-machine-a-tron.sh — deploy machine-a-tron end to end on a NICo site
#
# machine-a-tron is a bare-metal simulator: it hosts mock DPUs and servers via a
# Redfish BMC mock so NICo can run full ingestion flows without real hardware.
# This script sets up EVERYTHING needed for a running NICo Core site to discover
# and create the simulated machines, in setup.sh style (phased, idempotent).
#
# It assumes NICo Core (nico-api, postgres/nico-pg-cluster, Vault, ESO,
# cert-manager) is already deployed on the target cluster (i.e. setup.sh has run
# and the site is bootstrapped). It does NOT deploy NICo Core.
#
# ---------------------------------------------------------------------------
# WHY EACH STEP EXISTS — the non-obvious failure modes this script prevents
# (learned the hard way; do not remove without understanding them):
#
#  * CA refresh (Phase 3): after a site reprovision the nico-system CA and
#    nico-api are recreated. A machine-a-tron left over from before still trusts
#    the OLD CA (stale nico-roots) and presents a client cert signed by the OLD
#    CA, so mTLS to nico-api fails with "client error (Connect)" on every call.
#    We always re-copy nico-roots from nico-system and (Phase 8) delete the old
#    cert secret so cert-manager reissues from the CURRENT CA.
#
#  * BMC site-root credential (Phase 5): site-explorer's check_preconditions
#    requires the Vault credential machines/bmc/site/root. It is NOT in the
#    default nico-prereqs kvSeeds, so without it site-explorer aborts every run
#    with MissingCredentials and never explores anything.
#
#  * bmc_proxy field name (Phase 6): the site_explorer config field is
#    `bmc_proxy = "host:port"` (a single string). `override_target_host` is NOT
#    a real field (older docs were wrong); override_target_ip/port are
#    DEPRECATED. Setting bmc_proxy at launch also makes allow_changing_bmc_proxy
#    default true, which is what lets machine-a-tron's configureBmcProxyHost
#    runtime call succeed instead of being PermissionDenied.
#
#  * expected_machines (chart value registerExpectedMachines: true): without a
#    matching expected_machines row (by BMC MAC), MachineCreator refuses to
#    create the managed host. machine-a-tron auto-registers them when the value
#    is true — the script asserts it.
#
#  * DHCP pool sizing (Phase 7): machine-a-tron needs one OOB IP per BMC —
#    hostCount + hostCount*dpuPerHostCount. Overflowing the OOB pool yields
#    "No IP addresses left in prefix ..." and machines never register.
#
#  * machine_interfaces_deletion singleton (Phase 10 check): the
#    machine_dhcp_records VIEW inner-joins the singleton row id=1. If it is ever
#    deleted (e.g. by manual lease cleanup) the view returns zero rows and
#    DiscoverDhcp fails with "no rows ... expected to return at least one row".
#    The script restores the row if missing. NEVER delete it. To free stale
#    leases, force-delete machine records via the admin CLI or reprovision —
#    do NOT hand-delete interface/dhcp rows.
#
# ---------------------------------------------------------------------------
# Tool requirements: kubectl, helm, jq
#
# Required environment:
#   KUBECONFIG             Path to the target cluster kubeconfig (or current
#                          kubectl context already points at it).
#
# Optional environment:
#   NICO_IMAGE_REGISTRY    REQUIRED unless image.repository is set in the
#                          values file. Registry/repository prefix, without
#                          http(s):// (same convention as setup.sh). The
#                          machine-a-tron image is pulled from
#                          ${NICO_IMAGE_REGISTRY}/machine-a-tron.
#   MAT_IMAGE_TAG          REQUIRED unless image.tag is set in the values
#                          file. machine-a-tron image tag.
#   REGISTRY_PULL_SECRET   Registry password/API key. Only needed if the
#                          pull secret does not already exist in the
#                          machine-a-tron namespace.
#   REGISTRY_PULL_USERNAME Username for the pull secret. Default: $oauthtoken
#   MAT_NAMESPACE          Deployment namespace. Default: nico-mat
#   NICO_SYSTEM_NS         NICo Core namespace. Default: nico-system
#   POSTGRES_NS            Postgres namespace. Default: postgres
#   VAULT_NS               Vault namespace. Default: vault
#   BMC_USERNAME           Site BMC root username. Default: root
#   BMC_PASSWORD           Site BMC root password (rotation target). MUST
#                          differ from the mock factory defaults.
#                          Default: NicoSiteRoot1
#   OOB_DHCP_RELAY         OOB/underlay gateway (BMC DHCP relay). Auto-detected
#                          from nico-core site config if unset.
#   ADMIN_DHCP_RELAY       Admin network gateway. Auto-detected if unset.
#   HOST_COUNT             Override machines.dell-hosts.hostCount.
#   DPU_PER_HOST           Override machines.dell-hosts.dpuPerHostCount.
#   CHART_DIR              Path to the nico-machine-a-tron chart.
#                          Default: <repo>/helm/charts/nico-machine-a-tron
#   VALUES_FILE            Base values template.
#                          Default: <this dir>/values/machine-a-tron.yaml
#
# Usage:
#   export KUBECONFIG=/path/to/kubeconfig
#   ./setup-machine-a-tron.sh            # prompt before deploy
#   ./setup-machine-a-tron.sh -y         # non-interactive
#   ./setup-machine-a-tron.sh --skip-nico-core-config   # don't touch nico-core
# =============================================================================

set -euo pipefail

# --- config / defaults -------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

MAT_NAMESPACE="${MAT_NAMESPACE:-nico-mat}"
NICO_SYSTEM_NS="${NICO_SYSTEM_NS:-nico-system}"
POSTGRES_NS="${POSTGRES_NS:-postgres}"
VAULT_NS="${VAULT_NS:-vault}"
BMC_USERNAME="${BMC_USERNAME:-root}"
# Site-wide BMC root password — the ROTATION TARGET. site-explorer logs into
# each mock BMC with its factory-default password, then rotates it to this
# value. It MUST DIFFER from both factory defaults below, or the rotation is a
# no-op and the mock keeps rejecting with "Factory-default password must be
# changed" (403) forever.
BMC_PASSWORD="${BMC_PASSWORD:-NicoSiteRoot1}"
# Factory defaults HARDCODED in the bmc-mock binary (crates/bmc-mock/src/lib.rs):
#   host BMCs:  DUMMY_FACTORY_PASSWORD     = "factory_password"
#   DPU BMCs:   DUMMY_FACTORY_DPU_PASSWORD = "0penBmc"
# Do not change unless the mock changes.
FACTORY_HOST_BMC_PASSWORD="factory_password"
FACTORY_DPU_BMC_PASSWORD="0penBmc"
# Vendor path segment for the host factory cred. LOWERCASE is required: the
# credential path is built with format!("{vendor}") and BMCVendor's Display
# impl lowercases the variant name ("Dell Inc." → BMCVendor::Dell → "dell",
# crates/bmc-vendor/src/lib.rs impl Display). to_pascalcase() exists but is
# NOT used for Vault paths.
HOST_BMC_VENDOR="${HOST_BMC_VENDOR:-dell}"
# site-default UEFI passwords — check_preconditions requires them NON-EMPTY.
# The mock BMC does not validate them, so any non-empty value works.
UEFI_DPU_PASSWORD="${UEFI_DPU_PASSWORD:-bluefield}"
UEFI_HOST_PASSWORD="${UEFI_HOST_PASSWORD:-bluefield}"
REGISTRY_PULL_USERNAME="${REGISTRY_PULL_USERNAME:-\$oauthtoken}"
PULL_SECRET_NAME="${PULL_SECRET_NAME:-machine-a-tron-pull}"
RELEASE="nico-machine-a-tron"
BMC_MOCK_SVC="nico-machine-a-tron-bmc-mock"
BMC_MOCK_PORT="1266"
# site-explorer runs in nico-system, so it CANNOT resolve the bare service name
# (which resolves against its own namespace). bmc_proxy MUST use the
# cross-namespace FQDN of the bmc-mock service in the machine-a-tron namespace.
BMC_MOCK_FQDN="${BMC_MOCK_SVC}.${MAT_NAMESPACE}.svc.cluster.local"
NICO_DB="nico_system_nico"

# --- deployment mode ---------------------------------------------------------
# override (default): all Redfish through site_explorer.bmc_proxy → one mock.
# scale: MetalLB/nginx mode — one LB Service per BMC, bmc_proxy UNSET, mock
#   routes per-BMC via the Forwarded header. Uses values/machine-a-tron-scale.yaml
#   plus two SIMULATED networks added to the nico-core site config (below) and
#   raised site_explorer throughput knobs. See the chart README "METALLB MODE".
MAT_MODE="${MAT_MODE:-override}"
# Simulated networks for scale mode — must match the scale values file
# (relay addresses) and the MetalLB ipRange (inside the OOB prefix).
SCALE_OOB_PREFIX="10.100.0.0/17";  SCALE_OOB_GW="10.100.0.1"
SCALE_ADMIN_PREFIX="10.102.0.0/18"; SCALE_ADMIN_GW="10.102.0.1"
SCALE_RESERVE=1
# site_explorer throughput knobs applied in scale mode (defaults 30/90/4 make
# 4500-host ingestion take ~9h; these bring it to ~1-2h).
SCALE_CONCURRENT_EXPLORATIONS="${SCALE_CONCURRENT_EXPLORATIONS:-100}"
# NB: keep explorations_per_run MODERATE. Identification and machine creation
# only run at the END of a completed explore_site cycle — a huge per-run value
# makes every cycle deep-scan hundreds of endpoints (dozens of Redfish calls
# each) and cycles stop completing, so machines are never created. ~120 keeps
# cycles under ~2 min while still sweeping the fleet quickly.
SCALE_EXPLORATIONS_PER_RUN="${SCALE_EXPLORATIONS_PER_RUN:-120}"
SCALE_MACHINES_CREATED_PER_RUN="${SCALE_MACHINES_CREATED_PER_RUN:-40}"

CHART_DIR="${CHART_DIR:-${REPO_ROOT}/helm/charts/nico-machine-a-tron}"

ASSUME_YES=false
SKIP_NICO_CORE_CONFIG=false
CM_JSON=""
MERGED_VALUES=""
cleanup() { rm -f "$CM_JSON" "$MERGED_VALUES" 2>/dev/null || true; }
trap cleanup EXIT

for arg in "$@"; do
    case "$arg" in
        -y|--yes) ASSUME_YES=true ;;
        --scale) MAT_MODE="scale" ;;
        --skip-nico-core-config) SKIP_NICO_CORE_CONFIG=true ;;
        -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -110; exit 0 ;;
        *) echo "Unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [[ "$MAT_MODE" == "scale" ]]; then
    VALUES_FILE="${VALUES_FILE:-${SCRIPT_DIR}/values/machine-a-tron-scale.yaml}"
else
    VALUES_FILE="${VALUES_FILE:-${SCRIPT_DIR}/values/machine-a-tron.yaml}"
fi

# --- helpers -----------------------------------------------------------------
_c() { printf '\033[%sm' "$1"; }
BOLD="$(_c 1)"; RED="$(_c 31)"; GREEN="$(_c 32)"; YEL="$(_c 33)"; BLU="$(_c 34)"; NC="$(_c 0)"
phase() { echo; echo "${BOLD}${BLU}== $* ==${NC}"; }
info()  { echo "  $*"; }
ok()    { echo "  ${GREEN}✓${NC} $*"; }
warn()  { echo "  ${YEL}!${NC} $*" >&2; }
die()   { echo "${RED}ERROR:${NC} $*" >&2; exit 1; }
confirm() {
    $ASSUME_YES && return 0
    read -r -p "  $* [y/N] " ans
    [[ "$ans" == "y" || "$ans" == "Y" ]]
}

# psql against the consolidated NICo DB on the Patroni primary
PG_PRIMARY=""
_pg_primary() {
    [[ -n "$PG_PRIMARY" ]] && { echo "$PG_PRIMARY"; return; }
    PG_PRIMARY="$(kubectl get pods -n "$POSTGRES_NS" -l application=spilo \
        -o jsonpath='{range .items[*]}{.metadata.name} {.metadata.labels.spilo-role}{"\n"}{end}' 2>/dev/null \
        | awk '$2=="master"{print $1}' | head -1)"
    echo "$PG_PRIMARY"
}
psql_q() {
    local pg; pg="$(_pg_primary)"
    [[ -n "$pg" ]] || die "no Patroni primary found in namespace $POSTGRES_NS"
    kubectl exec -n "$POSTGRES_NS" "$pg" -- su postgres -c "psql -d $NICO_DB -v ON_ERROR_STOP=1 -tAc \"$1\"" 2>/dev/null
}
# count query that always yields a number — a transient kubectl/psql failure
# returns "0" instead of an empty string that would blow up (( )) arithmetic.
psql_count() { local r; r="$(psql_q "$1" || true)"; echo "${r:-0}"; }
# vault CLI on vault-0 using the root token stored in nico-system/nico-vault-token.
# Token is cached after the first read (it does not change within a run).
# env vars are exported (not inline-prefixed) so they apply across pipes, e.g.
# `echo ... | vault kv put ... -` — an inline prefix would bind them to echo only.
_VAULT_TOKEN=""
vault_cmd() {
    if [[ -z "$_VAULT_TOKEN" ]]; then
        _VAULT_TOKEN="$(kubectl get secret nico-vault-token -n "$NICO_SYSTEM_NS" -o jsonpath='{.data.token}' | base64 -d)"
        [[ -n "$_VAULT_TOKEN" ]] || die "could not read nico-vault-token from $NICO_SYSTEM_NS"
    fi
    kubectl exec -n "$VAULT_NS" vault-0 -c vault -- sh -c \
        "export VAULT_TOKEN='$_VAULT_TOKEN' VAULT_ADDR=https://127.0.0.1:8200 VAULT_SKIP_VERIFY=true; $1" 2>/dev/null
}
# copy a secret from nico-system into the machine-a-tron namespace (strip metadata)
copy_secret() {
    local name="$1"
    kubectl get secret "$name" -n "$NICO_SYSTEM_NS" -o json 2>/dev/null \
        | jq 'del(.metadata.namespace,.metadata.resourceVersion,.metadata.uid,.metadata.creationTimestamp,.metadata.ownerReferences,.metadata.annotations,.metadata.managedFields)' \
        | kubectl apply -n "$MAT_NAMESPACE" -f - >/dev/null
}

# =============================================================================
# Phase 0 — preflight
# =============================================================================
phase "Phase 0 — preflight"
for t in kubectl helm jq; do command -v "$t" >/dev/null || die "$t not found in PATH"; done
kubectl version -o json >/dev/null 2>&1 || kubectl cluster-info >/dev/null 2>&1 || die "cannot reach the cluster (check KUBECONFIG)"
ok "tools present, cluster reachable"
[[ -d "$CHART_DIR" ]] || die "chart dir not found: $CHART_DIR"
[[ -f "$VALUES_FILE" ]] || die "values file not found: $VALUES_FILE"
kubectl get deploy nico-api -n "$NICO_SYSTEM_NS" >/dev/null 2>&1 || die "nico-api not found in $NICO_SYSTEM_NS — deploy NICo Core (setup.sh) first"
[[ -n "$(_pg_primary)" ]] || die "no Postgres primary in $POSTGRES_NS"
kubectl get pod vault-0 -n "$VAULT_NS" >/dev/null 2>&1 || die "vault-0 not found in $VAULT_NS"
ok "NICo Core present: nico-api, postgres primary $(_pg_primary), vault-0"

# portable extraction (macOS BSD sed/grep lack \s): [[:space:]] + awk on quotes
MAT_IMAGE_TAG="${MAT_IMAGE_TAG:-$(grep -E '^[[:space:]]*tag:' "$VALUES_FILE" | head -1 | awk -F'"' '{print $2}')}"
MAT_IMAGE_REPO="${MAT_IMAGE_REPO:-$(grep -E '^[[:space:]]*repository:' "$VALUES_FILE" | head -1 | awk -F'"' '{print $2}')}"
# Registry-agnostic (mirrors setup.sh): the image location comes from the
# environment, never from committed defaults.
if [[ -z "$MAT_IMAGE_REPO" ]]; then
    [[ -n "${NICO_IMAGE_REGISTRY:-}" ]] || die "NICO_IMAGE_REGISTRY is unset and the values file has no image.repository (see setup.sh conventions)"
    MAT_IMAGE_REPO="${NICO_IMAGE_REGISTRY}/machine-a-tron"
fi
HOST_COUNT="${HOST_COUNT:-$(grep -E '^[[:space:]]*hostCount:' "$VALUES_FILE" | head -1 | grep -oE '[0-9]+')}"
DPU_PER_HOST="${DPU_PER_HOST:-$(grep -E '^[[:space:]]*dpuPerHostCount:' "$VALUES_FILE" | head -1 | grep -oE '[0-9]+')}"
[[ -n "$MAT_IMAGE_TAG" ]] || die "MAT_IMAGE_TAG is unset and the values file has no image.tag"
[[ "$HOST_COUNT" =~ ^[0-9]+$ && "$DPU_PER_HOST" =~ ^[0-9]+$ ]] \
    || die "could not determine hostCount/dpuPerHostCount from $VALUES_FILE (set HOST_COUNT / DPU_PER_HOST)"
# Passwords are inlined into sh -c JSON heredocs on the vault pod; quotes,
# backslashes, or whitespace would break quoting or corrupt the JSON silently.
for _pw in "$BMC_PASSWORD" "$UEFI_DPU_PASSWORD" "$UEFI_HOST_PASSWORD"; do
    case "$_pw" in
        *[\'\"\\\ ]*) die "passwords must not contain quotes, backslashes, or spaces (BMC_PASSWORD / UEFI_*_PASSWORD)" ;;
    esac
done
info "image: ${MAT_IMAGE_REPO}:${MAT_IMAGE_TAG}   hosts: ${HOST_COUNT}   dpus/host: ${DPU_PER_HOST}"

# =============================================================================
# Phase 1 — namespace
# =============================================================================
phase "Phase 1 — namespace ${MAT_NAMESPACE}"
kubectl create namespace "$MAT_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
# label so ESO / nico-roots sync treats it as a managed namespace
kubectl label namespace "$MAT_NAMESPACE" nico.nvidia.com/managed=true --overwrite >/dev/null
ok "namespace ready"

# =============================================================================
# Phase 2 — image pull secret
# =============================================================================
phase "Phase 2 — image pull secret"
if kubectl get secret "$PULL_SECRET_NAME" -n "$MAT_NAMESPACE" >/dev/null 2>&1; then
    ok "pull secret ${PULL_SECRET_NAME} already exists"
elif [[ -n "${REGISTRY_PULL_SECRET:-}" ]]; then
    kubectl create secret docker-registry "$PULL_SECRET_NAME" -n "$MAT_NAMESPACE" \
        --docker-server="${MAT_IMAGE_REPO%%/*}" --docker-username="$REGISTRY_PULL_USERNAME" \
        --docker-password="$REGISTRY_PULL_SECRET" \
        --dry-run=client -o yaml | kubectl apply -f - >/dev/null
    ok "pull secret ${PULL_SECRET_NAME} created"
else
    warn "pull secret ${PULL_SECRET_NAME} missing and REGISTRY_PULL_SECRET unset"
    warn "  → set REGISTRY_PULL_SECRET, or ensure the image is already cached on nodes"
fi

# =============================================================================
# Phase 3 — refresh CA + Vault secrets from nico-system  (GOTCHA: stale CA)
# =============================================================================
phase "Phase 3 — refresh nico-roots CA + Vault secrets"
copy_secret nico-roots
ok "nico-roots synced from ${NICO_SYSTEM_NS} (current CA)"
for s in nico-vault-approle-tokens nico-vault-token; do
    if kubectl get secret "$s" -n "$NICO_SYSTEM_NS" >/dev/null 2>&1; then
        copy_secret "$s"; ok "$s synced"
    else
        warn "$s not present in ${NICO_SYSTEM_NS}; skipping (may produce log noise only)"
    fi
done

# =============================================================================
# Phase 4 — seed site BMC root credential  (GOTCHA: not in default kvSeeds)
# =============================================================================
phase "Phase 4 — seed Vault BMC + UEFI credentials"
_kv_put() {   # $1=path  $2=username  $3=password
    vault_cmd "echo '{\"UsernamePassword\":{\"username\":\"$2\",\"password\":\"$3\"}}' | vault kv put secrets/$1 -" >/dev/null \
        || die "failed to write $1 to Vault"
}
_kv_password() {   # $1=path → prints current password (empty if absent)
    # `|| true` is load-bearing: when the path is absent, vault kv get fails and
    # under `set -e` a failing $(...) assignment would kill the whole script.
    vault_cmd "vault kv get -format=json secrets/$1" 2>/dev/null | jq -r '.data.data.UsernamePassword.password // empty' 2>/dev/null || true
}
# Factory-default creds — the INITIAL login site-explorer uses before rotating.
# Host and DPU factories DIFFER (see constants above); the wrong one yields 401
# Unauthorized on every host BMC and a permanent AvoidLockout latch.
_kv_put "machines/all_hosts/factory_default/bmc-metadata-items/${HOST_BMC_VENDOR}" root "$FACTORY_HOST_BMC_PASSWORD"
ok "factory host cred:  .../${HOST_BMC_VENDOR} = root/${FACTORY_HOST_BMC_PASSWORD}"
_kv_put "machines/all_dpus/factory_default/bmc-metadata-items/root" root "$FACTORY_DPU_BMC_PASSWORD"
ok "factory DPU cred:   .../root = root/${FACTORY_DPU_BMC_PASSWORD}"
# Site-wide root — the rotation target; must differ from both factory passwords.
_cur="$(_kv_password machines/bmc/site/root)"
if [[ -z "$_cur" || "$_cur" == "$FACTORY_HOST_BMC_PASSWORD" || "$_cur" == "$FACTORY_DPU_BMC_PASSWORD" ]]; then
    _kv_put "machines/bmc/site/root" "$BMC_USERNAME" "$BMC_PASSWORD"
    ok "machines/bmc/site/root seeded (${BMC_USERNAME}/**** — distinct from factory)"
else
    ok "machines/bmc/site/root already present with a non-factory password"
fi
# Self-heal stale per-MAC rotated creds (machines/bmc/<mac>/root). site-explorer
# writes one per BMC after rotating its password to the site root; entries
# surviving from a previous deployment poison a fresh one — the fresh mock is at
# the factory password, but the per-MAC entry makes site-explorer present the
# old rotated password: 401 → permanent AvoidLockout. Only safe to purge when
# the machine graph is empty (live machines' per-MAC creds are real).
# "Fresh deployment" = no machines AND no interfaces. machines==0 alone is
# NOT enough: mid-ingestion (interfaces DHCP'd, endpoints explored, machines
# not yet created) the per-MAC creds are LIVE — purging them forces every
# endpoint back through the credential fallback.
if [[ "$(psql_count "SELECT count(*) FROM machines;")" == "0" \
   && "$(psql_count "SELECT count(*) FROM machine_interfaces;")" == "0" ]]; then
    # Batched server-side in ONE kubectl exec — thousands of entries at scale;
    # one exec per deletion takes hours.
    _n="$(vault_cmd 'count=0
for m in $(vault kv list -format=yaml secrets/machines/bmc 2>/dev/null | sed "s/^- //" | grep -v "^site/"); do
  vault kv metadata delete "secrets/machines/bmc/${m%/}/root" >/dev/null 2>&1 && count=$((count+1))
done
echo $count' || echo 0)"
    if [[ "${_n:-0}" != "0" ]]; then
        warn "purged ${_n} stale per-MAC BMC creds from a previous deployment (machine graph was empty)"
    fi
fi
# site-explorer's check_preconditions ALSO requires the DPU + Host site_default
# UEFI creds to have a NON-EMPTY password. The nico-prereqs kvSeeds create these
# with empty passwords ("SITE SECRET: populate per site"), which fails the check
# with "vault does not have a valid password entry". Seed a non-empty value if
# the current password is empty/absent (the mock BMC does not validate it).
_seed_uefi() {   # $1=vault path  $2=password
    local path="$1" pw="$2" cur
    cur="$(_kv_password "$path")"
    if [[ -n "$cur" ]]; then
        ok "precondition cred present + valid: $path"
    else
        vault_cmd "echo '{\"UsernamePassword\":{\"username\":\"admin\",\"password\":\"${pw}\"}}' | vault kv put secrets/$path -" >/dev/null \
            || die "failed to seed UEFI cred $path"
        ok "seeded UEFI cred (was empty): $path"
    fi
}
_seed_uefi "machines/all_dpus/site_default/uefi-metadata-items/auth"  "$UEFI_DPU_PASSWORD"
_seed_uefi "machines/all_hosts/site_default/uefi-metadata-items/auth" "$UEFI_HOST_PASSWORD"

# =============================================================================
# Phase 5 — configure nico-core site config for the selected mode
#   override: set site_explorer.bmc_proxy (GOTCHA: field name; FQDN required)
#   scale:    REMOVE bmc_proxy, add simulated networks + throughput knobs
# =============================================================================
phase "Phase 5 — nico-core site config (${MAT_MODE} mode)"
if $SKIP_NICO_CORE_CONFIG; then
    warn "--skip-nico-core-config set; configure [site_explorer]/[networks] manually for ${MAT_MODE} mode"
elif [[ "$MAT_MODE" == "scale" ]]; then
    CM_JSON="$(mktemp)"
    kubectl get cm nico-api-site-config-files -n "$NICO_SYSTEM_NS" -o json > "$CM_JSON" 2>/dev/null \
        || die "nico-api-site-config-files configmap not found"
    _PATCH_RESULT="$(SCALE_OOB_PREFIX="$SCALE_OOB_PREFIX" SCALE_OOB_GW="$SCALE_OOB_GW" \
        SCALE_ADMIN_PREFIX="$SCALE_ADMIN_PREFIX" SCALE_ADMIN_GW="$SCALE_ADMIN_GW" \
        SCALE_RESERVE="$SCALE_RESERVE" \
        BMC_PROXY="${BMC_MOCK_FQDN}:${BMC_MOCK_PORT}" \
        KNOB_CONC="$SCALE_CONCURRENT_EXPLORATIONS" KNOB_EPR="$SCALE_EXPLORATIONS_PER_RUN" \
        KNOB_MCPR="$SCALE_MACHINES_CREATED_PER_RUN" python3 - "$CM_JSON" <<'PY'
import json, os, sys
path = sys.argv[1]
cm = json.load(open(path))
env = os.environ
# lines managed by this script inside [site_explorer]
drop = ("bmc_proxy", "override_target_host", "override_target_ip", "override_target_port",
        "concurrent_explorations", "explorations_per_run", "machines_created_per_run")
knobs = [
    # PROXY-DIRECT: the Redfish client injects "Forwarded: host=<BMC IP>"
    # whenever bmc_proxy is set; the mock's registry routes on it. One
    # ClusterIP service serves the whole simulated fleet.
    f'      bmc_proxy = "{env["BMC_PROXY"]}"',
    f'      concurrent_explorations = {env["KNOB_CONC"]}',
    f'      explorations_per_run = {env["KNOB_EPR"]}',
    f'      machines_created_per_run = {env["KNOB_MCPR"]}',
]
networks = f'''
# --- simulated networks for machine-a-tron scale testing (managed by
# --- setup-machine-a-tron.sh --scale; safe to leave in place) ---
[networks.simulated-oob]
type = "underlay"
prefix = "{env["SCALE_OOB_PREFIX"]}"
gateway = "{env["SCALE_OOB_GW"]}"
mtu = 9000
reserve_first = {env["SCALE_RESERVE"]}

[networks.simulated-admin]
type = "admin"
prefix = "{env["SCALE_ADMIN_PREFIX"]}"
gateway = "{env["SCALE_ADMIN_GW"]}"
mtu = 9000
reserve_first = {env["SCALE_RESERVE"]}
'''
# Machine creation allocates one loopback IP per machine from pools.lo-ip —
# site templates ship tiny ranges (dev6: 3 addresses) that exhaust instantly
# ("Resource pool lo-ip is empty"). Pools DO reconcile at startup (unlike
# networks), so appending a simulated range takes effect on restart.
SIM_LO = ', { start = "10.103.0.1", end = "10.103.63.254" }]'
changed = False
for k, v in cm["data"].items():
    if "[site_explorer]" not in v:
        continue
    out, in_lo = [], False
    for ln in v.splitlines():
        s = ln.strip()
        if any(t in ln for t in drop):
            continue
        if s.startswith("[pools."):
            in_lo = (s == "[pools.lo-ip]")
        if in_lo and s.startswith("ranges") and "10.103.0.1" not in ln:
            r = ln.rstrip(); idx = r.rfind("]")
            ln = r[:idx] + SIM_LO + r[idx+1:]
        out.append(ln)
        if s == "[site_explorer]":
            out.extend(knobs)
    new = "\n".join(out) + ("\n" if v.endswith("\n") else "")
    if "[networks.simulated-oob]" not in new:
        new = new.rstrip("\n") + "\n" + networks
    if new != v:
        cm["data"][k] = new
        changed = True
for f in ("resourceVersion","uid","creationTimestamp","managedFields"):
    cm["metadata"].pop(f, None)
json.dump(cm, open(path, "w"))
print("changed" if changed else "nochange")
PY
)"
    if [[ "$_PATCH_RESULT" == "changed" ]]; then
        kubectl apply -f "$CM_JSON" >/dev/null
        info "scale config applied (proxy-direct bmc_proxy, simulated networks, knobs, lo-ip); restarting nico-api"
        kubectl rollout restart deployment/nico-api -n "$NICO_SYSTEM_NS" >/dev/null
        kubectl rollout status deployment/nico-api -n "$NICO_SYSTEM_NS" --timeout=180s >/dev/null \
            || warn "nico-api rollout did not complete in time; continuing"
        ok "scale networks: oob ${SCALE_OOB_PREFIX} (gw ${SCALE_OOB_GW}), admin ${SCALE_ADMIN_PREFIX} (gw ${SCALE_ADMIN_GW})"
        ok "site_explorer knobs: concurrent=${SCALE_CONCURRENT_EXPLORATIONS} per_run=${SCALE_EXPLORATIONS_PER_RUN} create/run=${SCALE_MACHINES_CREATED_PER_RUN}"
    else
        ok "scale config already in place"
    fi

    # --- ensure the simulated network SEGMENTS exist -------------------------
    # Config-driven segment creation (create_initial_networks) is bootstrap-
    # once: it SKIPS entirely when the DB has multiple DNS domains ("we
    # probably created the network much earlier", crates/api-core/src/db_init.rs).
    # On an established site the new [networks.*] stanzas therefore never
    # materialize and every mat DHCP fails with "No network segment defined
    # for relay addresses". Fallback: clone an existing segment of the same
    # type (identity fields overridden, vlan/vni cleared) + insert the prefix.
    _ensure_segment() {   # $1=name $2=type-ilike $3=prefix $4=gateway $5=reserve
        local name="$1" typ="$2" pfx="$3" gw="$4" rsv="$5"
        if [[ "$(psql_count "SELECT count(*) FROM network_segments WHERE name='${name}';")" != "0" ]]; then
            ok "segment ${name} present"
            return
        fi
        warn "segment ${name} missing (config seeding is bootstrap-once on multi-domain sites) — creating from template"
        # allocation_strategy is forced to 'dynamic': templates may be
        # 'reserved' (static-assignments segments), which rejects every mat
        # DHCP with "configured for static DHCP leases only".
        psql_q "INSERT INTO network_segments
            SELECT (jsonb_populate_record(ns, jsonb_build_object(
                'id', gen_random_uuid()::text, 'name', '${name}',
                'allocation_strategy', 'dynamic',
                'vlan_id', NULL, 'vni_id', NULL))).*
            FROM network_segments ns
            WHERE ns.network_segment_type::text ILIKE '${typ}' LIMIT 1;" >/dev/null \
            || die "failed to create segment ${name} (no ${typ} template segment?)"
        psql_q "INSERT INTO network_prefixes (segment_id, prefix, gateway, num_reserved)
            SELECT id, '${pfx}'::cidr, '${gw}'::inet, ${rsv}
            FROM network_segments WHERE name='${name}';" >/dev/null \
            || die "failed to add prefix ${pfx} to segment ${name}"
        ok "segment ${name} created: ${pfx} (gw ${gw}, reserved ${rsv})"
    }
    _ensure_segment "simulated-oob"   "underlay" "$SCALE_OOB_PREFIX"   "$SCALE_OOB_GW"   "$SCALE_RESERVE"
    _ensure_segment "simulated-admin" "admin"    "$SCALE_ADMIN_PREFIX" "$SCALE_ADMIN_GW" "$SCALE_RESERVE"

    # --- widen the lo-ip resource pool ---------------------------------------
    # Machine creation allocates one loopback IP per machine from resource_pool
    # rows. Pool DEFINITIONS are seed-once ("Declaration has drifted since
    # seed ... not re-applying", crates/api-db/src/resource_pool.rs), so config
    # changes to [pools.lo-ip] are IGNORED on established sites — rows must be
    # inserted directly. Site templates ship tiny ranges (dev6: 3 addresses)
    # that exhaust instantly ("Resource pool lo-ip is empty").
    _LO_FREE="$(psql_count "SELECT count(*) FROM resource_pool WHERE name='lo-ip' AND allocated IS NULL;")"
    if (( _LO_FREE < HOST_COUNT * (1 + DPU_PER_HOST) )); then
        info "widening lo-ip pool (${_LO_FREE} free < needed) with simulated range 10.103.0.1-10.103.63.254"
        psql_q "INSERT INTO resource_pool (name, value, value_type, auto_assign, state, state_version, created)
            SELECT 'lo-ip', host('10.103.0.0'::inet + g), 'ipv4', true,
                   '{\\\"state\\\":\\\"free\\\"}'::jsonb,
                   (SELECT state_version FROM resource_pool WHERE name='lo-ip' LIMIT 1),
                   now()
            FROM generate_series(1, 16382) g
            WHERE NOT EXISTS (SELECT 1 FROM resource_pool rp WHERE rp.name='lo-ip' AND rp.value = host('10.103.0.0'::inet + g));" >/dev/null \
            || die "failed to widen lo-ip pool"
        ok "lo-ip pool: $(psql_count "SELECT count(*) FROM resource_pool WHERE name='lo-ip' AND allocated IS NULL;") free"
    else
        ok "lo-ip pool has ${_LO_FREE} free addresses"
    fi
else
    CM_JSON="$(mktemp)"
    kubectl get cm nico-api-site-config-files -n "$NICO_SYSTEM_NS" -o json > "$CM_JSON" 2>/dev/null \
        || die "nico-api-site-config-files configmap not found"
    if grep -q "bmc_proxy = \"${BMC_MOCK_FQDN}:${BMC_MOCK_PORT}\"" "$CM_JSON"; then
        ok "bmc_proxy already configured"
    else
        _PATCH_RESULT="$(BMC_PROXY="${BMC_MOCK_FQDN}:${BMC_MOCK_PORT}" python3 - "$CM_JSON" <<'PY'
import json, os, sys
proxy = os.environ["BMC_PROXY"]
path = sys.argv[1]
cm = json.load(open(path))
line = f'      bmc_proxy = "{proxy}"'
drop = ("bmc_proxy", "override_target_host", "override_target_ip", "override_target_port")
changed = False
for k, v in cm["data"].items():
    if "[site_explorer]" not in v:
        continue
    out = []
    for ln in v.splitlines():
        if any(t in ln for t in drop):   # strip any stale/legacy proxy lines
            continue
        out.append(ln)
        if ln.strip() == "[site_explorer]":
            out.append(line)             # insert the correct FQDN bmc_proxy
    cm["data"][k] = "\n".join(out) + ("\n" if v.endswith("\n") else "")
    changed = True
for f in ("resourceVersion","uid","creationTimestamp","managedFields"):
    cm["metadata"].pop(f, None)
json.dump(cm, open(path, "w"))
print("changed" if changed else "nochange")
PY
)"
        if [[ "$_PATCH_RESULT" == "changed" ]]; then
            kubectl apply -f "$CM_JSON" >/dev/null
            info "configmap patched; restarting nico-api to load bmc_proxy"
            kubectl rollout restart deployment/nico-api -n "$NICO_SYSTEM_NS" >/dev/null
            kubectl rollout status deployment/nico-api -n "$NICO_SYSTEM_NS" --timeout=180s >/dev/null \
                || warn "nico-api rollout did not complete in time; continuing"
            ok "bmc_proxy set to ${BMC_MOCK_FQDN}:${BMC_MOCK_PORT}"
        else
            ok "no [site_explorer] section found to patch — check the configmap manually"
        fi
    fi
fi

# =============================================================================
# Phase 6 — resolve DHCP relays + sizing check
# =============================================================================
phase "Phase 6 — DHCP relays + pool sizing (${MAT_MODE})"
if [[ "$MAT_MODE" == "scale" ]]; then
    # scale mode uses the SIMULATED networks added in Phase 5 — constants,
    # no live-config parsing needed.
    OOB_PREFIX="$SCALE_OOB_PREFIX";   OOB_DHCP_RELAY="${OOB_DHCP_RELAY:-$SCALE_OOB_GW}"
    ADMIN_PREFIX="$SCALE_ADMIN_PREFIX"; ADMIN_DHCP_RELAY="${ADMIN_DHCP_RELAY:-$SCALE_ADMIN_GW}"
    OOB_RESERVE="$SCALE_RESERVE"; ADMIN_RESERVE="$SCALE_RESERVE"
else
    SITE_CFG="$(kubectl get cm nico-api-site-config-files -n "$NICO_SYSTEM_NS" \
        -o jsonpath='{.data.nico-api-site-config\.toml}' 2>/dev/null || true)"
    # older deployments carry the config under the carbide-* key only
    [[ -n "$SITE_CFG" ]] || SITE_CFG="$(kubectl get cm nico-api-site-config-files -n "$NICO_SYSTEM_NS" \
        -o jsonpath='{.data.carbide-api-site-config\.toml}' 2>/dev/null || true)"
    # gateway lines appear as: gateway = "10.x.y.z" (admin then underlay in template order).
    # Portable parse (no mapfile / negative index — macOS ships bash 3.2).
    # Comment lines are stripped first: the config template carries commented
    # examples (e.g. "#   reserve_first = 5") that would otherwise be picked up.
    SITE_CFG_CODE="$(printf '%s\n' "$SITE_CFG" | grep -vE '^[[:space:]]*#' || true)"
    GW_LIST="$(printf '%s\n' "$SITE_CFG_CODE" | grep -oE 'gateway = "[0-9.]+"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)"
    PFX_LIST="$(printf '%s\n' "$SITE_CFG_CODE" | grep -oE 'prefix = "[0-9./]+"' | grep -oE '[0-9./]+' || true)"
    RSV_LIST="$(printf '%s\n' "$SITE_CFG_CODE" | grep -oE 'reserve_first = [0-9]+' | grep -oE '[0-9]+' || true)"
    # admin segment is the FIRST prefix/gateway pair, OOB/underlay the LAST.
    ADMIN_PREFIX="$(printf '%s\n' "$PFX_LIST" | head -1)"
    OOB_PREFIX="$(printf '%s\n' "$PFX_LIST" | tail -1)"
    OOB_DHCP_RELAY="${OOB_DHCP_RELAY:-$(printf '%s\n' "$GW_LIST" | tail -1)}"
    ADMIN_DHCP_RELAY="${ADMIN_DHCP_RELAY:-$(printf '%s\n' "$GW_LIST" | head -1)}"
    # Usable IPs per pool = 2^(32-mask) − reserve_first − 1 (broadcast).
    # reserve_first covers the network address, gateway, and operator-reserved
    # leading addresses — verified live: /28 with reserve_first=5 → 10 usable.
    ADMIN_RESERVE="$(printf '%s\n' "$RSV_LIST" | head -1)"; ADMIN_RESERVE="${ADMIN_RESERVE:-5}"
    OOB_RESERVE="$(printf '%s\n' "$RSV_LIST" | tail -1)"; OOB_RESERVE="${OOB_RESERVE:-5}"
fi
[[ -n "$OOB_DHCP_RELAY" && -n "$ADMIN_DHCP_RELAY" ]] \
    || die "could not resolve DHCP relays; set OOB_DHCP_RELAY and ADMIN_DHCP_RELAY"
ok "OOB:   relay ${OOB_DHCP_RELAY}   prefix ${OOB_PREFIX:-unknown}"
ok "admin: relay ${ADMIN_DHCP_RELAY}   prefix ${ADMIN_PREFIX:-unknown}"
_usable() { local m="${1##*/}" r="$2"; local u=$(( (1 << (32 - m)) - r - 1 )); (( u < 0 )) && u=0; echo "$u"; }
# Demand per pool (measured live):
#   OOB   = hostCount*(1 + dpuPerHost)   — one BMC IP per host and per DPU
#   admin = hostCount*(dpuPerHost + 1)   — one host-PF IP per DPU at DHCP time,
#           PLUS one admin IP per host allocated by machine creation (creation
#           fails with "No IP addresses left in prefix <admin>" without it)
if [[ "${OOB_PREFIX:-}" == */* && "${ADMIN_PREFIX:-}" == */* ]]; then
    OOB_USABLE="$(_usable "$OOB_PREFIX" "$OOB_RESERVE")"; ADMIN_USABLE="$(_usable "$ADMIN_PREFIX" "$ADMIN_RESERVE")"
    # max hosts each pool supports, then take the min
    FIT_OOB=$(( OOB_USABLE / (1 + DPU_PER_HOST) ))
    FIT_ADMIN=$(( ADMIN_USABLE / (DPU_PER_HOST + 1) ))
    FIT=$(( FIT_OOB < FIT_ADMIN ? FIT_OOB : FIT_ADMIN ))
    info "pool fit: OOB ${OOB_PREFIX} ≈${OOB_USABLE} usable → ≤${FIT_OOB} hosts; admin ${ADMIN_PREFIX} ≈${ADMIN_USABLE} usable → ≤${FIT_ADMIN} hosts"
    if (( HOST_COUNT > FIT )); then
        (( FIT < 1 )) && die "pools too small for even 1 host × ${DPU_PER_HOST} DPUs — widen the admin/OOB prefixes or lower DPU_PER_HOST"
        warn "requested ${HOST_COUNT} hosts exceeds pool capacity (${FIT}) — auto-fitting hostCount=${FIT}"
        warn "  (override with HOST_COUNT/DPU_PER_HOST env vars, or widen the site's DHCP prefixes)"
        confirm "Proceed with hostCount=${FIT} × ${DPU_PER_HOST} DPUs?" || die "aborted on sizing"
        HOST_COUNT="$FIT"
    fi
    NEED=$(( HOST_COUNT + HOST_COUNT * DPU_PER_HOST ))
    ok "sizing: ${HOST_COUNT} hosts × ${DPU_PER_HOST} DPUs → ${NEED} OOB + $(( HOST_COUNT * (DPU_PER_HOST + 1) )) admin IPs"
else
    NEED=$(( HOST_COUNT + HOST_COUNT * DPU_PER_HOST ))
    warn "could not parse both pool prefixes — skipping sizing check (need ${NEED} OOB IPs)"
fi

# =============================================================================
# Phase 7 — DB safety: restore machine_interfaces_deletion singleton  (GOTCHA)
# =============================================================================
phase "Phase 7 — DB safety checks"
# "!= 1" (not "== 0") so a transient query failure (empty result) also takes
# the restore path — the INSERT is idempotent (ON CONFLICT DO NOTHING).
SINGLETON="$(psql_count "SELECT count(*) FROM machine_interfaces_deletion WHERE id=1;")"
if [[ "$SINGLETON" != "1" ]]; then
    warn "machine_interfaces_deletion singleton (id=1) missing — restoring"
    warn "  (its absence breaks the machine_dhcp_records view → DiscoverDhcp 'no rows' errors)"
    psql_q "INSERT INTO machine_interfaces_deletion (id) VALUES (1) ON CONFLICT (id) DO NOTHING;" >/dev/null
    ok "singleton restored"
else
    ok "machine_interfaces_deletion singleton present"
fi
ORPHANS="$(psql_count "SELECT count(*) FROM machine_interfaces mi WHERE NOT EXISTS (SELECT 1 FROM machines m WHERE m.id = mi.machine_id);")"
MACHINES_NOW="$(psql_count "SELECT count(*) FROM machines;")"
if [[ "${ORPHANS:-0}" -gt 0 && "${MACHINES_NOW:-0}" == "0" ]]; then
    warn "${ORPHANS} orphaned machine_interfaces (no parent machine) may hold OOB leases"
    warn "  → if DHCP later reports exhaustion, force-delete stale records via the admin CLI"
    warn "    or reprovision. Do NOT hand-delete interface/dhcp rows (breaks the singleton)."
fi

# =============================================================================
# Phase 8 — reissue client cert from current CA  (GOTCHA: stale cert)
# =============================================================================
phase "Phase 8 — reissue machine-a-tron client cert"
# Always delete: a cert issued under a previous CA fails mTLS to nico-api with
# "client error (Connect)" on every call. cert-manager reissues from the
# current CA within seconds of the deploy — there is no reason to keep it.
kubectl delete secret "${RELEASE}-certificate" -n "$MAT_NAMESPACE" --ignore-not-found >/dev/null 2>&1
ok "client cert cleared; cert-manager reissues from the current CA on deploy"

# =============================================================================
# Phase 9 — deploy the chart
# =============================================================================
phase "Phase 9 — helm upgrade --install ${RELEASE}"
MERGED_VALUES="$(mktemp)"
# Site-specific overrides ONLY (never committed). Passed as a second -f so Helm
# deep-merges it over the base template (last -f wins per key) — avoids
# unreliable duplicate top-level keys within a single YAML file.
cat > "$MERGED_VALUES" <<EOF
# --- injected by setup-machine-a-tron.sh (site-specific, do not commit) ---
image:
  repository: "${MAT_IMAGE_REPO}"
  tag: "${MAT_IMAGE_TAG}"
pods:
  default:
    machines:
      dell-hosts:
        hostCount: ${HOST_COUNT}
        dpuPerHostCount: ${DPU_PER_HOST}
        oobDhcpRelayAddress: "${OOB_DHCP_RELAY}"
        adminDhcpRelayAddress: "${ADMIN_DHCP_RELAY}"
EOF
if [[ "$MAT_MODE" == "scale" ]]; then
    # Pin every mock BMC's password to the site root ("emulates a BMC already
    # rotated by an operator"). At scale, the rotation dance is fatally racy:
    # preingestion's initial BMC reset reboots the mock, which comes back at
    # the FACTORY password while its per-MAC Vault entry says "rotated" —
    # 401 → AvoidLockout latches every DPU endpoint forever. With the pin,
    # site-explorer's documented fallback ("expected/factory failed → try the
    # sitewide root without rotation") logs straight in, and resets are
    # harmless because the password never changes.
    cat >> "$MERGED_VALUES" <<EOF
machineATron:
  hostBmcPassword: "${BMC_PASSWORD}"
  dpuBmcPassword: "${BMC_PASSWORD}"
EOF
fi
info "values: image=${MAT_IMAGE_REPO}:${MAT_IMAGE_TAG} hosts=${HOST_COUNT} dpus=${DPU_PER_HOST} oob=${OOB_DHCP_RELAY} admin=${ADMIN_DHCP_RELAY}"
confirm "Deploy ${RELEASE} to ${MAT_NAMESPACE}?" || die "aborted before deploy"
# --qps/--burst-limit: scale mode creates one Service per BMC (hundreds to
# thousands); helm's default burst (100 concurrent API calls) overwhelms
# SOCKS/ssh tunnels to the API server ("connection reset by peer").
helm upgrade --install "$RELEASE" "$CHART_DIR" -n "$MAT_NAMESPACE" --create-namespace \
    --qps "${HELM_QPS:-15}" --burst-limit "${HELM_BURST:-30}" \
    -f "$VALUES_FILE" -f "$MERGED_VALUES"
kubectl rollout status deployment/"$RELEASE" -n "$MAT_NAMESPACE" --timeout=180s \
    || warn "deployment rollout did not complete in time"

# =============================================================================
# Phase 10 — verify end to end
# =============================================================================
phase "Phase 10 — verification"
info "waiting for cert to be issued from the current CA..."
kubectl wait --for=condition=Ready certificate/"${RELEASE}-certificate" -n "$MAT_NAMESPACE" --timeout=120s >/dev/null 2>&1 \
    && ok "client certificate Ready" || warn "certificate not Ready yet — check cert-manager"

# wait windows scale with the deployment size (scale mode: hundreds-thousands)
IFACE_WAIT=$(( 90 + NEED )); (( IFACE_WAIT > 1800 )) && IFACE_WAIT=1800
info "giving machine-a-tron time to register + DHCP (up to ${IFACE_WAIT}s)..."
_end=$((SECONDS+IFACE_WAIT))
IFACES=0
while (( SECONDS < _end )); do
    IFACES="$(psql_count "SELECT count(*) FROM machine_interfaces;")"
    (( IFACES >= NEED )) && break
    sleep 10
done
IPS="$(psql_count "SELECT count(*) FROM machine_interface_addresses;")"
info "machine_interfaces=${IFACES} (need ${NEED})  ips_allocated=${IPS}"
(( IFACES >= NEED )) && ok "BMC interfaces registered + DHCP allocated" \
    || warn "fewer interfaces than expected — check pool sizing / bmc DHCP"

# --- expected_machines: required for machine creation (matched by BMC MAC) ---
# machine-a-tron auto-registers them (registerExpectedMachines: true), but on
# nico-api builds without the Machineatron→AddExpectedMachine RBAC grant
# (crates/api-core/src/auth/internal_rbac_rules.rs) the call is 403'd. Fall
# back to direct DB registration mirroring what the API call would create.
info "waiting for expected_machines (auto-registration)..."
_end=$((SECONDS+45)); EXPECTED=0
while (( SECONDS < _end )); do
    EXPECTED="$(psql_count "SELECT count(*) FROM expected_machines;")"
    (( EXPECTED > 0 )) && break
    sleep 5
done
if (( EXPECTED > 0 )); then
    ok "expected_machines=${EXPECTED} (registerExpectedMachines worked — RBAC grant present)"
else
    warn "no expected_machines — this nico-api build lacks the Machineatron"
    warn "  AddExpectedMachine RBAC grant (403). Falling back to direct DB registration."
    # scope strictly to BMC interfaces in the OOB prefix — with an unparsed
    # prefix the filter would match admin-segment interfaces too and register
    # them with the wrong factory password.
    [[ "${OOB_PREFIX:-}" == */* ]] || die "cannot scope the expected_machines fallback: OOB prefix unknown"
    psql_q "INSERT INTO expected_machines (id, serial_number, bmc_mac_address, bmc_username, bmc_password)
        SELECT gen_random_uuid(), 'MAT-' || replace(mi.mac_address::text, ':', ''), mi.mac_address, 'root', '${FACTORY_HOST_BMC_PASSWORD}'
        FROM machine_interfaces mi
        JOIN machine_interface_addresses mia ON mia.interface_id = mi.id
        WHERE mia.address << '${OOB_PREFIX}'::inet
          AND NOT EXISTS (SELECT 1 FROM expected_machines em WHERE em.bmc_mac_address = mi.mac_address);" >/dev/null \
        || die "expected_machines DB fallback INSERT failed"
    EXPECTED="$(psql_count "SELECT count(*) FROM expected_machines;")"
    (( EXPECTED > 0 )) || die "expected_machines still 0 after fallback — machine creation cannot proceed"
    ok "expected_machines=${EXPECTED} registered via DB fallback"
fi

# --- kick exploration: clear any AvoidLockout latched before creds existed ---
# Exploration cycles that ran before Phase 4/5 completed record Unauthorized,
# which latches a self-perpetuating AvoidLockout in the exploration report.
# This mirrors the API's clear_last_known_error + request_exploration pair
# (crates/api-db/src/explored_endpoints.rs) — including the
# waiting_for_explorer_refresh flag, which gates preingestion until a fresh
# probe lands (skipping it would let preingestion act on the stale report).
psql_q "UPDATE explored_endpoints
    SET exploration_report = jsonb_set(exploration_report, '{LastExplorationError}', 'null'::jsonb),
        exploration_requested = true,
        waiting_for_explorer_refresh = true;" >/dev/null || true
ok "cleared exploration lockouts + requested re-exploration"

# machine target = one row per host + per DPU; wait scales with host count
MACHINE_TARGET=$(( HOST_COUNT * (1 + DPU_PER_HOST) ))
MACHINE_WAIT=$(( 420 + HOST_COUNT * 3 )); (( MACHINE_WAIT > 5400 )) && MACHINE_WAIT=5400
info "waiting for explore → rotate → preingest → identify → create (target ${MACHINE_TARGET} machines, up to ${MACHINE_WAIT}s)..."
_end=$((SECONDS+MACHINE_WAIT)); MACHINES=0
while (( SECONDS < _end )); do
    MACHINES="$(psql_count "SELECT count(*) FROM machines;")"
    (( MACHINES >= MACHINE_TARGET )) && break
    # single round-trip for the progress line
    _prog="$(psql_q "SELECT
        (SELECT count(*) FILTER (WHERE exploration_report->'LastExplorationError' = 'null'::jsonb) FROM explored_endpoints) || '/' ||
        (SELECT count(*) FROM explored_managed_hosts);" || echo '?/?')"
    info "  endpoints_ok=${_prog%%/*}/${IFACES}  managed_hosts=${_prog##*/}  machines=${MACHINES} ..."
    # Re-clear any AvoidLockout that latched during the wait (e.g. an
    # exploration racing a mock reboot from preingestion's initial BMC reset).
    # Idempotent; scoped to latched endpoints only so successful reports keep
    # their state.
    psql_q "UPDATE explored_endpoints
        SET exploration_report = jsonb_set(exploration_report, '{LastExplorationError}', 'null'::jsonb),
            exploration_requested = true,
            waiting_for_explorer_refresh = true
        WHERE exploration_report->'LastExplorationError'->>'Type' IN ('AvoidLockout','Unauthorized');" >/dev/null || true
    # ...and UNPARK endpoints that have since explored clean: a lingering
    # waiting_for_explorer_refresh gates them out of preingestion
    # (find_preingest_not_waiting) even after a healthy report lands, stalling
    # the pipeline at 'initial' indefinitely.
    psql_q "UPDATE explored_endpoints
        SET waiting_for_explorer_refresh = false, exploration_requested = false
        WHERE waiting_for_explorer_refresh
          AND exploration_report->'LastExplorationError' = 'null'::jsonb;" >/dev/null || true
    sleep 25
done
ENDPOINTS="$(psql_count "SELECT count(*) FROM explored_endpoints;")"
MHOSTS="$(psql_count "SELECT count(*) FROM explored_managed_hosts;")"
echo
if (( MACHINES >= MACHINE_TARGET )); then
    ok "${GREEN}END TO END OK${NC} — endpoints=${ENDPOINTS}, managed_hosts=${MHOSTS}, machines=${MACHINES}/${MACHINE_TARGET}"
elif (( MACHINES > 0 )); then
    ok "${GREEN}MACHINES CREATED${NC} (partial) — ${MACHINES}/${MACHINE_TARGET}; ingestion continuing in the background"
else
    warn "machines not created yet (endpoints=${ENDPOINTS}, managed_hosts=${MHOSTS})"
    warn "  check: kubectl logs -n ${NICO_SYSTEM_NS} deploy/nico-api | grep -i 'site.explor\\|MissingCred\\|Refusing\\|Failed to create'"
    warn "  check: kubectl logs -n ${MAT_NAMESPACE} deploy/${RELEASE} | grep -iE 'No IP addresses|error'"
    warn "  a common cause: admin/OOB pool exhaustion — see the sizing output of Phase 6"
fi

phase "Done"
info "machine-a-tron release ${RELEASE} deployed to ${MAT_NAMESPACE}."
info "Redeploy/iterate: re-run this script (idempotent) after 'export KUBECONFIG=...'."
