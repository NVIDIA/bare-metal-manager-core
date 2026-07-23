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
# cleanup-machine-a-tron.sh — tear down machine-a-tron for a from-scratch redeploy
#
# The inverse of setup-machine-a-tron.sh. By default it removes everything that
# script created EXCEPT the namespace and pull secret (so a re-run of setup does
# not need the registry API key again):
#   * uninstalls the nico-machine-a-tron Helm release
#   * deletes the client cert secret (so cert-manager reissues from the current CA)
#   * resets the machine graph in the NICo DB (TRUNCATE ... CASCADE) while
#     PRESERVING network config and the machine_interfaces_deletion singleton
#   * reverts nico-core site_explorer.bmc_proxy (and any legacy
#     override_target_* lines) and restarts nico-api
#   * removes the Vault credential machines/bmc/site/root
#
# ONLY for simulation-only clusters. The DB reset truncates machines,
# machine_interfaces, explored_endpoints, explored_managed_hosts, and
# expected_machines with CASCADE — every machine on the cluster is assumed to
# be a machine-a-tron simulation. NEVER run this against a site with real
# hardware inventory.
#
# The machine_interfaces_deletion singleton (id=1) is preserved and its
# last_deletion watermark bumped — deleting it would break the
# machine_dhcp_records view and every subsequent DiscoverDhcp call.
#
# Required environment:
#   KUBECONFIG             Path to the target cluster kubeconfig.
# Optional environment:
#   MAT_NAMESPACE          Default: nico-mat
#   NICO_SYSTEM_NS         Default: nico-system
#   POSTGRES_NS            Default: postgres
#   VAULT_NS               Default: vault
#
# Usage:
#   export KUBECONFIG=/path/to/kubeconfig
#   ./cleanup-machine-a-tron.sh              # prompt before each destructive step
#   ./cleanup-machine-a-tron.sh -y           # non-interactive
#   ./cleanup-machine-a-tron.sh --delete-namespace   # full teardown (also removes
#                                            #   pull secret + copied secrets)
#   ./cleanup-machine-a-tron.sh --keep-db    # leave the DB untouched
#   ./cleanup-machine-a-tron.sh --keep-nico-core-config   # leave bmc_proxy in place
#   ./cleanup-machine-a-tron.sh --keep-vault-cred         # leave BMC cred in Vault
# =============================================================================

set -euo pipefail

MAT_NAMESPACE="${MAT_NAMESPACE:-nico-mat}"
NICO_SYSTEM_NS="${NICO_SYSTEM_NS:-nico-system}"
POSTGRES_NS="${POSTGRES_NS:-postgres}"
VAULT_NS="${VAULT_NS:-vault}"
RELEASE="nico-machine-a-tron"
NICO_DB="nico_system_nico"

ASSUME_YES=false
DELETE_NAMESPACE=false
KEEP_DB=false
KEEP_NICO_CORE_CONFIG=false
KEEP_VAULT_CRED=false

for arg in "$@"; do
    case "$arg" in
        -y|--yes) ASSUME_YES=true ;;
        --delete-namespace) DELETE_NAMESPACE=true ;;
        --keep-db) KEEP_DB=true ;;
        --keep-nico-core-config) KEEP_NICO_CORE_CONFIG=true ;;
        --keep-vault-cred) KEEP_VAULT_CRED=true ;;
        -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -70; exit 0 ;;
        *) echo "Unknown argument: $arg" >&2; exit 2 ;;
    esac
done

# --- helpers (match setup-machine-a-tron.sh) --------------------------------
_c() { printf '\033[%sm' "$1"; }
BOLD="$(_c 1)"; RED="$(_c 31)"; GREEN="$(_c 32)"; YEL="$(_c 33)"; BLU="$(_c 34)"; NC="$(_c 0)"
phase() { echo; echo "${BOLD}${BLU}== $* ==${NC}"; }
info()  { echo "  $*"; }
ok()    { echo "  ${GREEN}✓${NC} $*"; }
warn()  { echo "  ${YEL}!${NC} $*" >&2; }
die()   { echo "${RED}ERROR:${NC} $*" >&2; exit 1; }
confirm() { $ASSUME_YES && return 0; read -r -p "  $* [y/N] " a; [[ "$a" == "y" || "$a" == "Y" ]]; }

CM_JSON=""
cleanup_tmp() { rm -f "$CM_JSON" 2>/dev/null || true; }
trap cleanup_tmp EXIT

PG_PRIMARY=""
_pg_primary() {
    [[ -n "$PG_PRIMARY" ]] && { echo "$PG_PRIMARY"; return; }
    PG_PRIMARY="$(kubectl get pods -n "$POSTGRES_NS" -l application=spilo \
        -o jsonpath='{range .items[*]}{.metadata.name} {.metadata.labels.spilo-role}{"\n"}{end}' 2>/dev/null \
        | awk '$2=="master"{print $1}' | head -1)"
    echo "$PG_PRIMARY"
}
psql_run() {  # runs SQL, returns raw psql output (not -tAc, so NOTICEs show)
    local pg; pg="$(_pg_primary)"; [[ -n "$pg" ]] || die "no Patroni primary in $POSTGRES_NS"
    kubectl exec -n "$POSTGRES_NS" "$pg" -- su postgres -c "psql -d $NICO_DB -v ON_ERROR_STOP=1 -c \"$1\"" 2>&1
}
psql_q() {
    local pg; pg="$(_pg_primary)"; [[ -n "$pg" ]] || die "no Patroni primary in $POSTGRES_NS"
    kubectl exec -n "$POSTGRES_NS" "$pg" -- su postgres -c "psql -d $NICO_DB -tAc \"$1\"" 2>/dev/null
}
_VAULT_TOKEN=""
vault_cmd() {
    if [[ -z "$_VAULT_TOKEN" ]]; then
        _VAULT_TOKEN="$(kubectl get secret nico-vault-token -n "$NICO_SYSTEM_NS" -o jsonpath='{.data.token}' | base64 -d)"
        [[ -n "$_VAULT_TOKEN" ]] || die "could not read nico-vault-token from $NICO_SYSTEM_NS"
    fi
    kubectl exec -n "$VAULT_NS" vault-0 -c vault -- sh -c \
        "export VAULT_TOKEN='$_VAULT_TOKEN' VAULT_ADDR=https://127.0.0.1:8200 VAULT_SKIP_VERIFY=true; $1" 2>/dev/null
}

# =============================================================================
# Phase 0 — preflight
# =============================================================================
phase "Phase 0 — preflight"
for t in kubectl helm; do command -v "$t" >/dev/null || die "$t not found in PATH"; done
kubectl cluster-info >/dev/null 2>&1 || die "cannot reach the cluster (check KUBECONFIG)"
ok "cluster reachable"
echo "  This will tear down machine-a-tron in namespace ${MAT_NAMESPACE} and reset"
echo "  the machine graph in DB ${NICO_DB}. Simulation clusters only."
confirm "Proceed with cleanup?" || die "aborted"

# =============================================================================
# Phase 1 — uninstall Helm release
# =============================================================================
phase "Phase 1 — uninstall Helm release"
if helm status "$RELEASE" -n "$MAT_NAMESPACE" >/dev/null 2>&1; then
    # retry — transient "http2: client connection lost" can abort the uninstall
    _uninstalled=false
    for _i in 1 2 3; do
        if helm uninstall "$RELEASE" -n "$MAT_NAMESPACE" >/dev/null 2>&1; then _uninstalled=true; break; fi
        helm status "$RELEASE" -n "$MAT_NAMESPACE" >/dev/null 2>&1 || { _uninstalled=true; break; }
        warn "uninstall attempt ${_i} failed (transient?) — retrying"
        sleep 5
    done
    $_uninstalled && ok "release ${RELEASE} uninstalled" || die "could not uninstall ${RELEASE}"
else
    ok "release ${RELEASE} not installed"
fi

# =============================================================================
# Phase 2 — namespace / cert secret
# =============================================================================
phase "Phase 2 — namespace / cert secret"
if $DELETE_NAMESPACE; then
    if kubectl get ns "$MAT_NAMESPACE" >/dev/null 2>&1; then
        confirm "Delete the entire ${MAT_NAMESPACE} namespace (removes pull secret + copied secrets)?" \
            && { kubectl delete namespace "$MAT_NAMESPACE" --wait=false >/dev/null; ok "namespace ${MAT_NAMESPACE} deletion requested"; } \
            || warn "skipped namespace deletion"
    else
        ok "namespace ${MAT_NAMESPACE} already absent"
    fi
else
    kubectl delete secret "${RELEASE}-certificate" -n "$MAT_NAMESPACE" --ignore-not-found >/dev/null 2>&1 \
        && ok "client cert secret deleted (cert-manager reissues on next deploy)"
    info "namespace + pull secret kept (use --delete-namespace for full teardown)"
fi

# =============================================================================
# Phase 3 — reset machine graph in the DB  (preserve singleton + network config)
# =============================================================================
phase "Phase 3 — reset machine graph in DB"
if $KEEP_DB; then
    warn "--keep-db set; leaving DB untouched"
else
    BEFORE="$(psql_q "SELECT
        (SELECT count(*) FROM machines) || '/' ||
        (SELECT count(*) FROM machine_interfaces) || '/' ||
        (SELECT count(*) FROM expected_machines) || '/' ||
        (SELECT count(*) FROM explored_endpoints);")"
    info "before (machines/interfaces/expected/endpoints): ${BEFORE:-?}"
    if confirm "TRUNCATE machine graph (machines, machine_interfaces, explored_endpoints, explored_managed_hosts, expected_machines) CASCADE?"; then
        OUT="$(psql_run "BEGIN;
            TRUNCATE machines, machine_interfaces, explored_endpoints, explored_managed_hosts, expected_machines RESTART IDENTITY CASCADE;
            UPDATE machine_interfaces_deletion SET last_deletion = now() WHERE id = 1;
            INSERT INTO machine_interfaces_deletion (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
            COMMIT;")" || die "DB reset failed (rolled back): $OUT"
        # surface which tables CASCADE touched
        printf '%s\n' "$OUT" | grep -i "truncate cascades" | sed 's/^/    /' || true
        AFTER="$(psql_q "SELECT
            (SELECT count(*) FROM machines) || '/' ||
            (SELECT count(*) FROM machine_interfaces) || '/' ||
            (SELECT count(*) FROM expected_machines) || '/' ||
            (SELECT count(*) FROM explored_endpoints);")"
        SINGLETON="$(psql_q "SELECT count(*) FROM machine_interfaces_deletion WHERE id=1;")"
        ok "machine graph reset; after: ${AFTER}  singleton_present: ${SINGLETON}"
        [[ "$SINGLETON" == "1" ]] || die "singleton row missing after reset — investigate before redeploy"
    else
        warn "skipped DB reset"
    fi
fi

# =============================================================================
# Phase 4 — revert nico-core site_explorer bmc_proxy
# =============================================================================
phase "Phase 4 — revert nico-core site_explorer config"
if $KEEP_NICO_CORE_CONFIG; then
    warn "--keep-nico-core-config set; leaving bmc_proxy in place"
else
    CM_JSON="$(mktemp)"
    if kubectl get cm nico-api-site-config-files -n "$NICO_SYSTEM_NS" -o json > "$CM_JSON" 2>/dev/null; then
        if grep -qE "bmc_proxy|override_target_(host|ip|port)" "$CM_JSON"; then
            python3 - "$CM_JSON" <<'PY'
import json, sys
path = sys.argv[1]
cm = json.load(open(path))
drop = ("bmc_proxy", "override_target_host", "override_target_ip", "override_target_port")
for k, v in cm["data"].items():
    lines = [ln for ln in v.splitlines() if not any(t in ln for t in drop)]
    cm["data"][k] = "\n".join(lines) + ("\n" if v.endswith("\n") else "")
for f in ("resourceVersion","uid","creationTimestamp","managedFields"):
    cm["metadata"].pop(f, None)
json.dump(cm, open(path, "w"))
PY
            kubectl apply -f "$CM_JSON" >/dev/null
            info "removed bmc_proxy / override_target_* lines; restarting nico-api"
            kubectl rollout restart deployment/nico-api -n "$NICO_SYSTEM_NS" >/dev/null
            kubectl rollout status deployment/nico-api -n "$NICO_SYSTEM_NS" --timeout=180s >/dev/null \
                || warn "nico-api rollout slow; continuing"
            ok "site_explorer config reverted"
        else
            ok "no bmc_proxy / override_target_* present"
        fi
    else
        warn "nico-api-site-config-files configmap not found; skipping"
    fi
fi

# =============================================================================
# Phase 5 — remove site BMC root Vault credential
# =============================================================================
phase "Phase 5 — remove machine-a-tron Vault credentials"
# site root + the host factory cred that setup-machine-a-tron.sh seeds.
# (The DPU factory + UEFI creds belong to nico-prereqs kvSeeds — left alone.)
# NB: vendor segment is lowercase ("dell") — BMCVendor's Display impl
# lowercases; must match what setup-machine-a-tron.sh seeds.
MAT_VAULT_PATHS="machines/bmc/site/root machines/all_hosts/factory_default/bmc-metadata-items/dell"
if $KEEP_VAULT_CRED; then
    warn "--keep-vault-cred set; leaving credentials in place"
elif confirm "Delete Vault credentials seeded/rotated for machine-a-tron (site root, host factory, per-MAC)?"; then
    for p in $MAT_VAULT_PATHS; do
        if vault_cmd "vault kv get secrets/$p" >/dev/null 2>&1; then
            vault_cmd "vault kv metadata delete secrets/$p" >/dev/null 2>&1 \
                || vault_cmd "vault kv delete secrets/$p" >/dev/null 2>&1 || true
            ok "removed $p"
        else
            ok "already absent: $p"
        fi
    done
    # Per-MAC rotated creds (machines/bmc/<mac>/root) — written by site-explorer
    # when it rotates each BMC's password to the site root. MUST be purged: a
    # fresh mock boots at the factory password, but a surviving per-MAC entry
    # tells site-explorer the BMC was already rotated, so it presents the old
    # rotated password, gets 401 Unauthorized, and permanently latches
    # AvoidLockout (NICO-SITEEXPLORER-144) on the endpoint.
    # Batch server-side in ONE kubectl exec: at scale there are thousands of
    # per-MAC entries and one exec per deletion takes HOURS (one round-trip +
    # exec setup each); a shell loop on the vault pod does them all in seconds.
    _n="$(vault_cmd 'count=0
for m in $(vault kv list -format=yaml secrets/machines/bmc 2>/dev/null | sed "s/^- //" | grep -v "^site/"); do
  vault kv metadata delete "secrets/machines/bmc/${m%/}/root" >/dev/null 2>&1 && count=$((count+1))
done
echo $count' || echo 0)"
    ok "removed ${_n:-0} per-MAC rotated creds (batched server-side)"
else
    warn "kept credentials"
fi

# =============================================================================
# Phase 6 — verify clean state
# =============================================================================
phase "Phase 6 — verify"
helm status "$RELEASE" -n "$MAT_NAMESPACE" >/dev/null 2>&1 && warn "release still present" || ok "release gone"
if ! $KEEP_DB; then
    M="$(psql_q "SELECT count(*) FROM machines;" || echo '?')"
    I="$(psql_q "SELECT count(*) FROM machine_interfaces;" || echo '?')"
    info "machines=${M} machine_interfaces=${I} (expect 0/0)"
fi
phase "Done"
info "Cluster reset for a from-scratch machine-a-tron deploy."
info "Next: ./setup-machine-a-tron.sh   (set REGISTRY_PULL_SECRET if you used --delete-namespace)"
