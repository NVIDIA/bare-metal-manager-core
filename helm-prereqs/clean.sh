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
# clean.sh — full teardown, inverse of setup.sh
#
# Destroys in reverse order:
#   0. NCX stack           (nico-rest helm, temporal, keycloak, ncx postgres)
#   1. nico core        (separate helm release, if installed)
#   1b. DPF stack          (DPF CRs, dpf-operator helm release — if installed)
#   2. helmfile releases   (nico-prereqs, external-secrets, vault, cert-manager,
#                           postgres-operator, DPF prereqs when installed)
#   3. cluster-scoped hook resources (ClusterIssuers, ClusterSecretStore, etc.)
#   4. vault init secrets  (vault-cluster-keys, vaultunsealkeys, vaultroottoken)
#   5. namespaces          (nico-system, cert-manager, vault, external-secrets,
#                           postgres, dpf-operator-system)
#   6. local-path-persistent PVs owned by this stack (Retain policy — not deleted with namespace)
#   7. local-path-provisioner + StorageClass (applied via kubectl, not helm-managed)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# ---------------------------------------------------------------------------
# 0. NCX stack — uninstall before nico since it depends on nico's
#    cert-manager and ClusterIssuers.
# ---------------------------------------------------------------------------
echo "=== [0/8] Uninstalling NICo REST stack ==="
# Flow goes first — it talks to Temporal + nico-api and depends on credentials
# from both nico-prereqs (DB creds, vault tokens) and the REST stack.
helm uninstall flow                 -n flow                            2>/dev/null || true
kubectl delete ns flow --wait=false --ignore-not-found                 2>/dev/null || true
helm uninstall nico-rest-site-agent -n nico-rest                       2>/dev/null || true
helm uninstall nico-rest            -n nico-rest                       2>/dev/null || true
helm uninstall temporal                -n temporal     2>/dev/null || true

if kubectl get deploy keycloak -n nico-rest &>/dev/null; then
    echo "  Cleaning up Keycloak..."
    "${SCRIPT_DIR}/keycloak/clean.sh" 2>/dev/null || true
else
    echo "  Keycloak not deployed — skipping cleanup"
fi

kubectl delete clusterissuer nico-rest-ca-issuer --ignore-not-found 2>/dev/null || true
kubectl delete ns nico-rest temporal flow \
    --wait=false --ignore-not-found 2>/dev/null || true
echo "Waiting for nico-rest, temporal, and flow namespaces to terminate..."
kubectl wait --for=delete ns/nico-rest ns/temporal ns/flow \
    --timeout=120s 2>/dev/null || true

# ---------------------------------------------------------------------------
# 0b. Observability stack (optional component; harmless no-ops if absent)
# ---------------------------------------------------------------------------
echo "=== [0b/8] Uninstalling observability stack (if present) ==="
helm uninstall obs                    -n monitoring 2>/dev/null || true
helm uninstall otel-agent             -n otel       2>/dev/null || true
helm uninstall otel-collector-gateway -n otel       2>/dev/null || true
helm uninstall tempo                  -n tempo      2>/dev/null || true
helm uninstall loki                   -n loki       2>/dev/null || true
kubectl delete ns monitoring otel tempo loki \
    --wait=false --ignore-not-found 2>/dev/null || true

# ---------------------------------------------------------------------------
# 1. NICo core (separate helm release, not in helmfile)
# ---------------------------------------------------------------------------
echo "=== [1/8] Uninstalling nico core ==="
helm uninstall nico -n nico-system 2>/dev/null || true

# ---------------------------------------------------------------------------
# 1b. DPF stack (setup.sh, DPF default), skipped fast when never installed.
#     Order matters: DPF CRs must be deleted while the operator, Kamaji, and
#     Argo CD controllers are still running so their finalizers can complete.
#     The four prereq releases (argo-cd, kamaji, maintenance-operator, NFD)
#     ride the helmfile destroy in step 2.
# ---------------------------------------------------------------------------
if kubectl get namespace dpf-operator-system &>/dev/null; then
    echo "=== [1b] Removing DPF stack ==="

    # DPU-facing CRs first (service chain, then provisioning objects), while
    # the controllers can still finalize them.
    kubectl delete dpudeployments,dpuservicechains,dpuservices,dpusets \
        --all -n dpf-operator-system --timeout=120s 2>/dev/null || true
    kubectl delete dpuserviceinterfaces,dpuservicetemplates,dpuserviceconfigurations,dpuservicenads \
        --all -n dpf-operator-system --timeout=120s 2>/dev/null || true
    # NOTE: if DPUs are mid-provisioning (OSInstall / ConfigureFirmware state)
    # this deletion will interrupt them and may leave them in an inconsistent
    # state. Confirm no active provisioning before running clean.sh on a live
    # site. `dpu` and `dpunodemaintenances` are omitted here: they carry owner
    # references to DpuNode and are garbage-collected automatically when
    # DpuNode is deleted.
    kubectl delete dpudevices,dpunodes \
        --all -n dpf-operator-system --timeout=180s 2>/dev/null || true
    kubectl delete bfbs,bluefieldsoftwares,dpuflavors \
        --all -n dpf-operator-system --timeout=120s 2>/dev/null || true
    kubectl delete dpfoperatorconfig --all -n dpf-operator-system \
        --timeout=120s 2>/dev/null || true
    # DPUCluster last among CRs — deleting it tears down the Kamaji
    # TenantControlPlane behind the DPU cluster.
    kubectl delete dpucluster --all -n dpf-operator-system \
        --timeout=180s 2>/dev/null || true
    kubectl delete tenantcontrolplane --all -A --timeout=180s 2>/dev/null || true
    # Kamaji `default` DataStore: carries helm.sh/resource-policy:keep (so
    # helmfile destroy won't remove it) and a kamaji finalizer. Delete it here,
    # while the kamaji controller is still alive to finalize it — otherwise its
    # finalizer blocks the datastores CRD deletion and namespace termination.
    kubectl delete datastores.kamaji.clastix.io --all -A \
        --timeout=120s 2>/dev/null || true
    # Argo CD Applications carry resources-finalizer.argocd.argoproj.io, which
    # cascades a delete onto the (now-gone) DPU cluster and cannot complete on a
    # DPU-less / VIP-unroutable cluster. Delete best-effort; stragglers get their
    # finalizers stripped below before argo-cd itself is destroyed.
    kubectl delete applications.argoproj.io --all -A \
        --timeout=60s 2>/dev/null || true

    # Best-effort finalizer strip for anything stuck after the bounded waits.
    # Cover every DPF CR kind here — plus the kamaji DataStore and the Argo CD
    # Applications/AppProjects — because `kubectl delete crd` (step 2) blocks
    # until all instances finalize, so any kind left finalizer-stuck would hang
    # the whole teardown. Applications must be stripped before argo-cd is
    # destroyed (below), or nothing can ever clear their cascade finalizer.
    for _kind in dpudeployments dpuservices dpuservicechains dpuserviceinterfaces \
                 dpuservicetemplates dpuserviceconfigurations dpuservicenads \
                 dpus dpudevices dpunodes dpunodemaintenances dpusets \
                 bfbs bluefieldsoftwares dpuflavors \
                 dpfoperatorconfigs dpuclusters tenantcontrolplanes \
                 datastores.kamaji.clastix.io \
                 applications.argoproj.io appprojects.argoproj.io; do
        # Discover with the namespace so the patch targets the resource's ACTUAL
        # namespace (a bare `-o name` + hard-coded `-n dpf-operator-system` would
        # silently miss anything outside it). Cluster-scoped kinds (e.g.
        # datastores) report an empty namespace and are patched without -n.
        # Read the whole line and split on the tab manually — `read` with
        # IFS=tab would strip the leading tab of a cluster-scoped resource's
        # empty namespace and drop it (the DataStore is exactly such a resource).
        while IFS= read -r _line; do
            _ns="${_line%%$'\t'*}"; _name="${_line#*$'\t'}"
            [[ -z "${_name}" ]] && continue
            echo "WARNING: force-removing finalizers on stuck ${_kind}/${_name}${_ns:+ (ns ${_ns})}"
            kubectl patch "${_kind}/${_name}" ${_ns:+-n "${_ns}"} --type merge \
                -p '{"metadata":{"finalizers":[]}}' 2>/dev/null || true
        done < <(kubectl get "${_kind}" -A \
            -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{end}' 2>/dev/null)
    done

    helm uninstall dpf-operator -n dpf-operator-system 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 2. All helmfile releases in reverse dependency order:
#    nico-prereqs → node-feature-discovery → maintenance-operator → kamaji →
#    argo-cd → external-secrets → vault → cert-manager → metallb
# ---------------------------------------------------------------------------
echo "=== [2/8] Destroying helmfile releases ==="

# Delete MetalLB site config resources BEFORE helmfile destroys the operator.
# The CRD instances (IPAddressPool, BGPPeer, etc.) are in metallb-system and
# must be removed while the webhook is still running to avoid stuck finalizers.
echo "Removing MetalLB site config resources..."
kubectl delete bgpadvertisement,l2advertisement --all \
    -n metallb-system --ignore-not-found 2>/dev/null || true
kubectl delete bgppeer --all \
    -n metallb-system --ignore-not-found 2>/dev/null || true
kubectl delete ipaddresspool --all \
    -n metallb-system --ignore-not-found 2>/dev/null || true

helmfile destroy 2>/dev/null || true

# MetalLB CRDs — helm does not delete CRDs on uninstall.
echo "Removing MetalLB CRDs..."
kubectl get crd -o name | grep metallb.io \
    | xargs kubectl delete --ignore-not-found 2>/dev/null || true

# Helm does NOT delete CRDs on uninstall (to prevent accidental data loss).
# Delete postgres-operator CRDs explicitly so a subsequent setup.sh can
# reinstall them cleanly — especially important when they were previously
# managed by a different field manager (e.g. ArgoCD) which causes SSA conflicts.
echo "Removing postgres-operator CRDs and cluster-scoped RBAC..."
kubectl delete crd \
    operatorconfigurations.acid.zalan.do \
    postgresqls.acid.zalan.do \
    postgresteams.acid.zalan.do \
    --ignore-not-found 2>/dev/null || true
kubectl delete clusterrole postgres-operator postgres-pod \
    --ignore-not-found 2>/dev/null || true
kubectl delete clusterrolebinding postgres-operator \
    --ignore-not-found 2>/dev/null || true

# cert-manager CRDs, webhooks, and cluster-scoped RBAC.
# Helm does not delete CRDs on uninstall, and kustomize/ArgoCD deployments leave
# behind cluster-scoped resources without Helm ownership annotations, causing
# "cannot be imported into the current release" errors on reinstall.
echo "Removing cert-manager CRDs, webhooks, and cluster-scoped RBAC..."
kubectl get crd -o name | grep cert-manager \
    | xargs kubectl delete --ignore-not-found 2>/dev/null || true
kubectl get clusterrole,clusterrolebinding -o name \
    | grep cert-manager \
    | xargs kubectl delete --ignore-not-found 2>/dev/null || true
kubectl delete mutatingwebhookconfiguration cert-manager-webhook \
    --ignore-not-found 2>/dev/null || true
kubectl delete validatingwebhookconfiguration cert-manager-webhook cert-manager-approver-policy \
    --ignore-not-found 2>/dev/null || true

# external-secrets CRDs and webhooks
echo "Removing external-secrets CRDs and webhooks..."
kubectl get crd -o name | grep external-secrets.io \
    | xargs kubectl delete --ignore-not-found 2>/dev/null || true
kubectl get clusterrole,clusterrolebinding -o name \
    | grep -E "external-secrets|^clusterrole.*/eso-|^clusterrolebinding.*/eso-" \
    | xargs kubectl delete --ignore-not-found 2>/dev/null || true
kubectl delete validatingwebhookconfiguration externalsecret-validate secretstore-validate \
    --ignore-not-found 2>/dev/null || true

# Prometheus Operator CRDs that setup.sh applies from operators/crds/ (servicemonitors,
# podmonitors, prometheusrules, scrapeconfigs). Helm/kubectl-apply leave these behind, so
# remove them for a complete wipe. NOTE: skip this if the cluster has its own cluster-level
# Prometheus Operator that owns these CRDs.
echo "Removing Prometheus Operator (monitoring.coreos.com) CRDs..."
kubectl get crd -o name | grep monitoring.coreos.com \
    | xargs kubectl delete --ignore-not-found 2>/dev/null || true

# vault cluster-scoped RBAC and webhooks
echo "Removing vault cluster-scoped RBAC and webhooks..."
kubectl get clusterrole,clusterrolebinding -o name \
    | grep -E "vault-agent-injector|vault-server-binding" \
    | xargs kubectl delete --ignore-not-found 2>/dev/null || true
kubectl delete mutatingwebhookconfiguration vault-agent-injector-cfg \
    --ignore-not-found 2>/dev/null || true

# nico-rest cluster-scoped RBAC (ClusterRole/Binding created by the nico-rest
# umbrella chart — not cleaned up by helm uninstall if originally deployed by ArgoCD)
echo "Removing nico-rest cluster-scoped RBAC..."
kubectl get clusterrole,clusterrolebinding -o name \
    | grep nico-rest \
    | xargs kubectl delete --ignore-not-found 2>/dev/null || true

# DPF stack CRDs and cluster-scoped leftovers (DPF is installed by default).
# Helm does not delete CRDs on uninstall; the prereq operators (argo-cd,
# kamaji, maintenance-operator, NFD) also leave their CRDs and cluster RBAC.
# NOTE: match only Argo *CD* CRDs (applications/appprojects/applicationsets),
# not the whole argoproj.io group — a cluster running Argo Workflows would
# otherwise have its workflows.argoproj.io CRDs (and live objects) deleted.
# --timeout bounds the delete: `kubectl delete crd` blocks on CR finalizers
# (the strip loop in step 1b handles those, but bound it anyway).
echo "Removing DPF, Argo CD, Kamaji, NFD, and maintenance-operator CRDs..."
kubectl get crd -o name \
    | grep -E '\.dpu\.nvidia\.com|(applications|appprojects|applicationsets)\.argoproj\.io|kamaji\.clastix\.io|nfd\.k8s-sigs\.io|maintenance\.nvidia\.com' \
    | xargs -r kubectl delete --ignore-not-found --timeout=120s 2>/dev/null || true
kubectl get clusterrole,clusterrolebinding -o name \
    | grep -E "dpf-operator|argo-cd|argocd|kamaji|maintenance-operator|node-feature-discovery" \
    | xargs kubectl delete --ignore-not-found 2>/dev/null || true
# CertificateRequestPolicy + RBAC (only present on approver-policy clusters)
kubectl delete certificaterequestpolicy dpf-approval-policy \
    --ignore-not-found 2>/dev/null || true
kubectl delete "clusterrole/cert-manager-policy:dpf-approval-policy" \
    "clusterrolebinding/cert-manager-policy:dpf-approval-policy" \
    --ignore-not-found 2>/dev/null || true

# ---------------------------------------------------------------------------
# 3. Cluster-scoped resources created by helm hooks.
#    These survive helm/helmfile uninstall because hook-delete-policy is
#    "before-hook-creation" (cleans up on next install, not on uninstall).
# ---------------------------------------------------------------------------
echo "=== [3/8] Removing cluster-scoped hook resources ==="
kubectl delete clusterissuer \
    vault-nico-issuer site-issuer selfsigned-bootstrap \
    --ignore-not-found 2>/dev/null || true
kubectl delete clustersecretstore \
    cert-manager-ns-secretstore postgres-ns-secretstore \
    --ignore-not-found 2>/dev/null || true
kubectl delete clusterexternalsecret \
    nico-roots-eso nico-db-eso \
    flow-db-eso psm-db-eso nsm-db-eso \
    --ignore-not-found 2>/dev/null || true
kubectl delete clusterrole \
    vault-pki-config-reader eso-postgres-ns-role flow-vault-tokens-writer \
    --ignore-not-found 2>/dev/null || true
kubectl delete clusterrolebinding \
    vault-pki-config-reader eso-postgres-ns-rolebinding flow-vault-tokens-writer \
    --ignore-not-found 2>/dev/null || true

# ---------------------------------------------------------------------------
# 4. Vault init secrets (written by unseal_vault.sh, not owned by helm)
# ---------------------------------------------------------------------------
echo "=== [4/8] Removing Vault init secrets ==="
kubectl delete secret vault-cluster-keys vaultunsealkeys vaultroottoken \
    -n vault --ignore-not-found 2>/dev/null || true

# ---------------------------------------------------------------------------
# 5. Namespaces — helm/helmfile does not delete namespaces on uninstall.
#    Deleting the namespace also deletes all PVCs inside it.
#
#    default namespace cannot be deleted but must be purged: ArgoCD may
#    have deployed ESO (external-secrets) directly into default, leaving
#    behind deployments, services, secrets, and serviceaccounts that
#    conflict with setup.sh's helmfile install into the external-secrets ns.
# ---------------------------------------------------------------------------
echo "=== [5/8] Deleting namespaces ==="
kubectl delete ns nico-system cert-manager vault external-secrets postgres metallb-system dpf-operator-system \
    --wait=false --ignore-not-found 2>/dev/null || true

echo "Waiting for namespaces to terminate..."
kubectl wait --for=delete \
    ns/nico-system ns/cert-manager ns/vault ns/external-secrets ns/postgres ns/metallb-system ns/dpf-operator-system \
    --timeout=180s 2>/dev/null || true

echo "Purging default namespace (ESO and other non-kubespray resources)..."
kubectl delete deployment,replicaset,pod,service,secret,serviceaccount,configmap \
    -n default \
    -l "app.kubernetes.io/name=external-secrets" \
    --ignore-not-found 2>/dev/null || true
# Also remove any lingering ESO webhook secret and nico secrets by name
kubectl delete secret external-secrets-webhook nico-root nico-roots \
    -n default --ignore-not-found 2>/dev/null || true
kubectl delete serviceaccount argo-workflow eso-default-ns \
    external-secrets external-secrets-cert-controller external-secrets-webhook \
    -n default --ignore-not-found 2>/dev/null || true

# ---------------------------------------------------------------------------
# 5b. Preflight pods — per-node check pods left in kube-system by preflight.sh.
#     Labeled ncx-preflight=true; cleaned here (not by preflight.sh) so they
#     accumulate across runs and are only removed on explicit teardown.
# ---------------------------------------------------------------------------
echo "Removing preflight check pods..."
kubectl delete pod -n kube-system -l ncx-preflight=true \
    --ignore-not-found 2>/dev/null || true

# ---------------------------------------------------------------------------
# 6. Vault PersistentVolumes — StorageClass has reclaimPolicy: Retain, so
#    PVs are NOT deleted when PVCs are deleted (they go to "Released" state).
#    Delete them explicitly for a clean reinstall.
#    Scoped to namespaces owned by this stack to avoid removing PVs belonging
#    to other components that share the local-path-persistent StorageClass.
# ---------------------------------------------------------------------------
echo "=== [6/8] Removing Released PersistentVolumes owned by this stack ==="
kubectl get pv -o json 2>/dev/null \
    | jq -r '.items[] | select(
        .spec.storageClassName == "local-path-persistent" and
        (.spec.claimRef.namespace // "" | test("^(nico-system|cert-manager|vault|external-secrets|postgres|metallb-system|dpf-operator-system|nico-rest|temporal|loki|tempo|monitoring|otel)$"))
      ) | .metadata.name' \
    | xargs -r kubectl delete pv --ignore-not-found 2>/dev/null || true

# ---------------------------------------------------------------------------
# 7. local-path-provisioner + StorageClass (applied via kubectl in setup.sh)
# ---------------------------------------------------------------------------
echo "=== [7/7] Removing local-path-provisioner ==="
kubectl delete -f operators/storageclass-local-path-persistent.yaml \
    --ignore-not-found 2>/dev/null || true
kubectl delete -f operators/local-path-provisioner.yaml \
    --ignore-not-found 2>/dev/null || true
kubectl delete ns local-path-storage --wait=false --ignore-not-found 2>/dev/null || true
kubectl wait --for=delete ns/local-path-storage --timeout=60s 2>/dev/null || true

echo ""
echo "=== Clean complete ==="
