#!/usr/bin/env bash
# =============================================================================
# clean.sh — full teardown, inverse of setup.sh
#
# Destroys in reverse order:
#   0. NCX stack           (carbide-rest helm, temporal, keycloak, ncx postgres)
#   1. carbide core        (separate helm release, if installed)
#   2. helmfile releases   (carbide-prereqs, external-secrets, vault, cert-manager,
#                           postgres-operator)
#   3. cluster-scoped hook resources (ClusterIssuers, ClusterSecretStore, etc.)
#   4. vault init secrets  (vault-cluster-keys, vaultunsealkeys, vaultroottoken)
#   5. namespaces          (forge-system, cert-manager, vault, external-secrets, postgres)
#   6. local-path-persistent PVs owned by this stack (Retain policy — not deleted with namespace)
#   7. local-path-provisioner + StorageClass (applied via kubectl, not helm-managed)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# ---------------------------------------------------------------------------
# 0. NCX stack — uninstall before carbide since it depends on carbide's
#    cert-manager and ClusterIssuers.
# ---------------------------------------------------------------------------
echo "=== [0/8] Uninstalling NCX REST stack ==="
helm uninstall carbide-rest-site-agent -n carbide-rest 2>/dev/null || true
helm uninstall carbide-rest            -n carbide-rest 2>/dev/null || true
helm uninstall temporal                -n temporal     2>/dev/null || true

if kubectl get deploy keycloak -n carbide-rest &>/dev/null; then
    echo "  Cleaning up Keycloak..."
    "${SCRIPT_DIR}/keycloak/clean.sh" 2>/dev/null || true
else
    echo "  Keycloak not deployed — skipping cleanup"
fi

kubectl delete clusterissuer carbide-rest-ca-issuer --ignore-not-found 2>/dev/null || true
kubectl delete ns carbide-rest temporal \
    --wait=false --ignore-not-found 2>/dev/null || true
echo "Waiting for carbide-rest and temporal namespaces to terminate..."
kubectl wait --for=delete ns/carbide-rest ns/temporal \
    --timeout=120s 2>/dev/null || true

# ---------------------------------------------------------------------------
# 1. Carbide core (separate helm release, not in helmfile)
# ---------------------------------------------------------------------------
echo "=== [1/8] Uninstalling carbide core ==="
helm uninstall carbide -n forge-system 2>/dev/null || true

# ---------------------------------------------------------------------------
# 2. All helmfile releases in reverse dependency order:
#    carbide-prereqs → external-secrets → vault → cert-manager → metallb
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

# vault cluster-scoped RBAC and webhooks
echo "Removing vault cluster-scoped RBAC and webhooks..."
kubectl get clusterrole,clusterrolebinding -o name \
    | grep -E "vault-agent-injector|vault-server-binding" \
    | xargs kubectl delete --ignore-not-found 2>/dev/null || true
kubectl delete mutatingwebhookconfiguration vault-agent-injector-cfg \
    --ignore-not-found 2>/dev/null || true

# carbide-rest cluster-scoped RBAC (ClusterRole/Binding created by the carbide-rest
# umbrella chart — not cleaned up by helm uninstall if originally deployed by ArgoCD)
echo "Removing carbide-rest cluster-scoped RBAC..."
kubectl get clusterrole,clusterrolebinding -o name \
    | grep carbide-rest \
    | xargs kubectl delete --ignore-not-found 2>/dev/null || true

# ---------------------------------------------------------------------------
# 3. Cluster-scoped resources created by helm hooks.
#    These survive helm/helmfile uninstall because hook-delete-policy is
#    "before-hook-creation" (cleans up on next install, not on uninstall).
# ---------------------------------------------------------------------------
echo "=== [3/8] Removing cluster-scoped hook resources ==="
kubectl delete clusterissuer \
    vault-forge-issuer site-issuer selfsigned-bootstrap \
    --ignore-not-found 2>/dev/null || true
kubectl delete clustersecretstore \
    cert-manager-ns-secretstore postgres-ns-secretstore \
    --ignore-not-found 2>/dev/null || true
kubectl delete clusterexternalsecret forge-roots-eso carbide-db-eso \
    --ignore-not-found 2>/dev/null || true
kubectl delete clusterrole \
    vault-pki-config-reader eso-postgres-ns-role \
    --ignore-not-found 2>/dev/null || true
kubectl delete clusterrolebinding \
    vault-pki-config-reader eso-postgres-ns-rolebinding \
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
kubectl delete ns forge-system cert-manager vault external-secrets postgres metallb-system \
    --wait=false --ignore-not-found 2>/dev/null || true

echo "Waiting for namespaces to terminate..."
kubectl wait --for=delete \
    ns/forge-system ns/cert-manager ns/vault ns/external-secrets ns/postgres ns/metallb-system \
    --timeout=180s 2>/dev/null || true

echo "Purging default namespace (ESO and other non-kubespray resources)..."
kubectl delete deployment,replicaset,pod,service,secret,serviceaccount,configmap \
    -n default \
    -l "app.kubernetes.io/name=external-secrets" \
    --ignore-not-found 2>/dev/null || true
# Also remove any lingering ESO webhook secret and forge secrets by name
kubectl delete secret external-secrets-webhook forge-root forge-roots \
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
        (.spec.claimRef.namespace // "" | test("^(forge-system|cert-manager|vault|external-secrets|postgres|metallb-system|carbide-rest|temporal)$"))
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
