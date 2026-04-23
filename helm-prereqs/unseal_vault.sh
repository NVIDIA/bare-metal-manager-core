#!/usr/bin/env bash
# =============================================================================
# unseal_vault.sh — initialize and unseal a 3-pod HashiCorp Vault HA cluster
#
# Run AFTER `helmfile sync -l name=vault` and BEFORE `helm install carbide-prereqs`.
#
# On first run: initializes Vault (5 shares, threshold 3) and stores keys/token
#   as K8s secrets: vault-cluster-keys, vaultunsealkeys, vaultroottoken
#   Also copies root token to forge-system/carbide-vault-token for carbide-prereqs.
#
# On subsequent runs: reads existing vault-cluster-keys secret and re-unseals
#   any pods that are sealed (e.g. after a node restart).
#
# Requires: kubectl, jq
# =============================================================================
set -euo pipefail

NAMESPACE="vault"

echo "Waiting for all 3 Vault pods to be Running..."
# StatefulSets create pods sequentially — vault-1/vault-2 may not exist yet.
# Poll until each pod exists, then wait for Initialized.
for POD in vault-0 vault-1 vault-2; do
    until kubectl get pod "${POD}" -n "${NAMESPACE}" &>/dev/null; do
        echo "  ${POD} not yet created, retrying in 5s..."
        sleep 5
    done
    kubectl wait pod/"${POD}" \
        -n "${NAMESPACE}" \
        --for=condition=Initialized \
        --timeout=300s
done
echo "All Vault pods are Running"

echo "Checking Vault status on vault-0..."
VAULT_STATUS_JSON="$(
    kubectl exec -n "${NAMESPACE}" vault-0 -c vault -- \
        vault status -tls-skip-verify -format=json 2>/dev/null || true
)"

if [[ -z "${VAULT_STATUS_JSON}" ]]; then
    echo "ERROR: Unable to retrieve Vault status from vault-0."
    echo "Make sure the Vault pods are running and try again."
    exit 1
fi

INITIALIZED="$(echo "${VAULT_STATUS_JSON}" | jq -r '.initialized')"
SEALED="$(echo "${VAULT_STATUS_JSON}" | jq -r '.sealed')"

echo "Vault initialized: ${INITIALIZED}"
echo "Vault sealed:      ${SEALED}"

if [[ "${INITIALIZED}" == "false" ]]; then
    echo "Vault is not initialized. Initializing via vault-0..."
    kubectl exec -n "${NAMESPACE}" vault-0 -c vault -- \
        vault operator init -tls-skip-verify -key-shares=5 -key-threshold=3 -format=json \
        > /tmp/cluster-keys.json

    kubectl create secret generic vault-cluster-keys \
        --namespace "${NAMESPACE}" \
        --from-file=cluster-keys.json=/tmp/cluster-keys.json

    rm -f /tmp/cluster-keys.json
    echo "vault-cluster-keys secret created"
else
    echo "Vault is already initialized. Skipping 'vault operator init'."
fi

# Read unseal keys from the K8s secret
KEY_1="$(kubectl -n "${NAMESPACE}" get secret vault-cluster-keys -o json \
    | jq -r '.data["cluster-keys.json"]' \
    | base64 -d \
    | jq -r '.unseal_keys_b64[0]')"

KEY_2="$(kubectl -n "${NAMESPACE}" get secret vault-cluster-keys -o json \
    | jq -r '.data["cluster-keys.json"]' \
    | base64 -d \
    | jq -r '.unseal_keys_b64[1]')"

KEY_3="$(kubectl -n "${NAMESPACE}" get secret vault-cluster-keys -o json \
    | jq -r '.data["cluster-keys.json"]' \
    | base64 -d \
    | jq -r '.unseal_keys_b64[2]')"

unseal_pod() {
    local POD="$1"
    local POD_STATUS POD_SEALED
    POD_STATUS="$(kubectl exec -n "${NAMESPACE}" "${POD}" -c vault -- \
        vault status -tls-skip-verify -format=json 2>/dev/null)" || true
    POD_SEALED="$(echo "${POD_STATUS}" | jq -r '.sealed')"

    if [[ "${POD_SEALED}" == "true" ]]; then
        echo "Unsealing ${POD}..."
        kubectl exec -n "${NAMESPACE}" "${POD}" -c vault -- \
            vault operator unseal -tls-skip-verify "${KEY_1}"
        sleep 5
        kubectl exec -n "${NAMESPACE}" "${POD}" -c vault -- \
            vault operator unseal -tls-skip-verify "${KEY_2}"
        sleep 5
        kubectl exec -n "${NAMESPACE}" "${POD}" -c vault -- \
            vault operator unseal -tls-skip-verify "${KEY_3}"
        sleep 5
        echo "${POD} unsealed"
    else
        echo "${POD} is already unsealed. Skipping."
    fi
}

unseal_pod vault-0
# Wait for vault-0 (leader) to be elected before unsealing followers
sleep 10
unseal_pod vault-1
unseal_pod vault-2

# Store individual unseal keys and root token as K8s secrets
CLUSTER_JSON="$(kubectl -n "${NAMESPACE}" get secret vault-cluster-keys -o json \
    | jq -r '.data["cluster-keys.json"]' \
    | base64 -d)"

B64_UNSEAL_0="$(echo "${CLUSTER_JSON}" | jq -r '.unseal_keys_b64[0]')"
B64_UNSEAL_1="$(echo "${CLUSTER_JSON}" | jq -r '.unseal_keys_b64[1]')"
B64_UNSEAL_2="$(echo "${CLUSTER_JSON}" | jq -r '.unseal_keys_b64[2]')"
B64_UNSEAL_3="$(echo "${CLUSTER_JSON}" | jq -r '.unseal_keys_b64[3]')"
B64_UNSEAL_4="$(echo "${CLUSTER_JSON}" | jq -r '.unseal_keys_b64[4]')"
ROOT_TOKEN="$(echo "${CLUSTER_JSON}" | jq -r '.root_token')"

echo "Storing unseal keys in vaultunsealkeys secret..."
kubectl delete secret vaultunsealkeys --namespace "${NAMESPACE}" --ignore-not-found
kubectl create secret generic vaultunsealkeys --namespace "${NAMESPACE}" --type=Opaque \
    --from-literal=0="${B64_UNSEAL_0}" \
    --from-literal=1="${B64_UNSEAL_1}" \
    --from-literal=2="${B64_UNSEAL_2}" \
    --from-literal=3="${B64_UNSEAL_3}" \
    --from-literal=4="${B64_UNSEAL_4}"

echo "Storing root token in vaultroottoken secret..."
kubectl delete secret vaultroottoken --namespace "${NAMESPACE}" --ignore-not-found
kubectl create secret generic vaultroottoken --namespace "${NAMESPACE}" --type=Opaque \
    --from-literal=token="${ROOT_TOKEN}"

# Set up forge-system namespace with Helm ownership so carbide-prereqs can adopt it
kubectl create namespace forge-system 2>/dev/null || true
kubectl label namespace forge-system \
    app.kubernetes.io/managed-by=Helm --overwrite
kubectl annotate namespace forge-system \
    meta.helm.sh/release-name=carbide-prereqs \
    meta.helm.sh/release-namespace=forge-system \
    --overwrite

# Copy root token to forge-system so vault-pki-config Job can use it
echo "Copying root token to forge-system/carbide-vault-token..."
kubectl delete secret carbide-vault-token --namespace forge-system --ignore-not-found
kubectl create secret generic carbide-vault-token --namespace forge-system --type=Opaque \
    --from-literal=token="${ROOT_TOKEN}"
# Add Helm ownership so carbide-prereqs can manage the secret
kubectl label secret carbide-vault-token -n forge-system \
    app.kubernetes.io/managed-by=Helm --overwrite
kubectl annotate secret carbide-vault-token -n forge-system \
    meta.helm.sh/release-name=carbide-prereqs \
    meta.helm.sh/release-namespace=forge-system \
    --overwrite

echo ""
echo "=== Vault initialized and unsealed ==="
echo "    vault-cluster-keys  — full init JSON (5 unseal keys + root token)"
echo "    vaultunsealkeys     — 5 individual unseal keys"
echo "    vaultroottoken      — root token (namespace: vault)"
echo "    carbide-vault-token — root token copy (namespace: forge-system)"
