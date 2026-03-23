#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../.." && pwd)"

NAMESPACE="${LOCAL_DEV_NAMESPACE:-forge-system}"
CERT_MANAGER_NAMESPACE="${LOCAL_DEV_CERT_MANAGER_NAMESPACE:-cert-manager}"
VALUES_FILE="${LOCAL_DEV_VALUES_FILE:-${REPO_ROOT}/dev/deployment/devspace/values.generated.yaml}"

INSTALL_CERT_MANAGER="${LOCAL_DEV_INSTALL_CERT_MANAGER:-1}"
INSTALL_LOCAL_ISSUER="${LOCAL_DEV_INSTALL_LOCAL_ISSUER:-1}"
INSTALL_POSTGRES="${LOCAL_DEV_INSTALL_POSTGRES:-1}"
INSTALL_VAULT="${LOCAL_DEV_INSTALL_VAULT:-1}"

POSTGRES_NAMESPACE="${POSTGRES_NAMESPACE:-postgres}"
POSTGRES_HOST="${LOCAL_DEV_POSTGRES_HOST:-postgres.${POSTGRES_NAMESPACE}.svc.cluster.local}"
POSTGRES_PORT="${LOCAL_DEV_POSTGRES_PORT:-5432}"
POSTGRES_DB="${LOCAL_DEV_POSTGRES_DB:-carbide}"
POSTGRES_USER="${LOCAL_DEV_POSTGRES_USER:-carbide}"
POSTGRES_PASSWORD="${LOCAL_DEV_POSTGRES_PASSWORD:-carbide}"
POSTGRES_SSL_MODE="${LOCAL_DEV_POSTGRES_SSL_MODE:-disable}"

VAULT_NAMESPACE="${VAULT_NAMESPACE:-vault}"
VAULT_ADDR="${LOCAL_DEV_VAULT_ADDR:-http://vault.${VAULT_NAMESPACE}.svc.cluster.local:8200}"
VAULT_TOKEN="${LOCAL_DEV_VAULT_TOKEN:-root}"
VAULT_KV_MOUNT="${LOCAL_DEV_VAULT_KV_MOUNT:-secrets}"
VAULT_PKI_MOUNT="${LOCAL_DEV_VAULT_PKI_MOUNT:-certs}"
VAULT_PKI_ROLE_NAME="${LOCAL_DEV_VAULT_PKI_ROLE_NAME:-forge-cluster}"
VAULT_AUTH_MODE="${LOCAL_DEV_VAULT_AUTH_MODE:-root-token}"

CERT_ISSUER_KIND="${LOCAL_DEV_CERT_ISSUER_KIND:-Issuer}"
CERT_ISSUER_NAME="${LOCAL_DEV_CERT_ISSUER_NAME:-local-ca-issuer}"
CERT_ISSUER_GROUP="${LOCAL_DEV_CERT_ISSUER_GROUP:-cert-manager.io}"

log() {
  printf '[local-dev] %s\n' "$*"
}

require_bin() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'missing required binary: %s\n' "$1" >&2
    exit 1
  }
}

install_cert_manager() {
  if [[ "${INSTALL_CERT_MANAGER}" != "1" ]]; then
    return
  fi

  log "Installing cert-manager into ${CERT_MANAGER_NAMESPACE}"
  helm repo add jetstack https://charts.jetstack.io --force-update >/dev/null
  helm upgrade --install cert-manager jetstack/cert-manager \
    --namespace "${CERT_MANAGER_NAMESPACE}" \
    --create-namespace \
    --set crds.enabled=true >/dev/null

  kubectl rollout status deployment/cert-manager -n "${CERT_MANAGER_NAMESPACE}" --timeout=180s >/dev/null
  kubectl rollout status deployment/cert-manager-cainjector -n "${CERT_MANAGER_NAMESPACE}" --timeout=180s >/dev/null
  kubectl rollout status deployment/cert-manager-webhook -n "${CERT_MANAGER_NAMESPACE}" --timeout=180s >/dev/null
}

apply_core_objects() {
  log "Applying namespace and connection objects in ${NAMESPACE}"
  kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${NAMESPACE}
---
apiVersion: v1
kind: Secret
metadata:
  name: forge-system.carbide.forge-pg-cluster.credentials
  namespace: ${NAMESPACE}
type: Opaque
stringData:
  username: ${POSTGRES_USER}
  password: ${POSTGRES_PASSWORD}
  host: ${POSTGRES_HOST}
  port: "${POSTGRES_PORT}"
  dbname: ${POSTGRES_DB}
  uri: postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: forge-system-carbide-database-config
  namespace: ${NAMESPACE}
data:
  DB_HOST: ${POSTGRES_HOST}
  DB_PORT: "${POSTGRES_PORT}"
  DB_NAME: ${POSTGRES_DB}
---
apiVersion: v1
kind: Secret
metadata:
  name: carbide-vault-token
  namespace: ${NAMESPACE}
type: Opaque
stringData:
  token: ${VAULT_TOKEN}
---
apiVersion: v1
kind: Secret
metadata:
  name: carbide-vault-approle-tokens
  namespace: ${NAMESPACE}
type: Opaque
stringData:
  VAULT_ROLE_ID: local-dev
  VAULT_SECRET_ID: local-dev
EOF
}

apply_local_postgres() {
  if [[ "${INSTALL_POSTGRES}" != "1" ]]; then
    return
  fi

  log "Applying local PostgreSQL deployment"
  kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${POSTGRES_NAMESPACE}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: postgres-init
  namespace: ${POSTGRES_NAMESPACE}
data:
  001-create-user-and-db.sql: |
    DO \$\$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${POSTGRES_USER}') THEN
        CREATE USER ${POSTGRES_USER} WITH PASSWORD '${POSTGRES_PASSWORD}';
      END IF;
    END
    \$\$;
    SELECT 'CREATE DATABASE ${POSTGRES_DB} OWNER ${POSTGRES_USER}'
    WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = '${POSTGRES_DB}')\gexec
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: ${POSTGRES_NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
        - name: postgres
          image: postgres:14.5-alpine
          imagePullPolicy: IfNotPresent
          env:
            - name: POSTGRES_PASSWORD
              value: admin
            - name: POSTGRES_HOST_AUTH_METHOD
              value: trust
          ports:
            - containerPort: 5432
              name: postgres
          readinessProbe:
            tcpSocket:
              port: 5432
            initialDelaySeconds: 5
            periodSeconds: 5
          volumeMounts:
            - name: data
              mountPath: /var/lib/postgresql/data
            - name: init
              mountPath: /docker-entrypoint-initdb.d
      volumes:
        - name: data
          emptyDir: {}
        - name: init
          configMap:
            name: postgres-init
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: ${POSTGRES_NAMESPACE}
spec:
  selector:
    app: postgres
  ports:
    - name: postgres
      port: 5432
      targetPort: 5432
EOF

  kubectl rollout status statefulset/postgres -n "${POSTGRES_NAMESPACE}" --timeout=180s >/dev/null
}

apply_local_vault() {
  if [[ "${INSTALL_VAULT}" != "1" ]]; then
    return
  fi

  log "Applying local Vault dev server"
  kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${VAULT_NAMESPACE}
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: vault
  namespace: ${VAULT_NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vault
  template:
    metadata:
      labels:
        app: vault
    spec:
      containers:
        - name: vault
          image: hashicorp/vault:1.20.2
          imagePullPolicy: IfNotPresent
          args:
            - server
            - -dev
            - -dev-listen-address=0.0.0.0:8200
            - -dev-root-token-id=${VAULT_TOKEN}
          env:
            - name: VAULT_DEV_LISTEN_ADDRESS
              value: 0.0.0.0:8200
          ports:
            - containerPort: 8200
              name: http
          readinessProbe:
            httpGet:
              path: /v1/sys/health?standbyok=true&sealedcode=204&uninitcode=204
              port: 8200
            initialDelaySeconds: 5
            periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: vault
  namespace: ${VAULT_NAMESPACE}
spec:
  selector:
    app: vault
  ports:
    - name: http
      port: 8200
      targetPort: 8200
EOF

  kubectl rollout status statefulset/vault -n "${VAULT_NAMESPACE}" --timeout=180s >/dev/null

  log "Configuring Vault mounts and local role"
  kubectl exec -n "${VAULT_NAMESPACE}" statefulset/vault -- sh -lc "
    set -euo pipefail
    export VAULT_ADDR=http://127.0.0.1:8200
    export VAULT_TOKEN='${VAULT_TOKEN}'

    vault secrets list -format=json | grep -q '\"${VAULT_KV_MOUNT}/\"' || \
      vault secrets enable -path='${VAULT_KV_MOUNT}' -version=2 kv

    vault secrets list -format=json | grep -q '\"${VAULT_PKI_MOUNT}/\"' || \
      vault secrets enable -path='${VAULT_PKI_MOUNT}' pki

    vault read '${VAULT_PKI_MOUNT}/cert/ca' >/dev/null 2>&1 || \
      vault write '${VAULT_PKI_MOUNT}/root/generate/internal' common_name='local-vault-ca' ttl='87600h' >/dev/null

    vault write '${VAULT_PKI_MOUNT}/config/urls' \
      issuing_certificates='${VAULT_ADDR}/v1/${VAULT_PKI_MOUNT}/ca' \
      crl_distribution_points='${VAULT_ADDR}/v1/${VAULT_PKI_MOUNT}/crl' >/dev/null

    vault write '${VAULT_PKI_MOUNT}/roles/${VAULT_PKI_ROLE_NAME}' \
      allow_any_name=true \
      allow_bare_domains=true \
      allow_subdomains=true \
      allow_localhost=true \
      require_cn=false \
      max_ttl='72h' \
      allowed_uri_sans='spiffe://forge.local/*' >/dev/null

    vault kv get '${VAULT_KV_MOUNT}/machines/bmc/site/root' >/dev/null 2>&1 || \
      echo '{\"UsernamePassword\":{\"username\":\"root\",\"password\":\"vault-password\"}}' | \
      vault kv put '${VAULT_KV_MOUNT}/machines/bmc/site/root' - >/dev/null

    vault kv get '${VAULT_KV_MOUNT}/machines/all_dpus/site_default/uefi-metadata-items/auth' >/dev/null 2>&1 || \
      echo '{\"UsernamePassword\":{\"username\":\"root\",\"password\":\"vault-password\"}}' | \
      vault kv put '${VAULT_KV_MOUNT}/machines/all_dpus/site_default/uefi-metadata-items/auth' - >/dev/null

    vault kv get '${VAULT_KV_MOUNT}/machines/all_hosts/site_default/uefi-metadata-items/auth' >/dev/null 2>&1 || \
      echo '{\"UsernamePassword\":{\"username\":\"root\",\"password\":\"vault-password\"}}' | \
      vault kv put '${VAULT_KV_MOUNT}/machines/all_hosts/site_default/uefi-metadata-items/auth' - >/dev/null
  " >/dev/null
}

apply_local_issuer() {
  if [[ "${INSTALL_LOCAL_ISSUER}" != "1" ]]; then
    return
  fi

  log "Applying local cert-manager issuer resources"
  kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: local-selfsigned
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: forge-local-ca
  namespace: ${NAMESPACE}
spec:
  isCA: true
  commonName: forge-local-ca
  secretName: forge-local-ca
  privateKey:
    algorithm: ECDSA
    size: 384
  issuerRef:
    name: local-selfsigned
    kind: ClusterIssuer
    group: cert-manager.io
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: ${CERT_ISSUER_NAME}
  namespace: ${NAMESPACE}
spec:
  ca:
    secretName: forge-local-ca
EOF

  kubectl wait --for=condition=Ready certificate/forge-local-ca -n "${NAMESPACE}" --timeout=180s >/dev/null
}

sync_forge_roots_secret() {
  local ca_b64=""

  if kubectl get secret forge-local-ca -n "${NAMESPACE}" >/dev/null 2>&1; then
    ca_b64="$(kubectl get secret forge-local-ca -n "${NAMESPACE}" -o jsonpath='{.data.tls\.crt}')"
  fi

  if [[ -z "${ca_b64}" ]]; then
    ca_b64="$(printf 'placeholder' | base64 | tr -d '\n')"
  fi

  kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: forge-roots
  namespace: ${NAMESPACE}
type: Opaque
data:
  ca.crt: ${ca_b64}
EOF
}

write_generated_values() {
  local disable_tls_enforcement=""
  local automount="true"

  if [[ "${POSTGRES_SSL_MODE}" == "disable" ]]; then
    disable_tls_enforcement=$'  extraEnv:\n    - name: DISABLE_TLS_ENFORCEMENT\n      value: "1"'
  fi

  if [[ "${VAULT_AUTH_MODE}" == "root-token" ]]; then
    automount="false"
  fi

  mkdir -p "$(dirname -- "${VALUES_FILE}")"
  cat > "${VALUES_FILE}" <<EOF
global:
  certificate:
    issuerRef:
      kind: ${CERT_ISSUER_KIND}
      name: ${CERT_ISSUER_NAME}
      group: ${CERT_ISSUER_GROUP}

carbide-api:
  automountServiceAccountToken: ${automount}
  migrationJob:
    enabled: true
    sslMode: ${POSTGRES_SSL_MODE}
  vaultClusterInfo:
    VAULT_SERVICE: ${VAULT_ADDR}
    FORGE_VAULT_MOUNT: ${VAULT_KV_MOUNT}
    FORGE_VAULT_PKI_MOUNT: ${VAULT_PKI_MOUNT}
  databaseConfig: {}
${disable_tls_enforcement}
EOF
}

print_summary() {
  cat <<EOF

Bootstrap complete.

Namespace: ${NAMESPACE}
Generated values: ${VALUES_FILE}
Postgres endpoint: ${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}
Vault address: ${VAULT_ADDR}
Cert issuer: ${CERT_ISSUER_KIND}/${CERT_ISSUER_NAME}

Next step:
  cd ${REPO_ROOT} && devspace deploy -n ${NAMESPACE}
EOF
}

main() {
  require_bin kubectl
  require_bin helm
  require_bin base64

  install_cert_manager
  apply_core_objects
  apply_local_postgres
  apply_local_vault
  apply_local_issuer
  sync_forge_roots_secret
  write_generated_values
  print_summary
}

main "$@"
