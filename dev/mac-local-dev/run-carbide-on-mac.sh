#!/bin/bash
#
# pre-requisites:
# - brew install yq sops vault
# - sudo mkdir -p /opt/carbide/firmware
# - ~/.config/sops/age/keys.txt must contain the sops key
#

set -e

CUR_DIR="$(pwd)"

# ensure we kill previous instances:
for name in vault pgdev; do
  DID="$(docker ps --filter name=${name} --format json | jq '.ID' | tr -d '"')"
  if [ -n "${DID}" ]; then
    docker kill ${DID}
    fi
  done
sleep 2

# Francis: I used vault version Vault v1.20.2 (824d12909d5b596ddd3f34d9c8f169b4f9701a0c), built 2025-08-05T19:05:39Z
docker run --rm --detach --name vault --cap-add=IPC_LOCK -e 'VAULT_LOCAL_CONFIG={"storage": {"file": {"path": "/vault/file"}}, "listener": [{"tcp": { "address": "0.0.0.0:8200", "tls_disable": true}}], "default_lease_ttl": "168h", "max_lease_ttl": "720h", "ui": true}' -p 8200:8200 hashicorp/vault server
sleep 2

# intialize vault and retrieve keys:
OUTPUT="$(docker exec -i vault sh -c 'export VAULT_ADDR="http://127.0.0.1:8200" && vault operator init -key-shares=1 -key-threshold=1 -format=yaml')"
export UNSEAL_KEY="$(yq <<< "${OUTPUT}" '.unseal_keys_b64[0]')"
export VAULT_TOKEN="$(yq <<< "${OUTPUT}" '.root_token')"
echo "# unseal key: $UNSEAL_KEY"
echo "# root token: $VAULT_TOKEN"

export VAULT_ADDR="http://127.0.0.1:8200"

# load vault:
vault operator unseal $UNSEAL_KEY
vault login $VAULT_TOKEN
vault secrets enable -path=secrets -version=2 kv
vault kv delete /secrets/machines/bmc/site/root
vault kv delete /secrets/machines/all_dpus/site_default/uefi-metadata-items/auth
vault kv delete /secrets/machines/all_hosts/site_default/uefi-metadata-items/auth
echo '{"UsernamePassword": {"username": "root", "password": "vault-password" }}' | vault kv put /secrets/machines/bmc/site/root -
echo '{"UsernamePassword": {"username": "root", "password": "vault-password" }}' | vault kv put /secrets/machines/all_dpus/site_default/uefi-metadata-items/auth -
echo '{"UsernamePassword": {"username": "root", "password": "vault-password" }}' | vault kv put /secrets/machines/all_hosts/site_default/uefi-metadata-items/auth -
vault secrets enable -path=certs pki
vault write certs/root/generate/internal common_name=myvault.com ttl=87600h
vault write certs/config/urls issuing_certificates="http://vault.example.com:8200/v1/pki/ca" crl_distribution_points="http://vault.example.com:8200/v1/pki/crl"
vault write certs/roles/role allowed_domains=example.com allow_subdomains=true max_ttl=72h require_cn=false allowed_uri_sans="spiffe://forge.local/*"

# postgres setup:
cd dev/certs/localhost
./gen-certs.sh
docker run --rm --detach --name pgdev --net=host -e POSTGRES_PASSWORD="admin" -e POSTGRES_HOST_AUTH_METHOD=trust -v "$(pwd)/localhost.crt:/var/lib/postgresql/server.crt:ro" -v "$(pwd)/localhost.key:/var/lib/postgresql/server.key:ro" postgres:14.5-alpine -c ssl=on -c ssl_cert_file=/var/lib/postgresql/server.crt -c ssl_key_file=/var/lib/postgresql/server.key -c max_connections=300
cd -

# set carbide API:
FORGED_PATH="../forged"
export CARBIDE_WEB_OAUTH2_CLIENT_SECRET=$(SOPS_AGE_KEY_FILE=~/.config/sops/age/keys.txt sops -d $FORGED_PATH/bases/carbide/api/secrets/azure-carbide-web-sso-NONPRODUCTION.enc.yaml  | sed -En 's/.*client_secret: (.*)/\1/p' | base64 -d)
export CARBIDE_WEB_AUTH_TYPE=oauth2
export CARBIDE_WEB_PRIVATE_COOKIEJAR_KEY=$(openssl rand -base64 64)
export DATABASE_URL="postgresql://postgres:admin@localhost"

export VAULT_KV_MOUNT_LOCATION="secrets"
export VAULT_PKI_MOUNT_LOCATION="certs"
export VAULT_PKI_ROLE_NAME="role"

# Run SQL migrations.
cargo run --package carbide-api --no-default-features migrate

RUST_BACKTRACE=1 cargo run --package carbide-api --no-default-features -- run --config-path dev/mac-local-dev/carbide-api-config.toml

echo "# done."

