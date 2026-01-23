# Local Carbide API (without machine-a-tron for now)

Notes:
- technically you can start machine-a-tron but it is useless on a Mac since its magic relies on Linux-specific features. It may work in docker on Mac...
- which is why we should run carbide on Mac in docker too. But for now this run native on Mac.

Assumptions:
- ~/.config/sops/age/keys.txt exists with content similar to 'AGE-SECRET-KEY-1MUQYH7VZ9RZ5ZWQ602A3ZCEJXU0T03W59C0C7S59RZ5TUVD70N5Q8239HT'

## To run carbide from the carbide directory:
```bash
SOPS_AGE_KEY_FILE=~/.config/sops/age/keys.txt FORGED_DIRECTORY="$(pwd)/../forged" just run-mac-carbide
```
This will setup everything and run carbide-api binary.

You can verify carbide-api is running by doing:
```bash
grpcurl -plaintext localhost:1079 list 
````
If you configure carbide to run with TLS , you can do:
```bash
grpcurl -insecure localhost:1079 list
```

## To run carbide in IntelliJ/RustRover IDE

IDE setup is not complete: you may want to configure 'Rust -> External Linters -> Additional Arguments' to include '--no-default-features'.

First run carbide stand-alone the kill it (it does setup everything).<br>
Then get some light setup and the needed variables by running:
```bash
SOPS_AGE_KEY_FILE=~/.config/sops/age/keys.txt dev/mac-local-dev/set-env.sh
```
It should output something like:
```bash
# required variables to run carbide-api:
export VAULT_PKI_ROLE_NAME=role
export VAULT_ADDR=http://localhost:8200
export CARBIDE_WEB_OAUTH2_CLIENT_SECRET=cVS8Q~wY2EC8QU~qhgDbbpFuAdfCUap5864bMcO0
export VAULT_PKI_MOUNT_LOCATION=certs
export VAULT_KV_MOUNT_LOCATION=secrets
export VAULT_TOKEN=hvs.fwlLLz8J7LfFchupSRf6le2U
export CARBIDE_WEB_AUTH_TYPE=oauth2
export CARBIDE_WEB_PRIVATE_COOKIEJAR_KEY=hFMh7Dasr8BHPGap86rEOr2OrzoOaXR1MEOlI3sYHvMNcJAz2eNnrNvsNO1BtOkP
export DATABASE_URL=postgresql://postgres:admin@localhost

# variables on a single line to feed IntelliJ run configuration:
VAULT_PKI_ROLE_NAME=role;VAULT_ADDR=http://localhost:8200;CARBIDE_WEB_OAUTH2_CLIENT_SECRET=cVS8Q~wY2EC8QU~qhgDbbpFuAdfCUap5864bMcO0;VAULT_PKI_MOUNT_LOCATION=certs;VAULT_KV_MOUNT_LOCATION=secrets;VAULT_TOKEN=hvs.fwlLLz8J7LfFchupSRf6le2U;CARBIDE_WEB_AUTH_TYPE=oauth2;CARBIDE_WEB_PRIVATE_COOKIEJAR_KEY=hFMh7Dasr8BHPGap86rEOr2OrzoOaXR1MEOlI3sYHvMNcJAz2eNnrNvsNO1BtOkP
```

You will need to create/modify a run configuration for carbide-api.
- cargo command parameters:
```
run --package carbide-api
--no-default-features -- run
--config-path dev/mac-local-dev/carbide-api-config-custom.toml
```
- environment variables: copy/paste the single line output from above into the 'Environment variables' section.

# Setting a local carbide-api for cloud-local

BEFORE setting the cloud-local environment you MUST configure auth by replacing 'kas-legacy' in `deploy/kustomize/overlays/local/configmap.yaml` by the following:
```yaml
- name: nvidia
  origin: 4 # TokenOriginCustom
  url: https://stg.authn.nvidia.com/pubJWKS
  issuer: "stg.auth.ngc.nvidia.com"
  serviceAccount: True
```

Setup cloud-local (<8m):
```bash
cd cloud-local
scripts/setup-forge-cloud.sh --clean
```

Make available the local carbide-api to cloud-local by running:
```bash
cd cloud-local
scripts/setup-local-carbide-service.sh
```

Start the elektra-site-agent:
```bash
cd cloud-local
scripts/setup-site.sh
````
# Exposing a remote 'dev' carbide-api to cloud-local

BEFORE setting the cloud-local environment you MUST configure auth by replacing 'kas-legacy' in `deploy/kustomize/overlays/local/configmap.yaml` by the following:
```yaml
- name: nvidia
  origin: 4 # TokenOriginCustom
  url: https://stg.authn.nvidia.com/pubJWKS
  issuer: "stg.auth.ngc.nvidia.com"
  serviceAccount: True
```

Setup cloud-local (<8m):
```bash
cd cloud-local
scripts/setup-forge-cloud.sh --clean
```

Make available the local carbide-api to cloud-local by running:
- use SSH port forwarding to expose carbide-api running remotely on your local machine.<br>
  Example: `ssh -L 10443:10.217.117.194:443 mydev`
  You can check access by going to 
- configure cloud-local to use your remote carbide-api by running:
```bash
cd cloud-local
scripts/setup-dev-carbide-service.sh
```

Start the elektra-site-agent:
```bash
cd cloud-local
scripts/setup-site.sh
````

# End-to-end test

## create a tenant and retrieve the Tenant ID

Create and retrieve Tenant by doing a 'Get Current Tenant' request...

Take note of the Tenant ID for subsequent requests.

## retrieve the Site ID

WARNING: you may have to wait for site to be in 'Registered' state before proceeding.

Retrieve the Site ID by doing a 'Get All Sites' request...

Take note of the Site ID for subsequent requests.

## create an ip block

```json
{
  "name": "allocation-test-super-block",
  "description": "IP Super block for Allocation test",
  "siteId": "{{siteId}}",
  "routingType": "DatacenterOnly",
  "prefix": "100.100.0.0",
  "prefixLength": 19,
  "protocolVersion": "IPv4"
}
```
Take note of the IP Block ID for subsequent requests.

## create an allocation

Use the ID of the above created IP Block as resourceTypeId.

```json
{
  "name": "allocation-test-dont-use-ip-block",
  "description": "Allocation Test IP Block for Demo Tenant",
  "tenantId": "{{tenantId}}",
  "siteId": "{{siteId}}",
  "allocationConstraints": [
    {
      "resourceType": "IPBlock",
      "resourceTypeId": "3b697bc7-27e2-479c-8152-51b33bfd4c5a",
      "constraintType": "Reserved",
      "constraintValue": 19
    }
  ]
}

```
## create a VPC (this will reach out to carbide API)
Ensure Site is in 'Registered' state before creating VPC: it should happen automatically if there is a proper connection already.

```json
{
  "name": "capi-test-vpc",
  "description": "VPC for Testing CAPI Integration",
  "siteId": "{{siteId}}"
}
```

# PREVIOUS INFORMATION FOR REFERENCE<br>YOU SHOULD PROBABLY IGNORE FOR NOW

Running machine-a-tron against carbide API locally.

Requires `sops` and corresponding key in `~/Library/Application Support/sops/age/keys.txt`
(just like with the normal development environment).


## Setup Vault and Postgres


Run vault and add the site-wide secrets that carbide API depends on.
```bash
# I used vault version Vault v1.20.2 (824d12909d5b596ddd3f34d9c8f169b4f9701a0c), built 2025-08-05T19:05:39Z
docker run --rm --detach --name vault --cap-add=IPC_LOCK -e 'VAULT_LOCAL_CONFIG={"storage": {"file": {"path": "/vault/file"}}, "listener": [{"tcp": { "address": "0.0.0.0:8200", "tls_disable": true}}], "default_lease_ttl": "168h", "max_lease_ttl": "720h", "ui": true}' -p 8200:8200 hashicorp/vault server
docker exec -it vault sh

export VAULT_ADDR="http://127.0.0.1:8200"
vault operator init -key-shares=1 -key-threshold=1 -format=json
# copy out unseal_keys_b64 and root_token
# don't forget any trailing '='s
# save the ROOT_TOKEN for running carbide API later
export UNSEAL_KEY="base64 encoded data"
export ROOT_TOKEN="hvs.something"
vault operator unseal $UNSEAL_KEY
vault login $ROOT_TOKEN
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
```

Run postgres with certs.
```bash
cd dev/certs/localhost
./gen-certs.sh
bash -c 'docker run --rm --detach --name pgdev --net=host -e POSTGRES_PASSWORD="admin" -e POSTGRES_HOST_AUTH_METHOD=trust -v "$(pwd)/localhost.crt:/var/lib/postgresql/server.crt:ro" -v "$(pwd)/localhost.key:/var/lib/postgresql/server.key:ro" postgres:14.5-alpine -c ssl=on -c ssl_cert_file=/var/lib/postgresql/server.crt -c ssl_key_file=/var/lib/postgresql/server.key -c max_connections=300'
```

## Run Carbide API

```bash
FORGED_PATH="../forged"
export CARBIDE_WEB_OAUTH2_CLIENT_SECRET=$(sops -d $FORGED_PATH/bases/carbide/api/secrets/azure-carbide-web-sso-NONPRODUCTION.enc.yaml  | sed -En 's/.*client_secret: (.*)/\1/p' | base64 -d)
export CARBIDE_WEB_AUTH_TYPE=oauth2
export CARBIDE_WEB_PRIVATE_COOKIEJAR_KEY=$(openssl rand -base64 64)
export DATABASE_URL="postgresql://postgres:admin@localhost"

export VAULT_ADDR="http://localhost:8200"
export VAULT_KV_MOUNT_LOCATION="secrets"
export VAULT_PKI_MOUNT_LOCATION="certs"
export VAULT_PKI_ROLE_NAME="role"
# copy the vault root token
export VAULT_TOKEN="hvs.something"

# Run SQL migrations.
cargo run --package carbide-api --no-default-features migrate

sudo mkdir /opt/carbide/firmware # carbide expects this directory to exist (even if empty).

RUST_BACKTRACE=1 cargo run --package carbide-api --no-default-features -- run --config-path dev/mac-local-dev/carbide-api-config.toml
```

In another terminal, run machine-a-tron.
```bash
sudo echo sudo enabled # get sudo without password (so we don't have to run cargo as root)

REPO_ROOT=. cargo run --bin machine-a-tron dev/machine-a-tron/config/mac.toml --forge-root-ca-path /Users/fchua/repos/carbide/dev/certs/localhost/ca.crt --client-cert-path /Users/fchua/repos/carbide/dev/certs/localhost/localhost.crt --client-key-path /Users/fchua/repos/carbide/dev/certs/localhost/localhost.key
```



[//]: # (Edit your config map entry 'carbide_address' to point to <service-IP>:1079 then restart the elektra-site-agent pods.)

[//]: # (```bash)

[//]: # (kubectl edit configmap elektra-config-map-6745d4gct5 -n elektra-site-agent)

[//]: # (kubectl delete pod elektra-site-agent-0 elektra-site-agent-1 elektra-site-agent-2 -n elektra-site-agent)

[//]: # (```)
