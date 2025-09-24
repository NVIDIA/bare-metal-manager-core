#set shell := ["bash", "-uc"]
export DOCKER_BUILDKIT := "1"

components_dir := "api pxe dns dhcp dev/bmc-mock dev/machine-a-tron admin health dhcp-server ssh-console"
components_name := "carbide-api carbide-pxe carbide-dns dhcp bmc-mock machine-a-tron admin health dhcp-server ssh-console"
image_name := "carbide-api carbide-pxe carbide-dns carbide-dhcp bmc-mock machine-a-tron carbide-hardware-health carbide-dhcp-server ssh-console-rs"

# Start cargo-watch for components "{{components}}"
watch: check forged-link skaffold-dirs
  parallel --link  -j+0 --tty --tag cargo --color=always watch --why -C {1} -s \"${REPO_ROOT}/.skaffold/build {2}\" ::: {{components_dir}} ::: {{components_name}}

# Build components one time
build: check forged-link skaffold-dirs
  parallel --link  -j+0 --tty --tag "${REPO_ROOT}"/.skaffold/build {1} ::: {{components_name}}

rmi: check forged-link skaffold-dirs
  docker rmi {{image_name}}

format-staged-files:
  git diff --name-only --staged | grep '.rs' | xargs rustfmt --config imports_granularity=Crate,group_imports=StdExternalCrate,skip_children=true --edition 2024

_dockerbuild NAME FILE CONTEXT=(invocation_directory()):
  DOCKER_BUILDKIT=1 docker build -t {{NAME}} -f {{FILE}} {{CONTEXT}}

_dockerclean NAME:
  docker rmi {{NAME}}

# Build the carbide build-container used for compiling
build-container: (_dockerbuild "urm.nvidia.com/swngc-ngcc-docker-local/forge/carbide/x86-64/build-container:latest" "dev/docker/Dockerfile.build-container-x86_64" "dev/docker")
clean-build-container: (_dockerclean "urm.nvidia.com/swngc-ngcc-docker-local/forge/carbide/x86-64/build-container:latest")

# Build the build-container used for minikube forge development
build-container-minikube: build-container (_dockerbuild "registry.minikube/build-container:latest" "dev/deployment/localdev/Dockerfile.build-container.localdev" "dev/deployment")
clean-build-container-minikube: (_dockerclean "registry.minikube/build-container:latest")
build-container-k3s: build-container (_dockerbuild "build-container-localdev:latest" "dev/deployment/localdev/Dockerfile.build-container.localdev" "dev/deployment")
clean-build-container-k3s: (_dockerclean "build-container-localdev:latest")

# Build the runtime-container for minikube development. This gets used for deploying forge containers
runtime-container-minikube: (_dockerbuild "registry.minikube/runtime-container:latest" "dev/deployment/localdev/Dockerfile.runtime-container.localdev")
clean-runtime-container-minikube: (_dockerclean "registry.minikube/runtime-container:latest")
runtime-container-k3s: (_dockerbuild "runtime-container-localdev:latest" "dev/deployment/localdev/Dockerfile.runtime-container.localdev")
clean-runtime-container-k3s: (_dockerclean "runtime-container-localdev:latest")

load-minikube-registry: runtime-container-minikube build-container-minikube
  minikube image load registry.minikube/build-container:latest
  minikube image load registry.minikube/runtime-container:latest

check-binaries-in-path:
  @which parallel 2>&1 &>/dev/null || (echo "parallel not found" && exit 1)
  @which skaffold 2>&1 &>/dev/null || (echo "skaffold not found" && exit 1)
  @echo "checked binaries, OK"

check-envs:
  @TMP_UNUSED_VAR=$FORGED_DIRECTORY
  @echo "checked environment variables, OK"

check:
  @just -f {{justfile()}} check-binaries-in-path
  @just -f {{justfile()}} check-envs

forged-link: check-envs
  #!/usr/bin/env bash
  set -euo pipefail
  test -e ./forged || ln -s $FORGED_DIRECTORY ./forged || (echo "Could not link FORGED_DIRECTORY $FORGED_DIRECTORY to ./forged, does it exist?" && exit 1)

skaffold-dirs:
  #!/usr/bin/env bash
  set -euo pipefail
  test -d .skaffold/cache || mkdir -p .skaffold/cache
  test -d .skaffold/target || mkdir -p .skaffold/target

test_docker_containers:
  #!/usr/bin/env bash
  echo "Initiating docker postgres container for testing named: pgdev"
  docker kill pgdev 2>/dev/null
  docker run --rm -di -e POSTGRES_PASSWORD="admin" --net=host --name pgdev postgres:14.5-alpine

clean_postgres:
  #!/usr/bin/env bash
  echo "Cleaning forge postgres DB"
  ./dev/bin/nuke-postgres.sh

run-docker-vault: check-envs
  #!/usr/bin/env bash
  if docker container ls | grep vault;
  then
    echo "Vault is already running in docker. Skipping setup";
    exit 0
  fi
  docker run --rm --detach --name vault --cap-add=IPC_LOCK -e 'VAULT_LOCAL_CONFIG={"storage": {"file": {"path": "/vault/file"}}, "listener": [{"tcp": { "address": "0.0.0.0:8200", "tls_disable": true}}], "default_lease_ttl": "168h", "max_lease_ttl": "720h", "ui": true}' -p 8200:8200 hashicorp/vault:1.20.2 server
  # wait till vault is available
  until docker exec -it vault sh -c "export VAULT_ADDR=http://127.0.0.1:8200; vault status -format json" | jq ".sealed" >/dev/null;
    do sleep 1;
  done
  INIT=$(docker exec -it vault sh -c "export VAULT_ADDR=http://127.0.0.1:8200; vault operator init -key-shares=1 -key-threshold=1 -format=json")
  echo $INIT
  UNSEAL_KEY=$(echo $INIT | jq -r ".unseal_keys_b64[0]")
  ROOT_TOKEN=$(echo $INIT | jq -r ".root_token")
  echo $ROOT_TOKEN > /tmp/localdev-docker-vault-root-token

  docker exec -it vault sh -c "\
    export VAULT_ADDR=http://127.0.0.1:8200; \
    vault operator unseal $UNSEAL_KEY; \
    vault login $ROOT_TOKEN; \
    vault secrets enable -path=secrets -version=2 kv; \
    vault kv delete /secrets/machines/bmc/site/root; \
    vault kv delete /secrets/machines/all_dpus/site_default/uefi-metadata-items/auth; \
    vault kv delete /secrets/machines/all_hosts/site_default/uefi-metadata-items/auth; \
    echo '{\"UsernamePassword\": {\"username\": \"root\", \"password\": \"vault-password\" }}' | vault kv put /secrets/machines/bmc/site/root -; \
    echo '{\"UsernamePassword\": {\"username\": \"root\", \"password\": \"vault-password\" }}' | vault kv put /secrets/machines/all_dpus/site_default/uefi-metadata-items/auth -; \
    echo '{\"UsernamePassword\": {\"username\": \"root\", \"password\": \"vault-password\" }}' | vault kv put /secrets/machines/all_hosts/site_default/uefi-metadata-items/auth -; \
    vault secrets enable -path=certs pki; \
    vault write certs/root/generate/internal common_name=myvault.com ttl=87600h; \
    vault write certs/config/urls issuing_certificates=\"http://vault.example.com:8200/v1/pki/ca\" crl_distribution_points=\"http://vault.example.com:8200/v1/pki/crl\"; \
    vault write certs/roles/role allowed_domains=example.com allow_subdomains=true max_ttl=72h require_cn=false allowed_uri_sans=\"spiffe://forge.local/*\"; \
  "
  echo "UNSEAL_KEY=$UNSEAL_KEY"
  echo "ROOT_TOKEN=$ROOT_TOKEN"

run-docker-postgres:
  #!/usr/bin/env bash
  if docker container ls | grep postgres;
  then
    echo "Postgres is already running in docker. Skipping setup";
    exit 0
  fi
  cd dev/certs/localhost
  ./gen-certs.sh
  bash -c 'docker run --rm --detach --name pgdev --net=host -e POSTGRES_PASSWORD="admin" -e POSTGRES_HOST_AUTH_METHOD=trust -v "$(pwd)/localhost.crt:/var/lib/postgresql/server.crt:ro" -v "$(pwd)/localhost.key:/var/lib/postgresql/server.key:ro" postgres:14.5-alpine -c ssl=on -c ssl_cert_file=/var/lib/postgresql/server.crt -c ssl_key_file=/var/lib/postgresql/server.key -c max_connections=300'

run-mac-carbide: run-docker-vault run-docker-postgres
  #!/usr/bin/env bash
  export CARBIDE_WEB_OAUTH2_CLIENT_SECRET=$(sops -d $FORGED_DIRECTORY/bases/carbide/api/secrets/azure-carbide-web-sso-NONPRODUCTION.enc.yaml  | sed -En 's/.*client_secret: (.*)/\1/p' | base64 -d)
  export CARBIDE_WEB_AUTH_TYPE=oauth2
  export CARBIDE_WEB_PRIVATE_COOKIEJAR_KEY=$(openssl rand -base64 64)
  export DATABASE_URL="postgresql://postgres:admin@localhost"

  export VAULT_ADDR="http://localhost:8200"
  export VAULT_KV_MOUNT_LOCATION="secrets"
  export VAULT_PKI_MOUNT_LOCATION="certs"
  export VAULT_PKI_ROLE_NAME="role"
  export VAULT_TOKEN=$(cat /tmp/localdev-docker-vault-root-token)

  cargo run --package carbide-api --no-default-features migrate || true

  echo "making carbide firmware dir, might ask for password"
  sudo mkdir /opt/carbide/firmware # carbide expects this directory to exist (even if empty).
  RUST_BACKTRACE=1 cargo run --package carbide-api --no-default-features -- run --config-path dev/mac-local-dev/carbide-api-config.toml

run-mac-mat:
  #!/usr/bin/env bash
  echo "need to bind modify ifconfig, might ask for password"
  sudo echo sudo enabled # get sudo without password (so we don't have to run cargo as root)
  REPO_ROOT=. cargo run --bin machine-a-tron dev/machine-a-tron/config/mac.toml --forge-root-ca-path dev/certs/localhost/ca.crt --client-cert-path dev/certs/localhost/localhost.crt --client-key-path dev/certs/localhost/localhost.key

