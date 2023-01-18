#!/bin/bash
set -ux pipefail

BUILDDATE="'$(date '+%FT%T%z' | sed -E -n 's/(\+[0-9]{2})([0-9]{2})$/\1:\2/p')'" # rfc 3339 date

BUILDTITLE=${BUILDTITLE:-carbide}
FORMATTED_BUILDTITLE=$(echo $BUILDTITLE | tr " " "_")
CPU_ARCH=${CPU_ARCH:-x86_64}

mkdir -p ${CI_PROJECT_DIR}/kaniko/.docker

cat /etc/hosts
echo '10.120.180.120 gitlab-master.nvidia.com' >> /etc/hosts

git fetch --tags
set +u
if [[ -z "$CI_COMMIT_TAG" ]]; then
    echo "VERSION=$(git describe --tags --first-parent --always)" > environment.env
else
    echo "VERSION=$CI_COMMIT_TAG" > environment.env
fi

IMAGE_LABELS="--label org.opencontainers.platform.architecture=$CPU_ARCH --label org.opencontainers.image.created=$BUILDDATE --label build-date=$BUILDDATE --label org.opencontainers.image.title=$FORMATTED_BUILDTITLE --label org.opencontainers.image.description=$FORMATTED_BUILDTITLE --label org.opencontainers.image.version=$VERSION --label org.opencontainers.image.vendor=nvidia"

echo BUILDDATE="${BUILDDATE}" >> environment.env
echo BUILDTITLE="${FORMATTED_BUILDTITLE}" >> environment.env
echo IMAGE_LABELS="${IMAGE_LABELS}" >> environment.env

VAULT_NAMESPACE=ngc
VAULT_ADDR=https://prod.vault.nvidia.com

# ROLE_ID and SECRET_ID are variables stored in gitlab-ci in the forge org, by devops team
export ROLE_ID=${VAULT_ROLE_ID}
export SECRET_ID=${VAULT_SECRET_ID}

VAULT_TOKEN=$(curl --header "X-Vault-Namespace:${VAULT_NAMESPACE}" -s --request POST --data "{\"role_id\":\"$ROLE_ID\",\"secret_id\":\"$SECRET_ID\"}" "${VAULT_ADDR}/v1/auth/approle/login" | jq -r '.auth.client_token')
curl --header "X-Vault-Token:${VAULT_TOKEN}" --header "X-Vault-Namespace: ${VAULT_NAMESPACE}" -s "${VAULT_ADDR}/v1/secrets/data/forge/docker" | jq -r '.data.data.docker_json'  > ${CI_PROJECT_DIR}/kaniko/.docker/config.json


