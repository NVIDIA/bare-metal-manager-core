#!/bin/bash

set -eux pipefail

KUBE_VERSION=${KUBE_VERSION}
#KUBE_VERSION=1.23.15
#KUBEVAL_SCHEMA_LOCATION="https://raw.githubusercontent.com/yannh/kubernetes-json-schema/master/"
KUBEVAL_SCHEMA_LOCATION="${KUBEVAL_SCHEMA_LOCATION}"

DIRS=($(find . -maxdepth 3 -type d -wholename "**/charts/*"))

for x in "${DIRS[@]}"; do
  helm kubeval ${x} --force-color --strict --kube-version $KUBE_VERSION $HELM_EXTRAS --skip-kinds "CustomResourceDefinition" -v $KUBE_VERSION -s ${KUBEVAL_SCHEMA_LOCATION}
done
