#!/bin/bash

set -eux pipefail

APPLICATION_VERSION=$(git describe --tags 2>/dev/null )
if [[ $? != 0 ]]; then
  LATEST="1.0.0"
fi

HELM_VERSION=$(awk '/^version/ {print $2}' Chart.yaml)
echo -n $APPLICATION_VERSION

