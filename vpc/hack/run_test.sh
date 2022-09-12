#!/usr/bin/env bash

#
# Copyright 2021 NVIDIA CORPORATION & AFFILIATES.
#

set -euo pipefail

ci=${IN_CI:-false}
ENVTEST=$(pwd)/bin/setup-envtest
if [[ "$ci" = true ]] ; then
    KUBEBUILDER_ASSETS=$($ENVTEST use $ENVTEST_K8S_VERSION -p path) go test -v -coverprofile cover.out ./... 2>&1 | go-junit-report > report.xml
    # KUBEBUILDER_ASSETS=$($ENVTEST use $ENVTEST_K8S_VERSION -p path) go test ./pkg/vpc/internal/... -v -ginkgo.v -coverprofile cover.out
else
    KUBEBUILDER_ASSETS=$($ENVTEST use $ENVTEST_K8S_VERSION -p path) go test -coverprofile cover.out ./... 2>&1
    # KUBEBUILDER_ASSETS=$($ENVTEST use $ENVTEST_K8S_VERSION -p path) go test ./pkg/vpc/internal/... -v -ginkgo.v
fi