#!/usr/bin/env bash

#
# Copyright 2021 NVIDIA CORPORATION & AFFILIATES.
#

set -euo pipefail

ci=${IN_CI:-false}
ENVTEST_ASSETS_DIR=$(pwd)/testbin
if [[ "$ci" = true ]] ; then
    source "$ENVTEST_ASSETS_DIR"/setup-envtest.sh; fetch_envtest_tools "$ENVTEST_ASSETS_DIR"; setup_envtest_env "$ENVTEST_ASSETS_DIR"; go test -v -coverprofile cover.out ./... 2>&1 | go-junit-report > report.xml
    # source "$ENVTEST_ASSETS_DIR"/setup-envtest.sh; fetch_envtest_tools "$ENVTEST_ASSETS_DIR"; setup_envtest_env "$ENVTEST_ASSETS_DIR"; go test ./pkg/vpc/internal/... -v -ginkgo.v -coverprofile cover.out
else
    source "$ENVTEST_ASSETS_DIR"/setup-envtest.sh; fetch_envtest_tools "$ENVTEST_ASSETS_DIR"; setup_envtest_env "$ENVTEST_ASSETS_DIR"; go test -v -coverprofile cover.out ./... 2>&1
fi