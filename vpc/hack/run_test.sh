#!/usr/bin/env bash

#
# Copyright 2021 NVIDIA CORPORATION & AFFILIATES.
#

set -euo pipefail

ENVTEST_ASSETS_DIR=$(pwd)/testbin
source "$ENVTEST_ASSETS_DIR"/setup-envtest.sh; fetch_envtest_tools "$ENVTEST_ASSETS_DIR"; setup_envtest_env "$ENVTEST_ASSETS_DIR"; go test -coverprofile cover.out ./...
# source "$ENVTEST_ASSETS_DIR"/setup-envtest.sh; fetch_envtest_tools "$ENVTEST_ASSETS_DIR"; setup_envtest_env "$ENVTEST_ASSETS_DIR"; go test ./pkg/vpc/internal/... -v -ginkgo.v -coverprofile cover.out
