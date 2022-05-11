#!/usr/bin/env bash

# Copyright 2021 NVIDIA CORPORATION & AFFILIATES.

set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

VPC_PKG="gitlab-master.nvidia.com/forge/vpc"
GOPATH=$(go env GOPATH)

# Generate mocks for testing with mockgen.
MOCKGEN_TARGETS=(
  "pkg/vpc VPCManager testing"
  "pkg/vpc/internal NetworkDeviceTransport testing"
  # TODO, need to manually modify generated mock code.
  # "rpc AgentServiceServer testing"
)

# Command mockgen does not automatically replace variable YEAR with current year
# like others do, e.g. client-gen.
for target in "${MOCKGEN_TARGETS[@]}"; do
  read -r package interfaces mock_package <<<"${target}"
  package_name=$(basename "${package}")
  if [[ "${mock_package}" == "." ]]; then # generate mocks in same package as src
      $GOPATH/bin/mockgen \
          -copyright_file hack/boilerplate.go.txt \
          -destination "${package}/mock_${package_name}_test.go" \
          -package="${package_name}" \
          "${VPC_PKG}/${package}" "${interfaces}"
  else # generate mocks in subpackage
      $GOPATH/bin/mockgen \
          -copyright_file hack/boilerplate.go.txt \
          -destination "${package}/${mock_package}/mock_${package_name}.go" \
          -package="${mock_package}" \
          "${VPC_PKG}/${package}" "${interfaces}"
  fi
done
