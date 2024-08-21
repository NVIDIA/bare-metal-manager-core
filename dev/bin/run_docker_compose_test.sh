#!/bin/bash

set -euxo pipefail

export DISABLE_TLS_ENFORCEMENT=true
export PGSSLMODE=disable
repo_root=$(git rev-parse --show-toplevel)
export REPO_ROOT=$repo_root

docker exec -ti carbide-carbide-api-1 bash -c "REPO_ROOT=/app/code /opt/forge-admin-cli/debug/forge-admin-cli credential add-bmc --kind=site-wide-root --password=pass" || echo "Setting BMC site-wide credential failed."
docker exec -ti carbide-carbide-api-1 bash -c "REPO_ROOT=/app/code /opt/forge-admin-cli/debug/forge-admin-cli credential add-uefi --kind=host --password=pass" || echo "Setting uefi password (host) failed."
docker exec -ti carbide-carbide-api-1 bash -c "REPO_ROOT=/app/code /opt/forge-admin-cli/debug/forge-admin-cli credential add-uefi --kind=dpu --password=pass" || echo "Setting uefi password (DPU) failed."

cd "$REPO_ROOT/dev/machine-a-tron/" || exit
cargo run -- "$REPO_ROOT/dev/docker-env/mat.toml"
