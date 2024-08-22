#!/bin/bash

set -euxo pipefail

export DISABLE_TLS_ENFORCEMENT=true
export PGSSLMODE=disable
repo_root=$(git rev-parse --show-toplevel)
export REPO_ROOT=$repo_root

export API_SERVER_HOST="127.0.0.1"
export API_SERVER_PORT="1079"

"$REPO_ROOT/dev/bin/admin-cli.sh" credential add-bmc --kind=site-wide-root --password=pass || echo "Setting BMC site-wide credential failed."
"$REPO_ROOT/dev/bin/admin-cli.sh" credential add-uefi --kind=host --password=pass || echo "Setting uefi password (host) failed."
"$REPO_ROOT/dev/bin/admin-cli.sh" credential add-uefi --kind=dpu --password=pass || echo "Setting uefi password (DPU) failed."

cd "$REPO_ROOT/dev/machine-a-tron/" || exit
cargo run -- "$REPO_ROOT/dev/docker-env/mat.toml"
