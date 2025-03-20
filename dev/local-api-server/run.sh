#!/bin/bash

# This script runs an API server locally via `cargo run`, using the database
# URL from a running kubernetes instance, and with a configuration that
# disables as much as possible so that you can point a local
# chrome/curl/grpcurl at it. It will not run things like site-explorer or any
# state controllers, nor will it have access to any vault secrets.

set -euo pipefail

DIR="$(dirname "${BASH_SOURCE}")"
source <("${DIR}/eval_me_for_env_vars.sh")
cd "${DIR}/../.."
exec cargo run -p carbide-api -- run --config-path dev/local-api-server/carbide-api-config.toml
