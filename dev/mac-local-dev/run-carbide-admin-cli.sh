#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Wrapper to run carbide-admin-cli against the local dev carbide-api instance
# started by run-carbide-api.sh.
#
# Usage (from repo root or any directory):
#   ./dev/mac-local-dev/run-carbide-admin-cli.sh <subcommand> [args...]
#
# Examples:
#   ./dev/mac-local-dev/run-carbide-admin-cli.sh version
#   ./dev/mac-local-dev/run-carbide-admin-cli.sh machine show
#   ./dev/mac-local-dev/run-carbide-admin-cli.sh ipxe-template list
#   ./dev/mac-local-dev/run-carbide-admin-cli.sh ipxe-template get ubuntu-24.04-netboot
#   ./dev/mac-local-dev/run-carbide-admin-cli.sh os-image show
#   ./dev/mac-local-dev/run-carbide-admin-cli.sh --format json ipxe-template list
#

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

export REPO_ROOT="$REPO_ROOT"
# Default to the locally-generated certs produced by dev/certs/localhost/gen-certs.sh.
# server_identity.pem / forge_developer_local_only_root_cert_pem are checked-in
# certs that have long expired and cannot be renewed without the NVIDIA CA private key.
CARBIDE_API_URL="${CARBIDE_API_URL:-https://localhost:1079}"
FORGE_ROOT_CA_PATH="${FORGE_ROOT_CA_PATH:-$REPO_ROOT/dev/certs/localhost/ca.crt}"
CLIENT_CERT_PATH="${CLIENT_CERT_PATH:-$REPO_ROOT/dev/certs/localhost/client.crt}"
CLIENT_KEY_PATH="${CLIENT_KEY_PATH:-$REPO_ROOT/dev/certs/localhost/client.key}"

CLI_BIN="$REPO_ROOT/target/debug/carbide-admin-cli"

if [ ! -x "$CLI_BIN" ]; then
  echo "Binary not found at $CLI_BIN — building first..."
  cargo build -p carbide-admin-cli --manifest-path "$REPO_ROOT/Cargo.toml"
fi

exec "$CLI_BIN" \
  --carbide-api "$CARBIDE_API_URL" \
  --forge-root-ca-path "$FORGE_ROOT_CA_PATH" \
  --client-cert-path "$CLIENT_CERT_PATH" \
  --client-key-path "$CLIENT_KEY_PATH" \
  "$@"
