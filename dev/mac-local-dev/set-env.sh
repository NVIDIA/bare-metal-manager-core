#!/bin/bash
#
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# set-env.sh
#
# Generate customized config and display environment variables needed to run a native carbide-api on MacOS.
#

set -e

CUR_DIR="$(pwd)"

# customize config to point to local certificates:
CUSTOM_CONFIG="dev/mac-local-dev/carbide-api-config-custom.toml"
sed -e 's|/.*carbide/dev|'"$CUR_DIR"'/dev|' < dev/mac-local-dev/carbide-api-config.toml > "${CUSTOM_CONFIG}"

export DATABASE_URL="postgresql://postgres:admin@localhost"

export CARBIDE_WEB_AUTH_TYPE=oauth2
export CARBIDE_WEB_OAUTH2_CLIENT_SECRET="$(sops -d forged/bases/carbide/api/secrets/azure-carbide-web-sso-NONPRODUCTION.enc.yaml  | sed -En 's/.*client_secret: (.*)/\1/p' | base64 -d)"
export CARBIDE_WEB_PRIVATE_COOKIEJAR_KEY="$(openssl rand -base64 64)"

export VAULT_ADDR="http://localhost:8200"
export VAULT_KV_MOUNT_LOCATION="secrets"
export VAULT_PKI_MOUNT_LOCATION="certs"
export VAULT_PKI_ROLE_NAME="role"
export VAULT_TOKEN="$(cat /tmp/localdev-docker-vault-root-token)"

echo "# required variables to run carbide-api:"
printenv | grep -e '^VAULT_' -e '^CARBIDE_' -e DATABASE_URL | sed -e 's/^/export /'
echo ""
echo "# variables on a single line to feed IntelliJ run configuration:"
printenv | grep -e '^VAULT_' -e '^CARBIDE_' | sed -e 's/$/;/' | tr -d '\n' | sed -e 's/;$//'
echo

