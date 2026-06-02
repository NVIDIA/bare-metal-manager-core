<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# NICo CLI

Command-line client for the NVIDIA Infrastructure Controller (NICo) REST API. Commands are dynamically generated from the embedded OpenAPI spec at startup, so every API endpoint is available with zero manual command code.

## Prerequisites

- Go 1.25.4 or later
- Access to a running NVIDIA Infrastructure Controller (NICo) REST API instance (local via `make kind-reset` or remote)

## Installation

### From the repo (recommended)

```bash
make nico-cli
```

This builds and installs `nicocli` to `$(go env GOPATH)/bin/nicocli`. Override the destination with:

```bash
make nico-cli INSTALL_DIR=/usr/local/bin
```

### With go install

```bash
go install ./cli/cmd/cli
```

### Manual go build

```bash
go build -o /usr/local/bin/nicocli ./cli/cmd/cli
```

### Via a coding agent

If you use a coding agent that has shell access, point it at [`cli/INSTALL.md`](INSTALL.md) -- that file is a self-contained prompt the agent can follow end-to-end to clone the repo, run `make nico-cli`, troubleshoot common environment issues, and verify the install.

```text
Install nicocli following the instructions at
https://github.com/NVIDIA/infra-controller-rest/blob/main/cli/INSTALL.md
```

### Inside the nico-rest-api container

The `nico-rest-api` container image ships `nicocli` at `/app/nicocli` as a convenience for ad-hoc debugging on a running deployment, so you can drive the API from inside the same pod without installing anything on the host:

```bash
# docker (local kind / docker-compose)
docker exec -it <container> /app/nicocli site list

# kubernetes
kubectl exec -it -n <namespace> <api-pod> -- /app/nicocli site list
```

When `nicocli` runs inside the API container, the server is reachable at `http://localhost:8388`. The image is distroless, so there is no shell or `/usr/bin/env` -- pass `nicocli` and its args directly to `exec`, and supply connection settings with CLI flags:

```bash
kubectl exec -it -n <namespace> <api-pod> -- \
    /app/nicocli \
    --base-url http://localhost:8388 \
    --org <org> \
    --token "$TOKEN" \
    site list
```

For day-to-day use, prefer installing `nicocli` locally with one of the methods above; the in-container copy is meant for one-off debugging.

### Verify

```bash
nicocli --version
```

## Quick Start

Generate a default config and add configs for each environment you work with:

```bash
nicocli init                    # writes ~/.nico/config.yaml
cp ~/.nico/config.yaml ~/.nico/config.staging.yaml
cp ~/.nico/config.yaml ~/.nico/config.prod.yaml
```

Edit each file with the appropriate server URL, org, and auth settings for that environment (see Configuration below), then launch interactive mode:

```bash
nicocli tui
```

The TUI will list your configs, let you pick an environment, authenticate, and start running commands. This is the recommended way to use `nicocli` since it handles environment selection, login, and token refresh automatically.

For direct one-off commands without the TUI:

```bash
nicocli login                   # exchange credentials for a token
nicocli site list               # list all sites
```

## Configuration

Config file: `~/.nico/config.yaml`

`nicocli init` writes a sample matching the layout below.

```yaml
api:
  base: http://localhost:8388
  org: test-org
  name: nico

auth:
  # Option 1: Direct bearer token
  # token: eyJhbGciOi...

  # Option 2: Auth script/token command
  # token_command: /path/to/get-nico-token.sh

  # Option 3: OIDC provider (e.g. Keycloak)
  oidc:
    token_url: http://localhost:8080/realms/nico-dev/protocol/openid-connect/token
    client_id: nico-api
    client_secret: nico-local-secret
    # Run `nicocli login` to authenticate; it will prompt for username/password
    # and persist the resulting bearer token (and refresh token) here.

  # Option 4: NGC API key
  # api_key:
  #   key: nvapi-xxxx
  #   # authn_url is only required for legacy NGC keys (without nvapi- prefix)
  #   # authn_url: https://your-authn-server/token
```

`nicocli login` writes bearer/refresh tokens back to this file, so restrict it (`chmod 600 ~/.nico/config*.yaml`) and do not commit it.

### Global flags

These flags apply to every command and override the corresponding config values. Where an env var is listed, exporting it has the same effect as passing the flag.

| Flag | Env Var | Description |
|------|---------|-------------|
| `--config` | `NICO_CONFIG` | Path to the config file (defaults to `~/.nico/config.yaml`) |
| `--base-url` | `NICO_BASE_URL` | API base URL |
| `--org` | `NICO_ORG` | Organization name |
| `--api-name` | `NICO_API_NAME` | API path segment used in `/v2/org/<org>/<name>/...` routes (default: `nico`) |
| `--token` | `NICO_TOKEN` | Bearer token (skips login) |
| `--token-command`, `--auth-script` | `NICO_TOKEN_COMMAND`, `NICO_AUTH_SCRIPT` | Shell command/script that prints a bearer token on stdout |
| `--token-url` | `NICO_TOKEN_URL` | OIDC token endpoint URL for login and refresh |
| `--keycloak-url` | `NICO_KEYCLOAK_URL` | Keycloak base URL (constructs `--token-url` if not set) |
| `--keycloak-realm` | `NICO_KEYCLOAK_REALM` | Keycloak realm (default: `nico-dev`) |
| `--client-id` | `NICO_CLIENT_ID` | OAuth client ID (default: `nico-api`) |
| `--debug` | | Log the full HTTP request and response, plus every `NICO_*` environment variable in use |

### Configuring with environment variables

Every field in `~/.nico/config.yaml` can also be set via a `NICO_*` environment variable. When both a config value and an env var are present, the env var wins; an explicit command-line flag still beats both. Set any of these in your shell instead of editing the config file:

| Env Var | Config field | Notes |
|---------|--------------|-------|
| `NICO_BASE_URL` | `api.base` | |
| `NICO_ORG` | `api.org` | |
| `NICO_API_NAME` | `api.name` | API path segment, defaults to `nico` |
| `NICO_TOKEN` | `auth.token` | Direct bearer token |
| `NICO_TOKEN_COMMAND` | `auth.token_command` | Shell command that prints a bearer token |
| `NICO_AUTH_SCRIPT` | `auth.token_command` | Alias of `NICO_TOKEN_COMMAND` (canonical name wins when both set) |
| `NICO_TOKEN_URL` | `auth.oidc.token_url` | |
| `NICO_CLIENT_ID` | `auth.oidc.client_id` | |
| `NICO_CLIENT_SECRET` | `auth.oidc.client_secret` | |
| `NICO_OIDC_USERNAME` | `auth.oidc.username` | |
| `NICO_OIDC_PASSWORD` | `auth.oidc.password` | |
| `NICO_OIDC_TOKEN` | `auth.oidc.token` | Persisted bearer token (also honored by direct `NICO_TOKEN`) |
| `NICO_OIDC_REFRESH_TOKEN` | `auth.oidc.refresh_token` | |
| `NICO_OIDC_EXPIRES_AT` | `auth.oidc.expires_at` | RFC3339 timestamp |
| `NICO_API_KEY` | `auth.api_key.key` | NGC API key |
| `NICO_AUTHN_URL` | `auth.api_key.authn_url` | Required for legacy NGC keys; ignored for `nvapi-` bearer keys |
| `NICO_API_KEY_TOKEN` | `auth.api_key.token` | Persisted token after NGC exchange |

`NICO_KEYCLOAK_URL` and `NICO_KEYCLOAK_REALM` do not map to a single config field; they feed the login command and construct the OIDC `token_url` at login time.

To see exactly which `NICO_*` variables are in use right now, pass `--debug` on any command:

```bash
nicocli --debug site list
# stderr starts with:
# [debug] env: 3 NICO_* variable(s) in use
# [debug] env: NICO_BASE_URL = https://api.example.com  -> api.base
# [debug] env: NICO_ORG      = my-org                   -> api.org
# [debug] env: NICO_TOKEN    = eyJh...                  -> auth.token (sensitive)
```

In interactive mode, type `env` to see the same listing (`env --mask` redacts tokens, secrets, and passwords).

### Per-command flags

Output formatting and pagination flags live on individual commands, not on the root, so they go after the resource and action -- `nicocli site list --output table`, not `nicocli --output table site list`. The common ones:

| Flag | Where | Description |
|------|-------|-------------|
| `--output` | every command | Output format: `json` (default), `yaml`, `table` |
| `--all` | list commands | Fetch every page instead of just the first |
| `--data` | create/update commands | Request body as inline JSON |
| `--data-file` | create/update commands | Path to a JSON file (use `-` for stdin) |

Run `nicocli <command> --help` for the full per-command flag list, including spec-derived query parameters and body fields.

## Authentication

```bash
# OIDC (credentials from config, prompts for password if not stored)
nicocli login

# OIDC with explicit flags
nicocli --token-url https://auth.example.com/token login --username admin@example.com

# OIDC client-credentials grant (no username -- use --client-secret)
nicocli --token-url https://auth.example.com/token login --client-secret "$NICO_CLIENT_SECRET"

# NGC API key (with explicit authn endpoint)
nicocli login --api-key nvapi-xxxx --authn-url https://your-authn-server/token

# Auth script/token command
nicocli --auth-script /path/to/get-nico-token.sh login

# Keycloak shorthand
nicocli --keycloak-url http://localhost:8080 login --username admin@example.com
```

Tokens are saved to the active config file (`~/.nico/config.yaml` by default, or the path selected with `--config` / the TUI config selector). OIDC is refreshed when possible; TUI mode reruns the configured auth method after `401 Unauthorized` API responses and retries safe read requests up to three times, logging each auth refresh/retry attempt.

`login` accepts these flags in addition to the OIDC/OAuth global flags above:

| Flag | Env Var | Description |
|------|---------|-------------|
| `--username` | `NICO_OIDC_USERNAME` | Username for OIDC password grant |
| `--password` | `NICO_OIDC_PASSWORD` | Password for OIDC password grant (prompted if not provided) |
| `--client-secret` | `NICO_CLIENT_SECRET` | Client secret for confidential OIDC clients (also enables the client-credentials grant when no username is set) |
| `--api-key` | `NICO_API_KEY` | NGC API key to exchange for a bearer token |
| `--authn-url` | `NICO_AUTHN_URL` | NGC authentication URL for the API-key exchange |

## Usage

```bash
nicocli site list
nicocli site get <siteId>
nicocli site create --name "SJC4"
nicocli site create --data-file site.json
cat site.json | nicocli site create --data-file -
nicocli site delete <siteId>
nicocli instance list --status provisioned --page-size 20
nicocli instance list --all                # fetch all pages
nicocli allocation constraint create <allocationId> --constraint-type SITE
nicocli site list --output table
nicocli --debug site list
```

## Command Structure

Commands follow `nicocli <resource> [sub-resource] <action> [args] [flags]`.

| Spec Pattern | CLI Action |
|---|---|
| `get-all-*` | `list` |
| `get-*` | `get` |
| `create-*` | `create` |
| `update-*` | `update` |
| `delete-*` | `delete` |
| `batch-create-*` | `batch-create` |
| `get-*-status-history` | `status-history` |
| `get-*-stats` | `stats` |

Nested API paths appear as sub-resource groups:

```
nicocli allocation list
nicocli allocation constraint list
nicocli allocation constraint create <allocationId>
```

## Shell Completion

```bash
# Bash
eval "$(nicocli completion bash)"

# Zsh
eval "$(nicocli completion zsh)"

# Fish
nicocli completion fish > ~/.config/fish/completions/nicocli.fish
```

## Multi-Environment Configs

Each environment (local dev, staging, prod) gets its own config file in `~/.nico/`:

```
~/.nico/config.yaml           # default (local dev)
~/.nico/config.staging.yaml   # staging
~/.nico/config.prod.yaml      # production
```

The TUI automatically discovers all `config*.yaml` files in `~/.nico/` and presents them as a selection list at startup. This is the easiest way to switch between environments without remembering URLs or re-authenticating.

For direct commands, select an environment with `--config`:

```bash
nicocli --config ~/.nico/config.staging.yaml site list
```

## Interactive TUI Mode

The TUI is the recommended way to interact with the API. It handles config selection, authentication, and token refresh in one session:

```bash
nicocli tui
```

You can also launch it with the `i` alias:

```bash
nicocli i
```

To skip the config selector and connect to a specific environment directly:

```bash
nicocli --config ~/.nico/config.prod.yaml tui
```

## Troubleshooting

If `nicocli` is not found after install, make sure `$(go env GOPATH)/bin` is in your PATH:

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
```

Use `--debug` on any command to see the full HTTP request and response for diagnosing issues:

```bash
nicocli --debug site list
```
