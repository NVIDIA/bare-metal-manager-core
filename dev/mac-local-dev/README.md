# Mac Local Development — Carbide API

Runs `carbide-api` natively on macOS (no Docker for the binary itself).
Docker Desktop is used only for Vault and Postgres.
This Carbide API instance is usable by Carbide REST stack.

> **Limitations**
> - TPM / attestation features require Linux and a physical TPM — they are disabled in this setup.
> - `machine-a-tron` relies on Linux-specific features and is unusable on macOS.

## Prerequisites

| Tool | Notes |
|------|-------|
| Docker Desktop | Must be running before the script is invoked |
| Rust toolchain | `cargo` must be on `$PATH` |
| `jq` | JSON processing for Vault init output |
| `curl` | Vault health-check polling |
| `openssl` | TLS cert generation (pre-installed on macOS) |

---

## Starting Carbide API

Run from **any directory** — the script resolves the repo root automatically:

```bash
./dev/mac-local-dev/run-carbide-api.sh
```

The script is fully self-contained and idempotent.  On each run it:

1. Checks prerequisites (`docker`, `cargo`, `jq`, `curl`).
2. Starts a **Vault** container (`carbide-vault`) on port **8201** and initialises it
   (KV secrets + PKI) if not already running.  The root token is cached at
   `/tmp/carbide-localdev-vault-root-token`.
3. Regenerates **TLS certificates** under `dev/certs/localhost/` if they are
   missing or stale (`gen-certs.sh` is idempotent).
4. Starts a **Postgres** container (`pgdev`) on port **5432** with SSL if not
   already running.
5. Creates `/opt/carbide/firmware` (may prompt for `sudo` once).
6. Writes a temporary resolved config to `/tmp/carbide-api-config-<PID>.toml`
   with absolute TLS cert paths (the checked-in config uses paths relative to
   `$CWD`, which would break when launched from an IDE).
7. Runs **database migrations**.
8. Starts `carbide-api` (foreground, `Ctrl-C` to stop).

Once running:

```bash
# Verify gRPC is up
grpcurl -insecure localhost:1079 list

# Web UI
open https://localhost:1079/admin
```

### Resetting state

```bash
# Remove containers (preserves cert files)
docker rm -f carbide-vault pgdev

# Also regenerate certs from scratch
rm -f dev/certs/localhost/*.crt dev/certs/localhost/*.key
```

---

## Using carbide-admin-cli

In a **second terminal**, use the wrapper script to talk to the running API:

```bash
./dev/mac-local-dev/run-carbide-admin-cli.sh <subcommand> [args...]
```

The script:
- Builds `carbide-admin-cli` automatically if `target/debug/carbide-admin-cli`
  does not exist.
- Wires up TLS using the locally-generated certs from `dev/certs/localhost/`
  (the same CA that `run-carbide-api.sh` configures the server to trust).
- certs provided are compatible with access to localhost or host.docker.internal (from Docker or Colima).
- Can be run from any directory.

### Global flags

| Flag | Short | Description |
|------|-------|-------------|
| `--format <fmt>` | `-f` | `ascii-table` (default), `json`, … |
| `--carbide-api <url>` | `-c` | Override API URL |
| `--output <file>` | `-o` | Write output to file |
| `--extended` | | Include internal UUIDs and extra fields |
| `--sort-by <field>` | | `primary-id` (default) or `state` |
| `--debug` | `-d` | Increase log verbosity (repeat for trace) |
| `--internal-page-size N` | `-p` | Paging size for list calls (default 100) |

### Common subcommands

```bash
# List all machines
./dev/mac-local-dev/run-carbide-admin-cli.sh machine list

# Show details for a specific machine
./dev/mac-local-dev/run-carbide-admin-cli.sh machine show <machine-id>

# List OS images
./dev/mac-local-dev/run-carbide-admin-cli.sh os-image list

# List network segments
./dev/mac-local-dev/run-carbide-admin-cli.sh network-segment list

# List tenants (JSON output)
./dev/mac-local-dev/run-carbide-admin-cli.sh --format json tenant show

# Explore all available subcommands
./dev/mac-local-dev/run-carbide-admin-cli.sh --help

# Explore sub-subcommands
./dev/mac-local-dev/run-carbide-admin-cli.sh machine --help
```

### Environment variable overrides

| Variable | Default | Purpose |
|----------|---------|---------|
| `CARBIDE_API_URL` | `https://localhost:1079` | API endpoint |
| `FORGE_ROOT_CA_PATH` | `dev/certs/localhost/ca.crt` | CA used to verify the server cert |
| `CLIENT_CERT_PATH` | `dev/certs/localhost/client.crt` | mTLS client certificate |
| `CLIENT_KEY_PATH` | `dev/certs/localhost/client.key` | mTLS client key |

### Expired certificate errors

If you see `invalid peer certificate: Expired`, the certs in
`dev/certs/localhost/` need to be regenerated:

```bash
rm -f dev/certs/localhost/*.crt dev/certs/localhost/*.key
(cd dev/certs/localhost && ./gen-certs.sh)
```

Then restart `run-carbide-api.sh` (the API must load the new server cert).

> **Note:** `dev/certs/server_identity.pem` and
> `dev/certs/forge_developer_local_only_root_cert_pem` are checked-in certs
> that expired in 2023/2024.  Do **not** use them — the scripts default to the
> locally-generated `localhost/` certs instead.

---

## Running carbide-api from an IDE (RustRover / IntelliJ)

IDE setup is not complete; you may want to set
**Rust → External Linters → Additional Arguments** to `--no-default-features`.

Run `./dev/mac-local-dev/run-carbide-api.sh` once to completion, then kill it —
this ensures Vault and Postgres are initialised and the token file exists.

Retrieve the environment variables for the run configuration:

```bash
echo "CARBIDE_WEB_AUTH_TYPE=basic"
echo "DATABASE_URL=postgresql://postgres:admin@localhost"
echo "VAULT_ADDR=http://localhost:8201"
echo "VAULT_KV_MOUNT_LOCATION=secrets"
echo "VAULT_PKI_MOUNT_LOCATION=certs"
echo "VAULT_PKI_ROLE_NAME=role"
echo "VAULT_TOKEN=$(cat /tmp/carbide-localdev-vault-root-token)"
```

Cargo run parameters:

```
run --package carbide-api --no-default-features -- run
--config-path <absolute-path-to-repo>/dev/mac-local-dev/carbide-api-config.toml
```

> The config file uses CWD-relative TLS paths.  Set the IDE run configuration's
> **Working Directory** to the repository root, or use the absolute-path temp
> config that `run-carbide-api.sh` writes to `/tmp/carbide-api-config-<PID>.toml`.
