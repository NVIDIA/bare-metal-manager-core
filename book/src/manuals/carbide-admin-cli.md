# Carbide Admin CLI

`carbide-admin-cli` is the command-line tool for managing a Carbide site. It communicates with
`carbide-api` over gRPC with mutual TLS (mTLS).

## Building

From the repository root:

```sh
# Debug build (faster compile, larger binary)
cargo build -p carbide-admin-cli

# Release build (optimized, for deployment)
cargo build -p carbide-admin-cli --release
```

The binary is written to:

- `target/debug/carbide-admin-cli` (debug)
- `target/release/carbide-admin-cli` (release)

## Connecting to carbide-api

The CLI needs three things to connect:

1. **API URL** -- where carbide-api is listening
2. **Root CA certificate** -- to verify the server's TLS certificate
3. **Client certificate + key** -- to authenticate this client to the server

### TLS options

| Flag | Environment variable | Config file key | Description |
|------|---------------------|-----------------|-------------|
| `-c` / `--carbide-api` | `CARBIDE_API_URL` | `carbide_api_url` | carbide-api URL |
| `--forge-root-ca-path` | `FORGE_ROOT_CA_PATH` | `forge_root_ca_path` | Root CA cert (PEM) used to verify the server |
| `--client-cert-path` | `CLIENT_CERT_PATH` | `client_cert_path` | Client certificate (PEM) |
| `--client-key-path` | `CLIENT_KEY_PATH` | `client_key_path` | Client private key (PEM) |

### Config file

Instead of passing flags every time, create
`$HOME/.config/carbide_api_cli.json`:

```json
{
  "carbide_api_url": "https://carbide-api.example.com:1079",
  "forge_root_ca_path": "/etc/carbide/certs/ca.crt",
  "client_cert_path": "/etc/carbide/certs/client.crt",
  "client_key_path": "/etc/carbide/certs/client.key"
}
```

### Example invocations

```sh
# Explicit flags
carbide-admin-cli \
  -c https://carbide-api.example.com:1079 \
  --forge-root-ca-path /etc/carbide/certs/ca.crt \
  --client-cert-path /etc/carbide/certs/client.crt \
  --client-key-path /etc/carbide/certs/client.key \
  version

# With config file (no flags needed)
carbide-admin-cli version
```

### SOCKS5 proxy support

If the CLI needs to reach carbide-api through a SOCKS5 proxy, set one
of: `http_proxy`, `https_proxy`, `HTTP_PROXY`, or `HTTPS_PROXY`. Only
the `socks5://` scheme is supported.

## Generating client certificates

carbide-api uses mTLS: the server verifies the client's certificate
against a trusted CA.

### Creating an admin CA and client cert with OpenSSL

The following creates a self-contained CA and client certificate. In
production you would typically use your organization's existing PKI
instead of a self-signed CA.

```sh
# 1. Generate the CA key and self-signed certificate
openssl ecparam -name prime256v1 -genkey -noout -out admin-ca.key
openssl req -x509 -new -key admin-ca.key -sha256 -days 3650 \
  -out admin-ca.crt \
  -subj "/O=ExampleCo/CN=ExampleCo Carbide Admin CA"

# 2. Generate a client key
openssl ecparam -name prime256v1 -genkey -noout -out client.key

# 3. Create a CSR with operator identity in the subject
#    - O  = organization (matched by required_equals if configured)
#    - OU = group (used for role-based authorization via group_from)
#    - CN = username (used for audit logging via username_from)
openssl req -new -key client.key -out client.csr \
  -subj "/O=ExampleCo/OU=site-admins/CN=jdoe"

# 4. Create an extensions file for clientAuth
cat > client_ext.cnf <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

# 5. Sign the client certificate with the CA
openssl x509 -req -in client.csr \
  -CA admin-ca.crt -CAkey admin-ca.key -CAcreateserial \
  -out client.crt -days 365 -sha256 \
  -extfile client_ext.cnf

# 6. Clean up intermediate files
rm -f client.csr client_ext.cnf admin-ca.srl
```

This produces:

| File | Purpose |
|------|---------|
| `admin-ca.crt` | Root CA -- configure as `admin_root_cafile_path` in carbide-api |
| `admin-ca.key` | CA private key -- keep offline/secured |
| `client.crt` | Operator's client certificate |
| `client.key` | Operator's client private key |

### Certificate subject fields and how they map to authorization

The `[auth.cli_certs]` section in `carbide-api-config.toml` controls how
certificate fields are interpreted:

| Config key | Purpose | Example |
|------------|---------|---------|
| `required_equals` | Issuer/subject fields that **must** match exactly for the cert to be accepted | `{ "IssuerO" = "ExampleCo", "IssuerCN" = "ExampleCo Carbide Admin CA" }` |
| `group_from` | Which cert field to extract the authorization group from | `"SubjectOU"` |
| `username_from` | Which cert field to extract the username from (for audit trails) | `"SubjectCN"` |
| `username` | Fixed username for all certs of this type (alternative to `username_from`) | `"shared-admin"` |

The available `CertComponent` values are:

- `IssuerO`, `IssuerOU`, `IssuerCN` -- from the certificate issuer
- `SubjectO`, `SubjectOU`, `SubjectCN` -- from the certificate subject

## Server-side configuration (carbide-api)

### TLS section

The `[tls]` section of `carbide-api-config.toml` tells carbide-api
where to find its own server certificate and which CAs to trust for
client authentication:

```toml
[tls]
identity_pemfile_path = "/path/to/server.crt"
identity_keyfile_path = "/path/to/server.key"
root_cafile_path = "/path/to/internal-ca.crt"
admin_root_cafile_path = "/path/to/admin-ca.crt"
```

| Key | Description |
|-----|-------------|
| `identity_pemfile_path` | Server's own TLS certificate (PEM) |
| `identity_keyfile_path` | Server's private key (PEM) |
| `root_cafile_path` | CA used to verify internal client certs |
| `admin_root_cafile_path` | CA used to verify external admin client certs |

carbide-api loads both `root_cafile_path` and `admin_root_cafile_path`
into its TLS trust store. A client presenting a certificate signed by
either CA will pass the TLS handshake. 

### Configuring authorization

Authorization is configured in the `[auth]` section of
`carbide-api-config.toml`.

#### Casbin policy

carbide-api uses [Casbin](https://casbin.org/) with an RBAC model for
authorization. The model is compiled into the binary and uses two rule
types:

- **`g` (grouping) rules** -- map a principal identifier to a role name
- **`p` (policy) rules** -- allow a principal or role to call a gRPC
  method (glob matching is supported on the method name)

The policy file is a CSV referenced by `casbin_policy_file`:

```toml
[auth]
permissive_mode = false
casbin_policy_file = "/path/to/casbin-policy.csv"
```

##### How principals are identified

| Certificate type | Principal identifier format | Example |
|-----------------|---------------------------|---------|
| External admin cert | `external-role/<group>` | `external-role/site-admins` |
| Any trusted cert | `trusted-certificate` | |
| No cert | `anonymous` | |

The `<group>` in `external-role/<group>` comes from the certificate
field specified by `group_from` in `[auth.cli_certs]`.

##### Writing policy rules

Sample policy file:

```csv
# On `g` rules: These associate a principal (second column) with a role name
# (third column). This causes the named role to also be looked up as if it were
# a principal.
#
# On `p` rules: These allow a principal or role (second column) to perform the
# named action (third column). Glob matching is available on the action field.
#


# Map the carbide-dhcp SPIFFE ID to the carbide-dhcp role.
# FIXME: verify that this is how these SPIFFE service identifiers look in reality.
g, spiffe-service-id/carbide-dhcp, carbide-dhcp
g, spiffe-service-id/carbide-dns, carbide-dns
g, spiffe-machine-id, machine

# Allow the carbide-dhcp role to call its methods.
p, carbide-dhcp, forge/DiscoverDhcp

# Same idea for carbide-dns.
p, carbide-dns, forge/LookupRecord

# Anonymous access to endpoints that don't modify state or expose any customer
# or site data should be fine.
p, anonymous, forge/Version

# Allow anonymous access to methods used by machines that may not have their
# certificates from us yet.
p, anonymous, forge/DiscoverMachine
p, anonymous, forge/ReportForgeScoutError
p, anonymous, forge/AttestQuote

# Allow anonymous access to methods used by dpu-agent. As of 2023-09-28 there
# are probably a fair amount of agents across the environments that don't have a
# certificate and are not ready for strict enforcement.
p, anonymous, forge/FindInstanceByMachineID
p, anonymous, forge/GetManagedHostNetworkConfig
p, anonymous, forge/RecordDpuNetworkStatus

# The client cert generated above has OU=site-admins in its subject.
# With group_from = "SubjectOU" in [auth.cli_certs], that becomes the
# principal "external-role/site-admins". Map it to a role and grant access.
g, external-role/site-admins, site-admin
p, site-admin, forge/*

# Example of a restricted role: a cert with OU=viewers would only get
# read access to a handful of methods.
g, external-role/viewers, viewer
p, viewer, forge/Version
p, viewer, forge/GetMachine
p, viewer, forge/ListMachines
p, viewer, forge/GetInstance
p, viewer, forge/ListInstances


# Allow any certificate we trust to hit any Forge method.
# FIXME: This should be removed once we have more fine-grained rule coverage.
p, trusted-certificate, forge/*
```

The method names in the `forge/<Method>` column correspond to the gRPC
method names defined in the protobuf service definitions. Glob matching
(`*`) is supported.

##### Full example: carbide-api config with external admin certs

```toml
[tls]
identity_pemfile_path = "/path/to/server.crt"
identity_keyfile_path = "/path/to/server.key"
root_cafile_path = "/path/to/internal-ca.crt"
admin_root_cafile_path = "/path/to/admin-ca.crt"

[auth]
permissive_mode = false
casbin_policy_file = "/path/to/casbin-policy.csv"

[auth.cli_certs]
required_equals = { "IssuerO" = "ExampleCo", "IssuerCN" = "ExampleCo Carbide Admin CA" }
group_from = "SubjectOU"
username_from = "SubjectCN"

[auth.trust]
spiffe_trust_domain = "forge.local"
spiffe_service_base_paths = [
  "/forge-system/sa/",
  "/default/sa/",
  "/elektra-site-agent/sa/",
]
spiffe_machine_base_path = "/forge-system/machine/"
additional_issuer_cns = []
```

With this configuration, a client certificate with subject
`/O=ExampleCo/OU=site-admins/CN=jdoe` and issuer
`/O=ExampleCo/CN=ExampleCo Carbide Admin CA` would:

1. Pass the `required_equals` check (IssuerO and IssuerCN match)
2. Be assigned group `site-admins` (from SubjectOU)
3. Be identified as user `jdoe` (from SubjectCN)
4. Receive the principal `external-role/site-admins`
5. Be authorized according to whatever casbin policy rules match that
   principal


You can see an example of a complete carbide-api configuration file 
[here](https://github.com/NVIDIA/ncx-infra-controller-core/blob/main/crates/api/src/cfg/test_data/full_config.toml)

### Permissive mode

Setting `permissive_mode = true` in the `[auth]` section causes the
authorization engine to **allow all requests**, even when the casbin
policy would deny them. Denied requests are logged with a warning
instead of being rejected:

```toml
[auth]
permissive_mode = true
```

When permissive mode is active, carbide-api logs messages like:

```
WARN The policy engine denied this request, but --auth-permissive-mode overrides it.
```

**Use permissive mode only for:**

- Initial deployment and bring-up, before certificates are fully
  configured
- Debugging authorization issues (enable temporarily, check logs, then
  disable)
- Development environments

**Do not leave permissive mode enabled in production.** It bypasses all
authorization checks. Any client that can complete the TLS handshake
(or any client at all, if TLS is also disabled) can call any API method.

You can also set permissive mode via environment variable without
editing the config file:

```sh
CARBIDE_API_AUTH="{permissive_mode=true}"
```
