# carbide-bmc-proxy Helm Chart

This chart deploys `carbide-bmc-proxy` and renders its main TOML config into the
`carbide-bmc-proxy-config-files` ConfigMap.

## Configuring ACLs

The proxy authorizes requests with the `[auth.acls]` section in `carbide-bmc-proxy.toml`.
That section maps a caller principal such as `spiffe-service-id/nv-dps` to an ordered list
of ACL entries.

By default the chart ships a baseline config at
[`files/carbide-bmc-proxy.toml`](files/carbide-bmc-proxy.toml). To replace it from Helm values,
set `configFiles.carbideBmcProxyConfig` to the full TOML contents:

```yaml
configFiles:
  carbideBmcProxyConfig: |
    listen = "[::]:1079"
    metrics_endpoint = "[::]:1080"
    database_url = "postgres://replaced-by-env-var"
    allowed_principals = ["spiffe-service-id/carbide-api", "spiffe-service-id/nv-dps"]

    [tls]
    identity_pemfile_path = "/var/run/secrets/spiffe.io/tls.crt"
    identity_keyfile_path = "/var/run/secrets/spiffe.io/tls.key"
    root_cafile_path = "/var/run/secrets/spiffe.io/ca.crt"
    admin_root_cafile_path = "/etc/forge/carbide-bmc-proxy/site/admin_root_cert_pem"

    [auth.trust]
    spiffe_trust_domain = "forge.local"
    spiffe_service_base_paths = ["/forge-system/sa/", "/default/sa/"]
    spiffe_machine_base_path = "/forge-system/machine/"
    additional_issuer_cns = []

    [auth.acls]
    "spiffe-service-id/carbide-api" = ["/**"]
    "spiffe-service-id/nv-dps" = [
      "GET /redfish/v1",
      "GET,POST /redfish/v1/Managers/BMC/NodeManager/Domains",
      "GET,PATCH,DELETE /redfish/v1/Managers/BMC/NodeManager/Domains/*",
    ]
```

## ACL Entry Format

Each ACL entry is a string:

```text
[!]VERB[,VERB...] /path/pattern
```

Examples:

- `"/**"`
- `"GET /redfish/v1/**"`
- `"GET,POST /redfish/v1/Managers/BMC/NodeManager/Domains"`
- `"!POST,PATCH /redfish/v1/Systems/*/SecureBoot/**"`

Semantics:

- The leading `!` makes the rule a deny rule.
- If the verb list is omitted, the rule matches any method.
- Rules are evaluated in order and the first match wins.
- If no rule matches, access is denied.

Path wildcards:

- `*` matches exactly one path component.
- `prefix*` matches one path component with the given prefix.
- `*suffix` matches one path component with the given suffix.
- `**` matches zero or more path components.
- A single `*` may be the whole component, or appear at the beginning or end.
- `foo*bar` is not valid.
- Only one `**` is allowed per path pattern.

When converting Redfish-style documented endpoints to ACLs, replace templated path components
like `{id}` or `{session_id}` with `*`.
