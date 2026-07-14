---
title: "NICo MCP Server"
description: "Deploy and operate the NICo MCP server, including configuration precedence and security requirements."
---

# NICo MCP Server

`nico-mcp` exposes the read-only NICo REST API surface as Model Context
Protocol (MCP) tools over streamable HTTP. It generates tools for the `GET`
operations in the embedded OpenAPI specification and does not expose REST
operations that create, update, or delete resources.

The server is stateless. It does not authenticate or authorize callers. NICo
REST validates the bearer token and enforces organization and role permissions
for every forwarded request.

## Supported Deployment Topologies

### Production: ClusterIP Alongside NICo REST

The supported production topology deploys `nico-mcp` in Kubernetes alongside
NICo REST with the Helm chart at `helm/rest/nico-mcp`. The chart creates a
`ClusterIP` Service on port `8080` and serves MCP requests at `/mcp` by default.

Configure one fixed NICo REST base URL at startup. An in-cluster Service URL is
the normal choice:

```yaml
config:
  baseURL: http://nico-rest-api:8388
  apiName: nico
```

The MCP listener is plaintext HTTP. Place an upstream service in front of it
that provides all of the following controls:

- authenticates callers and passes each caller's bearer token to `nico-mcp`;
- terminates TLS for client connections;
- routes MCP traffic to the `nico-mcp` ClusterIP Service; and
- restricts direct access to the MCP Service from untrusted networks.

The chart does not deploy these controls. Use the ingress, gateway, proxy, and
network-policy components approved for your environment.

### Standalone Development and Testing

For development and testing, build and run the binary directly against a
reachable NICo REST endpoint:

```bash
cd rest-api
make nico-mcp
nico-mcp \
  --listen 127.0.0.1:8080 \
  --path /mcp \
  --base-url https://nico.example.com \
  --org example-org
```

Keep the listener on localhost or a trusted network. If it must be reachable
from an untrusted network, put it behind the same authentication, TLS, routing,
and network controls required for production.

## Install the Helm Chart

Before installing the chart, make sure that:

- the `nico-mcp` image is available to the cluster;
- NICo REST is reachable from the target namespace; and
- the upstream authentication and TLS front is configured.

Create a values file for the deployment:

```yaml
global:
  image:
    repository: registry.example.com/nico
    tag: "2.0.0"
    pullPolicy: IfNotPresent
  imagePullSecrets:
    - name: image-pull-secret

config:
  baseURL: http://nico-rest-api:8388
  org: example-org
  apiName: nico
```

Install the chart in the NICo REST namespace:

```bash
helm upgrade --install nico-mcp helm/rest/nico-mcp \
  --namespace nico-rest \
  --create-namespace \
  --values nico-mcp-values.yaml
```

The rendered image is
`<global.image.repository>/<image.name>:<global.image.tag>`. The chart does not
create `global.imagePullSecrets`; create the referenced Secret before the
Deployment starts when the registry requires authentication.

### Chart Values

| Value | Default | Purpose |
| --- | --- | --- |
| `global.image.repository` | empty | Image registry and repository prefix. Required for deployment. |
| `global.image.tag` | empty | Image tag. Required for deployment. |
| `global.image.pullPolicy` | `IfNotPresent` | Kubernetes image pull policy. |
| `global.imagePullSecrets` | `image-pull-secret` | Existing image pull Secrets attached to the Pod. |
| `replicaCount` | `1` | Number of MCP server replicas. |
| `nameOverride` | empty | Override for the Deployment and Service name. |
| `namespaceOverride` | empty | Namespace override; otherwise the Helm release namespace is used. |
| `image.name` | `nico-mcp` | Image name appended to the repository. |
| `service.type` | `ClusterIP` | Kubernetes Service type. Keep `ClusterIP` for production. |
| `service.port` | `8080` | Listener and Service port. |
| `config.path` | `/mcp` | HTTP path for the MCP handler. |
| `config.shutdownTimeout` | `10s` | Graceful shutdown timeout. |
| `config.baseURL` | empty | Fixed default NICo REST URL. Set this in production. |
| `config.org` | empty | Default organization for tool calls. |
| `config.apiName` | empty | REST API path segment; the binary defaults to `nico`. |
| `config.debug` | `false` | Log outbound NICo REST HTTP requests and responses. |
| `resources.requests` | `50m` CPU, `64Mi` memory | Pod resource requests. |
| `resources.limits` | `250m` CPU, `256Mi` memory | Pod resource limits. |

Bearer tokens are intentionally not exposed as chart values. Shared production
deployments should use the authenticated caller's token instead of a static
service token.

## Runtime Configuration

The standalone binary accepts these startup settings. A command-line flag takes
its value from the corresponding environment variable when the flag is omitted.

| Flag | Environment variable | Default | Helm value |
| --- | --- | --- | --- |
| `--listen` | `NICO_MCP_LISTEN` | `:8080` | `service.port` sets the port |
| `--path` | `NICO_MCP_PATH` | `/mcp` | `config.path` |
| `--shutdown-timeout` | `NICO_MCP_SHUTDOWN_TIMEOUT` | `10s` | `config.shutdownTimeout` |
| `--base-url` | `NICO_BASE_URL` | none | `config.baseURL` |
| `--org` | `NICO_ORG` | none | `config.org` |
| `--api-name` | `NICO_API_NAME` | `nico` | `config.apiName` |
| `--token` | `NICO_TOKEN` | none | not exposed |
| `--debug` | none | `false` | `config.debug` |

`nico-mcp` does not read `~/.nico/config.yaml`.

Every tool accepts optional `base_url`, `org`, `api_name`, and `token`
arguments. Non-empty values are resolved for each call as follows:

| Setting | Precedence, highest first |
| --- | --- |
| `base_url` | fixed startup `--base-url` or `NICO_BASE_URL`; without a startup value, the tool argument |
| `org` | tool argument, then startup `--org` or `NICO_ORG` |
| `api_name` | tool argument, then startup `--api-name` or `NICO_API_NAME`, then `nico` |
| `token` | tool argument, inbound `Authorization: Bearer` header, then startup `--token` or `NICO_TOKEN` |

When a startup base URL is configured, a tool argument may repeat that
destination, with or without a trailing slash, but it cannot select a different
one. When no startup base URL is configured, a tool call can supply `base_url`
only with an explicit per-call `token` or with no resolved token. The server
does not combine a caller-chosen destination with an inherited inbound or
startup token.

`base_url` and `org` must resolve to non-empty values. A token can be empty,
but NICo REST normally rejects the resulting unauthenticated request.

## Security Requirements

Treat the REST destination and the bearer token as one trust decision:

- Set a fixed startup base URL for every production deployment.
- Use caller-specific bearer tokens on shared endpoints. NICo REST remains the
  authorization enforcement point.
- A configured startup base URL pins the REST destination. A different
  per-call `base_url` is rejected, including when the call supplies an explicit
  token.
- Without a startup base URL, a per-call `base_url` is allowed only when the
  call also supplies its own explicit `token`, or when the request resolves to
  no token. The server does not send an inherited inbound or startup credential
  to a caller-selected destination.
- Do not configure `NICO_TOKEN` for a shared production deployment. It is a
  common credential used whenever a caller supplies no token. Limit any
  development use of a startup token to a trusted network and a fixed base URL.
- Restrict network access even though NICo REST independently validates each
  token. The MCP endpoint provides a convenient read-only interface to every
  eligible REST `GET` operation.

### Debug Logging

`--debug` and `config.debug` log the outbound NICo REST request and response.
Sensitive header values, including `Authorization`, cookies, and API-key
headers, are redacted. URLs, request bodies, and response bodies are not
content-redacted.

NICo REST response bodies can contain inventory, configuration, and tenant
data. Protect debug logs as sensitive operational data, enable debug logging
only while diagnosing an issue, and disable it afterward.
