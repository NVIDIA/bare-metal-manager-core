# NICo Helm Chart

NCX Infra Controller (NICo) -- Kubernetes Deployment

## Overview

NICo (also known as NCX Infra Controller) is a platform for provisioning, managing, and monitoring bare metal GPU servers, including DGX and HGX systems. This Helm chart deploys NICo services into a Kubernetes cluster as a single umbrella chart with independently toggleable subcharts.

The chart is designed for production environments where NICo manages the full lifecycle of bare metal infrastructure: DHCP/PXE-based OS provisioning, DNS resolution, hardware health monitoring, SSH console access, and a unified REST/gRPC API.

## Subcharts

| # | Subchart | Description |
|---|----------|-------------|
| 1 | **nico-api** | Core API server (gRPC + REST). Manages machines, provisioning, networking, and firmware. Requires PostgreSQL and Vault. |
| 2 | **nico-bmc-proxy** | Authenticating proxy for connecting to BMC's over HTTPS (redfish) |
| 2 | **nico-dhcp** | DHCP server (Kea-based) for bare metal PXE boot and network assignment. |
| 3 | **nico-dns** | Authoritative DNS server for managed machines and VPCs. |
| 4 | **nico-dsx-exchange-consumer** | Consumes DSX exchange messages for machine telemetry and state updates. |
| 5 | **nico-hardware-health** | Collects and reports hardware health metrics from managed machines. |
| 6 | **nico-pxe** | PXE boot server (HTTP-based) for OS provisioning workflows. |
| 7 | **nico-ssh-console-rs** | SSH console proxy for remote access to managed machine BMCs and consoles. |
| 8 | **unbound** | Recursive DNS resolver forwarding queries for managed infrastructure. Disabled by default. |

## Prerequisites

- **Kubernetes** 1.27+
- **Helm** 3.12+
- **cert-manager** with a `ClusterIssuer` configured (default issuer name: `vault-nico-issuer`)
- **HashiCorp Vault** for PKI certificate issuance and secret storage
- **PostgreSQL** (SSL-enabled) for the `nico-api` database backend
- **Prometheus Operator CRDs** if you enable `ServiceMonitor` resources
- **Required Kubernetes Secrets and ConfigMaps** (Vault tokens, database credentials, SSO secrets, etc.)

For the full list of required secrets, ConfigMaps, and infrastructure setup steps, see [PREREQUISITES.md](./PREREQUISITES.md).

## Quick Start

```bash
helm upgrade --install nico ./helm \
  --namespace forge-system --create-namespace \
  --set global.image.repository=<your-registry>/nico-core \
  --set global.image.tag=<version>
```

To verify the deployment:

```bash
kubectl get pods -n forge-system
kubectl get svc -n forge-system
```

## Configuration

### Global Values

Top-level `global:` values are automatically passed to all subcharts.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `global.image.repository` | Container image repository (**REQUIRED**) | `""` |
| `global.image.tag` | Container image tag (**REQUIRED**) | `""` |
| `global.image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `global.imagePullSecrets` | Image pull secrets | `[]` |
| `global.certificate.duration` | Certificate validity period | `720h0m0s` |
| `global.certificate.renewBefore` | Renew certificates before expiry | `360h0m0s` |
| `global.certificate.privateKey.algorithm` | Certificate private key algorithm | `ECDSA` |
| `global.certificate.privateKey.size` | Certificate private key size | `384` |
| `global.certificate.issuerRef.name` | cert-manager ClusterIssuer name | `vault-nico-issuer` |
| `global.certificate.issuerRef.kind` | cert-manager issuer kind | `ClusterIssuer` |
| `global.certificate.issuerRef.group` | cert-manager issuer API group | `cert-manager.io` |
| `global.spiffe.trustDomain` | SPIFFE trust domain for mTLS | `nico.local` |
| `global.labels` | Common labels applied to all resources | See `values.yaml` |

### Subchart Enable/Disable Flags

Each subchart can be independently enabled or disabled. All core NICo services are enabled by default. Infrastructure services (`unbound`) that may already be provided by the environment are disabled by default.

```yaml
nico-api:
  enabled: true        # Core API -- usually always enabled
nico-dhcp:
  enabled: true        # DHCP for PXE boot
nico-dns:
  enabled: true        # Authoritative DNS
nico-dsx-exchange-consumer:
  enabled: true        # DSX exchange telemetry consumer
nico-hardware-health:
  enabled: true        # Hardware health monitoring
nico-pxe:
  enabled: true        # PXE boot server
nico-ssh-console-rs:
  enabled: true        # SSH console proxy
unbound:
  enabled: false       # Recursive DNS resolver (disabled by default)
```

### Image Configuration

The `global.image.repository` and `global.image.tag` values **must** be set -- they default to empty strings. Most subcharts use the global image reference. The following subcharts use their own separate image references and do **not** inherit `global.image`:

| Subchart | Image Parameter | Default |
|----------|----------------|---------|
| `nico-ssh-console-rs` (log collector) | `nico-ssh-console-rs.lokiLogCollector.image.repository` / `.tag` | `""` — sidecar disabled by default (`lokiLogCollector.enabled: false`); reference image: `ghcr.io/open-telemetry/opentelemetry-collector-releases/opentelemetry-collector-contrib:0.81.0` |
| `unbound` | `unbound.image.repository` / `.tag` | `""` (must be set) |
| `unbound` (exporter) | `unbound.exporterImage.repository` / `.tag` | `""` (must be set) |

### OAuth2 / SSO Setup

To enable OAuth2 authentication (for example, Azure AD or Okta), configure the `nico-api.extraEnv` values:

```yaml
nico-api:
  extraEnv:
    - name: CARBIDE_WEB_AUTH_TYPE
      value: "oauth2"
    - name: CARBIDE_WEB_OAUTH2_AUTH_ENDPOINT
      value: "https://your-idp/authorize"
    - name: CARBIDE_WEB_OAUTH2_TOKEN_ENDPOINT
      value: "https://your-idp/token"
    - name: CARBIDE_WEB_OAUTH2_CLIENT_ID
      value: "your-client-id"
    - name: CARBIDE_WEB_ALLOWED_ACCESS_GROUPS
      value: "group1,group2"
    - name: CARBIDE_WEB_OAUTH2_CLIENT_SECRET
      valueFrom:
        secretKeyRef:
          name: your-sso-secret
          key: client_secret
```

The `extraEnv` array supports any Kubernetes `env` spec, including `valueFrom` references to Secrets and ConfigMaps.

### External LoadBalancer Services

Several services support optional external LoadBalancer exposure, typically used with MetalLB on bare metal clusters. Enable and configure them per subchart:

```yaml
nico-api:
  externalService:
    enabled: true
    type: LoadBalancer
    externalTrafficPolicy: Local
    annotations:
      metallb.universe.tf/loadBalancerIPs: "10.x.x.x"
```

Services with external LoadBalancer support: `nico-api`, `nico-dhcp`, `nico-dns`, `nico-pxe`, and `nico-ssh-console-rs`.

For StatefulSet-based services (`nico-dns`), per-pod LoadBalancer IPs can be assigned:

```yaml
nico-dns:
  externalService:
    enabled: true
    perPodAnnotations:
      - metallb.universe.tf/loadBalancerIPs: "10.x.x.1"   # pod-0
      - metallb.universe.tf/loadBalancerIPs: "10.x.x.2"   # pod-1
```

## Architecture

### Workload Summary

| Subchart | Workload Type | Primary Port(s) | TLS Certificate | Metrics |
|----------|--------------|-----------------|-----------------|---------|
| nico-api | Deployment | 1079 (gRPC), 1080 (metrics), 1081 (profiler) | Yes | ServiceMonitor |
| nico-bmc-proxy | Deployment | 1079 (gRPC), 1080 (metrics) | Yes | ServiceMonitor |
| nico-dhcp | Deployment | 67/UDP, 1089 (metrics) | Yes | ServiceMonitor |
| nico-dns | StatefulSet | 53/TCP, 53/UDP | Yes | -- |
| nico-dsx-exchange-consumer | Deployment | 9009 | Yes | ServiceMonitor |
| nico-hardware-health | Deployment | 9009 (`/metrics`, `/telemetry`) | Yes | ServiceMonitor; optional telemetry ServiceMonitor (sensor data, off by default) |
| nico-pxe | Deployment | 8080 | Yes | ServiceMonitor |
| nico-ssh-console-rs | Deployment | 22, 9009 (metrics) | Yes | ServiceMonitor |
| unbound | Deployment | 53 | No | ServiceMonitor |

### Service Dependencies

```
                         +------------------+
                         |   nico-api    |  <-- PostgreSQL, Vault
                         +--------+---------+
                                  |
          +-----------+-----------+-----------+-----------+
          |           |           |           |           |
    nico-dhcp  nico-dns  nico-pxe  nico-ssh-console-rs  unbound (optional)
          |                       |                                      |
          v                       v                                      v
     Bare Metal            Bare Metal                              Upstream DNS
     (PXE boot)            (OS install)
```

All services that communicate with `nico-api` use mTLS via SPIFFE-based certificates issued by cert-manager and backed by Vault PKI.

## Examples

For reference configurations, see:

- [`examples/values-minimal.yaml`](./examples/values-minimal.yaml) -- Minimal deployment with only the core services
- [`examples/values-full.yaml`](./examples/values-full.yaml) -- Full deployment with all services and production settings

## Migrating from Kustomize

This Helm chart supersedes the Kustomize-based deployment previously located in `deploy/`. The mapping is straightforward:

- Each Kustomize component maps to a subchart with the same name.
- Base resources (Deployments, Services, ConfigMaps) are now templated within each subchart.
- Environment-specific configuration that was previously managed through Kustomize overlays should be provided via Helm values overrides (`-f values-myenv.yaml` or `--set` flags).
- ConfigMap generators in Kustomize are replaced by `config:` sections in each subchart's values, with the option to provide external ConfigMaps instead (`config.enabled: false`).

## Upgrading

```bash
helm upgrade nico ./helm \
  --namespace forge-system \
  -f values-production.yaml
```

Review changes before applying:

```bash
helm diff upgrade nico ./helm \
  --namespace forge-system \
  -f values-production.yaml
```

## Uninstalling

```bash
helm uninstall nico --namespace forge-system
```

Note that PersistentVolumeClaims, Secrets, and ConfigMaps created outside of Helm (by operators, Vault, or database controllers) are not removed by `helm uninstall`.

## License

Apache-2.0
