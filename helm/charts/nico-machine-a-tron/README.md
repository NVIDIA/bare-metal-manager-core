# Machine-A-Tron Helm Chart

Helm chart for deploying Machine-A-Tron - a mock machine simulator for NICo development and testing.

## Overview

Machine-A-Tron creates simulated bare-metal machines that behave like real hosts, allowing developers to:
- Test NICo without physical hardware
- Simulate multiple hosts, DPUs, switches and power shelves
- Develop and debug the full machine lifecycle

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+
- cert-manager for TLS certificate management
- NICo API server deployed and accessible

## Installation

```bash
# Install with default values
helm install machine-a-tron ./helm/charts/nico-machine-a-tron

# Install with custom values, eg. with 10 hosts, 2 DPUs each
helm install machine-a-tron ./helm/charts/nico-machine-a-tron \
  --set machines.config.hostCount=10 \
  --set machines.config.dpuPerHostCount=2

# Install with a values file
helm install machine-a-tron ./helm/charts/nico-machine-a-tron -f my-values.yaml
```

## Configuration

### Key Configuration Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `machineATron.nicoApiUrl` | URL of the NICo API server | `https://nico-api:443` |
| `machineATron.bmcMockPort` | Port for BMC mock service | `2000` |
| `machineATron.useSingleBmcMock` | Use header-based BMC routing (required for k8s) | `true` |
| `machineATron.usePxeApi` | Use PXE API instead of direct server | `true` |
| `machines.config.hostCount` | Number of mock hosts to create | `3` |
| `machines.config.dpuPerHostCount` | DPUs per host | `1` |
| `machines.config.vpcCount` | Number of VPCs to create | `0` |
| `persistence.enabled` | Enable persistent storage for machine state | `false` |

### Machine Configuration

The `machines` section supports **multiple named groups** with different hardware types:

```yaml
machines:
  # Remove default section if not needed
  config: null
  
  # Dell hosts with 2 DPUs each
  dell-hosts:
    hwType: DellR760XA
    hostCount: 10
    dpuPerHostCount: 2
    oobDhcpRelayAddress: "192.168.192.1"
    adminDhcpRelayAddress: "192.168.176.1"
  
  # Gigabyte hosts with 1 DPU each  
  gigabyte-hosts:
    hwType: GigabyteG493
    hostCount: 5
    dpuPerHostCount: 1
    oobDhcpRelayAddress: "192.168.192.1"
    adminDhcpRelayAddress: "192.168.176.1"
  
  # Power shelves (no DPUs)
  power-shelves:
    hwType: LiteOnPowerShelf
    hostCount: 2
    dpuPerHostCount: 0
    oobDhcpRelayAddress: "192.168.192.1"
    adminDhcpRelayAddress: "192.168.176.1"
```

### Hardware Types

Supported `hwType` values:
- `DellR760XA` (default)
- `DellR760`
- `GigabyteG493`
- `LiteOnPowerShelf`
- `NvidiaSwitchNd5200Ld`

### NICo Site Configuration

For Machine-A-Tron to work correctly, NICo must be configured to route Redfish calls through the mock:

```toml
[site_explorer]
override_target_port = 2000
override_target_host = "nico-machine-a-tron"  # k8s service name
enabled = true
create_machines = true
```

## Persistence

Enable persistence to preserve machine state across pod restarts:

```yaml
persistence:
  enabled: true
  storageClass: "standard"
  size: 1Gi
```

## External Access

To expose the BMC mock externally (eg. for local development):

```yaml
externalService:
  enabled: true
  type: LoadBalancer
```

## Monitoring

Enable Prometheus ServiceMonitor:

```yaml
serviceMonitor:
  enabled: true
  interval: 30s
```
