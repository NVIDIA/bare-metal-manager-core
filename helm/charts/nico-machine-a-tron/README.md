# Machine-A-Tron Helm Chart

Helm chart for deploying Machine-A-Tron - a mock machine simulator for NICo development and testing.

## Overview

Machine-A-Tron creates simulated bare-metal machines that behave like real hosts, allowing developers to:
- Test NICo without physical hardware
- Simulate multiple hosts, DPUs, switches and power shelves
- Develop and debug the full machine lifecycle

## Prerequisites

- Kubernetes 1.27+
- Helm 3.12+
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
| `machineATron.nicoApiUrl` | URL of the NICo API server | `https://nico-api.nico-system.svc.cluster.local:1079` |
| `machineATron.bmcMockPort` | Port for BMC mock service | `1266` |
| `machineATron.useSingleBmcMock` | Use header-based BMC routing (required for k8s) | `true` |
| `machineATron.cleanupOnQuit` | Delete created machines from API on quit | `false` |
| `terminationGracePeriodSeconds` | Graceful shutdown timeout | `60` |
| `machines.<name>.hostCount` | Number of mock hosts to create | `10` |
| `machines.<name>.dpuPerHostCount` | DPUs per host | `2` |
| `machines.<name>.hwType` | Hardware type to simulate | `dell_poweredge_r750` |
| `persistence.enabled` | Enable persistent storage for machine state | `false` |

### Machine Configuration

The `machines` section supports **multiple named groups** with different hardware types:

```yaml
machines:
  # Dell hosts with 2 DPUs each
  dell-hosts:
    hwType: dell_poweredge_r750
    hostCount: 10
    dpuPerHostCount: 2
    oobDhcpRelayAddress: "192.168.192.1"
    adminDhcpRelayAddress: "192.168.176.1"

  # NVIDIA DGX H100 hosts
  dgx-hosts:
    hwType: nvidia_dgx_h100
    hostCount: 5
    dpuPerHostCount: 1
    oobDhcpRelayAddress: "192.168.192.1"
    adminDhcpRelayAddress: "192.168.176.1"

  # Power shelves (no DPUs)
  power-shelves:
    hwType: liteon_power_shelf
    hostCount: 2
    dpuPerHostCount: 0
    oobDhcpRelayAddress: "192.168.192.1"
    adminDhcpRelayAddress: "192.168.176.1"
```

#### DHCP Relay Addresses

The `oobDhcpRelayAddress` and `adminDhcpRelayAddress` values tell NICo which network
segment to allocate IPs from. These must match gateway addresses of networks configured
in NICo's site config.

**Note:** All machine groups typically share the same relay addresses since they connect
to the same OOB and admin networks. The relay address is used only for network segment
matching - NICo handles IP allocation from the configured prefix.

#### NICo Network Configuration

Machine-A-Tron requires corresponding networks to be configured in NICo's
`nico-api-site-config.toml`. The relay addresses must match the gateway of these networks:

```toml
# OOB network for BMC management (matches oobDhcpRelayAddress)
[networks.oob-bmc]
type = "underlay"
prefix = "192.168.192.0/24"      # Any prefix size works (/16, /23, /24, etc.)
gateway = "192.168.192.1"        # This is the oobDhcpRelayAddress
mtu = 1500
reserve_first = 2

# Admin network for host provisioning (matches adminDhcpRelayAddress)
[networks.admin]
type = "admin"
prefix = "192.168.176.0/24"
gateway = "192.168.176.1"        # This is the adminDhcpRelayAddress
mtu = 9000
reserve_first = 5
```

NICo uses PostgreSQL's `<<=` operator to match relay addresses against configured
network prefixes, so the network size is fully configurable based on your environment.

### Hardware Types

Supported `hwType` values (from `HostHardwareType` enum in `crates/bmc-mock/src/lib.rs`):

- `dell_poweredge_r750` (default)
- `wiwynn_gb200_nvl`
- `lenovo_gb300_nvl`
- `nvidia_dgx_gb300`
- `supermicro_gb300_nvl`
- `liteon_power_shelf`
- `nvidia_switch_nd5200_ld`
- `nvidia_dgx_h100`
- `generic_ami`
- `generic_supermicro`

### NICo Site Configuration

For Machine-A-Tron to work correctly, NICo must be configured to route Redfish calls through the mock:

```toml
[site_explorer]
override_target_port = 1266
override_target_host = "nico-machine-a-tron-bmc-mock"  # k8s service name
enabled = true
create_machines = true
```

## Graceful Shutdown

The chart supports graceful shutdown when pods are deleted. This gives machine-a-tron
time to clean up resources:

```yaml
# Shutdown timeout
terminationGracePeriodSeconds: 60

machineATron:
  # Set to true to delete created machines from NICo API on shutdown
  cleanupOnQuit: true
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
