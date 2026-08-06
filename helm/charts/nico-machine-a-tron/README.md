# Machine-A-Tron Helm Chart

Helm chart for deploying Machine-A-Tron - a mock machine simulator for NICo testing.

## Overview

Machine-A-Tron creates simulated bare-metal machines that behave like real hosts,
allowing you to:

- Test NICo without physical hardware
- Simulate multiple hosts, DPUs, switches and power shelves
- Perform load testing at scale (multiple pods, thousands of BMCs)
- Run simulations alongside real hardware

## Namespace Configuration

Use `global.namespaceOverride` to deploy into a specific namespace:

```bash
helm upgrade --install mat ./helm/charts/nico-machine-a-tron \
  --set global.namespaceOverride=nico-system \
  --set createNamespace=true
```

When `mat-k8s-controller` is enabled, it always deploys into the same namespace
as nico-machine-a-tron. The controller does not support a separate namespace.

## Deployment Modes

| Mode | Use Case | Real HW Compatible | Network Setup |
|------|----------|--------------------|---------------|
| **Override Mode** | Development | No | Simple - single endpoint |
| **Controller Mode** | Scale testing | Yes | Per-BMC ClusterIP (controller-managed) |

**Default:** Override Mode (controller disabled, single pod).

---

## Mode 1: Override Mode (Development)

**Use for development environments where only simulated machines are needed.**

NICo's Site-Explorer is configured to redirect ALL Redfish calls to machine-a-tron.
Simple but **incompatible with real hardware**.

### Setup

```bash
helm upgrade --install nico ./helm \
  --set global.namespaceOverride=nico-system \
  --set nico-machine-a-tron.enabled=true \
  --set nico-machine-a-tron.pods.default.machines.rack-machines.hostCount=10 \
  --set nico-machine-a-tron.pods.default.machines.rack-machines.dpuPerHostCount=2
```

**NICo Site Config:**

```toml
[site_explorer]
bmc_proxy = "nico-machine-a-tron-bmc-mock.nico-system.svc.cluster.local:1266"
```

The port defaults to 1266 and must match the `service.bmcMock.port` value if
you customize it. Use the cross-namespace FQDN when machine-a-tron runs outside
the nico-api namespace.

---

## Mode 2: Controller Mode (Scale Testing)

**Use for dynamic service management in multi-pod deployments.**

The `mat-k8s-controller` watches machine-a-tron's `/machines/status` API and
dynamically creates/updates/deletes Kubernetes Services as machines come online.

### Features

- Dynamic service creation/deletion
- No CIDR planning required per pod
- Auto-reconciles on machine changes
- Automatic stale service cleanup
- OwnerReference garbage collection on Helm uninstall

### Setup

All pods can share the same `oobDhcpRelayAddress` - NICo assigns unique IPs
from the subnet.

```yaml
# values.yaml
global:
  namespaceOverride: nico-system  # Deploy to nico-system namespace

pods:
  default: null  # Disable default pod
  mat-0:
    machines:
      rack-machines:
        hwType: wiwynn_gb200_nvl
        hostCount: 5
        dpuPerHostCount: 2
        oobDhcpRelayAddress: "10.96.64.1"  # All pods share same relay
        adminDhcpRelayAddress: "192.168.176.1"
  mat-1:
    machines:
      rack-machines:
        hwType: wiwynn_gb200_nvl
        hostCount: 5
        dpuPerHostCount: 2
        oobDhcpRelayAddress: "10.96.64.1"
        adminDhcpRelayAddress: "192.168.176.1"

macAddressPool:
  enabled: true

mat-k8s-controller:
  enabled: true
  config:
    insecureSkipVerify: true  # For self-signed certs in dev
```

### How It Works

1. Controller discovers machine-a-tron pods via
   `nvidia-infra-controller/mat-service=true` label
2. Polls `/machines/status` from each discovered machine-a-tron instance
3. Creates Services with BMC IP as ClusterIP
4. Services route traffic to correct pod via `nvidia-infra-controller/pod-name`
   selector
5. Deletes stale Services when machines disappear

### Service Structure

Each created Service has an ownerReference to the machine-a-tron Deployment it
routes traffic to, enabling automatic garbage collection when that Deployment
is deleted (e.g., when a pod is removed from Helm values or the release is uninstalled):

```yaml
apiVersion: v1
kind: Service
metadata:
  name: mat-bmc-host-abc123def456
  labels:
    app.kubernetes.io/managed-by: mat-k8s-controller
    nvidia-infra-controller/mat-machine-type: host
  annotations:
    nvidia-infra-controller/mat-id: "uuid-..."
    nvidia-infra-controller/mat-bmc-ip: "10.96.64.5"
    nvidia-infra-controller/mat-hardware-type: wiwynn_gb200_nvl
  ownerReferences:
  - apiVersion: apps/v1
    kind: Deployment
    name: nico-machine-a-tron-mat-0  # The mat pod this Service routes to
    uid: <deployment-uid>
spec:
  type: ClusterIP
  clusterIP: 10.96.64.5  # BMC IP assigned by NICo
  ports:
  - name: redfish
    port: 443
    targetPort: 1266  # Redfish listen port from machine-a-tron (default: service.bmcMock.port)
    protocol: TCP
  - name: ipmi        # Only present when IPMI simulation is enabled and BMC reports bmc.ipmi
    port: 623
    targetPort: 16023  # IPMI listen port from machine-a-tron
    protocol: UDP
  selector:
    app.kubernetes.io/name: nico-machine-a-tron
    nvidia-infra-controller/pod-name: mat-0
```

The `targetPort` is the Redfish listen port reported by machine-a-tron, which
defaults to the configured `service.bmcMock.port` (1266). When IPMI simulation
is enabled and the BMC reports `bmc.ipmi` in its status, the controller also
adds a dynamic target UDP port for IPMI access.

### Requirements

- `oobDhcpRelayAddress` must be within Kubernetes ServiceCIDR
- NICo assigns unique BMC IPs from the configured network
- Default ServiceCIDR ranges:
  - `10.96.0.0/12` - vanilla Kubernetes (kubeadm)
  - `10.96.0.0/16` - KinD
  - `10.43.0.0/16` - K3s
- Check with: `kubectl cluster-info dump | grep service-cluster-ip-range`

### NICo Configuration

Add the BMC network and enable insecure discovery in NICo siteConfig:

```toml
# Required: machine-a-tron submits discovery for many IPs from a single pod
allow_insecure_discovery = true

# Network for all machine-a-tron BMCs
[networks.MAT-BMC-SERVICES]
type = "underlay"
prefix = "10.96.64.0/18"
gateway = "10.96.64.1"
mtu = 1500
```

### Monitoring

```bash
# Check controller logs
kubectl -n nico-system logs -l app.kubernetes.io/name=mat-k8s-controller -f

# List controller-created services
kubectl -n nico-system get svc -l app.kubernetes.io/managed-by=mat-k8s-controller

# Check reconciliation stats
kubectl -n nico-system logs -l app.kubernetes.io/name=mat-k8s-controller | \
grep "reconciliation complete"
```

---

## Configuration Reference

### Pod Configuration

```yaml
pods:
  <pod-name>:
    machines:
      <group-name>:
        hwType: wiwynn_gb200_nvl
        hostCount: 10
        dpuPerHostCount: 2
        oobDhcpRelayAddress: "10.96.64.1"
        adminDhcpRelayAddress: "192.168.176.1"
```

### IPMI/SOL Simulation

Enable IPMI/SOL simulation to expose per-BMC IPMI endpoints for IPMI-capable
mocked BMCs. This is optional and only affects BMCs that support IPMI (not all
hardware types have IPMI support).

```yaml
machineATron:
  enableIpmiSimulation: true
```

When enabled:

1. Machine-a-tron starts an independent IPMI simulator (`ipmi_sim`) for each
   IPMI-capable host BMC
2. The `/machines/status` API reports `bmc.ipmi` with `reachable_port` and
   `listen_port` for each BMC with IPMI enabled
3. The `mat-k8s-controller` creates UDP Service ports for IPMI access alongside
   the existing TCP Redfish port

**Requirements:**

- The machine-a-tron container image must include `ipmi_sim` (from `openipmi-utils`)
  and `ipmitool` - these are included in the standard image
- Only IPMI-capable hardware types will expose IPMI endpoints

### MAC Address Pool Configuration

Each pod needs unique MAC addresses to avoid collisions in multi-pod deployments.
By default, the chart auto-generates unique MAC pools per pod based on pod index.

```yaml
macAddressPool:
  enabled: true
  basePrefix: "02:00"
  hostBits: 16

hwMacAddressRanges:
  enabled: true
  basePrefix: "02:01"
  hostBits: 24
  rangeHostBits: 8
```

### Persistence

Persistence is disabled by default. Enable it when machine-a-tron runs alongside
a long-lived NICo database:

```yaml
persistence:
  enabled: true
  size: 1Gi
  accessModes:
    - ReadWriteOnce
  storageClass: ""
```

The shown `size`, `accessModes`, and `storageClass` values are the chart
defaults. `size` accepts a Kubernetes storage quantity, and `accessModes`
accepts Kubernetes PersistentVolumeClaim access modes supported by the selected
storage. Set `storageClass` to a StorageClass name to request that class. When
it is empty, the chart omits `storageClassName`; the cluster then uses its
default StorageClass. The cluster must provide a default or explicitly selected
StorageClass capable of satisfying the request, or an eligible pre-provisioned
PersistentVolume.

The chart creates one PersistentVolumeClaim for each configured `pods` entry
that contains at least one machine group. It mounts the claim at
`machineATron.persistDir`, which defaults to `/tmp/machine-a-tron-data`.
Machine-a-tron stores simulated machine identity and installed operating-system
state there. On a graceful pod restart it restores the devices and resumes them
powered on. Without persistence, a restart creates new powered-off simulator
state while Core may still consider the old machines assigned, preventing the
simulated DPU agents from resuming their reports.

The PVC does not use Helm's `keep` resource policy. Uninstalling the release or
deleting the PVC deletes the claim and makes its simulator state unavailable.
Whether Kubernetes also deletes the bound PersistentVolume and underlying data
depends on that volume's reclaim policy.

### Supported Hardware Types

| Type | Description |
|------|-------------|
| `supermicro_gb300_nvl` | Supermicro GB300 NVL |
| `nvidia_dgx_gb300` | NVIDIA DGX GB300 |
| `nvidia_dgx_h100` | NVIDIA DGX H100 |
| `wiwynn_gb200_nvl` | Wiwynn GB200 NVL |
| `lenovo_gb300_nvl` | Lenovo GB300 NVL |
| `dell_poweredge_r750` | Dell PowerEdge R750 |
| `liteon_power_shelf` | Liteon Power Shelf |
| `nvidia_switch_nd5200_ld` | NVIDIA ND5200 Switch |
| `generic_ami` | Generic AMI BMC |
| `generic_supermicro` | Generic Supermicro BMC |

---

## Troubleshooting

### ClusterIP already allocated

```text
creating service mat-bmc-host-xxx: Service is invalid: spec.clusterIP:
provided IP is already allocated
```

The BMC IP conflicts with an existing Service. Either:

- Use a different `oobDhcpRelayAddress` range
- Reserve a ServiceCIDR for machine-a-tron (K8s 1.29+)

### ClusterIP outside ServiceCIDR

```text
failed to allocate IP: the provided network does not match the current range
```

The BMC IP range is outside Kubernetes ServiceCIDR

### No instances discovered

```text
WRN no machine-a-tron instances discovered
```

Check that bmc-mock Services have the `nvidia-infra-controller/mat-service=true`
label.

### View Generated Config

```bash
kubectl -n nico-system get cm nico-machine-a-tron-mat-0-config-files -o yaml
```
