# Network Isolation

NICo enforces separation between tenants across all network planes. This isolation is established automatically during instance provisioning -- operators do not need to configure isolation manually.

## Ethernet (North-South)

BlueField DPUs running HBN (Host-Based Networking with Containerized Cumulus) enforce L3 VXLAN/EVPN boundaries. Each VPC gets its own VRF (Virtual Routing and Forwarding instance) on every DPU that hosts an instance in that VPC. Traffic between VPCs is isolated at the network layer without requiring any leaf switch configuration changes.

Key properties:
- Per-VPC VRF with dedicated VNI (VXLAN Network Identifier) from the site's VNI pool
- Route targets control which VRFs can exchange routes
- `deny_prefixes` ACLs block tenant traffic from reaching management networks
- Network Security Groups provide per-subnet firewall rules

For the full networking architecture, see [VPC Network Virtualization](../manuals/vpc/vpc_network_virtualization.md).

## InfiniBand (East-West)

UFM assigns P_Key partitions to each tenant's IB ports. Only hosts sharing a P_Key partition can communicate over InfiniBand, enforcing tenant isolation on the high-performance fabric.

View IB partition assignments:

```
nicocli tui
> infiniband-partition list
> infiniband-partition get
```

## NVLink

NMX-M APIs configure NVLink partition assignments, ensuring that NVLink domains are dedicated to a single tenant. For GB200 NVL72 systems, NICo gates instance allocation on NVLink cluster readiness -- if the fabric is not healthy, provisioning is blocked.

View NVLink partition state:

```
nicocli tui
> nvlink-logical-partition list
> nvlink-logical-partition get
```

## What a Tenant Can and Cannot Access

| Resource | Tenant Can Access | Tenant Cannot Access |
|----------|------------------|---------------------|
| Instances | Own instances in own VPCs | Other tenants' instances |
| Network | Traffic within own VPCs and subnets | Management networks, other tenants' VPCs (unless peered) |
| Storage | NVMe on assigned machines | Storage on unassigned machines |
| InfiniBand | P_Key partitions assigned to their instances | Other tenants' IB partitions |
| NVLink | NVLink domains allocated to their instances | Other tenants' NVLink domains |
| BMC/UEFI | No access (managed by NICo) | All BMC and UEFI interfaces |
