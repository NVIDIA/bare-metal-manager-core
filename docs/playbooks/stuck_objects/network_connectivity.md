# Network Connectivity Issues

Use this playbook when a state-machine stall appears to come from BMC, DHCP,
PXE/HTTP boot, DPU agent, BGP/HBN, or API reachability.

## Connectivity Matrix

| Path | Why it matters | First check |
|---|---|---|
| Operator to `nico-api` | CLI and incident response. | `nico-admin-cli version` |
| `nico-api` to Vault | BMC and platform credentials. | Vault metrics and `nico-api` logs. |
| `nico-api` to BMC | Redfish power, inventory, firmware, and discovery. | Site Explorer and `redfish browse`. |
| Host or DPU to `nico-dhcp` | discovery, install, admin and OOB leases. | DHCP logs and IP pool metrics. |
| Host or DPU to `nico-pxe` | discovery image, iPXE, BFB or HTTP boot content. | PXE logs and boot console. |
| DPU to `nico-api` | DPU health and network status reporting. | DPU agent logs and `Last seen`. |
| DPU to TOR or route server | BGP and HBN service health. | HBN container and BGP summary. |

## BMC or OOB Unreachable

NICo cannot discover, provision, or manage a machine when its BMC is unreachable.

Check:

```bash
nico-admin-cli site-explorer get-report all
nico-admin-cli redfish browse --address <bmc-ip> /redfish/v1
kubectl -n <nico-namespace> logs deploy/nico-api --tail=500 | grep <bmc-ip>
```

Common causes:

- BMC is powered off or on the wrong network.
- OOB route or VLAN is missing.
- Vault credential lookup failed.
- BMC certificate or TLS settings changed.
- Redfish endpoint is slow or rate-limited.

## DHCP Failures

DHCP appears in two places:

- site DHCP through `nico-dhcp`
- DPU-local DHCP or relay for host-facing networking

Check site DHCP:

```bash
kubectl -n <nico-namespace> logs deploy/nico-dhcp --tail=500 | grep <mac>
```

Check pool pressure:

- `carbide_available_ips_count`
- `carbide_reserved_ips_count`
- `carbide_resourcepool_free_count`

Common causes:

| Symptom | Likely cause |
|---|---|
| No DHCP request | relay, VLAN, cabling, boot order, or client not reaching NICo. |
| Request but no lease | no matching reservation or exhausted pool. |
| Lease assigned but no progress | PXE/HTTP boot, scout, or API reachability failure. |

## PXE and HTTP Boot

`nico-pxe` serves discovery images, iPXE scripts, cloud-init, kickstart, BFB
URLs, and root CA content used by install paths.

```bash
kubectl -n <nico-namespace> logs deploy/nico-pxe --tail=500 | grep <mac-or-ip>
```

If there are no PXE or HTTP requests, inspect the serial console and boot order.
If requests exist but the host does not advance, inspect scout or DPU agent logs.

## DPU Agent Cannot Reach `nico-api`

NICo waits for the DPU agent to report health and applied network config.

Check:

```bash
nico-admin-cli managed-host show <host-machine-id>
nico-admin-cli machine network status
nico-admin-cli machine health-report show <dpu-machine-id>
```

On the DPU:

```bash
journalctl -u nico-dpu-agent.service -e --no-pager
```

Common causes:

- DPU OS did not boot.
- `nico-dpu-agent` is not running.
- DPU cannot resolve or reach `nico-api`.
- TLS root CA is missing or stale.
- DPU network config version does not match desired state.

## BGP, HBN, and Edge Connectivity

When DPU services are up but network health is not, inspect HBN and FRR.

```bash
sudo crictl ps
sudo crictl exec -ti $(sudo crictl ps | grep doca-hbn | awk '{print $1}') vtysh -c 'show bgp summary'
```

Common causes:

- TOR or route-server peering is down.
- DPU interface is down.
- HBN container is unhealthy.
- DPU config version is stale.
- Fabric configuration is not applied.
