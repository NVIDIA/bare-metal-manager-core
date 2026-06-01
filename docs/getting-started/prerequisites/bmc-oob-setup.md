# BMC and Out-of-Band Setup

This page covers the out-of-band (OOB) network configuration and BMC preparation required before NICo can discover and manage hosts.

## OOB Network and DHCP Relay

NICo discovers hosts when their BMCs send DHCP requests over the OOB network. The OOB network must be configured to forward these requests to the NICo DHCP service.

**Requirements:**
- A dedicated OOB management network connecting all host BMCs and DPU BMCs to the site controller
- A DHCP relay configured on OOB switches, pointing to the NICo DHCP service IP (`NICo_DHCP_EXTERNAL`)
- Separate OOB management connectivity for DPU BMCs

NICo manages IP allocation for the management network—the OOB switches only need to relay DHCP traffic, not assign addresses. For the full switch configuration requirements, refer to the [Network Prerequisites](network.md) page.

## BMC Credentials

NICo needs factory default BMC credentials for each host in order to authenticate with the BMC during initial discovery. After discovery, NICo rotates these credentials to site-managed values.

### Information Required per Host

For each host to be ingested, the following values are required:

| Field | Description |
|---|---|
| BMC MAC address | MAC address of the host BMC interface |
| Chassis serial number | Used to verify that the BMC MAC matches the actual chassis |
| BMC username | Factory default username (typically `root`) |
| BMC password | Factory default password |

### Expected Machines Manifest

This information is provided to NICo as a JSON manifest called `expected_machines.json`. Only hosts listed in this manifest will be discovered and ingested.

```json
{
  "expected_machines": [
    {
      "bmc_mac_address": "C4:5A:B1:C8:38:0D",
      "bmc_username": "root",
      "bmc_password": "default-password1",
      "chassis_serial_number": "SERIAL-1"
    },
    {
      "bmc_mac_address": "C4:5A:FF:FF:FF:FF",
      "bmc_username": "root",
      "bmc_password": "default-password2",
      "chassis_serial_number": "SERIAL-2"
    }
  ]
}
```

Prepare this file before starting host ingestion. For details on uploading the file and managing credentials, refer to the [Ingesting Hosts](../../provisioning/ingesting-hosts.md) page.

## Site-Wide Credentials

Before ingesting hosts, you must also configure the credentials NICo will set on BMCs and UEFI after it takes ownership:

- **Host BMC credential**: Applied to all host BMCs after ingestion
- **DPU BMC credential**: Applied to all DPU BMCs after ingestion
- **Host UEFI password**: Per-device UEFI password for managed hosts
- **DPU UEFI password**: Per-device UEFI password for managed DPUs

These are configured via `nico-admin-cli` after NICo is deployed. Refer to the [Ingesting Hosts](../../provisioning/ingesting-hosts.md) page for the credential setup commands.

## BMC Redfish Requirements

NICo communicates with host BMCs and DPU BMCs exclusively via Redfish. The BMC must support the following Redfish operations:

| Operation | Purpose |
|---|---|
| Power control | Power on, power off, and reset managed hosts and DPUs. |
| Boot order configuration | Set UEFI boot order (DPU first). |
| UEFI Secure Boot toggle | Enable/disable Secure Boot |
| Firmware inventory | Inventory UEFI, BMC, and NIC firmware versions. |
| Firmware update | Apply firmware updates out-of-band. |
| Serial-over-LAN | Enable SSH console access to managed hosts. |
| IPv6 | Support the IPv6 protocol; used for BMC communication. |

For a complete list of Redfish endpoints and required response fields, refer to the [Redfish Endpoints Reference](../../architecture/redfish/endpoints_reference.md) page.
