# `nico-admin-cli expected-machine add`

_[Tenant commands](../../tenant.md) › [expected-machine](./expected-machine.md) › **add**_

## NAME

nico-admin-cli-expected-machine-add - Add expected machine

## SYNOPSIS

**nico-admin-cli expected-machine add**
\<**-a**\|**--bmc-mac-address**\> \<**-u**\|**--bmc-username**\>
\[**-p**\|**--bmc-password**\] \<**-s**\|**--chassis-serial-number**\>
\[**-d**\|**--fallback-dpu-serial-number**\] \[**--meta-name**\]
\[**--meta-description**\] \[**--label**\] \[**--sku-id**\] \[**--id**\]
\[**--host_nics**\] \[**--rack_id**\]
\[**--default_pause_ingestion_and_poweron**\] \[**--dpf-enabled**\]
\[**--extended**\] \[**--bmc-ip-address**\]
\[**--bmc-retain-credentials**\] \[**--dpu-mode**\]
\[**--disable-lockdown**\] \[**--sort-by**\] \[**-h**\|**--help**\]

## DESCRIPTION

Add expected machine

## OPTIONS

**-a**, **--bmc-mac-address** *\<BMC_MAC_ADDRESS\>*  
BMC MAC Address of the expected machine

**-u**, **--bmc-username** *\<BMC_USERNAME\>*  
BMC username of the expected machine

**-p**, **--bmc-password** *\<BMC_PASSWORD\>*  
BMC password of the expected machine (optional; defaults to empty string
if not provided)

**-s**, **--chassis-serial-number** *\<CHASSIS_SERIAL_NUMBER\>*  
Chassis serial number of the expected machine

**-d**, **--fallback-dpu-serial-number** *\<DPU_SERIAL_NUMBER\>*  
Serial number of the DPU attached to the expected machine. This option
should be used only as a last resort for ingesting those servers whose
BMC/Redfish do not report serial number of network devices. This option
can be repeated.

**--meta-name** *\<META_NAME\>*  
The name that should be used as part of the Metadata for newly created
Machines. If empty, the MachineId will be used

**--meta-description** *\<META_DESCRIPTION\>*  
The description that should be used as part of the Metadata for newly
created Machines

**--label** *\<LABEL\>*  
A label that will be added as metadata for the newly created Machine.
The labels key and value must be separated by a : character. E.g.
DATACENTER:XYZ

**--sku-id** *\<SKU_ID\>*  
A SKU ID that will be added for the newly created Machine.

**--id** *\<UUID\>*  
Optional unique ID to assign to the ExpectedMachine on create

**--host_nics** *\<HOST_NICS\>*  
Host NICs as a JSON array of ExpectedHostNic objects (fields:
mac_address, nic_type, fixed_ip, fixed_mask, fixed_gateway, primary)

**--rack_id** *\<RACK_ID\>*  
Rack ID for this machine

**--default_pause_ingestion_and_poweron** *\<DEFAULT_PAUSE_INGESTION_AND_POWERON\>*  
Optional flag to pause machines ingestion and power on. False - dont
pause, true - will pause it. The actual mutable state is stored in
explored_endpoints.\

\
*Possible values:*

- true

- false

**--dpf-enabled** *\<DPF_ENABLED\>*  
DPF enable/disable for this machine. Default is updated as true.\

\
*Possible values:*

- true

- false

**--extended**  
Extended result output.

This used by measured boot, where basic output contains just what you
probably care about, and "extended" output also dumps out all the
internal UUIDs that are used to associate instances.

**--bmc-ip-address** *\<BMC_IP_ADDRESS\>*  
Static BMC IP (pre-allocates machine_interface for site explorer, same
as expected switches)

**--bmc-retain-credentials** *\<BMC_RETAIN_CREDENTIALS\>*  
When true, site-explorer skips BMC password rotation and stores
factory-default credentials in Vault as-is\

\
*Possible values:*

- true

- false

**--dpu-mode** *\<DPU_MODE\>*  
Per-host DPU operating mode. \`dpu-mode\` (default): DPUs are managed by
NICo; \`nic-mode\`: DPU hardware present but treated as a plain NIC;
\`no-dpu\`: no DPU hardware at all. Unset defers to the site-wide
\`\[site_explorer\] dpu_mode\` setting (which itself falls back to
\`dpu-mode\` when not set).\

\
*Possible values:*

- unspecified

- dpu-mode

- nic-mode

- no-dpu

**--disable-lockdown** *\<DISABLE_LOCKDOWN\>*  
If true, do not lock down the server as part of lifecycle management
within the state machine. If unset or false, preserve the default
behavior of locking down the server after configuring the BIOS.\

\
*Possible values:*

- true

- false

**--sort-by** *\<SORT_BY\>* \[default: primary-id\]  
Sort output by specified field\

\
*Possible values:*

- primary-id: Sort by the primary id

- state: Sort by state

**-h**, **--help**  
Print help (see a summary with -h)

## Examples

```sh
nico-admin-cli expected-machine add --bmc-mac-address 00:11:22:33:44:55 --bmc-username admin --bmc-password mypassword --chassis-serial-number sample_serial-1
nico-admin-cli expected-machine add --bmc-mac-address 00:11:22:33:44:55 --bmc-username admin --bmc-password mypassword --chassis-serial-number sample_serial-1 --meta-name MyMachine --label DATACENTER:XYZ --sku-id DGX-H100-640GB
nico-admin-cli expected-machine add --bmc-mac-address 00:11:22:33:44:55 --bmc-username admin --bmc-password mypassword --chassis-serial-number sample_serial-1 --bmc-ip-address 192.0.2.20
nico-admin-cli expected-machine add --bmc-mac-address 00:11:22:33:44:55 --bmc-username admin --bmc-password mypassword --chassis-serial-number sample_serial-1 --dpu-mode nic-mode
```

---

**See also:** [Tenant commands](../../tenant.md) · [CLI reference index](../../README.md)
