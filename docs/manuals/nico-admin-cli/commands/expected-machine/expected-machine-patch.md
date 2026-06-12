# `nico-admin-cli expected-machine patch`

_[Tenant commands](../../tenant.md) › [expected-machine](./expected-machine.md) › **patch**_

## NAME

nico-admin-cli-expected-machine-patch - Patch expected machine (partial
update, preserves unprovided fields).

## SYNOPSIS

**nico-admin-cli expected-machine patch**
\[**-a**\|**--bmc-mac-address**\] \[**--id**\]
\[**-u**\|**--bmc-username**\] \[**-p**\|**--bmc-password**\]
\[**-s**\|**--chassis-serial-number**\]
\[**-d**\|**--fallback-dpu-serial-number**\] \[**--meta-name**\]
\[**--meta-description**\] \[**--label**\] \[**--sku-id**\]
\[**--rack-id**\] \[**--default_pause_ingestion_and_poweron**\]
\[**--dpf-enabled**\] \[**--bmc-ip-address**\] \[**--extended**\]
\[**--bmc-retain-credentials**\] \[**--dpu-mode**\]
\[**--disable-lockdown**\] \[**--sort-by**\] \[**-h**\|**--help**\]

## DESCRIPTION

Patch expected machine (partial update, preserves unprovided fields).

Only the fields provided in the command will be updated. All other
fields remain unchanged.

Examples: \# Update only SKU, preserve all other fields including
metadata nico-admin-cli expected-machine patch --bmc-mac-address
1a:1b:1c:1d:1e:1f --sku-id new_sku

\# Update only labels, preserve name and description nico-admin-cli
expected-machine patch --bmc-mac-address 1a:1b:1c:1d:1e:1f \\ --sku-id
sku123 --label env:prod --label team:platform

## OPTIONS

**-a**, **--bmc-mac-address** *\<BMC_MAC_ADDRESS\>*  
BMC MAC Address of the expected machine

**--id** *\<ID\>*  
ID (UUID) of the expected machine to patch.

**-u**, **--bmc-username** *\<BMC_USERNAME\>*  
BMC username of the expected machine

**-p**, **--bmc-password** *\<BMC_PASSWORD\>*  
BMC password of the expected machine

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
The labels key and value must be separated by a : character

**--sku-id** *\<SKU_ID\>*  
A SKU ID that will be added for the newly created Machine.

**--rack-id** *\<RACK_ID\>*  
A RACK ID that will be added for the newly created Machine.

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

**--bmc-ip-address** *\<BMC_IP_ADDRESS\>*  
Static BMC IP (updates pre-allocated machine_interface when safe, same
as expected switches)

**--extended**  
Extended result output.

This used by measured boot, where basic output contains just what you
probably care about, and "extended" output also dumps out all the
internal UUIDs that are used to associate instances.

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
\`no-dpu\`: no DPU hardware at all. Unset preserves the existing
per-host value.\

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
nico-admin-cli expected-machine patch --bmc-mac-address 00:11:22:33:44:55 --sku-id DGX-H100-640GB
nico-admin-cli expected-machine patch --id 12345678-1234-5678-90ab-cdef01234567 --sku-id DGX-H100-640GB
nico-admin-cli expected-machine patch --bmc-mac-address 00:11:22:33:44:55 --bmc-username admin --bmc-password mynewpassword
nico-admin-cli expected-machine patch --bmc-mac-address 00:11:22:33:44:55 --dpu-mode no-dpu
```

---

**See also:** [Tenant commands](../../tenant.md) · [CLI reference index](../../README.md)
