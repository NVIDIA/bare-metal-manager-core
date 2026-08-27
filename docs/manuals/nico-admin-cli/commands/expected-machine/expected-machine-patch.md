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
\[**--bmc-retain-credentials**\] \[**--dpu-policy**\]
\[**--bmc-ip-allocation**\] \[**--interfaces**\]
\[**--disable-lockdown**\] \[**--bmc-vendor-override**\]
\[**--sort-by**\] \[**-h**\|**--help**\]

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

**-a**, **--bmc-mac-address** *\<BMC_MAC_ADDRESS\>*\
BMC MAC Address of the expected machine

**--id** *\<ID\>*\
ID (UUID) of the expected machine to patch.

**-u**, **--bmc-username** *\<BMC_USERNAME\>*\
BMC username of the expected machine

**-p**, **--bmc-password** *\<BMC_PASSWORD\>*\
BMC password of the expected machine

**-s**, **--chassis-serial-number** *\<CHASSIS_SERIAL_NUMBER\>*\
Chassis serial number of the expected machine

**-d**, **--fallback-dpu-serial-number** *\<DPU_SERIAL_NUMBER\>*\
Serial number of the DPU attached to the expected machine. This option
should be used only as a last resort for ingesting those servers whose
BMC/Redfish do not report serial number of network devices. This option
can be repeated.

**--meta-name** *\<META_NAME\>*\
The name that should be used as part of the Metadata for newly created
Machines. If empty, the MachineId will be used

**--meta-description** *\<META_DESCRIPTION\>*\
The description that should be used as part of the Metadata for newly
created Machines

**--label** *\<LABEL\>*\
A label that will be added as metadata for the newly created Machine.
The labels key and value must be separated by a : character

**--sku-id** *\<SKU_ID\>*\
A SKU ID that will be added for the newly created Machine.

**--rack-id** *\<RACK_ID\>*\
A RACK ID that will be added for the newly created Machine.

**--default_pause_ingestion_and_poweron** *\<DEFAULT_PAUSE_INGESTION_AND_POWERON\>*\
Optional flag to pause machines ingestion and power on. False - dont
pause, true - will pause it. The actual mutable state is stored in
explored_endpoints.\

\
*Possible values:*

- true

- false

**--dpf-enabled** *\<DPF_ENABLED\>*\
DPF enable/disable for this machine. Default is updated as true.\

\
*Possible values:*

- true

- false

**--bmc-ip-address** *\<BMC_IP_ADDRESS\>*\
Static BMC IP (updates pre-allocated machine_interface when safe, same
as expected switches)

**--extended**\
Extended result output.

This used by measured boot, where basic output contains just what you
probably care about, and "extended" output also dumps out all the
internal UUIDs that are used to associate instances.

**--bmc-retain-credentials** *\<BMC_RETAIN_CREDENTIALS\>*\
When true, site-explorer skips BMC password rotation and stores
factory-default credentials in Vault as-is\

\
*Possible values:*

- true

- false

**--dpu-policy** *\<DPU_POLICY\>*\
Per-host DPU policy. \`manage\`: inherit the site policy, which defaults
to managing DPUs; \`nic\`: configure DPU hardware as plain NICs;
\`ignore\`: do not configure or attach DPU hardware. Unset preserves the
existing per-host value. The previous \`use-as-nic\` value remains
accepted as an alias. The legacy \`--dpu-mode\` flag also remains
accepted: \`dpu-mode\` maps to \`manage\`, \`nic-mode\` to \`nic\`, and
\`no-dpu\` to \`ignore\`.\

\
*Possible values:*

- manage

- nic

- ignore

**--bmc-ip-allocation** *\<BMC_IP_ALLOCATION\>*\
Per-host control over how this BMCs IP is assigned and retained.
\`auto\` (default): infer from \`--bmc-ip-address\` -- a configured
address is \`fixed\`, no address is \`retained\`; \`dynamic\`: a normal
DHCP lease that may expire and change; \`fixed\`: the operator-specified
\`--bmc-ip-address\` (static); \`retained\`: an auto-allocated DHCP
address that stays static for the lifetime of its machine-interface
record. Unset preserves the existing per-host value.\

\
*Possible values:*

- unspecified

- auto

- dynamic

- fixed

- retained

**--interfaces** *\<INTERFACES\>*\
Interfaces as a JSON array of ExpectedInterface objects (fields:
mac_address, role, ip_allocation, network_segment_type, fixed_ip,
fixed_mask, fixed_gateway, primary; legacy: nic_type). Accepted values:
role=host\|dpu_os\|dpu_bmc\|host_bmc\|unspecified and
ip_allocation=dynamic\|fixed\|retained\|unspecified.
network_segment_type uses protobuf enum numbers: tenant=0, admin=1,
underlay=2, host_inband=3. Replaces the machines full interface list.
For a matching stored MAC, omitting role preserves the stored role;
role=unspecified resets it to host. Omitting ip_allocation preserves the
stored policy when the presence of fixed_ip is unchanged;
ip_allocation=unspecified resets it to fixed_ip inference. Omitting any
other optional interface field, including network_segment_type, clears
its stored value.

**--disable-lockdown** *\<DISABLE_LOCKDOWN\>*\
If true, do not lock down the server as part of lifecycle management
within the state machine. If unset or false, preserve the default
behavior of locking down the server after configuring the BIOS.\

\
*Possible values:*

- true

- false

**--bmc-vendor-override** *\<BMC_VENDOR_OVERRIDE\>*\
Pin the Redfish BMC vendor for this host. Once set it governs how NICo
talks to this BMC. It picks which libredfish driver each Redfish client
dispatches on, the vendor nv-redfish classifies the host by, the vendor
recorded by Site Explorer, and therefore the firmware config lookup, the
IPMI-vs-Redfish restart choice and the BMC console transport. The hosts
own DMI data is untouched, though where NICo would pick a Redfish client
from that DMI vendor the pin outranks it. A RedfishVendor variant name,
case-sensitive (e.g. Dell, Supermicro, NvidiaDpu, Hpe, Lenovo). Redfish
clients pick it up within a minute, and the recorded vendor changes at
the next successful exploration. Pass an empty string to clear the
override (return to automatic detection). Only the vendor is asserted,
and everything else the BMC reports is left alone, so each library
classifies the host the way it normally would for that vendor. Because
the pin replaces detection rather than supplementing it, a wrong value
can fail exploration outright instead of being ignored, and the failure
is reported as the hosts last exploration error. It also selects which
Redfish account change NICo issues when it changes this BMCs password on
the initial factory bootstrap, on the site-wide rotation schedule, when
restoring credentials after a factory reset, and for bmc-machine
set-root-password. A wrong pin can therefore send the wrong account
change to a factory BMC. Only that choice is pinned. The clients that
probe a BMC, that bootstrap it from the factory, and that carry the
password change itself are still built with no vendor at all, since they
must reach a BMC before any vendor is usable. bmc-machine probe-vendor
is unaffected and keeps reporting what the BMC says about itself. A pin
asserts a vendor rather than a platform, so it also brings that vendors
behavior, including how BMC user accounts are created and deleted and
which vendor workarounds apply. Because only the vendor field is
asserted, a pin naming a sub-variant such as NvidiaGH200, VeraRubin,
NvidiaDpu or a power shelf still needs the product and Redfish version
the BMC reports to agree, and where they do not the host can end up
classified as nothing rather than as the pinned platform.

**--sort-by** *\<SORT_BY\>* \[default: primary-id\]\
Sort output by specified field\

\
*Possible values:*

- primary-id: Sort by the primary ID

- state: Sort by state

**-h**, **--help**\
Print help (see a summary with -h)

## Examples

```sh
nico-admin-cli expected-machine patch --bmc-mac-address 00:11:22:33:44:55 --sku-id DGX-H100-640GB
nico-admin-cli expected-machine patch --id 12345678-1234-5678-90ab-cdef01234567 --sku-id DGX-H100-640GB
nico-admin-cli expected-machine patch --bmc-mac-address 00:11:22:33:44:55 --bmc-username admin --bmc-password mynewpassword
nico-admin-cli expected-machine patch --bmc-mac-address 00:11:22:33:44:55 --dpu-policy ignore
nico-admin-cli expected-machine patch --bmc-mac-address 00:11:22:33:44:55 --bmc-ip-allocation retained
nico-admin-cli expected-machine patch --bmc-mac-address 00:11:22:33:44:55 --interfaces '[{"mac_address":"02:00:00:00:20:01","fixed_ip":"192.0.2.10"}]'
nico-admin-cli expected-machine patch --bmc-mac-address 00:11:22:33:44:55 --interfaces '[{"mac_address":"02:00:00:00:20:01","role":"unspecified","ip_allocation":"unspecified","fixed_ip":"192.0.2.10"}]'
nico-admin-cli expected-machine patch --bmc-mac-address 00:11:22:33:44:55 --bmc-vendor-override Dell
nico-admin-cli expected-machine patch --bmc-mac-address 00:11:22:33:44:55 --bmc-vendor-override ""
```

---

**See also:** [Tenant commands](../../tenant.md) · [CLI reference index](../../README.md)
