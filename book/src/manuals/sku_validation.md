# SKU Validation

As of April 2025, Carbide supports checking and validating the hardware in a machine, known as "SKU Validation."

## Summary

A SKU is a collection of definitions managed by Carbide that define a specific configuration of machine.
Each host managed by Carbide must have a SKU associated with it before it can be made available for use by a tenant
(TODO: did we actually implement this?).

Hardware configurations or SKUs are generated from existing machines by an admin and uploaded to forge via the CLI.
SKU's can be downloaded for modification or use with other sites.

Machines that are assigned a SKU are automatically validated during ingestion based on their discovery information.
Hardware validation occurs during initial ingestion and after an instance is released and new discovery information is received.

New machines are automatically checked against existing SKUs and if a match is found, the machine passes
SKU validation and continues with the normal ingestion process.  If no match is found the machine waits until
a matching SKU is available or until the machine is made compatible with an existing SKU, if SKU validation is enabled
in the site (`ignore_unassigned_machines` configuration option).

## Behavior

SKU Validation can be enabled or disabled for a site, however, when it is enabled, it may or may not
apply to a given machine. For a machine to have SKU Validation enforced, it must have an assigned SKU,
however, note that SKUs will automatically be assigned to machines that match a given SKU, if they are in ready state.

If a machine has an assigned SKU, and Carbide (when the machine changes state and is not assigned) detects that
the hardware configuration does not match, the machine will have a SKU mismatch health alert placed on it, and it
will be prevented from having allocations assigned to it.

Generally, SKUs must be manually added a site to configure its SKUs. At some point, we may do this during the site
bring-up process. However, for now, SKUs are only manually added to sites. It is also expected that, generally,
the SKU assignments for individual machines are added automatically by Carbide as those machines are reconfigured.

### BOM Validation States
Verifying a SKU against a machine goes through several steps to aquire updated machine inventory and perform the validation.  Depending on the inventory of the machine and the SKU configuration, the state machine needs to handle several situations.  The bom validation process is broken down into the following sub-states:
- `MatchingSku` - The state machine will attempt to find an existing SKU that matches the machine inventory.
- `UpdatingInventory` - Carbide is requesting that scout re-inventory the machine.  This ensures that other operations are using a recent version of the machine inventory
- `VerifyingSku` - Carbide is comparing the machine inventory against the SKU
- `SkuVerificationFailed` - The machine did not match the SKU.  Manual intervention is required.  The `sku verify` command may be used to retry the verification
- `WaitingForSkuAssignment` - The machine does not have a SKU assigned and the configuration requires one.
- `SkuMissing` - The machine has a SKU assigned, but the SKU does not exist.  This happens when a SKU is specified in the expected machines, but was not created.  If configured, Carbide will attempt to generate a SKU

### Versions
Carbide maintains a version of the SKU schema used when a SKU is created.  This ensures that the same comparison is used during the lifetime of a SKU and ensures that the behavior of BOM validation does not change between Carbide versions.  When new components are added, or new data sources are used during validation, existing SKUs will not be updated with the change and continue to behave as they did in previous Carbide versions.  In order to use the new version, a new SKU must be created.

### Configuration

SKU validation is enabled or disabled for an entire site at once, using the forge configuration file.
The block that defines it is called `bom_validation`:

```toml
[bom_validation]
enabled = false
ignore_unassigned_machines = false
allow_allocation_on_validation_failure = false
find_match_interval = "300s"
auto_generate_missing_sku = false,
auto_generate_missing_sku_interval = "300s"
```

 - `enabled` - Enables or disables the entire bom validation process.  When disabled, machines
  will skip bom validation and proceed as if all validation has passed.
 - `allow_allocation_on_validation_failure` - When true, machines are allowed to stay in Ready state and remain allocatable
  even when SKU validation fails. Validation still occurs but only logs are recorded - health reports are cleared instead
  of recording validation failures. Machines do not transition into failed states (SkuVerificationFailed, SkuMissing,
  WaitingForSkuAssignment). When false (default), standard mode applies where validation failures are recorded in health
  reports and machines enter failed states and become unallocatable until fixed. This is useful for avoiding machine
  allocation blockage due to SKU validation issues when you only need logging without health report alerts.
 - `ignore_unassigned_machines` - When true and BOM validation encounters a machine that does not have an associated SKU,
  it will proceed as if all validation has passed. Only machines with an associated SKU will be validated. This allows
  existing sites to be upgraded and BOM Validation enabled as SKUs are added to the system without impacting site operation.
  Machines that do not have an assigned SKU will still be usable and assignable.
 - `find_match_interval` - determines how often Carbide will attempt to find a matching SKU for a machine.  Carbide will only
  attempt to find a SKU when the machine is in the `Ready` state.
 - `auto_generate_missing_sku` - enable or disable generation of a SKU from a machine.  This only applies to a machine with a SKU
  specified in the expected machine configuration and in the `SkuMissing` state.
 - `auto_generate_missing_sku_interval` - determines how often Carbide will attempt to generate a sku from the machine data.

### Hardware Validated

Machines will (currently) have the following hardware validated against the SKU:

 - Chassis (motherboard): Vendor and model matched
 - CPU: Model and count matched
 - GPUs: Model, memory capacity, and count matched
 - Memory: Type, capacity, and count matched
 - Storage: Model and count matched

## Design Information

See the [design document](https://gitlab-master.nvidia.com/nvmetal/designs/-/blob/hw-bom/designs/0055-hardware-bom.md).

## SKU Names

By convention, SKU names (defined per site) are in the following format:

`<vendor>.<model>.<node_type>.<idx>`

Where:

 - `<vendor>` is the first word of the "chassis" "vendor" field, e.g. `dell` or `lenovo`
 - `<model>` is the unique ending to the "chassis" "model" field, e.g. `r750` or `sr670v2`
 - `<node_type>` is one of the following types of node that are deployed in forge:
    - `gpu`
    - `cpu`
    - `storage`
    - `controller` (site controller node, if applicable)
 - `<idx>` arbitrary index starting at 1 to define different configurations, if required, generally 1

Some example SKU names:

 - `lenovo.sr670v2.gpu.1`
 - `dell.r750.gpu.1`
 - `dell.r750.storage.1`

## Managing SKU Validation

### Browse SKUs, their configuration, and assigned machines

You can view all the SKUs for a site, and click into their specific configurations and list assigned machines
by visting the admin page for a site and clicking "SKUs" from the left-side navigation bar.

e.g. [https://api-pdx01.frg.nvidia.com/admin/sku](https://api-pdx01.frg.nvidia.com/admin/sku)

### Viewing SKU information

There are 2 commands for showing information related to SKUs:
- `sku show` lists SKUs or shows information related to an existing SKU.
- `sku generate` shows what a SKU would look like for a machine.  The generate command does not create the SKU or assign the SKU to the machine.

Both commands honor the JSON format flag `-f json` to change the output to JSON.  JSON is used by other commands.

The `sku show` command can be used to list all SKUs, or show the details of a single SKU:
```sh
carbide-admin-cli sku show [<sku id>]

> carbide-admin-cli sku show
+----------------------------------------------------------------+---------------------------------------------------------+------------------------------+-----------------------------+
| ID                                                             | Description                                             | Model                        | Created                     |
+================================================================+=========================================================+==============================+=============================+
| PowerEdge R750 1xGPU 1xIB                                      | PowerEdge R750; 2xCPU; 1xGPU; 128 GiB                   | PowerEdge R750               | 2025-02-27T13:57:19.435162Z |
+----------------------------------------------------------------+---------------------------------------------------------+------------------------------+-----------------------------+

> carbide-admin-cli sku show 'PowerEdge R750 1xGPU 1xIB'
ID                  : PowerEdge R750 1xGPU 1xIB
Schema Version      : 4
Description         : PowerEdge R750; 2xCPU; 1xGPU; 128 GiB
Device Type         :
Model               : PowerEdge R750
Architecture        : x86_64
Created At          : 2025-02-27T13:57:19.435162Z
TPM Version         : 2.0

CPUs:
          +--------------+------------------------------------------+---------+-------+
          | Vendor       | Model                                    | Threads | Count |
          +==============+==========================================+=========+=======+
          | GenuineIntel | Intel(R) Xeon(R) Gold 6354 CPU @ 3.00GHz | 36      | 2     |
          +--------------+------------------------------------------+---------+-------+
GPUs:
          +--------+--------------+------------------+-------+
          | Vendor | Total Memory | Model            | Count |
          +========+==============+==================+=======+
          | NVIDIA | 81559 MiB    | NVIDIA H100 PCIe | 1     |
          +--------+--------------+------------------+-------+
Memory (128 GiB):
          +------+----------+-------+
          | Type | Capacity | Count |
          +======+==========+=======+
          | DDR4 | 16 GiB   | 8     |
          +------+----------+-------+
IB Devices:
          +-----------------------+-----------------------------+-------+------------------+
          | Vendor                | Model                       | Count | Inactive Devices |
          +=======================+=============================+=======+==================+
          | Mellanox Technologies | MT28908 Family [ConnectX-6] | 2     | [0,1]            |
          +-----------------------+-----------------------------+-------+------------------+


```

The `sku generate` command can be used to show what would match a given machine.

```sh
carbide-admin-cli sku generate <machineid>

> carbide-admin-cli sku generate fm100hts7tqfqtgn3imi7ipd2jk7r37idk5r4aa41krpcelg498hasoqtkg
ID                  : PowerEdge R750 1xGPU 1xIB
Schema Version      : 4
Description         : PowerEdge R750; 2xCPU; 1xGPU; 128 GiB
Device Type         :
Model               : PowerEdge R750
Architecture        : x86_64
Created At          : 2025-02-27T13:57:19.435162Z
TPM Version         : 2.0

CPUs:
          +--------------+-------------------------------+---------+-------+
          | Vendor       | Model                         | Threads | Count |
          +==============+===============================+=========+=======+
          | GenuineIntel | Intel(R) Xeon(R) Silver 4416+ | 40      | 2     |
          +--------------+-------------------------------+---------+-------+
GPUs:
          +--------+--------------+-------+-------+
          | Vendor | Total Memory | Model | Count |
          +========+==============+=======+=======+
          +--------+--------------+-------+-------+
Memory (256 GiB):
          +------+----------+-------+
          | Type | Capacity | Count |
          +======+==========+=======+
          | DDR5 | 16 GiB   | 16    |
          +------+----------+-------+
IB Devices:
          +--------+-------+-------+------------------+
          | Vendor | Model | Count | Inactive Devices |
          +========+=======+=======+==================+
          +--------+-------+-------+------------------+
Storage Devices:
          +----------------------------+-------+
          | Model                      | Count |
          +============================+=======+
          | Dell DC NVMe CD7 U.2 960GB | 1     |
          +----------------------------+-------+
          | KIOXIA KCD8DRUG7T68        | 8     |
          +----------------------------+-------+

```

### Creating SKUs for a Site

To create a SKU, the easiest method is generally taking the configuration of an example, known good machine
(this can be verified during creation) and applying that to the site.

Using information from the viewed SKU information above (vendor, model, and node type), you should be able to
create the `sku_name`, and using the example machine, then create the SKU config and upload it to the
site controller.

Save the SKU information (on your local machine, written to an output file):

```sh
carbide-admin-cli -f json -o <sku_name>.json sku generate <machineid> --id <sku_name>
```

This will create a file in the current directory with the name `<sku_name>.json`, at this point you can create the
SKU on the site controller:

```sh
carbide-admin-cli sku create <sku_name>.json
```

### Assign a SKU to a machine

Note that generally, you do not need to assign a SKU to a machine, since the SKU is automatically assigned when the
machine goes to ready (not assigned) state, or goes through a machine validation workflow.

```sh
carbide-admin-cli sku assign <sku_name> <machineid>
```

### Remove a SKU assignment from a machine

To remove the assignment of a SKU from a machine, the `sku unassign` can be used. Note that if a machine already matches
a SKU in the given site, and it is not in an assigned state, it will likely be quickly reassigned automatically by
the site controller after this command is run.

```sh
carbide-admin-cli sku unassign <machineid>
```

### Replacing an existing SKU
If a SKU has a set of components that do not work for a set of machines (either due to bugs, or Carbide software updates) updating machines by unassigning and assigning a SKU would be challenging.  Replacing the components of a SKU can be done with the `sku replace` command.  This will force all machines to go through verification when no instance is allocated to the machine (all machines are verified when an instance is released).

```sh
forge-acmin-cli sku replace <filename> [--id <sku_name>]
```

### Remove a SKU from a site

To remove a SKU from a site, you must first remove all machines that have been assigned that SKU manually, you may want
to run the `sku unassign` command above in a shell loop to remove all the machines quickly. Note that you can query which
machines have a given SKU using the command below, `sku show-machines` then follow it with the
following command to remove the SKU:

```sh
carbide-admin-cli sku delete <sku_name>
```

#### Upgrading a SKU to the current version example
When a new version of Carbide is released that changes how SKUs behave, existing SKUs maintain their previous behavior.  In order to use the new version of the SKU, a manual "upgrade" process is required using the the `sku replace` command.

The existing SKU is below.  Note that the "Storage Devices" section includes a device with a model of "NO_MODEL" and there is no TPM.  The extra storage device is created by the raid card and may not always exist and should not have been included in the SKU.

```sh
carbide-admin-cli sku show XE9680
ID:              XE9680
Schema Version:  2
Description:     PowerEdge XE9680; 2xCPU; 8xGPU; 2 TiB
Device Type:
Model:           PowerEdge XE9680
Architecture:    x86_64
Created At:      2025-04-18T16:30:58.748991Z
CPUs:
          +--------------+---------------------------------+---------+-------+
          | Vendor       | Model                           | Threads | Count |
          +==============+=================================+=========+=======+
          | GenuineIntel | Intel(R) Xeon(R) Platinum 8480+ | 56      | 2     |
          +--------------+---------------------------------+---------+-------+
GPUs:
          +--------+--------------+-----------------------+-------+
          | Vendor | Total Memory | Model                 | Count |
          +========+==============+=======================+=======+
          | NVIDIA | 81559 MiB    | NVIDIA H100 80GB HBM3 | 8     |
          +--------+--------------+-----------------------+-------+
Memory (2 TiB):
          +------+----------+-------+
          | Type | Capacity | Count |
          +======+==========+=======+
          | DDR5 | 64 GiB   | 32    |
          +------+----------+-------+
IB Devices:
          +--------+-------+-------+------------------+
          | Vendor | Model | Count | Inactive Devices |
          +========+=======+=======+==================+
          +--------+-------+-------+------------------+
Storage Devices:
          +----------------------------------+-------+
          | Model                            | Count |
          +==================================+=======+
          | Dell Ent NVMe FIPS CM6 RI 3.84TB | 8     |
          +----------------------------------+-------+
          | NO_MODEL                         | 1     |
          +----------------------------------+-------+
```

Using the `sku generate` command, we can see what the updated SKU looks like for the same machine.  This is the same machine that generated the older SKU in a previous release.  Note that the "NO_MODEL" device is gone, the RAID controller is now shown as `Dell BOSS-N1` and the version of the TPM is shown.

``` sh
carbide-admin-cli sku generate fm100hti7olik00gefc9qlma831n6q49d1odkksp86q639cugt5afjnm4s0
ID                  : PowerEdge R750 1xGPU 1xIB
Schema Version      : 4
Description         : PowerEdge R750; 2xCPU; 1xGPU; 128 GiB
Device Type         :
Model               : PowerEdge R750
Architecture        : x86_64
Created At          : 2025-02-27T13:57:19.435162Z
TPM Version         : 2.0

CPUs:
          +--------------+---------------------------------+---------+-------+
          | Vendor       | Model                           | Threads | Count |
          +==============+=================================+=========+=======+
          | GenuineIntel | Intel(R) Xeon(R) Platinum 8480+ | 56      | 2     |
          +--------------+---------------------------------+---------+-------+
GPUs:
          +--------+--------------+-----------------------+-------+
          | Vendor | Total Memory | Model                 | Count |
          +========+==============+=======================+=======+
          | NVIDIA | 81559 MiB    | NVIDIA H100 80GB HBM3 | 8     |
          +--------+--------------+-----------------------+-------+
Memory (2 TiB):
          +------+----------+-------+
          | Type | Capacity | Count |
          +======+==========+=======+
          | DDR5 | 64 GiB   | 32    |
          +------+----------+-------+
IB Devices:
          +--------+-------+-------+------------------+
          | Vendor | Model | Count | Inactive Devices |
          +========+=======+=======+==================+
          +--------+-------+-------+------------------+
Storage Devices:
          +----------------------------------+-------+
          | Model                            | Count |
          +==================================+=======+
          | Dell BOSS-N1                     | 1     |
          +----------------------------------+-------+
          | Dell Ent NVMe FIPS CM6 RI 3.84TB | 8     |
          +----------------------------------+-------+

```

Create a new SKU file using the generate command again, but create a json file.  Note that the same ID needs to be specified as the existing SKU in order for the replace command to find the old SKU.
```sh
carbide-admin-cli -f json -o /tmp/xe9680.json sku g fm100hti7olik00gefc9qlma831n6q49d1odkksp86q639cugt5afjnm4s0 --id XE9680

```

Then replace the old SKU
```sh
carbide-admin-clisku replace /tmp/xe9680.json
+--------+---------------------------------------+------------------+-----------------------------+
| ID     | Description                           | Model            | Created                     |
+========+=======================================+==================+=============================+
| XE9680 | PowerEdge XE9680; 2xCPU; 8xGPU; 2 TiB | PowerEdge XE9680 | 2025-04-18T16:30:58.748991Z |
+--------+---------------------------------------+------------------+-----------------------------+

```

The `show sku` command now shows the updated components (and version)
```sh
carbide-admin-cli sku show XE9680
ID                  : XE9680
Schema Version      : 4
Description         : PowerEdge R750; 2xCPU; 1xGPU; 128 GiB
Device Type         :
Model               : PowerEdge R750
Architecture        : x86_64
Created At          : 2025-02-27T13:57:19.435162Z
TPM Version         : 2.0

CPUs:
          +--------------+---------------------------------+---------+-------+
          | Vendor       | Model                           | Threads | Count |
          +==============+=================================+=========+=======+
          | GenuineIntel | Intel(R) Xeon(R) Platinum 8480+ | 56      | 2     |
          +--------------+---------------------------------+---------+-------+
GPUs:
          +--------+--------------+-----------------------+-------+
          | Vendor | Total Memory | Model                 | Count |
          +========+==============+=======================+=======+
          | NVIDIA | 81559 MiB    | NVIDIA H100 80GB HBM3 | 8     |
          +--------+--------------+-----------------------+-------+
Memory (2 TiB):
          +------+----------+-------+
          | Type | Capacity | Count |
          +======+==========+=======+
          | DDR5 | 64 GiB   | 32    |
          +------+----------+-------+
IB Devices:
          +--------+-------+-------+------------------+
          | Vendor | Model | Count | Inactive Devices |
          +========+=======+=======+==================+
          +--------+-------+-------+------------------+
Storage Devices:
          +----------------------------------+-------+
          | Model                            | Count |
          +==================================+=======+
          | Dell BOSS-N1                     | 1     |
          +----------------------------------+-------+
          | Dell Ent NVMe FIPS CM6 RI 3.84TB | 8     |
          +----------------------------------+-------+
```


### Finding assigned machines for a SKU

To find all the assigned machines for a given SKU:

```sh
carbide-admin-cli sku show-machines <sku_name>
```

### Force SKU revalidation

It may be beneficial when diagnosing a machine to force Carbide to revalidate a SKU on a machine, if the machine is suspected
of issues, or if you believe that the validation may be out of date. You can force a revalidation with the command below,
it will be validated the next time the machine is unassigned. Note that you cannot validate an assigned machine, and Carbide
will refrain from doing so automatically.

```sh
carbide-admin-cli sku verify <sku_name>
```

## Issues

### What to do if a machine is failing validation

For a given machine, if it has already been assigned a SKU manually or automatically, it likely
was correct at some point, and the effort of the investigation should be to determine what has
changed on the machine to cause it to now fail validation.

For example, the machine may have gone through maintenance and is now missing one of its GPUs or
storage drives. The health alert generated by failing the validation should provide some context
as to where the mismatch is believed to be. Using this, it should be possible to diagnose if the
machine is actually configured incorrectly, or in the case that the new configuration should be
correct, you can remove the SKU from the machine `sku unassign` and create a new SKU as shown
above to represent this machine.

###
