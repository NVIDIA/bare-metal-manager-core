# SKU Validation

As of April 2025, Forge (Carbide) supports checking and validating the hardware in a machine,
known as "SKU Validation."

## Summary

A SKU is a collection of definitions managed by Forge that define a specific configuration of machine.
Each host managed by Forge must have a SKU associated with it before it can be made available for use by a tenant 
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

If the flag `ignore_unassigned_machines` is set in the site configuration, then machines that do not have an
assigned SKU will still be usable and assignable.

If a machine has an assigned SKU, and Forge (when the machine changes state and is not assigned) detects that
the hardware configuration does not match, the machine will have a SKU mismatch health alert placed on it, and it
will be prevented from having allocations assigned to it.

Generally, SKUs must be manually added a site to configure its SKUs. At some point, we may do this during the site
bring-up process. However, for now, SKUs are only manually added to sites. It is also expected that, generally,
the SKU assignments for individual machines are added automatically by Forge as those machines are reconfigured.

### Configuration

SKU validation is enabled or disabled for an entire site at once, using the forge configuration file.
The block that defines it is called `bom_validation`, and it currently has two options:

```toml
[bom_validation]
enabled = false
ignore_unassigned_machines = false
```

 - `enabled` - Enables or disables the entire bom validation process.  When disabled, machines
  will skip bom validation and proceed as if all validation has passed.
 - `ignore_unassigned_machines` - When true and BOM validation encounters a machine that does not have an associated SKU,
  it will proceed as if all validation has passed. Only machines with an associated SKU will be validated. This allows 
  existing sites to be upgraded and BOM Validation enabled as SKUs are added to the system without impacting site operation.

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

For a given machine ID to show the SKU information (note this has no effect on the site and is safe to run):

```sh
export CARBIDE_API_URL="https://api-<site>.frg.nvidia.com"

forge-admin-cli sku generate <machineid>
```

### Creating SKUs for a Site

To create a SKU, the easiest method is generally taking the configuration of an example, known good machine
(this can be verified during creation) and applying that to the site.

Using information from the viewed SKU information above (vendor, model, and node type), you should be able to
create the `sku_name`, and using the example machine, then create the SKU config and upload it to the
site controller.

Create the SKU information (on your local machine, written to an output file):

```sh
export CARBIDE_API_URL="https://api-<site>.frg.nvidia.com"

forge-admin-cli -f json -o <sku_name>.json sku generate <machineid> --id <sku_name> 
```

This will create a file in the current directory with the name `<sku_name>.json`, at this point you can create the 
SKU on the site controller:

```sh
forge-admin-cli sku create <sku_name>.json
```

### Assign a SKU to a machine

Note that generally, you do not need to assign a SKU to a machine, since the SKU is automatically assigned when the
machine goes to ready (not assigned) state, or goes through a machine validation workflow.

```sh
export CARBIDE_API_URL="https://api-<site>.frg.nvidia.com"

forge-admin-cli sku assign <sku_name> <machineid> 
```

### Remove a SKU assignment from a machine

To remove the assignment of a SKU from a machine, the `sku unassign` can be used. Note that if a machine already matches
a SKU in the given site, and it is not in an assigned state, it will likely be quickly reassigned automatically by
the site controller after this command is run.

```sh
export CARBIDE_API_URL="https://api-<site>.frg.nvidia.com"

forge-admin-cli sku unassign <machineid> 
```

### Remove a SKU from a site

To remove a SKU from a site, you must first remove all machines that have been assigned that SKU manually, you may want
to run the `sku unassign` command above in a shell loop to remove all the machines quickly. Note that you can query which
machines have a given SKU using the command below, `sku show-machines` then follow it with the
following command to remove the SKU:

```sh
export CARBIDE_API_URL="https://api-<site>.frg.nvidia.com"

forge-admin-cli sku delete <sku_name>
```

### Finding assigned machines for a SKU

To find all the assigned machines for a given SKU:

```sh
export CARBIDE_API_URL="https://api-<site>.frg.nvidia.com"

forge-admin-cli sku show-machines <sku_name>
```

### Force SKU revalidation

It may be beneficial when diagnosing a machine to force Forge to revalidate a SKU on a machine, if the machine is suspected
of issues, or if you believe that the validation may be out of date. You can force a revalidation with the command below,
it will be validated the next time the machine is unreserved. Note that you cannot validate a reserved machine, and Forge
will refrain from doing so automatically.

NOTE: SKU Validation may have bugs that require a machine reboot to reconcile.

```sh
export CARBIDE_API_URL="https://api-<site>.frg.nvidia.com"

forge-admin-cli sku verify <sku_name>
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