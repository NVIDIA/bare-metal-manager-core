# Force deleting and rebuilding Carbide hosts

In various cases it might be necessary to force-delete knowledge about hosts from
the Carbide database, and to restart the discovery process for those. Examples for
use-cases where force-delete can be helpful:

- If a host managed by Carbide has entered an errorenous state from which it can not
automatically recover
- If a non backward compatible software update requires the host to go through the discovery phase again

## Important note

*This this is not a site-provider facing workflow, since force-deleting a machine
does skip any cleanup on the machine and leaves it in an undefined state where the tenants OS could be still running.
force-deleting machines is purely an operational tool. The operator which executed the
command needs to make sure that either no tenant image is running anymore, or take additional steps
(like rebooting the machine) to interrupt the image.
Site providers would get a safe version of this workflow later on that moves the machine through all necessary cleanup steps*

## Force-Deletion Steps

The following steps can be used to force-delete knowledge about a a Carbide host:

### 1. Obtain access to `carbide-admin-cli`

See [carbide-admin-cli access on a Carbide cluster](../sites/forge_admin_cli.md).

### 2. Execute the `carbide-admin-cli machine force-delete` command

Executing `carbide-admin-cli machine force-delete` will wipe most knowledge about
machines and instances running on top of them from the database, and clean up associated CRDs.
It accepts the machine-id, hostname,  MAC or IP of either the managed host or DPU as input,
and will delete information about both of them (since they are heavily coupled).

It returns all machine-ids and instance-ids it acted on, as well as the BMC information for the host.

Example:

```
/opt/carbide/carbide-admin-cli -c https://127.0.0.1:1079 machine force-delete --machine="60cef902-9779-4666-8362-c9bb4b37184f"
```

### 3. Use the returned BMP IP/port and machine-id to reboot the host

See [Rebooting a machine](machine_reboot.md).
Supply the BMC IP and port of the managed host, as well as its `machine_id`
as parameters.

Force-deleting a machine will not delete its last set of credentials from `vault`. Therefore the site controller can still access those.

Once a reboot is triggered, the DPU of the Machine should boot into the
Carbide discovery image again. This should initiate DPU discovery. A second
reboot is required to initiate host discovery. After those steps, the host
should be fully rebuilt and available.

## Reinstall OS Steps

Deleting and recreating a Carbide instance can take upwards of 1.5 hours. However, if you do not need to change the
PXE image you can reinstall the OS in place and reuse your allocated system. All the other information about your
instance will stay the same. *This procedure will delete any data on the host!*

The following steps can be used to reinstall the host OS on a Carbide host:

### 1. Obtain access to the `carbide-admin-cli` tool

See [carbide-admin-cli access on a Carbide cluster](../sites/forge_admin_cli.md).

### 3. Execute the `carbide-admin-cli instance reboot --custom-pxe` command

```
carbide-admin-cli -f json -c https://api-dev4.frg.nvidia.com/ instance reboot --custom-pxe -i 26204c21-83ac-445e-8ea7-b9130deb6315
Reboot for instance 26204c21-83ac-445e-8ea7-b9130deb6315 (machine fm100hti4deucakqqgteo692efnfo7egh7pq1lkl7vkgas4o6e0c42hnb80) is requested successfully!
```
