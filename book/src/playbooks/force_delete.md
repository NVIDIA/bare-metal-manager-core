# Force deleting an rebuilding Forge hosts

In various cases it might be necessary to force-delete knowledge about hosts from
the Forge database, and to restart the discovery process for those. Examples for
use-cases where force-delete can be helpful are:
- If a host managed by Forge has entered an errorenous state from which it can not
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

The following steps can be used to force-delete knowledge about a a Forge host:

### 1. Obtain access to `forge-admin-cli`

See [forge-admin-cli access on a Forge cluster](forge_admin_cli.md).

### 2. Execute the `forge-admin-cli machine force-delete` command

Executing `forge-admin-cli machine force-delete` will wipe most knowledge about
machines and instances running on top of them from the database, and clean up associated CRDs.
It accepts the machine-id, hostname,  MAC or IP of either the managed host or DPU as input,
and will delete information about both of them (since they are heavily coupled).

It returns all machine-ids and instance-ids it acted on, as well as the BMC informations for the host.

Example:

```
/opt/carbide/forge-admin-cli -c https://127.0.0.1:1079 machine force-delete --machine="60cef902-9779-4666-8362-c9bb4b37184f"
```

### 3. Use the returned BMP IP/port and machine-id to reboot the host

See [Rebooting a machine](machine_reboot.md).
Supply the BMC IP and port of the manged host, as well as it's `machine_id`
as parameters.

Force-deleting a machine will not delete its last set of credentials from `vault`. Therefore the site controller can still access those.

Once a reboot is triggered, the DPU of the Machine should boot into the
Forge discovery image again. This should initiate DPU discovery. A second
reboot is required to initiate host discovery. After those steps, the host
should be fully rebuilt and available.
