# Decommission NICo-managed hardware

Decommissioning returns managed hardware to a factory or pre-ingestion baseline
while NICo still has credentials and management access. Use it when you intend
one of these outcomes:

1. The hardware is permanently leaving the site, either because the site is
   being torn down or the device is leaving service.
2. The hardware should be ingested again from a clean pre-ingestion state.

After the controller reaches `Decommissioning/Decommissioned`, remove the
hardware from this site by force-deleting it, or move it to a new site. If
you force-delete and the hardware is still physically present, Site Explorer
ingests it again. If you confirm it is gone, it does not return and the
control-plane records are removed.

Decommissioning is the graceful device-cleanup step before you force-delete
or move the hardware. Tenant lifecycle cleanup is different: it returns a
host to `Ready` in the same installation without removing NICo ownership.

<Warning>
Run decommissioning while the current NICo API, database, credentials store,
DHCP service, PXE service, and required management backends are available. If
you destroy the control plane first, the credentials and state needed to reset
the devices can be unrecoverable.
</Warning>

## Choose a procedure

- [Decommission hosts and DPUs](hosts.md) resets host firmware configuration,
  SuperNIC lockdown, DPU images, host and DPU BMCs, and managed credentials.
- [Decommission managed switches](switches.md) factory-resets NVOS and the
  switch BMC, then removes managed NVOS and BMC credentials.
- [Decommission power shelves](power-shelves.md) factory-resets the shelf BMC
  or PMC, then removes its managed BMC credential.

## Decommission a rack

The Flow `DecommissionRack` API returns `Unimplemented`. Decommission each
component with `nico-admin-cli`. Hosts must be `Ready` (no assigned instance)
before you start. Switch and power-shelf decommissioning also reject the
request while a managed host in the same rack remains assigned.

Use this order:

1. Decommission every managed host and wait for all of them to reach
   `Decommissioning/Decommissioned`.
2. Decommission every managed switch and wait for all of them to reach
   `Decommissioning/Decommissioned`.
3. Decommission every power shelf and wait for all of them to reach
   `Decommissioning/Decommissioned`.

After those steps finish, remove the hardware from this site with
[force-delete](#force-delete-after-decommissioning), or move it to a new
site. This order preserves network and rack power management while compute
devices are being reset.

## Force-delete after decommissioning

Use these commands when you are removing decommissioned hardware from this
site. They remove interfaces, suppressions, and retained boot entries where
those exist. Skip force-delete when you are moving the hardware to a new
site and tearing down this installation.

Host:

```bash
nico-admin-cli -a <api-url> machine force-delete \
  --machine <host-machine-id> \
  --delete-interfaces \
  --delete-bmc-interfaces \
  --delete-bmc-suppressions \
  --delete-retained-boot-interfaces
```

Switch:

```bash
nico-admin-cli -a <api-url> switch force-delete \
  <switch-id> \
  --delete-interfaces \
  --delete-bmc-suppressions
```

Power shelf:

```bash
nico-admin-cli -a <api-url> power-shelf force-delete \
  <power-shelf-id> \
  --delete-interfaces \
  --delete-bmc-suppressions
```

## Understand the terminal state

`Decommissioning/Decommissioned` is a terminal controller state. It does not
delete the object. Site Explorer and DHCP suppressions remain until you
force-delete them, so the same installation does not immediately ingest a
reset device.

Some Redfish and RMS reset calls return after accepting a request rather than
after the hardware finishes applying it. Verify the resulting device state and
factory credentials before you force-delete or tear down the installation.

## Rebuild and re-ingest

When the same hardware will join a rebuilt NICo installation:

1. Decommission the hardware and force-delete the old records, or tear down
   the old database after decommissioning completes.
2. Rebuild NICo and its credentials store and database.
3. Point the rack management networks and DHCP relays at the new site.
4. Recreate the expected host, switch, and power-shelf inventory with the
   factory credentials that now exist on the devices.
5. Configure the new site's desired BMC, UEFI, and NVOS credentials.
6. Start ingestion and verify that Site Explorer discovers only identities
   owned by the new installation.

Refer to [Ingesting Hosts](../provisioning/ingesting-hosts.md) and
[Rack-Level Administration](../manuals/rack_level_admin.md) for site and rack
setup.
