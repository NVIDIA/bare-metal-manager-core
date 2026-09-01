# Decommission power shelves

Use this procedure to return a managed power shelf BMC or power-management
controller (PMC) to its factory baseline. After the shelf reaches
`Decommissioning/Decommissioned`, force-delete it to remove the control-plane
records.

<Warning>
Decommissioning a power shelf resets its management controller. Preserve rack
power until all hosts and switches have finished decommissioning and passed
their post-reset checks.
</Warning>

## Before you begin

- The power shelf must be in the exact controller state `Ready`.
- No managed host assigned to an instance can remain in the same rack.
- Keep the NICo API, database, credentials store, DHCP service, Site
  Explorer, and BMC management network available.
- If the shelf will be ingested again, record the BMC MAC, shelf serial
  number, rack ID, and factory BMC credentials needed to create the Expected
  Power Shelf.

Decommission power shelves last, after managed hosts and managed switches.

## Start and monitor decommissioning

Start the asynchronous workflow with the stable power-shelf ID:

```bash
nico-admin-cli -a <old-api-url> power-shelf decommission <power-shelf-id>
```

Monitor it until the state reaches `Decommissioning/Decommissioned`:

```bash
nico-admin-cli -a <old-api-url> power-shelf show <power-shelf-id>
```

Operational failures leave the shelf in the same substate for retry instead
of moving it to the top-level `Error` state. Inspect the controller outcome
before intervening.

## What the workflow changes

NICo performs these operations in order:

1. Creates a Site Explorer suppression for the shelf BMC and waits for Site
   Explorer to acknowledge it.
1. Creates a DHCP suppression for the shelf BMC.
1. Uses a direct Redfish connection to factory-reset the BMC or PMC. This
   operation does not use RMS.
1. Waits for the DHCP service to acknowledge the BMC suppression.
1. Deletes the shelf's managed BMC root credential from the old credentials
   store.
1. Deletes the BMC credential-convergence record.
1. Stops in `Decommissioning/Decommissioned`.

A successful Redfish response means that the BMC accepted the factory-reset
request. The BMC can still be restarting when the workflow advances.
Decommissioning resets management state; it does not delete the expected
inventory definition or explicitly change rack power output.

## Verify the resulting state

Before you force-delete the shelf, verify:

- The BMC or PMC completed its reset and accepts the applicable factory
  credentials.
- The management interface no longer receives configuration from the old NICo
  DHCP service.
- The old NICo credentials store no longer contains the per-shelf BMC
  credential.
- Rack power remains in the state required for the rest of the maintenance
  procedure.

The `Decommissioned` record and its Site Explorer and DHCP suppressions remain
until you force-delete them. The database also retains the Expected Power
Shelf, interface records, state history, rack association, and metadata until
that delete. Site-wide BMC rotation targets remain in the credentials store;
only the per-shelf credential is deleted.

## After decommissioning

When the shelf reaches `Decommissioning/Decommissioned`, force-delete it with
the flags that remove interfaces and suppressions:

```bash
nico-admin-cli -a <api-url> power-shelf force-delete \
  <power-shelf-id> \
  --delete-interfaces \
  --delete-bmc-suppressions
```

If the shelf is still physically present, Site Explorer ingests it from the
reset state. If you confirm it is no longer in the site, it does not come
back and those records are gone.

Refer to the
[power-shelf force-delete command](../manuals/nico-admin-cli/commands/power-shelf/power-shelf-force-delete.md)
for the control-plane cleanup options.

## Prepare the new installation

Create the new Expected Power Shelf with values that match the reset device:

- `--bmc-mac-address` and `--shelf-serial-number` identify the shelf.
- `--bmc-username` and `--bmc-password` must be the factory credentials that
  work after the reset.
- Set `--bmc-retain-credentials true` only when the new site must keep the
  factory credential. Otherwise, Site Explorer rotates the BMC password to the
  new site's configured value.

Refer to the
[expected-power-shelf add command](../manuals/nico-admin-cli/commands/expected-power-shelf/expected-power-shelf-add.md)
for the complete interface.

## Recover a shelf after the old site is gone

If you know the current shelf BMC credentials, request the reset directly:

```bash
nico-admin-cli redfish \
  --address <power-shelf-bmc-ip> \
  --username <bmc-user> \
  --password '<current-bmc-password>' \
  bmc-reset-to-defaults
```

Wait for the BMC to restart and verify the factory login before adding the
Expected Power Shelf to the new site. If the old credential is unknown, use the
power-shelf vendor's approved recovery procedure; the new credentials store
cannot infer it.

<Warning>
Command-line passwords can be visible in shell history and process listings.
Use direct Redfish commands only in an approved recovery environment and follow
your site's secret-handling policy.
</Warning>
