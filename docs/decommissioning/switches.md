# Decommission managed switches

Use this procedure to return a managed NVIDIA switch to a factory baseline.
After the switch reaches `Decommissioning/Decommissioned`, force-delete it to
remove the control-plane records. The workflow resets both the NVOS data plane
and the switch BMC.

## Before you begin

- The switch must be in the exact controller state `Ready`.
- No managed host assigned to an instance can remain in the same rack.
- Managed-switch decommissioning requires the RMS component-manager backend.
  The API rejects the request when RMS is unavailable or another switch backend
  is configured.
- Keep the NICo API, database, credentials store, DHCP service, Site
  Explorer, RMS, and BMC and NVOS management networks available.
- If the switch will be ingested again, record the BMC MAC, NVOS MAC
  addresses, chassis serial number, rack ID, and factory BMC and NVOS
  credentials needed to create the Expected Switch.

Decommission hosts first so that switch and rack connectivity remain available
while compute devices reset.

## Start and monitor decommissioning

Start the asynchronous workflow with the stable managed-switch ID:

```bash
nico-admin-cli -a <old-api-url> managed-switch decommission <switch-id>
```

Monitor it until the state reaches `Decommissioning/Decommissioned`:

```bash
nico-admin-cli -a <old-api-url> managed-switch show <switch-id>
```

Operational failures leave the switch in the same substate for retry instead
of moving it to the top-level `Error` state. Inspect the controller outcome
before intervening.

## What the workflow changes

NICo performs these operations in order:

1. Creates a Site Explorer suppression for the switch BMC and waits for Site
   Explorer to acknowledge it.
1. Creates a DHCP suppression for the NVOS interface.
1. Uses the RMS component-manager backend to submit an NVOS factory-reset job.
   The RMS reset wipes NVOS configuration, restarts the switch, and preserves
   the factory-default password.
1. Waits for the DHCP service to acknowledge the NVOS suppression.
1. Creates a DHCP suppression for the switch BMC.
1. Uses Redfish to factory-reset the switch BMC.
1. Waits for the DHCP service to acknowledge the BMC suppression.
1. Deletes the switch's managed BMC root credential and NVOS administrator
   credential from the old credentials store.
1. Deletes the BMC and NVOS credential-convergence records.
1. Stops in `Decommissioning/Decommissioned`.

The workflow does not poll the RMS factory-reset job to completion. After
submitting the reset, it advances when the DHCP suppression is acknowledged.
Similarly, a successful Redfish response means that the BMC accepted its reset
request; the BMC can still be restarting.

## Verify the resulting state

Before you force-delete the switch, verify:

- NVOS completed its factory reset and no old configuration, users,
  certificates, or controller trust remain.
- The BMC completed its reset and accepts the applicable factory credentials.
- The BMC and NVOS interfaces no longer receive configuration from the old
  NICo DHCP service.
- The old NICo credentials store no longer contains the per-switch BMC and
  NVOS credentials.

The `Decommissioned` record and its Site Explorer and DHCP suppressions remain
until you force-delete them. The database also retains the Expected Switch,
interface records, state history, rack association, and metadata until that
delete. Site-wide NVOS rotation targets remain in the credentials store; only
the per-switch credentials are deleted.

## After decommissioning

When the switch reaches `Decommissioning/Decommissioned`, force-delete it with
the flags that remove interfaces and suppressions:

```bash
nico-admin-cli -a <api-url> switch force-delete \
  <switch-id> \
  --delete-interfaces \
  --delete-bmc-suppressions
```

If the switch is still physically present, Site Explorer ingests it from the
reset state. If you confirm it is no longer in the site, it does not come
back and those records are gone.

Refer to the
[switch force-delete command](../manuals/nico-admin-cli/commands/switch/switch-force-delete.md)
for the control-plane cleanup options.

## Prepare the new installation

Create the new Expected Switch with values that match the reset device:

- `--bmc-mac-address`, `--switch-serial-number`, and each
  `--nvos-mac-address` identify the switch.
- `--bmc-username` and `--bmc-password` must be the factory credentials that
  work after the reset.
- `--nvos-username` and `--nvos-password`, when supplied, must match the NVOS
  factory credentials.
- Set `--bmc-retain-credentials true` only when the new site must keep the
  factory BMC credential. Otherwise, Site Explorer rotates the BMC password to
  the new site's configured value.

Refer to the
[expected-switch add command](../manuals/nico-admin-cli/commands/expected-switch/expected-switch-add.md)
for the complete interface.

## Recover a switch after the old site is gone

The supported NVOS factory reset depends on RMS and credentials from the old
site. If that path is gone, use the switch platform's approved RMS or
out-of-band factory-reset procedure. Verify that it removes configuration,
users, and certificates; deleting the NICo switch row cannot do that.

If you know the current switch BMC credentials, you can request the BMC reset
directly:

```bash
nico-admin-cli redfish \
  --address <switch-bmc-ip> \
  --username <bmc-user> \
  --password '<current-bmc-password>' \
  bmc-reset-to-defaults
```

Wait for the BMC to restart and verify the factory login before adding the
Expected Switch to the new site. If the old credential is unknown, use the
hardware vendor's recovery procedure; the new credentials store cannot infer
it.

<Warning>
Command-line passwords can be visible in shell history and process listings.
Use direct Redfish commands only in an approved recovery environment and follow
your site's secret-handling policy.
</Warning>
