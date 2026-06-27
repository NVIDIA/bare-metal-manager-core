# Tenant Lifecycle Cleanup

Use this workflow to release an instance, track NICo cleanup progress, and
verify that the host is ready for reuse.

When an instance is released, NICo removes the host from tenant service, returns
networking to the admin side, runs cleanup and sanitization workflows, performs
the configured trust checks, validates the host, and returns the managed host to
`Ready` when it is eligible for allocation again.

For reference, see:

- [Managed Host State Diagrams](../architecture/state_machines/managedhost.md)
- [Repair Workflows](../manuals/repair/overview.md)
- [Measured Boot Ingest Guidance](../provisioning/ingesting-hosts.md#measured-boot)
- [Core Metrics](../observability/core_metrics.md)

## Release an Instance

Release the instance:

```bash
nicocli instance delete <instance-id>
```

In TUI mode:

```text
nicocli tui
> instance delete
```

Instance deletion triggers the same cleanup and sanitization workflow described
on this page. Track the REST-side instance lifecycle with:

```bash
nicocli instance status-history <instance-id>
nicocli instance get <instance-id>
```

`nico-admin-cli` can also release by instance ID or by machine ID when a
Core gRPC operation is required:

```bash
nico-admin-cli -c <core-api-url> instance release --instance <instance-id>
nico-admin-cli -c <core-api-url> instance release --machine <machine-id>
```

`<core-api-url>` is the NICo Core gRPC API endpoint used by
`nico-admin-cli`. REST and `nicocli` commands use the REST API base URL from
the `nicocli` config.

To report a hardware, network, performance, or other issue during release, see
[Repair Workflows](../manuals/repair/overview.md).

When the release request is accepted, cleanup is asynchronous. Track the
instance lifecycle first, then inspect the managed-host state when site-level
cleanup detail is needed.

## Cleanup Flow

NICo drives tenant cleanup through the managed-host state machine. The normal
release-to-ready flow is:

```text
Assigned/BootingWithDiscoveryImage
Assigned/SwitchToAdminNetwork
Assigned/WaitingForNetworkReconfig
PostAssignedMeasuring/WaitingForMeasurements   (when attestation is enabled)
WaitingForCleanup/Init
WaitingForCleanup/SecureEraseBoss              (Dell BOSS platforms)
WaitingForCleanup/HostCleanup
WaitingForCleanup/CreateBossVolume             (Dell BOSS platforms)
BomValidating/UpdatingInventory
Ready
```

If attestation is disabled, NICo moves from
`Assigned/WaitingForNetworkReconfig` directly into `WaitingForCleanup/Init`.

During the flow, NICo:

1. Reboots the host into the discovery image used by Scout.
2. Switches DPU and DPA networking back to the admin network.
3. Waits for network configuration, extension services, and cleanup-related
   health reports to converge.
4. Deletes the instance record and releases tenant network resources.
5. Runs measured boot or attestation checks when configured.
6. Runs storage, memory-overwrite, and InfiniBand cleanup from Scout.
7. Applies Redfish power control where needed to complete cleanup and pending
   platform changes.
8. Validates inventory before returning the host to `Ready`.

## Track Progress

Use two layers of inspection:

| Layer | Tool | Use |
|---|---|---|
| REST tenant and provider lifecycle | `nicocli` | Instance deletion, instance status, status history, and tenant-visible errors. |
| Core site cleanup lifecycle | `nico-admin-cli` | Managed-host state, machine state history, health reports, measured boot, and cleanup-specific debugging. |

Start with the REST-side instance status:

```bash
nicocli instance status-history <instance-id>
nicocli instance get <instance-id>
```

If cleanup progress is unclear from the instance lifecycle, check the
managed-host state:

```bash
nico-admin-cli -c <core-api-url> managed-host show <machine-id>
```

Check the machine view for state history and platform details:

```bash
nico-admin-cli -c <core-api-url> machine show <machine-id>
```

Check health reports when cleanup appears blocked:

```bash
nico-admin-cli -c <core-api-url> machine health-report show <machine-id>
```

### Happy Path Verification

A normal release can be verified with this sequence:

```bash
nicocli instance delete <instance-id>
nicocli instance status-history <instance-id>
nico-admin-cli -c <core-api-url> managed-host show <machine-id>
nico-admin-cli -c <core-api-url> machine health-report show <machine-id>
```

Success indicators:

- The instance moves through deletion or termination from the REST perspective.
- The managed host progresses through the cleanup states and reaches `Ready`.
- Cleanup-related health reports are clear.
- No blocking health report prevents allocation.

Useful metrics for fleet-level monitoring include:

| Metric | Use |
|---|---|
| `carbide_machines_per_state` | Count machines in each managed-host state. |
| `carbide_machines_per_state_above_sla` | Find machines that have remained in a state longer than the state-machine SLA. |
| `carbide_machines_time_in_state_seconds` | Review time spent in each state. |
| `carbide_reboot_attempts_in_booting_with_discovery_image` | Detect hosts that require repeated discovery-image reboots. |
| `carbide_measured_boot_machines_per_machine_state_total` | Review measured boot machine state coverage. |
| `carbide_pending_host_firmware_update_count` | Count hosts that need host firmware updates. |
| `carbide_pending_dpu_nic_firmware_update_count` | Count DPUs that need NIC firmware updates. |
| `carbide_active_host_firmware_update_count` | Count hosts actively updating firmware. |
| `carbide_running_dpu_updates_count` | Count DPUs actively updating firmware. |

## Sanitization Steps

Scout reports cleanup through `CleanupMachineCompleted`. The cleanup report can
include these step results:

| Field | Meaning |
|---|---|
| `nvme` | NVMe cleanup result. |
| `hdd` | HDD/SAS block-device cleanup result. |
| `ram` | RAM cleanup result, when present. |
| `mem_overwrite` | UEFI `MemoryOverwriteRequestControl` validation result. |
| `ib` | InfiniBand cleanup result. |

Each step has a result and a message. A failed NVMe cleanup moves the host to an
`NVMECleanFailed` failure state and keeps the host out of `Ready`.

### NVMe Secure Erase

Scout discovers NVMe controller devices and formats each namespace with secure
erase:

```bash
nvme format <controller-device> -s2 -f -n <namespace-id>
```

When namespace management is supported, Scout deletes existing namespaces after
format, creates a replacement namespace sized from controller capacity, and
attaches it to the controller.

On supported Lenovo M.2 NVMe 2-Bay RAID Kit systems, Scout uses `mnv_cli` to
remove RAID virtual disks and send NVMe passthrough cleanup commands to the
underlying disks.

### HDD and SAS Cleanup

Scout also reports an `hdd` cleanup result for HDD/SAS block-device cleanup.
Treat a failed `hdd` result the same way as other cleanup failures: keep the
host out of allocation until the failure is remediated and the cleanup path
completes successfully.

### Memory Overwrite

Scout validates the UEFI memory-overwrite control variable:

```text
MemoryOverwriteRequestControl-e20939be-32d4-41be-a150-897f85d49829
```

The `mem_overwrite` cleanup step passes when the variable is set to `1`. If site
policy requires a manual volatile-memory procedure, such as a full AC drain,
complete that procedure before returning the host to allocation.

### Dell BOSS Cleanup

On supported Dell platforms with a BOSS controller, NICo performs additional
storage cleanup:

1. Disable iDRAC lockdown for the storage operation.
2. Decommission the BOSS storage controller through Redfish.
3. Wait for the Redfish job to complete.
4. Run Scout host cleanup.
5. Recreate the BOSS virtual disk as `VD_0`.
6. Re-enable host lockdown.
7. Continue to post-cleanup validation.

If the Redfish job fails, NICo retries the job path and may power-cycle the host
as part of the recovery loop.

### InfiniBand Cleanup

Scout reports InfiniBand cleanup through the `ib` cleanup step. NICo also uses
cleanup-related health reports, including `IbCleanupPending`, to prevent the
state machine from advancing before InfiniBand cleanup has cleared.

## Platform Reset and Trust Controls

Tenant cleanup includes platform and trust controls that run through Redfish,
firmware management, measured boot, and site policy.

| Control | How to verify |
|---|---|
| Redfish power control | The state machine uses `ForceRestart` during cleanup and after Scout cleanup completion. Redfish `ForceRestart` is also the reset type used to apply pending BIOS or UEFI changes. |
| TPM clear | NICo includes vendor-specific Redfish support for TPM clear. Verify completion through the platform-specific cleanup evidence used by the site. |
| BIOS recommit | Verify that pending BIOS or UEFI settings have been applied after the cleanup `ForceRestart` path. |
| DPU restricted mode and BMC in-band restrictions | Verify that tenant-side network configuration has been removed, admin-network configuration has synced, and platform lockdown settings are in the expected post-cleanup state. |
| Firmware default version | Verify that host and DPU firmware match the configured site default or are under an approved firmware update workflow. |
| Measured boot | Verify measured boot state when attestation is enabled. Measured boot may be configured in permissive mode; in that mode, use measurement results as cleanup evidence according to site policy. |

Useful attestation commands include:

```bash
nico-admin-cli -c <core-api-url> attestation measured-boot machine show <machine-id>
nico-admin-cli -c <core-api-url> att mb machine show <machine-id>
```

## Return-to-Pool Checklist

A released host is ready for reuse when all required gates pass:

- The prior instance is released and no longer active.
- Tenant VPC prefix segments and DPU loopback IP allocations are released.
- DPU and DPA networking have returned to the admin network.
- Extension services from the prior tenant have terminated.
- Scout cleanup has completed.
- NVMe and HDD/SAS cleanup have succeeded, or an approved exception exists.
- The memory-overwrite check has passed, and any required manual
  volatile-memory procedure is complete.
- InfiniBand cleanup has completed and blocking cleanup health reports are
  clear.
- TPM, BIOS/UEFI, lockdown, and firmware checks satisfy site policy.
- Measured boot or attestation checks satisfy site policy.
- Inventory validation has completed.
- The managed host is in `Ready`.
- No blocking health report prevents allocation.

## Troubleshooting Stuck Cleanup

Use the current managed-host state to choose the next check.

Start with the REST lifecycle:

```bash
nicocli instance status-history <instance-id>
nicocli instance list --status error --output table
```

If the REST lifecycle does not explain the stall, inspect the Core cleanup
state:

```bash
nico-admin-cli -c <core-api-url> managed-host show <machine-id>
nico-admin-cli -c <core-api-url> machine health-report show <machine-id>
```

| State | What it means | Checks |
|---|---|---|
| `Assigned/BootingWithDiscoveryImage` | The host is rebooting into the discovery image. | Check BMC reachability, host power state, boot order, and repeated reboot metrics. |
| `Assigned/SwitchToAdminNetwork` | NICo is moving the host out of tenant networking. | Check DPU agent status, DPA status, and admin-network config generation. |
| `Assigned/WaitingForNetworkReconfig` | NICo is waiting for network configuration to converge. | Check DPU sync, DPA sync, extension-service termination, and cleanup-related health reports. |
| `PostAssignedMeasuring/WaitingForMeasurements` | Attestation is enabled and NICo is waiting for measurements. | Check measured boot machine state, trusted profile or bundle status, and site policy for permissive mode. |
| `WaitingForCleanup/SecureEraseBoss` | NICo is decommissioning Dell BOSS storage. | Check iDRAC lockdown state, Redfish job status, and BOSS controller reachability. |
| `WaitingForCleanup/HostCleanup` | NICo is waiting for Scout cleanup completion. | Check Scout logs, cleanup report submission, NVMe/HDD cleanup, memory-overwrite result, and InfiniBand cleanup result. |
| `WaitingForCleanup/CreateBossVolume` | NICo is recreating the Dell BOSS virtual disk. | Check Redfish job status and confirm the recreated volume is `VD_0`. |
| `BomValidating/UpdatingInventory` | Cleanup completed and NICo is validating inventory. | Check BMC reachability, inventory collection, firmware update status, and blocking health reports. |
| `Failed` with `NVMECleanFailed` | Storage cleanup failed. | Keep the host out of allocation, inspect the cleanup error message, remediate the storage issue, and rerun the approved cleanup recovery path. |

For log review, start with the NICo API or state-controller logs, Scout cleanup
logs, DPU agent logs, hardware-health logs, and Redfish job status from the BMC.

## Manual Procedures

Some environments require additional manual assurance before a host is reused.
Apply these only when required by site policy:

- Full AC drain for volatile-memory handling.
- Firmware bundle reflash.
- Manual TPM clear if automated platform cleanup is unavailable.
- Manual firmware remediation when a host or DPU does not match the configured
  site default.

Record the completed procedure, the target machine ID, the reason, the operator,
and the evidence used to approve return to allocation.
