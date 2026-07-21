# Managed Power Shelf Decommissioning

## Status

Draft

## Summary

This document defines the managed-power-shelf specialization of the
[shared decommissioning lifecycle](/docs/design/decommissioning/decommissioning-workflow.md).
A managed
power shelf is returned to a neutral state by resetting its PMC management
credential and removing NICo's stored per-shelf credential state. No firmware,
configuration, or power-state change is required by this design.

Decommissioning starts only from `Ready` and only when no managed host on the
power shelf's rack is in use. It ends in the retained terminal
`Decommissioned` state. Final deletion preserves the
`expected_power_shelves` record so a connected shelf can be discovered and
ingested again.

## Invariants

The power-shelf workflow inherits all
[common invariants](/docs/design/decommissioning/decommissioning-workflow.md#common-invariants).
In
particular:

1. The PMC credential is reset and verified before NICo removes its stored
   credential.
2. The power shelf cannot enter `Decommissioned` while the credential reset is
   unverified.
3. Decommissioning does not change shelf power state or firmware.
4. `expected_power_shelves` is preserved by decommissioning and final deletion.

## Proposed state model

Add two states to `PowerShelfControllerState`:

```rust
Decommissioning {
    decommissioning_state: PowerShelfDecommissioningState,
},
Decommissioned,
```

```rust
enum PowerShelfDecommissioningState {
    Preparing,
    RemovingManagedCredentials,
    Finalizing,
}
```

Each substate persists its retry count, last redacted error, last-attempt time,
and any asynchronous operation identifier in the normal controller outcome
fields.

The externally reported state strings are:

- `Decommissioning/Preparing`
- `Decommissioning/RemovingManagedCredentials`
- `Decommissioning/Finalizing`
- `Decommissioned`

### State diagram

```mermaid
stateDiagram-v2
    state "Ready" as Ready
    state "Decommissioning/Preparing" as Preparing
    state "Decommissioning/RemovingManagedCredentials" as RemovingCredentials
    state "Decommissioning/Finalizing" as Finalizing
    state "Decommissioned" as Decommissioned
    state "Deleted" as Deleted
    state "Fresh ingestion" as FreshIngestion

    Ready --> Preparing : DecommissionPowerShelf accepted
    Preparing --> RemovingCredentials : preflight and rack gate pass
    RemovingCredentials --> Finalizing : PMC reset and stored cleanup verified
    Finalizing --> Decommissioned : DHCP suppression committed
    Decommissioned --> Deleted : DeleteDecommissionedPowerShelf
    Deleted --> FreshIngestion : expected power shelf remains
```

### Transition criteria

| From | To | Required criteria |
| --- | --- | --- |
| `Ready` | `Decommissioning/Preparing` | The request is authorized; the power shelf is exactly `Ready`; its rack is known; no managed host on the rack is in use; and no maintenance, firmware, rack, or other exclusive operation is active. |
| `Preparing` | `RemovingManagedCredentials` | The PMC MAC and `expected_power_shelves` record exist; Site Explorer is suppressed for the PMC; and the current and neutral PMC credentials are available. |
| `RemovingManagedCredentials` | `Finalizing` | The PMC credential reset is verified, and NICo-held PMC credential material, sessions, and rotation markers are absent. |
| `Finalizing` | `Decommissioned` | PMC DHCP is suppressed, the current PMC lease is revoked, and the DHCP record cache is invalidated. |
| `Decommissioned` | deleted | `DeleteDecommissionedPowerShelf` is authorized; associated power-shelf state and the PMC ignore row are removed; `expected_power_shelves` remains. |

## State behavior

### `Decommissioning/Preparing`

The start API changes `Ready` to `Preparing`. The state first applies the
[rack unused-host gate](/docs/design/decommissioning/decommissioning-workflow.md#rack-dependency-gate-and-ordering).
It then resolves the expected-power-shelf record, PMC identity, current PMC
credential, and defined neutral credential before changing hardware.

After preflight succeeds, NICo adds the PMC MAC to `ignored_bmc_macs` and sets
`suppress_site_explorer` to `true`. Pending maintenance, firmware, and other
power-shelf requests are cleared so another controller cannot act on the shelf
during decommissioning.

### `Decommissioning/RemovingManagedCredentials`

NICo resets the PMC password to its factory or other defined neutral value,
then reconnects with that value to verify the reset. Only after verification
does NICo remove its per-shelf credential material, active sessions, and
credential-rotation markers.

The operation is converge-and-verify. A PMC already using the neutral password
is successful after authentication verifies that state. An unreachable PMC or
unsupported password-reset operation blocks decommissioning rather than being
treated as success.

This workflow does not power the shelf off, reset its configuration, or change
its firmware.

### `Decommissioning/Finalizing`

The power shelf follows the
[shared finalization](/docs/design/decommissioning/decommissioning-workflow.md#finalizing):
suppress PMC
DHCP, revoke the current lease and address allocation, invalidate the DHCP
cache, and transition to `Decommissioned`.

### `Decommissioned`

NICo retains the power-shelf inventory and completion summary for operator
verification. The shelf is excluded from rack health remediation, maintenance,
firmware, and power operations. The only normal mutation accepted in this state
is final deletion.

## APIs and authorization

### Start decommissioning

```protobuf
rpc DecommissionPowerShelf(DecommissionPowerShelfRequest)
    returns (DecommissionPowerShelfResponse);

message DecommissionPowerShelfRequest {
  PowerShelfId power_shelf_id = 1;
  string message = 2;
}
```

The response returns the canonical power-shelf ID.

### Resume/retry

```protobuf
rpc ResumePowerShelfDecommissioning(
    ResumePowerShelfDecommissioningRequest
) returns (DecommissionPowerShelfResponse);
```

The API reruns the current persisted substate. It does not skip the credential
reset or advance past an unverified result.

### Final deletion

```protobuf
rpc DeleteDecommissionedPowerShelf(
    DeleteDecommissionedPowerShelfRequest
) returns (DeleteDecommissionedPowerShelfResponse);
```

The request is accepted only from exactly `Decommissioned`. It removes the
power shelf, interfaces, observations, health records, DNS/DHCP state, stored
operation state, and PMC ignore row. The `expected_power_shelves` record is
deliberately preserved.

The existing `DeletePowerShelf` and `AdminForceDeletePowerShelf` operations do
not perform or prove this cleanup and are not substitutes for decommissioning.

## Verification plan

In addition to the
[shared verification requirements](/docs/design/decommissioning/decommissioning-workflow.md#shared-verification-requirements),
unit, integration, and hardware qualification must cover:

- rejection when the rack is unknown or any managed host on it is in use;
- rejection while power-shelf maintenance, firmware, rack, or other exclusive
  work is active;
- PMC password reset and verification, including an already-neutral PMC;
- retry after the password write succeeds but verification or stored cleanup
  fails;
- retention of the PMC credential until reset verification finishes;
- no power-state, configuration, or firmware change during decommissioning;
- terminal exclusion from rack and power-shelf controller work; and
- final deletion preserving `expected_power_shelves` and permitting
  reingestion of still-connected hardware.
