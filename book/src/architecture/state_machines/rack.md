# Rack State Machine

This document describes the Finite State Machine (FSM) that governs the lifecycle of a rack in BMMC -- from initial discovery through maintenance, partition-aware validation, and production readiness.

## Design Principles

The rack state machine follows a few key architectural principles:

- **BMMC is minimal**: It only tracks rack/partition state -- it does not orchestrate tests or define which firmware to apply.
- **RVS (Rack Validation Service) drives validation**: An external validation service creates instances with metadata labels that BMMC polls to derive validation progress.
- **Partition-aware**: Validation is tracked at the partition level (groups of nodes, e.g. NVLink domains), not individual components.
- **Maintenance is pluggable**: Firmware upgrades and power sequencing are handled as sub-states with stub transitions, ready for integration with Rack Manager Service.

## High-Level Overview

The following shows the primary states and transitions between them. Note that Error and Deleting states are omitted and transitions out of them are TBD:

<div style="background: white; ">
<!-- Keep the empty line after this or here or the diagram will break -->

```plantuml
@startuml
skinparam state {
  BackgroundColor White
}

state "Expected" as Expected
state "Discovering" as Discovering
state "Maintenance" as Maintenance
state "Validation" as Validation
state "Ready" as Ready

[*] --> Expected : ExpectedMachine/Switch/PS\ncreated with rack ID

Expected --> Discovering : All expected devices\ndiscovered and linked
Discovering --> Maintenance : All machines reached\nManagedHostState::Ready

Maintenance --> Validation : Maintenance completed

Validation --> Ready : All partitions validated

note left of Maintenance
  Sub-states: FirmwareUpgrade,
  PowerSequence, Completed.
  See Maintenance Phase diagram.
end note

note left of Validation
  Sub-states: Pending, InProgress,
  Partial, FailedPartial,
  Validated, Failed.
  See Validation Phase diagram.
end note


note right of Ready
  TODO: Ready should also be able
  to transition into Maintenance
  (e.g. firmware upgrade on live rack).
  Mechanism is TBD.
end note

@enduml
```
</div>

## State Descriptions

| State | Description |
|-------|-------------|
| **Expected** | Initial state. Rack is expected -- waiting for machines, switches, and power shelves to be discovered. Created when `ExpectedMachine`/`ExpectedSwitch`/`ExpectedPowerShelf` references this rack ID. |
| **Discovering** | At least some devices have been linked. Waiting for all expected devices to appear and for all compute trays to reach `ManagedHostState::Ready`. |
| **Maintenance** | Rack is undergoing maintenance (firmware upgrades, power sequencing). See [Maintenance Phase](#maintenance-phase) for sub-states. |
| **Validation** | Rack is in the validation phase. RVS drives partition-level validation via instance metadata labels. See [Validation Phase](#validation-phase) for sub-states. |
| **Ready** | Rack is fully validated and available for production workloads. Monitors for new validation runs. |
| **Error** | Unrecoverable error. Requires manual intervention. Mechanism TBD. **Not shown on the diagram** |
| **Deleting** | Rack is being deleted. Terminal state. Transitioning out of it is TBD. **Not shown on the diagram** |

## Maintenance Phase

After all machines are discovered and ready, the rack enters maintenance before validation begins. Maintenance is currently stubbed -- the firmware upgrade sub-state immediately completes.

<div style="background: white; ">
<!-- Keep the empty line after this or here or the diagram will break -->

```plantuml
@startuml
skinparam state {
  BackgroundColor White
}

state "Discovering" as Discovering

state "Maintenance" as Maintenance {
  state "FirmwareUpgrade" as FW {
    state "Compute" as FW_Compute
    state "Switch" as FW_Switch
    state "PowerShelf" as FW_PS
    state "All" as FW_All
  }

  state "PowerSequence" as Power {
    state "PoweringOn" as POn
    state "PoweringOff" as POff
    state "PowerReset" as PReset
  }

  state "Completed" as Completed
}

state "Validation(Pending)" as VP

Discovering --> FW_Compute : All machines ready

FW_Compute --> Completed : Firmware upgrade done\n(currently stubbed)
FW_Switch --> Completed : (stubbed)
FW_PS --> Completed : (stubbed)
FW_All --> Completed : (stubbed)

POn --> Completed : (stubbed)
POff --> Completed : (stubbed)
PReset --> Completed : (stubbed)

Completed --> VP : Enter validation flow

note top of FW
  TODO: Entry point is currently hardcoded
  to FirmwareUpgrade(Compute). Should become
  configurable per rack/site.
end note

note top of Power
  TODO: Transitions between
  sub-states are TBD.
end note
@enduml
```
</div>

### Maintenance Sub-States

| Sub-State | Description |
|-----------|-------------|
| **FirmwareUpgrade(Compute)** | Firmware upgrade for compute trays. Currently the hardcoded entry point from `Discovering`. |
| **FirmwareUpgrade(Switch)** | Firmware upgrade for switches. Stubbed. |
| **FirmwareUpgrade(PowerShelf)** | Firmware upgrade for power shelves. Stubbed. |
| **FirmwareUpgrade(All)** | Full-rack firmware upgrade, likely delegated to Rack Manager. Stubbed. |
| **PowerSequence(PoweringOn)** | Power-on sequencing. Stubbed. |
| **PowerSequence(PoweringOff)** | Power-off sequencing. Stubbed. |
| **PowerSequence(PowerReset)** | Power reset sequencing. Stubbed. |
| **Completed** | Maintenance is done. Transitions to `Validation(Pending)` to enter the validation flow. |

## Validation Phase

Validation is **partition-aware** and **externally driven**. BMMC does not orchestrate tests -- it polls instance metadata labels set by RVS and aggregates partition status to compute state transitions.

All validation states are sub-states of `Validation { rack_validation }`, mirroring the pattern used by `Maintenance { rack_maintenance }`.

<div style="width: 100%; background: white; ">
<!-- Keep the empty line after this or here or the diagram will break -->

```plantuml
@startuml
skinparam state {
  BackgroundColor White
}

state "Ready" as Ready

state "Validation" as Validation {
  state "Pending" as VP : Waiting for RVS\nto start validation.
  state "InProgress" as VIP : At least one partition started.\nNone completed yet.
  state "Partial" as VP : Some partitions passed.\nNone failed.
  state "FailedPartial" as FP : At least one partition failed.\nRecovery possible.
  state "Validated" as RV : All partitions passed.
  state "Failed" as RF : All partitions failed.
}

[*] --> VP : Maintenance completed

VP --> VIP : RVS starts validation\n(any partition started)

VIP --> VP : At least one\npartition passed\n(none failed)
VIP --> FP : At least one\npartition failed

VP --> RV : All partitions passed
VP --> FP : A partition failed

FP --> RF : All partitions failed
FP --> VP : All failures resolved\n(and at least one passed)
FP --> VIP : All failures resolved\n(none passed yet)
FP --> VP : All partitions reset\nto idle (re-run)

RF --> FP : Recovery started\n(at least one partition\nno longer failed)

RV --> Ready : Validation\ncomplete

Ready --> VIP : New validation\nrun started
Ready --> FP : New validation run\nwith failure

@enduml
```
</div>

### Validation Sub-States

| Sub-State | Description |
|-----------|-------------|
| **Pending** | All nodes discovered, all machines ready, maintenance complete. Waiting for RVS to begin partition validation. Entry point into the validation phase. |
| **InProgress** | At least one partition has started validation, but none have completed yet. |
| **Partial** | At least one partition has passed validation. No partitions have failed. Waiting for remaining partitions to complete. |
| **FailedPartial** | At least one partition has failed validation. Can recover if failed partitions are re-validated successfully. Can also transition back to Pending if all partitions are reset to idle (e.g. RVS clears labels before a re-run). |
| **Validated** | All partitions have passed validation. The handler promotes this to the top-level `Ready` state. |
| **Failed** | All partitions have failed validation. Requires intervention or re-validation. Can recover if at least one partition is retried (transitions to FailedPartial). |

### How Validation State is Derived

BMMC derives validation state by reading instance metadata labels on instances allocated to the rack's machines. The labels are set by RVS.

#### Instance Metadata Labels

| Label | Values | Purpose |
|-------|--------|---------|
| `rv.part-id` | String (e.g. `"nvlink-domain-0"`) | Groups nodes into validation partitions |
| `rv.st` | `idle`, `inp`, `pass`, `fail` | Per-node validation status |
| `rv.run-id` | String (e.g. `"run-20250227-001"`) | Correlates nodes in the same validation run |
| `rv.fail-desc` | String (e.g. `"nccl-allreduce-timeout"`) | Failure description (only when `rv.st = fail`) |

Instances without the `rv.part-id` label are **not** validation instances and are silently skipped.

#### Per-Partition Aggregation

For each partition (group of nodes sharing the same `rv.part-id`), the aggregate status is determined from the individual node statuses:

| Condition | Partition Status |
|-----------|-----------------|
| Any node has `rv.st = fail` | **Failed** |
| Else if any node has `rv.st = inp` | **InProgress** |
| Else if all nodes have `rv.st = pass` | **Validated** |
| Otherwise | **Pending** |

The per-partition statuses are then counted to produce a `RackPartitionSummary`, which drives the state transitions shown in the diagram above.

## Key Implementation Files

| File | Purpose |
|------|---------|
| `crates/api-model/src/rack.rs` | `RackState` enum, `RackValidationState` sub-enum, `RackMaintenanceState` sub-enum, serde config |
| `crates/api/src/state_controller/rack/handler.rs` | State handler, `compute_validation_transition()`, `RvPartitions`, `InstanceRvState`, `load_partition_summary()` |
| `crates/api/src/state_controller/rack/io.rs` | DB persistence, metrics, state history |
| `crates/api/src/state_controller/rack/context.rs` | Handler context (services, DB pool) |

## Open Items

- **Node-level gating**: Each node should have an `AwaitingPartitionValidation` (or similar) state to prevent production allocation before validation completes. Currently there is a potential race condition at the `Validation(Pending)` stage.
- **Maintenance from Ready**: A mechanism for triggering firmware upgrades on an already-running rack (transition from `Ready` back into `Maintenance`).
- **Configurable maintenance entry point**: The entry into maintenance is hardcoded to `FirmwareUpgrade(Compute)`. Should be configurable per rack/site.
- **SLA definitions**: No SLA timeouts are defined for any rack state yet.
- **Maintenance sub-state transitions**: The firmware upgrade and power sequencing sub-states are stubbed. Full orchestration via Rack Manager Service is TBD.
