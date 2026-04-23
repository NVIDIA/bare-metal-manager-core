# Rack Handler — Convergence Engine Mapping

## 1. Current State

**Handler file:** `crates/api/src/state_controller/rack/handler.rs` (92 lines)  
**State enum:** `RackState` in `crates/api-model/src/rack.rs`  
**Controller I/O:** `RackStateControllerIO`

The rack handler manages rack lifecycle: creation, switch/host discovery, validation, maintenance operations (firmware upgrades, NMX cluster configuration, power sequencing), and deletion.

### 1.1 RackState Variants

| # | Variant | Sub-state | Description |
|---|---------|-----------|-------------|
| 1 | `Created` | — | Initial state after rack is created in the database. |
| 2 | `Discovering` | — | Discovering switches and hosts in the rack. |
| 3 | `Validating` | `RackValidationState` | Running rack-level validation checks. |
| 4 | `Ready` | — | Rack is operational and ready for use. |
| 5 | `Maintenance` | `RackMaintenanceState` | Rack is undergoing maintenance (firmware upgrade, NMX config, power sequence). |
| 6 | `Error` | `cause: String` | Rack is in an error state. |
| 7 | `Deleting` | — | Rack is being deleted. |

### 1.2 Sub-state Enums

**`RackMaintenanceState`:**
- `FirmwareUpgrade` — Coordinated firmware upgrade across rack switches/hosts.
- `ConfigureNmxCluster` — NMX cluster configuration.
- `PowerSequence` — Rack-level power sequencing.
- `Completed` — Maintenance completed, returning to `Ready`.

**`RackValidationState`:**
- Validates rack topology, switch connectivity, and host reachability.

---

## 2. State Keys

| Observation Source | State Key | Type | Example Values |
|-------------------|-----------|------|----------------|
| `config.rack_type` | `RackType` | Str | `"standard"`, `"high-density"` |
| `config.topology_changed` | `RackTopologyChanged` | Bool | `"true"`, `"false"` |
| `config.validation_run_id` | `RackValidationRunId` | Str | `"run-2024-001"` |
| `firmware_upgrade_job` | `RackFirmwareUpgradeStatus` | Str | `"none"`, `"in_progress"`, `"completed"` |
| Switch discovery count | `RackSwitchCount` | Int | `"8"` (0 = not yet discovered) |
| Host discovery count | `RackHostCount` | Int | `"32"` (0 = not yet discovered) |
| Validation runner | `RackValidationResult` | Str | `"passed"`, `"failed"`, `"not_run"` |
| `health_report_overrides` | `RackHealthOverride` | Str | Health override status |
| `deleted` | `LifecycleDeleted` | Bool | `"true"`, `"false"` |

**Typical desired-state sources.** Firmware manifests (`RackFirmwareUpgradeStatus`), operator intent (`LifecycleDeleted`). A fleet policy might also set `RackValidationResult = "passed"` or `RackSwitchCount` to assert rack composition.

---

## 3. Operations

Operations are organized by setting domain. See §7.4 of the main specification for the design rationale.

### `discover_rack`

**Replaces:** `RackState::Created` → `Discovering` transition and `handle_discovering`

`RackSwitchCount` and `RackHostCount` are **observed-only** — they come from the discovery scan. No operation explicitly "provides" them in desired state. The discovery operation runs when counts are zero and populates them with real data.

```rust
op!(discover_rack {
    provides: [RackSwitchCount, RackHostCount],
    guard: or(
        eq(RackSwitchCount, "0"),
        eq(RackHostCount, "0"),
    ),
    locks: [RackDiscovery],
    effects: [
        RackSwitchCount => "{discovered_switch_count}",
        RackHostCount => "{discovered_host_count}",
    ],
    steps: [
        action(discover_rack_switches),
        action(discover_rack_hosts),
        action(build_rack_topology),
    ],
    priority: 90,
});
```

### `validate_rack`

**Replaces:** `RackState::Validating` match arm and `handle_validating`

```rust
op!(validate_rack {
    provides: [RackValidationResult],
    guard: and(
        neq(RackSwitchCount, "0"),
        neq(RackHostCount, "0"),
        neq(RackValidationResult, "passed"),
    ),
    locks: [RackValidation],
    effects: [RackValidationResult => "passed"],
    steps: [
        action(validate_rack_topology),
        action(validate_switch_connectivity),
        action(validate_host_reachability),
    ],
    priority: 80,
});
```

### `upgrade_rack_firmware`

**Replaces:** `RackState::Maintenance { FirmwareUpgrade }` match arm

```rust
op!(upgrade_rack_firmware {
    provides: [RackFirmwareUpgradeStatus],
    guard: and(
        eq(RackValidationResult, "passed"),
        neq(RackFirmwareUpgradeStatus, desired(RackFirmwareUpgradeStatus)),
    ),
    locks: [RackMaintenance],
    effects: [RackFirmwareUpgradeStatus => desired(RackFirmwareUpgradeStatus)],
    steps: [
        action(coordinate_switch_firmware_upgrade),
        action(wait_for_all_switches_updated),
        action(verify_rack_health),
    ],
    priority: 60,
});
```

### `delete_rack`

**Replaces:** `RackState::Deleting` match arm

```rust
op!(delete_rack {
    provides: [LifecycleDeleted],
    guard: eq(LifecycleDeleted, "true"),
    locks: [Lifecycle],
    effects: [LifecycleDeleted => "true"],
    steps: [action(cleanup_rack_resources), action(final_delete)],
    priority: 110,
});
```

### What Disappears

- **`RackState::Maintenance` phases** — Each maintenance type is an independent operation.
- **`RackState::Error`** — Failure is observable state drift; the engine retries.
- **`RackState::Ready`** — Not a state; just **Δ = ∅**.

---

## 4. Profiles

Racks have a single profile since rack management is hardware-agnostic:

| Profile | Match Rule | Operations |
|---------|-----------|------------|
| `rack_default` | `true` | All rack operations |

---

## 6. Example Convergence Trace

**Scenario:** A new rack is created and needs discovery and validation.

**Initial observed state:**
```
RackSwitchCount       = "0"
RackHostCount         = "0"
RackValidationResult  = "not_run"
```

No explicit desired state for discovery or validation — these are observed-only prerequisites. The rack converges when its firmware status (if applicable) and lifecycle keys match desired state.

**Tick 1:**
- `discover_rack` is ready (counts are `"0"`). Scheduled.
- **Actions:** `discover_rack`.

**Tick 2:**
- `RackSwitchCount = "8"`, `RackHostCount = "32"`.
- `validate_rack` is now ready (counts are non-zero, result is `"not_run"`). Scheduled.
- **Actions:** `validate_rack`.

**Tick 3:**
- `RackValidationResult = "passed"`.
- No further deltas.
- **Result:** CONVERGED.

**Self-healing:** If a switch is removed from the rack, `RackSwitchCount` changes on the next observation. `validate_rack` detects `RackValidationResult` is stale and re-runs validation.
