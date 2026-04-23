# Power Shelf Handler — Convergence Engine Mapping

## 1. Current State

**Handler file:** `crates/api/src/state_controller/power_shelf/handler.rs` (121 lines)  
**State enum:** `PowerShelfControllerState` in `crates/api-model/src/power_shelf/mod.rs`  
**Controller I/O:** `PowerShelfStateControllerIO`

The power shelf handler manages power shelf lifecycle. The current implementation is largely a placeholder with linear state transitions and minimal business logic — most states transition immediately to the next without performing real work (marked as `TODO`).

### 1.1 PowerShelfControllerState Variants

| # | Variant | Description |
|---|---------|-------------|
| 1 | `Initializing` | Initial state; transitions to `FetchingData`. |
| 2 | `FetchingData` | Fetching power shelf data; transitions to `Configuring`. |
| 3 | `Configuring` | Configuring power shelf; transitions to `Ready`. |
| 4 | `Ready` | Power shelf is operational. Watches for deletion requests. |
| 5 | `Error` | Power shelf in error. If deleted, transitions to `Deleting`; otherwise requires manual recovery. |
| 6 | `Deleting` | Power shelf is being deleted; performs `final_delete`. |

### 1.2 Handler Logic

The current handler is a simple linear pipeline:

```
Initializing → FetchingData → Configuring → Ready
                                               ↓ (if deleted)
                                           Deleting → deleted
Error → Deleting (if deleted) | do_nothing
```

Each transition is immediate — no real I/O or configuration is performed. This makes it an ideal candidate for early convergence engine migration.

---

## 2. State Keys

| Observation Source | State Key | Type | Example Values |
|-------------------|-----------|------|----------------|
| `config.name` | `ShelfName` | Str | `"power-shelf-01"` |
| `config.capacity` | `ShelfCapacity` | Str | `"20kW"` |
| `config.voltage` | `ShelfVoltage` | Str | `"48V"` |
| `config.location` | `ShelfLocation` | Str | `"rack-1-shelf-3"` |
| `status.shelf_name` | `ShelfReportedName` | Str | `"power-shelf-01"` or `""` |
| `status.power` | `ShelfPowerStatus` | Str | `"on"`, `"off"`, `"unknown"` |
| `status.health` | `ShelfHealth` | Str | `"ok"`, `"warning"`, `"critical"` |
| `rack_id` | `ShelfRackId` | Str | `"rack-001"` |
| `deleted` | `LifecycleDeleted` | Bool | `"true"`, `"false"` |

**Typical desired-state sources.** Operator intent (`LifecycleDeleted`). The desired-state composition layer may also set `ShelfPowerStatus` or `ShelfHealth` to drive data fetching and configuration.

---

## 3. Operations

Operations are organized by setting domain — each manages a single, independently configurable property. See [§7.4](README.md#74-design-principle-properties-not-phases) for the design rationale.

### `fetch_shelf_data`

**Replaces:** `PowerShelfControllerState::Initializing` → `FetchingData` transition

```rust
op!(fetch_shelf_data {
    provides: [ShelfPowerStatus, ShelfHealth],
    guard: and(
        eq(ShelfPowerStatus, ""),
        eq(ShelfHealth, ""),
    ),
    locks: [PowerShelf],
    effects: [
        ShelfPowerStatus => "{observed_power}",
        ShelfHealth => "{observed_health}",
    ],
    steps: [
        action(query_power_shelf_hardware),
        action(store_power_shelf_status),
    ],
    priority: 90,
});
```

### `configure_shelf`

**Replaces:** `PowerShelfControllerState::FetchingData` → `Configuring` → `Ready` transitions

```rust
op!(configure_shelf {
    provides: [ShelfReportedName],
    guard: and(
        neq(ShelfPowerStatus, ""),
        eq(ShelfReportedName, ""),
    ),
    locks: [PowerShelf],
    effects: [ShelfReportedName => "{configured_name}"],
    steps: [
        action(apply_power_shelf_config),
        action(verify_power_shelf_health),
    ],
    priority: 80,
});
```

### `delete_shelf`

**Replaces:** `PowerShelfControllerState::Deleting` match arm

```rust
op!(delete_shelf {
    provides: [LifecycleDeleted],
    guard: eq(LifecycleDeleted, "true"),
    locks: [PowerShelf, Lifecycle],
    effects: [LifecycleDeleted => "true"],
    steps: [
        action(cleanup_power_shelf),
        action(final_delete),
    ],
    priority: 110,
});
```

### What Disappears

| Old | Property-oriented view |
|-----|------------------------|
| Linear Initializing → FetchingData → Configuring → Ready | Each step is an independent property |
| `Ready` | Δ = ∅ |
| `Error` | Observable drift |

---

## 4. Profiles

| Profile | Match Rule | Description |
|---------|-----------|-------------|
| `power_shelf_default` | `true` | Single profile — power shelf management is hardware-agnostic |

---

## 5. Example Convergence Trace

**Scenario:** A new power shelf is created and needs initialization.

**Initial observed state:**
```
ShelfPowerStatus  = ""
ShelfHealth       = ""
ShelfReportedName = ""
```

No explicit desired state for data fetching or configuration -- operations fire when observed data is empty.

**Tick 1:**
- `fetch_shelf_data` is ready (power status and health are empty). Scheduled.
- `configure_shelf` is blocked (power status is empty).
- **Actions:** `fetch_shelf_data`.

**Tick 2:**
- `ShelfPowerStatus = "on"`, `ShelfHealth = "ok"`.
- `configure_shelf` is now ready (power status is non-empty, reported name is empty). Scheduled.
- **Actions:** `configure_shelf`.

**Tick 3:**
- `ShelfReportedName = "power-shelf-01"`.
- No further deltas.
- **Result:** CONVERGED.

### Migration Priority

Due to the handler's simplicity (linear transitions, no real I/O, placeholder logic), the power shelf handler is an ideal **first candidate** for convergence engine migration. It can serve as a proof-of-concept for the migration strategy outlined in the [main specification](README.md#7-migration-strategy).
