# Switch Handler — Convergence Engine Mapping

## 1. Current State

**Handler file:** `crates/api/src/state_controller/switch/handler.rs` (103 lines)  
**State enum:** `SwitchControllerState` in `crates/api-model/src/switch/mod.rs`  
**Controller I/O:** `SwitchStateControllerIO`

The switch handler manages network switch lifecycle: initialization, configuration, validation, BOM validation, reprovisioning, and deletion. The convergence mapping below replaces sequential FSM phases with **property-oriented operations**; §1 documents the legacy controller for reference.

### 1.1 SwitchControllerState Variants

| # | Variant | Sub-state | Description |
|---|---------|-----------|-------------|
| 1 | `Created` | — | Initial state after switch creation. |
| 2 | `Initializing` | `InitializingState` | Switch is being initialized (firmware check, basic config). |
| 3 | `Configuring` | `ConfiguringState` | Switch is being configured with network settings. |
| 4 | `Validating` | `ValidatingState` | Running switch-level validation checks. |
| 5 | `BomValidating` | `BomValidatingState` | BOM/SKU validation for the switch. |
| 6 | `Ready` | — | Switch is operational. |
| 7 | `ReProvisioning` | `ReProvisioningState` | Switch is being reprovisioned. |
| 8 | `Error` | `cause: String` | Switch is in an error state. |
| 9 | `Deleting` | — | Switch is being deleted. |

### 1.2 Handler Dispatch

The handler's `attempt_state_transition` delegates each variant to a dedicated function (`handle_created`, `handle_initializing`, etc.). The handler ignores the passed `controller_state` parameter and instead reads `state.controller_state.value` directly.

---

## 2. State Keys

| Observation Source | State Key | Type | Example Values |
|-------------------|-----------|------|----------------|
| `config` | `SwitchConfigVersion` | Str | `"v3"` |
| `status` | `SwitchConnectivityStatus` | Str | `"connected"`, `"disconnected"`, `"error"` |
| `bmc_mac_address` | `SwitchBmcMac` | Str | `"aa:bb:cc:dd:ee:ff"` |
| Firmware version query | `SwitchFirmwareVersion` | Str | `"3.10.4"` or `""` (not checked) |
| `firmware_upgrade_status` | `SwitchFirmwareStatus` | Str | `"current"`, `"upgrading"`, `"outdated"` |
| Basic config hash | `SwitchBasicConfigHash` | Str | `"b3c2a1"` or `""` (not applied) |
| Validation runner | `SwitchValidationResult` | Str | `"passed"`, `"failed"`, `"not_run"` |
| BOM validation runner | `SwitchBomValidationResult` | Str | `"passed"`, `"failed"`, `"not_run"` |
| `rack_id` | `SwitchRackId` | Str | `"rack-001"` |
| `deleted` | `LifecycleDeleted` | Bool | `"true"`, `"false"` |

**Typical desired-state sources.** Network config templates (`SwitchConfigVersion`), firmware manifests (`SwitchFirmwareStatus`), operator intent (`LifecycleDeleted`).

---

## 3. Operations

Operations are grouped by **setting domain**. There is no monolithic init phase or reprovision phase; guards encode dependencies. See [§7.4](README.md#74-design-principle-properties-not-phases) in the convergence README for rationale.

### 3.1 Firmware and reachability

```rust
op!(check_switch_firmware {
    provides: [SwitchFirmwareVersion],
    guard: eq(SwitchFirmwareVersion, ""),
    locks: [SwitchFirmware],
    effects: [SwitchFirmwareVersion => "{detected_version}"],
    steps: [action("switch_check_firmware")],
    priority: 90,
});
```

```rust
op!(apply_switch_basic_config {
    provides: [SwitchBasicConfigHash],
    guard: and(
        neq(SwitchFirmwareVersion, ""),
        eq(SwitchBasicConfigHash, ""),
    ),
    locks: [SwitchBasicConfig],
    effects: [SwitchBasicConfigHash => "{config_hash}"],
    steps: [action("switch_basic_config")],
    priority: 89,
});
```

`SwitchConnectivityStatus` is **observed-only** -- it comes from the switch's health monitoring, not from an operation. Once basic config is applied, the observation layer detects connectivity.

### 3.2 Configuration

```rust
op!(configure_switch {
    provides: [SwitchConfigVersion],
    guard: and(
        eq(SwitchConnectivityStatus, "connected"),
        neq(SwitchConfigVersion, desired(SwitchConfigVersion)),
    ),
    locks: [SwitchConfig],
    effects: [SwitchConfigVersion => desired(SwitchConfigVersion)],
    steps: [
        action("switch_apply_network_config"),
        action("switch_verify_port_status"),
    ],
    priority: 80,
});
```

### 3.3 Validation

```rust
op!(validate_switch {
    provides: [SwitchValidationResult],
    guard: and(
        eq(SwitchConfigVersion, desired(SwitchConfigVersion)),
        neq(SwitchValidationResult, "passed"),
    ),
    locks: [SwitchValidation],
    effects: [SwitchValidationResult => "passed"],
    steps: [
        action("switch_run_validation"),
        action("switch_check_validation_result"),
    ],
    priority: 75,
});
```

```rust
op!(validate_switch_bom {
    provides: [SwitchBomValidationResult],
    guard: and(
        eq(SwitchValidationResult, "passed"),
        neq(SwitchBomValidationResult, "passed"),
    ),
    locks: [SwitchValidation],
    effects: [SwitchBomValidationResult => "passed"],
    steps: [action("switch_bom_check")],
    priority: 73,
});
```

### 3.4 Lifecycle

```rust
op!(delete_switch {
    provides: [LifecycleDeleted],
    guard: eq(LifecycleDeleted, "true"),
    locks: [Lifecycle],
    effects: [LifecycleDeleted => "true"],
    steps: [action("switch_cleanup"), action("final_delete")],
    priority: 110,
});
```

### 3.5 What Disappears

The following FSM-centric concepts have no dedicated operation in the convergence model:

| FSM / legacy concept | Why it disappears |
|---------------------|-------------------|
| `ReProvisioning` | Reprovisioning is not an operation. When desired `SwitchConfigVersion` changes, the engine detects a delta and reconverges. |
| Monolithic `initialize_switch` | Split into `check_switch_firmware` (provides `SwitchFirmwareVersion`), `apply_switch_basic_config` (provides `SwitchBasicConfigHash`), and passive connectivity observation (`SwitchConnectivityStatus`). |
| Boolean flags (`SwitchConfigured`, `SwitchInitialized`, etc.) | Replaced by real observables: firmware version, config hash, validation/BOM result. |
| `Ready` | Not a state -- delta is empty. |

---

## 4. Profiles

| Profile | Match Rule | Description |
|---------|-----------|-------------|
| `switch_default` | `true` | Default switch profile for all switch types |
| `switch_infiniband` | `eq(SwitchType, "infiniband")` | InfiniBand-specific switch operations (future) |

---

## 5. Example Convergence Trace

**Scenario:** A new switch is created. The desired state specifies only a target config version; intermediate properties (firmware version, basic config hash, connectivity, validation results) are observed-only prerequisites.

**Initial observed state:**
```
SwitchFirmwareVersion     = ""
SwitchBasicConfigHash     = ""
SwitchConnectivityStatus  = "disconnected"
SwitchConfigVersion       = ""
SwitchValidationResult    = "not_run"
SwitchBomValidationResult = "not_run"
```

**Desired state:**
```
SwitchConfigVersion  = "v3"
SwitchFirmwareStatus = "current"
```

**Tick 1:** `check_switch_firmware` is ready (`SwitchFirmwareVersion = ""`). Scheduled. Fleet: other switches advance concurrently.

**Tick 2:** `SwitchFirmwareVersion = "3.10.4"`. `apply_switch_basic_config` is ready (firmware version is non-empty, config hash is empty). Scheduled.

**Tick 3:** `SwitchBasicConfigHash = "b3c2a1"`. Observation refreshes: `SwitchConnectivityStatus = "connected"`. `configure_switch` is ready (connected, config version differs). Scheduled.

**Tick 4:** `SwitchConfigVersion = "v3"`. `validate_switch` is ready (config matches desired, result is `"not_run"`). Scheduled.

**Tick 5:** `SwitchValidationResult = "passed"`. `validate_switch_bom` is ready. Scheduled.

**Tick 6:** `SwitchBomValidationResult = "passed"`. All desired keys match.

**Result:** CONVERGED in 6 ticks.

**Config-only delta:** If desired `SwitchConfigVersion` changes to `"v4"` while the switch is already converged, only `configure_switch` becomes eligible. The engine does not re-check firmware or re-apply basic config.

**Self-healing:** If `SwitchConnectivityStatus` goes to `"disconnected"`, `configure_switch` is blocked until connectivity is restored. No manual intervention needed.
