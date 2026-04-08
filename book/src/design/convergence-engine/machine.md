# Machine Handler — Convergence Engine Mapping

## 1. Current State

**Handler file:** `crates/api/src/state_controller/machine/handler.rs` (10,257 lines)  
**State enum:** `ManagedHostState` in `crates/api-model/src/machine/mod.rs`  
**Controller I/O:** `MachineStateControllerIO` in `crates/api/src/state_controller/machine/io.rs`

The machine handler is the largest and most complex state handler in Carbide. It manages the full lifecycle of a bare-metal host: from initial RMS registration, through DPU and host initialization, validation, readiness, instance assignment, cleanup, reprovisioning, firmware updates, attestation measurement, and failure recovery.

### 1.1 ManagedHostState Variants

| # | Variant | Sub-state | Description |
|---|---------|-----------|-------------|
| 1 | `VerifyRmsMembership` | — | Verify the host is registered with Rack Manager Service by checking inventory. |
| 2 | `RegisterRmsMembership` | — | Register the host with RMS. On success, transitions to DPU discovery. |
| 3 | `DpuDiscoveringState` | `dpu_states` | DPU discovered by site-explorer; being configured via Redfish. |
| 4 | `DPUInit` | `dpu_states` | DPU is not yet ready; delegated to `dpu_handler`. |
| 5 | `HostInit` | `machine_state` | DPU is ready; host initialization in progress. |
| 6 | `Validation` | `validation_state` | Host validation for machine and DPU. |
| 7 | `BomValidating` | `bom_validating_state` | BOM/SKU validation flow. |
| 8 | `Measuring` | `measuring_state` | Waiting on attestation measurements or valid bundle. |
| 9 | `Ready` | — | Host is ready for instance creation. |
| 10 | `Assigned` | `instance_state` | Host is assigned to an instance; delegated to `instance_handler`. |
| 11 | `PostAssignedMeasuring` | `measuring_state` | Re-measurement after instance assignment. |
| 12 | `WaitingForCleanup` | `cleanup_state` | Cleanup in progress (BOSS secure erase, volume creation, etc.). |
| 13 | `HostReprovision` | `reprovision_state` | Host reprovisioning in progress. |
| 14 | `DPUReprovision` | `dpu_states` | DPU reprovisioning in progress. |
| 15 | `Failed` | `details, retry_count` | Machine in failed state; recovery depends on cause. |
| 16 | `ForceDeletion` | — | Admin-triggered forced deletion. |
| 17 | `Created` | — | Dummy initial state for DPU creation. |

### 1.2 Handler Dispatch Structure

The handler's `attempt_state_transition` method is a single `match` on `ManagedHostState` that spans ~1,100 lines. Pre-match logic handles:

- DPU network staleness detection
- Restart verification
- DPU reprovision restart conditions
- Promotion to `Failed` state when `get_failed_state()` triggers

Each match arm either handles the transition inline or delegates to sub-handlers:

- `DPUInit` → `dpu_handler.handle_object_state()`
- `HostInit` → `host_handler.handle_object_state()`
- `Assigned` → `instance_handler.handle_object_state()`
- `WaitingForCleanup` → nested `match cleanup_state` with ~15 sub-states
- `HostReprovision` → `host_upgrade.handle_host_reprovision()`

---

## 2. Observed State Mapping

The observed state `S_o` for a machine is built from the `Machine` struct, BMC queries (Redfish/IPMI), and agent reports.

Every key holds **real observable data**, not boolean step-completion flags. If data is present, the thing exists (see [§7.4](README.md#74-design-principle-properties-not-phases)).

| Source Field | State Key | Type | Example Values |
|-------------|-----------|------|----------------|
| Redfish power query | `PowerState` | Str | `"on"`, `"off"`, `"powering_on"`, `"powering_off"` |
| `bmc_info.firmware_version` | `FirmwareBmcVersion` | Str | `"2.14.0"` |
| `inventory.bios_version` | `FirmwareBiosVersion` | Str | `"1.8.3"` |
| `inventory.host_firmware_version` | `FirmwareHostVersion` | Str | `"3.2.1"` |
| DPU agent health report | `DpuFirmwareVersion` | Str | `"24.04.1"` or `""` (no DPU) |
| DPU network status | `DpuNetworkConfigVersion` | Str | `"v5"` |
| `hardware_info.manufacturer` | `HardwareManufacturer` | Str | `"NVIDIA"` |
| `hw_sku` | `HwSku` | Str | `"NVIDIA-GB300-XYZ"` |
| Redfish DPU discovery | `DpuCount` | Int | `"2"` (0 = not yet discovered) |
| Redfish DPU interface query | `DpuInterfaceIp` | Str | `"10.0.1.5"` or `""` (not configured) |
| Redfish DPU mode query | `DpuMode` | Str | `"dpu"`, `"nic"`, `""` (not set) |
| DPU agent version query | `DpuAgentVersion` | Str | `"1.4.0"` or `""` (not connected) |
| Scout agent version query | `ScoutVersion` | Str | `"3.2.1"` or `""` (not installed) |
| Scout heartbeat monitoring | `ScoutHeartbeat` | Str | `"alive"`, `"stale"` |
| Redfish BIOS attributes hash | `BiosSettingsHash` | Str | `"a3f8c2"` (hash of current attributes) |
| `network_config` | `NetworkConfigVersion` | Str | `"v12"` |
| `network_status_observation` | `NetworkStatus` | Str | `"configured"`, `"pending"`, `"error"` |
| Health report aggregation | `HealthStatus` | Str | `"healthy"`, `"degraded"`, `"critical"` |
| `dpf.enabled` | `DpfEnabled` | Bool | `"true"`, `"false"` |
| `firmware_autoupdate` | `FirmwareAutoupdate` | Bool | `"true"`, `"false"` |
| Lockdown status query | `LockdownEnabled` | Bool | `"true"`, `"false"` |
| RMS inventory query | `RmsInventoryId` | Str | `"rms-12345"` or `""` (not registered) |
| Validation runner | `ValidationResult` | Str | `"passed"`, `"failed"`, `"not_run"` |
| BOM validation runner | `BomValidationResult` | Str | `"passed"`, `"failed"`, `"not_run"` |
| Attestation status | `AttestationStatus` | Str | `"not_started"`, `"measuring"`, `"passed"`, `"failed"` |
| Instance assignment | `InstanceAssigned` | Bool | `"true"`, `"false"` |
| `deleted` | `LifecycleDeleted` | Bool | `"true"`, `"false"` |
| Drive erase status | `DriveEraseStatus` | Str | `"erased"`, `"not_erased"` |

---

## 3. Operations

Operations are organized by **setting domain** — each manages a single, independently configurable property. There are no "init" or "reprovision" phases. See [§7.4](README.md#74-design-principle-properties-not-phases) for the design rationale.

### 3.1 Power

```rust
op!(power_on {
    provides: [PowerState],
    guard: eq(PowerState, "off"),
    locks: [Power],
    effects: [PowerState => "on"],
    steps: [
        action(redfish_power_on),
        action(wait_for_power_state, target = "on", timeout_seconds = 120),
    ],
    priority: 100,
});
```

```rust
op!(power_off {
    provides: [PowerState],
    guard: eq(PowerState, "on"),
    locks: [Power],
    effects: [PowerState => "off"],
    steps: [
        action(redfish_power_off, reset_type = "GracefulShutdown"),
        action(wait_for_power_state, target = "off", timeout_seconds = 120),
    ],
    priority: 100,
});
```

```rust
op!(reboot_host {
    provides: [BootGeneration],
    guard: and(
        eq(PowerState, "on"),
        neq(BootGeneration, desired(BootGeneration)),
    ),
    locks: [Power],
    effects: [BootGeneration => desired(BootGeneration)],
    steps: [
        action(redfish_power_cycle),
        action(wait_for_power_state, target = "on", timeout_seconds = 180),
    ],
    priority: 95,
});
```

### 3.2 Registration

```rust
op!(register_with_rms {
    provides: [RmsInventoryId],
    guard: eq(RmsInventoryId, ""),
    locks: [Rms],
    effects: [RmsInventoryId => "rms-{machine_id}"],
    steps: [
        action(rms_check_inventory),
        action(rms_register_if_missing),
    ],
    priority: 100,
});
```

### 3.3 DPU Discovery and Setup

Each step of what the FSM called "DPU Init" is an independent property, guarded by physical constraints. Note: no operation "provides" `DpuCount` — it is **observed-only** from Redfish. The engine uses it as a prerequisite in guards.

```rust
op!(configure_dpu_interfaces {
    provides: [DpuInterfaceIp],
    guard: and(
        neq(DpuCount, "0"),
        eq(DpuInterfaceIp, ""),
    ),
    locks: [Dpu],
    effects: [DpuInterfaceIp => "{configured_ip}"],
    steps: [
        action(redfish_configure_dpu_network_interfaces),
    ],
    priority: 90,
});
```

```rust
op!(set_dpu_mode {
    provides: [DpuMode],
    guard: and(
        neq(DpuInterfaceIp, ""),
        neq(DpuMode, desired(DpuMode)),
    ),
    locks: [Dpu],
    effects: [DpuMode => desired(DpuMode)],
    steps: [
        action(redfish_set_dpu_mode),
    ],
    priority: 89,
});
```

```rust
op!(wait_for_dpu_agent {
    provides: [DpuAgentVersion],
    guard: and(
        eq(DpuMode, desired(DpuMode)),
        eq(DpuAgentVersion, ""),
    ),
    locks: [Dpu],
    effects: [DpuAgentVersion => "{reported_version}"],
    steps: [
        action(dpu_wait_for_agent_ready, timeout_seconds = 120),
        action(dpu_query_agent_version),
    ],
    priority: 88,
});
```

### 3.4 Firmware

Each firmware target is an independent property. All require power. The engine parallelizes BMC and BIOS updates if resource locks allow.

```rust
op!(update_bmc_firmware {
    provides: [FirmwareBmcVersion],
    guard: and(
        eq(PowerState, "on"),
        neq(FirmwareBmcVersion, desired(FirmwareBmcVersion)),
        eq(PolicyFirmwareUpdateAllowed, "true"),
    ),
    locks: [Firmware, Power],
    effects: [FirmwareBmcVersion => desired(FirmwareBmcVersion)],
    steps: [
        action(redfish_firmware_update, target = "bmc"),
        action(wait_for_bmc_ready, timeout_seconds = 600),
    ],
    priority: 80,
});
```

```rust
op!(update_bios_firmware {
    provides: [FirmwareBiosVersion],
    guard: and(
        eq(PowerState, "on"),
        neq(FirmwareBiosVersion, desired(FirmwareBiosVersion)),
    ),
    locks: [Firmware, Power],
    effects: [FirmwareBiosVersion => desired(FirmwareBiosVersion)],
    steps: [
        action(redfish_firmware_update, target = "bios"),
        action(redfish_power_cycle),
        action(wait_for_bios_post, timeout_seconds = 600),
    ],
    priority: 79,
});
```

```rust
op!(update_dpu_firmware {
    provides: [DpuFirmwareVersion],
    guard: and(
        eq(PowerState, "on"),
        neq(DpuAgentVersion, ""),
        neq(DpuFirmwareVersion, desired(DpuFirmwareVersion)),
    ),
    locks: [Dpu, Firmware],
    effects: [DpuFirmwareVersion => desired(DpuFirmwareVersion)],
    steps: [
        action(dpu_flash_firmware),
        action(dpu_reset),
        action(wait_for_dpu_ready, timeout_seconds = 300),
    ],
    priority: 78,
});
```

### 3.5 BIOS Configuration

```rust
op!(configure_bios {
    provides: [BiosSettingsHash],
    guard: and(
        eq(PowerState, "on"),
        neq(BiosSettingsHash, desired(BiosSettingsHash)),
    ),
    locks: [Bios],
    effects: [BiosSettingsHash => desired(BiosSettingsHash)],
    steps: [
        action(redfish_set_bios_attributes),
        action(redfish_power_cycle),
        action(wait_for_bios_post),
    ],
    priority: 82,
});
```

### 3.6 Network

```rust
op!(configure_network {
    provides: [NetworkConfigVersion],
    guard: and(
        eq(PowerState, "on"),
        neq(NetworkConfigVersion, desired(NetworkConfigVersion)),
    ),
    locks: [Network],
    effects: [NetworkConfigVersion => desired(NetworkConfigVersion)],
    steps: [
        action(apply_network_config),
        action(verify_network_connectivity),
    ],
    priority: 83,
});
```

```rust
op!(configure_dpu_network {
    provides: [DpuNetworkConfigVersion],
    guard: and(
        neq(DpuAgentVersion, ""),
        neq(DpuNetworkConfigVersion, desired(DpuNetworkConfigVersion)),
    ),
    locks: [Dpu, Network],
    effects: [DpuNetworkConfigVersion => desired(DpuNetworkConfigVersion)],
    steps: [
        action(dpu_apply_network_config),
        action(dpu_verify_connectivity),
    ],
    priority: 81,
});
```

### 3.7 Host Agent

Previously buried inside the monolithic `initialize_host` FSM phase. As independent properties, each can be tested, retried, and monitored individually. Note how guards reference real data — `ScoutVersion` guards on `neq(ScoutVersion, "")`, not on a boolean flag.

```rust
op!(load_scout {
    provides: [ScoutVersion],
    guard: and(
        eq(PowerState, "on"),
        eq(NetworkConfigVersion, desired(NetworkConfigVersion)),
        neq(ScoutVersion, desired(ScoutVersion)),
    ),
    locks: [Scout],
    effects: [ScoutVersion => desired(ScoutVersion)],
    steps: [
        action(boot_scout_via_initrd, version = desired(ScoutVersion)),
        action(verify_scout_running),
    ],
    priority: 84,
});
```

`ScoutHeartbeat` is **observed-only** — it comes from continuous heartbeat monitoring, not from an operation. When the scout agent is running, the observation layer sets `ScoutHeartbeat = "alive"`. No explicit "verify reachability" operation is needed.

### 3.8 Security

```rust
op!(enable_lockdown {
    provides: [LockdownEnabled],
    guard: and(eq(PowerState, "on"), eq(LockdownEnabled, "false")),
    locks: [Lockdown],
    effects: [LockdownEnabled => "true"],
    steps: [
        action(redfish_enable_lockdown),
        action(set_bios_password),
    ],
    priority: 70,
});
```

```rust
op!(run_attestation {
    provides: [AttestationStatus],
    guard: and(
        eq(BomValidationResult, "passed"),
        eq(PowerState, "on"),
    ),
    locks: [Attestation],
    effects: [AttestationStatus => "passed"],
    steps: [
        action(spdm_check_support),
        action(spdm_fetch_targets),
        action(spdm_collect_measurements),
        action(spdm_verify_measurements),
        action(spdm_apply_appraisal),
    ],
    priority: 75,
});
```

### 3.9 Validation

Validation is a *check*, not a lifecycle phase. Its guard expresses the real dependencies — the settings it validates must be in place. The result is a real value (`"passed"` or `"failed"`), not a boolean flag. Compare with the FSM approach where validation was gated behind an `HostInitialized` phase marker.

```rust
op!(validate_machine {
    provides: [ValidationResult],
    guard: and(
        eq(PowerState, "on"),
        eq(ScoutHeartbeat, "alive"),
        eq(BiosSettingsHash, desired(BiosSettingsHash)),
        eq(NetworkConfigVersion, desired(NetworkConfigVersion)),
    ),
    locks: [Validation],
    effects: [ValidationResult => "passed"],
    steps: [
        action(run_machine_validation),
        action(check_validation_result),
    ],
    priority: 70,
});
```

```rust
op!(validate_bom {
    provides: [BomValidationResult],
    guard: eq(ValidationResult, "passed"),
    locks: [Validation],
    effects: [BomValidationResult => "passed"],
    steps: [
        action(run_bom_validation),
        action(check_bom_result),
    ],
    priority: 68,
});
```

### 3.10 Cleanup

What the FSM called `WaitingForCleanup` was a monolithic phase bundling four unrelated actions. In the convergence model, cleanup is just driving properties to their "empty" or "erased" values — the same mechanism as provisioning, just in the opposite direction.

```rust
op!(erase_drives {
    provides: [DriveEraseStatus],
    guard: and(
        eq(InstanceAssigned, "false"),
        neq(DriveEraseStatus, "erased"),
    ),
    locks: [Cleanup],
    effects: [DriveEraseStatus => "erased"],
    steps: [action(secure_erase_drives)],
    priority: 60,
});
```

```rust
op!(stop_scout {
    provides: [ScoutVersion],
    guard: and(
        eq(InstanceAssigned, "false"),
        neq(ScoutVersion, ""),
    ),
    locks: [Scout],
    effects: [ScoutVersion => ""],
    steps: [action(stop_scout_agent)],
    priority: 59,
});
```

Note: `stop_scout` and `load_scout` both provide `ScoutVersion`. The scheduler selects based on which direction the delta points — if desired `ScoutVersion` is non-empty and observed is empty, `load_scout` fires; if desired is empty and observed is non-empty, `stop_scout` fires.

### 3.11 Lifecycle

```rust
op!(delete_machine {
    provides: [LifecycleDeleted],
    guard: eq(LifecycleDeleted, "true"),
    locks: [Lifecycle],
    effects: [LifecycleDeleted => "true"],
    steps: [
        action(deregister_from_rms),
        action(cleanup_database_records),
        action(emit_deletion_event),
    ],
    priority: 110,
});
```

### 3.12 What Disappears

The following FSM concepts have no operation equivalent in the convergence model:

| FSM Concept | Why It Disappears |
|-------------|-------------------|
| `DPUInit` | Decomposed into `configure_dpu_interfaces` (→ `DpuInterfaceIp`), `set_dpu_mode` (→ `DpuMode`), `wait_for_dpu_agent` (→ `DpuAgentVersion`) — three real observables with physical-constraint guards. |
| `HostInit` | The "init phase" bundled BIOS, network, scout, and reachability. These are now independent operations with real observables: `configure_bios` (→ `BiosSettingsHash`), `configure_network` (→ `NetworkConfigVersion`), `load_scout` (→ `ScoutVersion`). Reachability is observed continuously (`ScoutHeartbeat`). |
| `WaitingForCleanup` | Decomposed into `erase_drives` (→ `DriveEraseStatus`) and `stop_scout` (→ `ScoutVersion = ""`). Power-off is already its own operation. |
| `HostReprovision` | Not an operation — it's a desired-state change. When an operator requests reprovisioning, `S_d` is updated (new firmware version, new BIOS hash, new scout version). The engine detects the deltas and converges. |
| `DPUReprovision` | Same: update `S_d` with the new DPU firmware version, the engine runs `update_dpu_firmware`. |
| `Ready` | Not a state — it's the absence of a delta. When `Δ = ∅`, the machine is "ready." |
| `Assigned` | Instance assignment is an observed property (`InstanceAssigned`), not a lifecycle phase. Operations that should not run while assigned guard on `eq(InstanceAssigned, "false")`. |
| `Failed` | Failure is observable state drift. If firmware flashing fails, `FirmwareBmcVersion` still differs from desired. The engine retries on the next tick. Persistent failures surface as "idle with non-empty delta." |
| Boolean flags | Keys like `RmsRegistered`, `DpuDiscovered`, `ScoutInstalled`, `ValidationPassed` are replaced by real observables (`RmsInventoryId`, `DpuCount`, `ScoutVersion`, `ValidationResult`). Presence of data implies the property is satisfied. |

---

## 4. Profiles

The machine handler maps to multiple hardware profiles, organized in an inheritance hierarchy:

```
common
├── power_on, power_off, configure_bios, enable_lockdown
├── register_with_rms, configure_network, load_scout, stop_scout
├── validate_machine, validate_bom, run_attestation
├── erase_drives, delete_machine
│
├── generic_x86
│   └── update_bmc_firmware (generic Redfish firmware update)
│
├── nvidia_gbx00_base (abstract)
│   └── update_bmc_firmware (NVIDIA-specific Redfish + reset sequence)
│
│   ├── nvidia_gb300
│   │   ├── inherits: [nvidia_gbx00_base, nvidia_bf3_dpu]
│   │   └── power_off (GPU-specific graceful shutdown)
│   │
│   └── nvidia_h100
│       ├── inherits: [nvidia_gbx00_base]
│       └── (uses inherited operations)
│
└── nvidia_bf3_dpu (abstract)
    ├── update_dpu_firmware
    ├── configure_dpu_network
    ├── configure_dpu_interfaces
    ├── set_dpu_mode
    └── wait_for_dpu_agent
```

**Profile selection** is determined by the `HwSku` field in observed state:

| Profile | Match Rule |
|---------|-----------|
| `nvidia_gb300` | `contains(HwSku, "GB300")` |
| `nvidia_h100` | `contains(HwSku, "H100")` |
| `generic_x86` | `true` (fallback) |

---

## 5. Example Convergence Trace

**Scenario:** A new GB300 machine is ingested. The desired state contains only real goals from real sources (firmware manifests, config templates, deployment manifests, security policies). There are no boolean "done" flags — every desired key holds concrete data.

**Initial observed state** (from Redfish/agent observation):
```
PowerState         = "off"
RmsInventoryId     = ""
DpuCount           = "0"
DpuInterfaceIp     = ""
DpuMode            = ""
DpuAgentVersion    = ""
FirmwareBmcVersion = "2.12.0"
BiosSettingsHash   = "d4e1f0"
NetworkConfigVersion = "v10"
ScoutVersion       = ""
ScoutHeartbeat     = "stale"
ValidationResult   = "not_run"
BomValidationResult = "not_run"
AttestationStatus  = "not_started"
LockdownEnabled    = "false"
HwSku              = "NVIDIA-GB300-XYZ"
```

**Desired state** (from config sources):
```
PowerState         = "on"                  ← operator intent
FirmwareBmcVersion = "2.14.0"              ← firmware manifest
FirmwareBiosVersion = "1.8.3"              ← firmware manifest
DpuFirmwareVersion = "24.04.1"             ← firmware manifest
BiosSettingsHash   = "a3f8c2"              ← BIOS config template
NetworkConfigVersion = "v12"               ← network config template
DpuNetworkConfigVersion = "v5"             ← network config template
DpuMode            = "dpu"                 ← hardware config
ScoutVersion       = "3.2.1"              ← deployment manifest
LockdownEnabled    = "true"                ← security policy
AttestationStatus  = "passed"              ← security policy
```

Note: keys like `RmsInventoryId`, `DpuCount`, `DpuAgentVersion`, `ScoutHeartbeat`, `ValidationResult`, and `BomValidationResult` are **not in desired state**. They are observed-only — their values appear as prerequisites in operation guards.

**Tick 1:**
- Delta: 10 keys differ (only keys present in `S_d`).
- `power_on` is ready (guard: `PowerState = "off"`). Scheduled.
- `register_with_rms` is ready (guard: `RmsInventoryId = ""`). Scheduled.
- Everything else blocked — most require `PowerState = "on"`.
- **Actions:** `power_on`, `register_with_rms` (parallel).

**Tick 2:**
- `PowerState = "on"`, `RmsInventoryId = "rms-12345"`. Observation refreshes: `DpuCount = "2"` (Redfish discovered DPUs as part of standard observation).
- `update_bmc_firmware` is ready (power on, version differs). Scheduled. Locks: `[Firmware, Power]`.
- `configure_bios` is ready (power on, hash differs: `d4e1f0 ≠ a3f8c2`). Scheduled. Locks: `[Bios]`.
- `configure_network` is ready (power on, version differs: `v10 ≠ v12`). Scheduled. Locks: `[Network]`.
- `configure_dpu_interfaces` is ready (`DpuCount ≠ "0"`, `DpuInterfaceIp = ""`). Scheduled. Locks: `[Dpu]`.
- No lock conflicts between these four operations.
- **Actions:** `update_bmc_firmware`, `configure_bios`, `configure_network`, `configure_dpu_interfaces` (all parallel).

**Tick 3:**
- `FirmwareBmcVersion = "2.14.0"`, `BiosSettingsHash = "a3f8c2"`, `NetworkConfigVersion = "v12"`, `DpuInterfaceIp = "10.0.1.5"`.
- `load_scout` is ready (power on, network matches desired, `ScoutVersion` differs). Scheduled.
- `set_dpu_mode` is ready (`DpuInterfaceIp ≠ ""`, `DpuMode ≠ "dpu"`). Scheduled.
- **Actions:** `load_scout`, `set_dpu_mode` (parallel).

**Tick 4:**
- `ScoutVersion = "3.2.1"`, `DpuMode = "dpu"`. Observation refreshes: `ScoutHeartbeat = "alive"` (heartbeat detected).
- `wait_for_dpu_agent` is ready (`DpuMode` matches desired, `DpuAgentVersion = ""`). Scheduled.
- `validate_machine` is ready (`ScoutHeartbeat = "alive"`, `BiosSettingsHash` matches, `NetworkConfigVersion` matches). Scheduled.
- **Actions:** `wait_for_dpu_agent`, `validate_machine` (parallel).

**Tick 5:**
- `DpuAgentVersion = "1.4.0"`, `ValidationResult = "passed"`.
- `validate_bom` is ready (`ValidationResult = "passed"`). Scheduled.
- `configure_dpu_network` is ready (`DpuAgentVersion ≠ ""`, `DpuNetworkConfigVersion` differs). Scheduled.
- **Actions:** `validate_bom`, `configure_dpu_network` (parallel).

**Tick 6:**
- `BomValidationResult = "passed"`, `DpuNetworkConfigVersion = "v5"`.
- `run_attestation` is ready (`BomValidationResult = "passed"`, power on). Scheduled.
- `enable_lockdown` is ready (power on, `LockdownEnabled = "false"`). Scheduled.
- **Actions:** `run_attestation`, `enable_lockdown` (parallel).

**Tick 7:**
- `AttestationStatus = "passed"`, `LockdownEnabled = "true"`.
- Delta is empty — all desired keys match observed.
- **Result:** CONVERGED.

**Comparison with boolean-flag version.** The real-observable model converges in 7 ticks vs. 8 with boolean flags. The key difference: `DpuCount` is observed data, not an operation output, so "DPU discovery" is eliminated as a step. Tick 2 runs four operations in parallel because there are no artificial phase boundaries.

**Self-healing example.** Suppose after convergence, BIOS settings drift (a user resets BIOS defaults via the BMC console). On the next observation tick, `BiosSettingsHash` changes from `"a3f8c2"` to `"b7c3d1"`. The engine detects the delta against desired `"a3f8c2"` and schedules `configure_bios`. No "re-init" phase, no reprovisioning request — just delta detection and convergence. With boolean flags, `BiosSettingsApplied = "true"` would have remained true despite the actual drift, masking the problem.

**DPU agent crash example.** If the DPU agent crashes, the next observation sees `DpuAgentVersion = ""`. The engine schedules `wait_for_dpu_agent`. Downstream operations that guard on `neq(DpuAgentVersion, "")` (like `configure_dpu_network`) are automatically blocked until the agent recovers. No manual intervention needed.
