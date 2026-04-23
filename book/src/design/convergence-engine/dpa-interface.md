# DPA Interface Handler — Convergence Engine Mapping

## 1. Current State

**Handler file:** `crates/api/src/state_controller/dpa_interface/handler.rs` (600 lines)  
**State enum:** `DpaInterfaceControllerState` in `crates/api-model/src/dpa_interface/mod.rs`  
**Controller I/O:** `DpaInterfaceStateControllerIO`

The DPA (Data Path Accelerator) interface handler manages the lifecycle of SuperNIC/BlueField DPA interfaces: provisioning, card lock/unlock cycles, firmware application, MlxConfig profile application, VNI (Virtual Network Identifier) assignment, and MQTT heartbeat monitoring.

### 1.1 DpaInterfaceControllerState Variants

| # | Variant | Description |
|---|---------|-------------|
| 1 | `Provisioning` | Initial state. If using admin network, stays here; otherwise transitions to `Ready`. |
| 2 | `Ready` | Configured with zero VNI. If not admin network, transitions to `Unlocking` for tenancy prep. |
| 3 | `Unlocking` | Waiting for the card to report `Unlocked` state via scout. |
| 4 | `ApplyFirmware` | Sending a `FirmwareFlasherProfile` to scout for firmware update. May send `None` (noop). |
| 5 | `ApplyProfile` | Applying an MlxConfig profile to the device. When `profile_synced`, transitions to `Locking`. |
| 6 | `Locking` | Waiting for the card to report `Locked` state via scout. |
| 7 | `WaitingForSetVNI` | VNI is being set on the DPA interface. |
| 8 | `Assigned` | DPA interface is configured with a non-zero VNI and assigned to a tenant. |
| 9 | `WaitingForResetVNI` | VNI is being reset back to zero (returning to admin network). |

### 1.2 Handler Flow

The handler implements a linear lifecycle with MQTT heartbeat integration:

```
Provisioning → Ready → Unlocking → ApplyFirmware → ApplyProfile → Locking → WaitingForSetVNI → Assigned
                  ↑                                                                                    |
                  └──────────────── WaitingForResetVNI ←──────────────────────────────────────────────────┘
```

Each state transition is driven by scout agent reports via MQTT (`card_state`, `firmware_report`, `profile_synced`).

---

## 2. State Keys

| Observation Source | State Key | Type | Example Values |
|-------------------|-----------|------|----------------|
| `mac_address` | `DpaMacAddress` | Str | `"aa:bb:cc:dd:ee:ff"` |
| `pci_name` | `DpaPciName` | Str | `"0000:03:00.0"` |
| `underlay_ip` | `DpaUnderlayIp` | Str | `"10.0.1.5"` or `""` |
| `overlay_ip` | `DpaOverlayIp` | Str | `"192.168.1.10"` or `""` |
| `card_state.lock_mode` | `DpaLockMode` | Str | `"locked"`, `"unlocked"` |
| `card_state.firmware_report` | `DpaFirmwareVersion` | Str | `"28.40.1000"` or `""` |
| `card_state.profile_synced` | `DpaMlxconfigHash` | Str | `"c4d2e1"` or `""` (not synced) |
| `device_info.part_number` | `DpaPartNumber` | Str | `"MCX75310AAS-NEAT"` |
| `device_info.psid` | `DpaPsid` | Str | `"MT_0000000884"` |
| `network_config` | `DpaNetworkConfigVersion` | Str | `"v2"` |
| `network_status_observation` | `DpaNetworkStatus` | Str | `"configured"`, `"pending"` |
| `mlxconfig_profile` | `DpaMlxconfigProfile` | Str | `"bf3_default"` |
| `last_hb_time` | `DpaHeartbeatAge` | Str | `"2s"`, `"stale"` |
| VNI from network config | `DpaVni` | Str | `"12345"` or `"0"` (admin) |
| `deleted` | `LifecycleDeleted` | Bool | `"true"`, `"false"` |

**Typical desired-state sources.** Tenancy lifecycle (`DpaLockMode`, `DpaVni`), firmware manifests (`DpaFirmwareVersion`), operator intent (`LifecycleDeleted`).

---

## 3. Operations

Operations are organized by setting domain — each manages a single, independently configurable property. See [§7.4](README.md#74-design-principle-properties-not-phases) for the design rationale.

### `provision_dpa`

**Replaces:** `DpaInterfaceControllerState::Provisioning` match arm

```rust
op!(provision_dpa {
    provides: [DpaUnderlayIp],
    guard: eq(DpaUnderlayIp, ""),
    locks: [DpaInterface],
    effects: [DpaUnderlayIp => "{assigned_ip}"],
    steps: [
        action(dpa_check_admin_network),
        action(dpa_initial_config),
    ],
    priority: 90,
});
```

### `unlock_dpa`

**Replaces:** `DpaInterfaceControllerState::Ready` → `Unlocking` transition and `Unlocking` match arm

```rust
op!(unlock_dpa {
    provides: [DpaLockMode],
    guard: and(
        neq(DpaUnderlayIp, ""),
        eq(DpaLockMode, "locked"),
    ),
    locks: [DpaInterface],
    effects: [DpaLockMode => "unlocked"],
    steps: [
        action(dpa_send_unlock_command),
        action(dpa_wait_for_unlock, timeout_seconds = 120),
    ],
    priority: 80,
});
```

### `apply_dpa_firmware`

**Replaces:** `DpaInterfaceControllerState::ApplyFirmware` match arm

```rust
op!(apply_dpa_firmware {
    provides: [DpaFirmwareVersion],
    guard: and(
        eq(DpaLockMode, "unlocked"),
        neq(DpaFirmwareVersion, desired(DpaFirmwareVersion)),
    ),
    locks: [DpaInterface, DpaFirmware],
    effects: [DpaFirmwareVersion => desired(DpaFirmwareVersion)],
    steps: [
        action(dpa_build_firmware_profile),
        action(dpa_send_firmware_profile_to_scout),
        action(dpa_wait_for_firmware_report, timeout_seconds = 600),
    ],
    priority: 75,
});
```

### `apply_dpa_profile`

**Replaces:** `DpaInterfaceControllerState::ApplyProfile` match arm

```rust
op!(apply_dpa_profile {
    provides: [DpaMlxconfigHash],
    guard: and(
        eq(DpaFirmwareVersion, desired(DpaFirmwareVersion)),
        eq(DpaLockMode, "unlocked"),
        eq(DpaMlxconfigHash, ""),
    ),
    locks: [DpaInterface],
    effects: [DpaMlxconfigHash => "{profile_hash}"],
    steps: [
        action(dpa_send_mlxconfig_profile),
        action(dpa_wait_for_profile_sync, timeout_seconds = 300),
    ],
    priority: 73,
});
```

### `lock_dpa`

**Replaces:** `DpaInterfaceControllerState::Locking` match arm

```rust
op!(lock_dpa {
    provides: [DpaLockMode],
    guard: and(
        neq(DpaMlxconfigHash, ""),
        eq(DpaLockMode, "unlocked"),
    ),
    locks: [DpaInterface],
    effects: [DpaLockMode => "locked"],
    steps: [
        action(dpa_send_lock_command),
        action(dpa_wait_for_lock, timeout_seconds = 120),
    ],
    priority: 70,
});
```

### `set_dpa_vni`

**Replaces:** `DpaInterfaceControllerState::WaitingForSetVNI` match arm

```rust
op!(set_dpa_vni {
    provides: [DpaVni],
    guard: and(
        eq(DpaLockMode, "locked"),
        neq(DpaVni, desired(DpaVni)),
    ),
    locks: [DpaInterface, DpaNetwork],
    effects: [DpaVni => desired(DpaVni)],
    steps: [
        action(dpa_send_set_vni_command),
        action(dpa_wait_for_vni_sync),
    ],
    priority: 65,
});
```

### `reset_dpa_vni`

**Replaces:** `DpaInterfaceControllerState::WaitingForResetVNI` match arm

```rust
op!(reset_dpa_vni {
    provides: [DpaVni],
    guard: and(
        eq(DpaLockMode, "locked"),
        neq(DpaVni, "0"),
    ),
    locks: [DpaInterface, DpaNetwork],
    effects: [DpaVni => "0"],
    steps: [
        action(dpa_send_reset_vni_command),
        action(dpa_wait_for_vni_reset),
    ],
    priority: 65,
});
```

### `dpa_heartbeat`

**Replaces:** Heartbeat logic embedded across multiple states (`Ready`, `Assigned`)

```rust
op!(dpa_heartbeat {
    provides: [DpaHeartbeatAge],
    guard: eq(DpaHeartbeatAge, "stale"),
    locks: [],
    effects: [DpaHeartbeatAge => "{current_age}"],
    steps: [
        action(dpa_send_mqtt_heartbeat),
    ],
    priority: 50,
});
```

### What Disappears

| Old | Property-oriented view |
|-----|------------------------|
| `DpaInterfaceControllerState::Provisioning` | Initial property convergence only |
| Linear lifecycle Provisioning → Ready → Unlocking → … | Parallel property convergence |
| `Ready` as a controller state | Not a state — Δ = ∅ |

---

## 4. Profiles

| Profile | Match Rule | Description |
|---------|-----------|-------------|
| `dpa_default` | `true` | Default DPA interface profile (BlueField 3+ devices) |

Future profiles could distinguish between BlueField generations:

| Profile | Match Rule |
|---------|-----------|
| `dpa_bf2` | `contains(DpaPartNumber, "BF2")` |
| `dpa_bf3` | `contains(DpaPartNumber, "BF3")` |

---

## 5. Example Convergence Trace

**Scenario:** A DPA interface is assigned to a tenant, requiring unlock → firmware → profile → lock → VNI.

**Initial observed state:**
```
DpaUnderlayIp      = "10.0.1.5"
DpaLockMode        = "locked"
DpaFirmwareVersion = "28.39.0"
DpaMlxconfigHash   = ""
DpaVni             = "0"
```

**Desired state:**
```
DpaLockMode        = "locked"
DpaVni             = "12345"
DpaFirmwareVersion = "28.40.1000"
```

**Tick 1:** `unlock_dpa` is ready (underlay IP is non-empty, card is locked, needs firmware update which requires unlock). Scheduled.

**Tick 2:** `DpaLockMode = "unlocked"`. `apply_dpa_firmware` is ready (unlocked, firmware version differs). Scheduled.

**Tick 3:** `DpaFirmwareVersion = "28.40.1000"`. `apply_dpa_profile` is ready (firmware matches desired, unlocked, profile hash is empty). Scheduled.

**Tick 4:** `DpaMlxconfigHash = "c4d2e1"`. `lock_dpa` is ready (profile hash is non-empty, card is unlocked). Scheduled.

**Tick 5:** `DpaLockMode = "locked"`. `set_dpa_vni` is ready (VNI differs: `"0"` vs `"12345"`). Scheduled.

**Tick 6:** `DpaVni = "12345"`. All desired keys match.

**Result:** CONVERGED.
