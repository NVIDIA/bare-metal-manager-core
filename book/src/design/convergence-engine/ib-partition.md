# IB Partition Handler — Convergence Engine Mapping

## 1. Current State

**Handler file:** `crates/api/src/state_controller/ib_partition/handler.rs` (275 lines)  
**State enum:** `IBPartitionControllerState` in `crates/api-model/src/ib_partition/mod.rs`  
**Controller I/O:** `IBPartitionStateControllerIO`

The IB partition handler manages InfiniBand partition lifecycle: provisioning pkeys on the IB fabric, synchronizing partition state from the fabric manager, managing QoS settings, and cleaning up on deletion.

### 1.1 IBPartitionControllerState Variants

| # | Variant | Sub-state | Description |
|---|---------|-----------|-------------|
| 1 | `Provisioning` | — | Initial state; transitions immediately to `Ready`. |
| 2 | `Ready` | — | Partition is active; syncs state from IB fabric on each tick. |
| 3 | `Error` | `cause: String` | Partition is in error; may transition to `Deleting` if marked deleted. |
| 4 | `Deleting` | — | Partition is being cleaned up and removed from fabric. |

### 1.2 Handler Logic

The handler has notable inline logic (not delegated to sub-handlers):

- **`Provisioning`:** Transitions immediately to `Ready` (no actual provisioning step).
- **`Ready`:** Checks for `pkey` in status, queries IB fabric for partition state, syncs QoS and membership, detects deletion requests.
- **`Deleting`:** Validates `pkey` exists, queries fabric, handles `NotFound`, checks instance count, releases pkey, performs `final_delete`.
- **`Error`:** Transitions to `Deleting` if `pkey` present and marked deleted; otherwise does nothing.

---

## 2. State Keys

| Observation Source | State Key | Type | Example Values |
|-------------------|-----------|------|----------------|
| `config.name` | `PartitionName` | Str | `"gpu-partition-1"` |
| `config.pkey` | `PartitionPkey` | Str | `"0x8001"` |
| `config.mtu` | `PartitionMtu` | Int | `"2048"` |
| `config.rate_limit` | `PartitionRateLimit` | Str | `"100Gbps"` |
| `config.service_level` | `PartitionServiceLevel` | Str | `"high"` |
| `status.partition` | `PartitionFabricStatus` | Str | Status from IB fabric manager |
| `status.pkey` | `PartitionFabricPkey` | Str | Pkey as seen by fabric |
| IB fabric query | `PartitionFabricSyncHash` | Str | `"f4e2a1"` or `""` (not synced) |
| IB fabric QoS query | `PartitionQosHash` | Str | `"b3c1d0"` or `""` (not synced) |
| Instance count | `PartitionInstanceCount` | Int | `"5"` |
| `deleted` | `LifecycleDeleted` | Bool | `"true"`, `"false"` |

**Typical desired-state sources.** Operator intent (`LifecycleDeleted`). A fabric policy might also set `PartitionFabricSyncHash` or `PartitionQosHash` as desired goals to drive sync operations.

---

## 3. Operations

Operations are organized by setting domain — each manages a single, independently configurable property. See [§7.4](README.md#74-design-principle-properties-not-phases) for the design rationale.

### `provision_partition`

**Replaces:** `IBPartitionControllerState::Provisioning` match arm

```rust
op!(provision_partition {
    provides: [PartitionFabricSyncHash],
    guard: eq(PartitionFabricSyncHash, ""),
    locks: [IbPartition],
    effects: [PartitionFabricSyncHash => "{computed_hash}"],
    steps: [
        action(ib_create_partition_on_fabric),
        action(ib_verify_pkey_allocated),
    ],
    priority: 90,
});
```

### `sync_partition`

**Replaces:** Fabric sync logic in `IBPartitionControllerState::Ready` match arm

```rust
op!(sync_partition {
    provides: [PartitionFabricSyncHash],
    guard: eq(PartitionFabricSyncHash, "stale"),
    locks: [IbPartition],
    effects: [PartitionFabricSyncHash => "{computed_hash}"],
    steps: [
        action(ib_query_fabric_state),
        action(ib_update_local_state),
    ],
    priority: 70,
});
```

### `sync_partition_qos`

**Replaces:** QoS update logic in `IBPartitionControllerState::Ready` match arm

```rust
op!(sync_partition_qos {
    provides: [PartitionQosHash],
    guard: and(
        neq(PartitionFabricSyncHash, ""),
        eq(PartitionQosHash, ""),
    ),
    locks: [IbPartition],
    effects: [PartitionQosHash => "{computed_qos_hash}"],
    steps: [
        action(ib_update_qos_on_fabric),
        action(ib_verify_qos_applied),
    ],
    priority: 65,
});
```

### `delete_partition`

**Replaces:** `IBPartitionControllerState::Deleting` match arm

```rust
op!(delete_partition {
    provides: [LifecycleDeleted],
    guard: and(
        eq(LifecycleDeleted, "true"),
        eq(PartitionInstanceCount, "0"),
    ),
    locks: [IbPartition, Lifecycle],
    effects: [LifecycleDeleted => "true"],
    steps: [
        action(ib_release_pkey),
        action(ib_remove_partition_from_fabric),
        action(final_delete),
    ],
    priority: 110,
});
```

### What Disappears

| Old | Property-oriented view |
|-----|------------------------|
| `IBPartitionControllerState::Provisioning` | Initial property setting only |
| `Error` | Observable drift; engine retries |

---

## 4. Profiles

| Profile | Match Rule | Description |
|---------|-----------|-------------|
| `ib_partition_default` | `true` | Single profile — IB partition management is fabric-agnostic |

---

## 5. Example Convergence Trace

**Scenario:** A new IB partition is created with pkey `0x8001`, needing provisioning and QoS sync.

**Initial observed state:**
```
PartitionPkey          = "0x8001"
PartitionFabricSyncHash = ""
PartitionQosHash       = ""
```

No explicit desired state for sync -- the operations fire when the observed hashes are empty (meaning out of sync or not yet provisioned).

**Tick 1:**
- `provision_partition` is ready (`PartitionFabricSyncHash = ""`). Scheduled.
- **Actions:** `provision_partition`.

**Tick 2:**
- `PartitionFabricSyncHash = "f4e2a1"`.
- `sync_partition_qos` is now ready (sync hash is non-empty, QoS hash is empty). Scheduled.
- **Actions:** `sync_partition_qos`.

**Tick 3:**
- `PartitionQosHash = "b3c1d0"`.
- No further deltas.
- **Result:** CONVERGED.

**Self-healing:** If the fabric drifts (e.g., QoS settings are changed externally), the observation layer detects the hash mismatch and marks `PartitionQosHash = ""`. The engine re-runs `sync_partition_qos`.
