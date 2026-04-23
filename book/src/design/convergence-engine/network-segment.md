# Network Segment Handler — Convergence Engine Mapping

## 1. Current State

**Handler file:** `crates/api/src/state_controller/network_segment/handler.rs` (190 lines)  
**State enum:** `NetworkSegmentControllerState` in `crates/api-model/src/network_segment/mod.rs`  
**Controller I/O:** `NetworkSegmentStateControllerIO`

The network segment handler manages VLAN/VNI network segment lifecycle: provisioning, readiness, and deletion with a graceful IP drain period. The handler is relatively simple with a linear state machine and a two-phase deletion process.

### 1.1 NetworkSegmentControllerState Variants

| # | Variant | Sub-state | Description |
|---|---------|-----------|-------------|
| 1 | `Provisioning` | — | Initial state; transitions immediately to `Ready`. |
| 2 | `Ready` | — | Segment is active; instances can be created. Watches for deletion requests. |
| 3 | `Deleting` | `NetworkSegmentDeletionState` | Segment is being deleted through a two-phase process. |

### 1.2 NetworkSegmentDeletionState

| Sub-state | Description |
|-----------|-------------|
| `DrainAllocatedIps { delete_at }` | Waiting for all IPs to be released. A `delete_at` timestamp is set; if IPs are still in use, the timestamp is pushed forward. Deletion proceeds only when IPs are drained AND `delete_at` is reached. |
| `DBDelete` | Final deletion: release VNI/VLAN pool allocations and delete from database. |

---

## 2. State Keys

| Observation Source | State Key | Type | Example Values |
|-------------------|-----------|------|----------------|
| `name` | `SegmentName` | Str | `"gpu-network-1"` |
| `segment_type` | `SegmentType` | Str | `"l2"`, `"l3"` |
| `mtu` | `SegmentMtu` | Int | `"9000"` |
| `vlan_id` | `SegmentVlanId` | Str | `"100"` or `""` (not allocated) |
| `vni` | `SegmentVni` | Str | `"50001"` or `""` (not allocated) |
| `prefixes` | `SegmentPrefixCount` | Int | `"4"` |
| `can_stretch` | `SegmentCanStretch` | Bool | `"true"`, `"false"` |
| IP allocation query | `SegmentAllocatedIpCount` | Int | `"3"` |
| `deleted` | `LifecycleDeleted` | Bool | `"true"`, `"false"` |

**Typical desired-state sources.** Operator intent (`LifecycleDeleted`). The desired-state composition layer may also set `SegmentVni` and `SegmentVlanId` to drive initial provisioning from pool allocation.

---

## 3. Operations

Operations are organized by setting domain — each manages a single, independently configurable property. See [§7.4](README.md#74-design-principle-properties-not-phases) for the design rationale.

### `provision_segment`

**Replaces:** `NetworkSegmentControllerState::Provisioning` match arm

```rust
op!(provision_segment {
    provides: [SegmentVni, SegmentVlanId],
    guard: and(
        eq(SegmentVni, ""),
        eq(SegmentVlanId, ""),
    ),
    locks: [NetworkSegment],
    effects: [
        SegmentVni => "{allocated_vni}",
        SegmentVlanId => "{allocated_vlan}",
    ],
    steps: [
        action(allocate_vni_from_pool),
        action(allocate_vlan_from_pool),
        action(configure_segment),
    ],
    priority: 90,
});
```

### `drain_segment_ips`

**Replaces:** `NetworkSegmentDeletionState::DrainAllocatedIps` logic

```rust
op!(drain_segment_ips {
    provides: [SegmentAllocatedIpCount],
    guard: and(
        eq(LifecycleDeleted, "true"),
        neq(SegmentAllocatedIpCount, "0"),
    ),
    locks: [NetworkSegment],
    effects: [SegmentAllocatedIpCount => "0"],
    steps: [
        action(check_allocated_ip_count),
        action(wait_for_drain_period, grace_period_seconds = 300),
    ],
    priority: 80,
});
```

### `delete_segment`

**Replaces:** `NetworkSegmentDeletionState::DBDelete` logic

```rust
op!(delete_segment {
    provides: [LifecycleDeleted],
    guard: and(
        eq(LifecycleDeleted, "true"),
        eq(SegmentAllocatedIpCount, "0"),
    ),
    locks: [NetworkSegment, Lifecycle],
    effects: [LifecycleDeleted => "true"],
    steps: [
        action(release_vni_allocation),
        action(release_vlan_allocation),
        action(final_delete),
    ],
    priority: 110,
});
```

### What Disappears

| Old | Property-oriented view |
|-----|------------------------|
| `NetworkSegmentControllerState::Provisioning` | Initial property only |
| `Ready` | Δ = ∅ |

---

## 4. Profiles

| Profile | Match Rule | Description |
|---------|-----------|-------------|
| `network_segment_default` | `true` | Single profile — segment management is type-agnostic |

---

## 6. Example Convergence Trace

**Scenario:** A network segment is created, becomes ready, and later is deleted with IP draining.

### Phase 1: Provisioning

**Initial observed state:**
```
SegmentVni             = ""
SegmentVlanId          = ""
SegmentAllocatedIpCount = "0"
```

No explicit desired state for provisioning -- the operation fires when VNI and VLAN are empty.

**Tick 1:**
- `provision_segment` is ready (VNI and VLAN are empty). Scheduled.
- **Actions:** `provision_segment`.

**Tick 2:**
- `SegmentVni = "50001"`, `SegmentVlanId = "100"`.
- **Result:** CONVERGED.

### Phase 2: Deletion (desired state changes)

**Observed state:**
```
SegmentVni              = "50001"
SegmentVlanId           = "100"
SegmentAllocatedIpCount = "3"
LifecycleDeleted        = "false"
```

**Desired state changes to:**
```
LifecycleDeleted = "true"
```

**Tick 1:**
- `drain_segment_ips` is ready (deletion requested, IP count is non-zero). Scheduled.
- **Actions:** `drain_segment_ips` (waits for IPs to drain and grace period).

**Tick 2 (after drain completes):**
- `SegmentAllocatedIpCount = "0"`.
- `delete_segment` is now ready (deletion requested, IPs drained). Scheduled.
- **Actions:** `delete_segment`.

**Tick 3:**
- Object deleted from database.
- **Result:** CONVERGED (deleted).
