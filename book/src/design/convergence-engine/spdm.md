# SPDM / Attestation Handler — Convergence Engine Mapping

## 1. Current State

**Handler file:** `crates/api/src/state_controller/spdm/handler.rs` (834 lines)  
**State enums:** `AttestationState` and `AttestationDeviceState` in `crates/api-model/src/attestation.rs`  
**Controller I/O:** `SpdmStateControllerIO`

The SPDM (Security Protocol and Data Model) handler manages hardware attestation for bare-metal machines. It operates at two levels:

1. **Machine level** — orchestrates the overall attestation flow through `AttestationState`.
2. **Device level** — manages per-device attestation through `AttestationDeviceState` (each machine may have multiple attestable devices).

This two-level structure is unique among Carbide state handlers.

### 1.1 AttestationState Variants (Machine Level)

| # | Variant | Description |
|---|---------|-------------|
| 1 | `CheckIfAttestationSupported` | Query Redfish root for `ComponentIntegrity` field. If absent, attestation is not supported. |
| 2 | `FetchAttestationTargetsAndUpdateDb` | Discover all SPDM-capable components. Delete stale targets, insert new ones. |
| 3 | `FetchData` | Per-device: fetch measurements, certificates, and metadata. |
| 4 | `Verification` | Per-device: submit evidence to NRAS (NVIDIA Remote Attestation Service) for verification. |
| 5 | `ApplyEvidenceResultAppraisalPolicy` | Per-device: apply appraisal policies to verification results. |
| 6 | `Completed` | All devices attested successfully. Do nothing. |

### 1.2 AttestationDeviceState Variants (Device Level)

| # | Variant | Sub-states | Description |
|---|---------|------------|-------------|
| 1 | `NotApplicable` | — | Device does not require attestation. |
| 2 | `FetchData` | `FetchMetadata`, `FetchCertificate`, `Trigger`, `Poll`, `Collect`, `Collected` | Multi-step data collection from device via Redfish. |
| 3 | `Verification` | `GetVerifierResponse`, `VerifyResponse`, `VerificationCompleted` | Submit to NRAS verifier and validate response. |
| 4 | `ApplyEvidenceResultAppraisalPolicy` | `ApplyAppraisalPolicy`, `AppraisalPolicyValidationCompleted` | Apply compliance policies to attestation evidence. |
| 5 | `AttestationCompleted` | `status: AttestationStatus` | Terminal state with pass/fail status. |

### 1.3 Handler Structure

The handler uses `SpdmMachineStateSnapshot` as its controller state, which bundles:
- `machine_state: AttestationState` — the machine-level state
- `devices_state` — states of all attestable devices
- `device_state` — optional current device being processed

The machine-level handler dispatches to the device-level handler for `FetchData`, `Verification`, and `ApplyEvidenceResultAppraisalPolicy` states. It advances the machine-level state only when all devices have completed their current phase.

---

## 2. State Keys

### Machine-Level Keys

| Observation Source | State Key | Type | Example Values |
|-------------------|-----------|------|----------------|
| Redfish `ComponentIntegrity` | `AttestationComponentCount` | Int | `"5"` (0 = not supported) |
| Device discovery count | `AttestationTargetCount` | Int | `"2"` (0 = not yet discovered) |
| Overall attestation result | `AttestationStatus` | Str | `"not_started"`, `"in_progress"`, `"passed"`, `"failed"` |
| `started_at` | `AttestationStartedAt` | Str | `"2024-01-15T10:30:00Z"` |
| `canceled_at` | `AttestationCanceled` | Bool | `"true"`, `"false"` |

### Per-Device Keys

For each attestable device `d` with index `i`:

| Observation Source | State Key | Type | Example Values |
|-------------------|-----------|------|----------------|
| Device metadata | `AttestationDeviceMetadataHash(i)` | Str | `"a1b2c3"` or `""` (not fetched) |
| Device certificate | `AttestationDeviceCertFingerprint(i)` | Str | `"SHA256:..."` or `""` (not fetched) |
| Measurement collection | `AttestationDeviceMeasurementHash(i)` | Str | `"d4e5f6"` or `""` (not collected) |
| NRAS verification | `AttestationDeviceVerifierResult(i)` | Str | `"passed"`, `"failed"`, `""` |
| Appraisal result | `AttestationDeviceAppraisalResult(i)` | Str | `"passed"`, `"failed"`, `""` |
| Device attestation status | `AttestationDeviceStatus(i)` | Str | `"passed"`, `"failed"`, `"not_applicable"` |

**Typical desired-state sources.** Security policies (`AttestationStatus`, `AttestationDeviceStatus(i)`), operator intent (`LifecycleDeleted`).

---

## 3. Operations

Operations are organized by setting domain — each manages a single, independently configurable property. See [§7.4](README.md#74-design-principle-properties-not-phases) for the design rationale.

### 3.1 Machine-Level Operations

#### `check_attestation_support`

**Replaces:** `AttestationState::CheckIfAttestationSupported` match arm

```rust
fn check_attestation_support() -> Operation {
    op!(check_attestation_support {
        provides: [AttestationComponentCount],
        guard: eq(AttestationComponentCount, "0"),
        locks: [Attestation],
        effects: [AttestationComponentCount => "{discovered_count}"],
        steps: [
            action(redfish_query_component_integrity),
            action(determine_attestation_support),
        ],
        priority: 95,
    })
}
```

#### `discover_attestation_targets`

**Replaces:** `AttestationState::FetchAttestationTargetsAndUpdateDb` match arm

```rust
fn discover_attestation_targets() -> Operation {
    op!(discover_attestation_targets {
        provides: [AttestationTargetCount],
        guard: and(
            neq(AttestationComponentCount, "0"),
            eq(AttestationTargetCount, "0"),
        ),
        locks: [Attestation],
        effects: [AttestationTargetCount => "{discovered_target_count}"],
        steps: [
            action(redfish_list_spdm_components),
            action(db_upsert_attestation_devices),
            action(db_cleanup_stale_targets),
        ],
        priority: 90,
    })
}
```

### 3.2 Per-Device Operations

#### `fetch_device_metadata`

**Replaces:** `FetchDataDeviceStates::FetchMetadata`

```rust
fn fetch_device_metadata(i: usize) -> Operation {
    op!(fetch_device_metadata_{i} {
        provides: [AttestationDeviceMetadataHash(i)],
        guard: and(
            neq(AttestationTargetCount, "0"),
            eq(AttestationDeviceMetadataHash(i), ""),
        ),
        locks: [AttestationDevice(i)],
        effects: [AttestationDeviceMetadataHash(i) => "{metadata_hash}"],
        steps: [action(redfish_fetch_device_metadata, device_index = i)],
        priority: 85,
    })
}
```

#### `fetch_device_certificate`

**Replaces:** `FetchDataDeviceStates::FetchCertificate`

```rust
fn fetch_device_certificate(i: usize) -> Operation {
    op!(fetch_device_certificate_{i} {
        provides: [AttestationDeviceCertFingerprint(i)],
        guard: and(
            neq(AttestationDeviceMetadataHash(i), ""),
            eq(AttestationDeviceCertFingerprint(i), ""),
        ),
        locks: [AttestationDevice(i)],
        effects: [AttestationDeviceCertFingerprint(i) => "{cert_fingerprint}"],
        steps: [action(redfish_fetch_ca_certificate, device_index = i)],
        priority: 84,
    })
}
```

#### `collect_device_measurements`

**Replaces:** `FetchDataDeviceStates::Trigger`, `Poll`, `Collect`, `Collected`

```rust
fn collect_device_measurements(i: usize) -> Operation {
    op!(collect_device_measurements_{i} {
        provides: [AttestationDeviceMeasurementHash(i)],
        guard: and(
            neq(AttestationDeviceCertFingerprint(i), ""),
            eq(AttestationDeviceMeasurementHash(i), ""),
        ),
        locks: [AttestationDevice(i)],
        effects: [AttestationDeviceMeasurementHash(i) => "{measurement_hash}"],
        steps: [
            action(redfish_trigger_measurement_collection),
            action(redfish_poll_measurement_status, timeout_seconds = 300),
            action(redfish_collect_measurements),
        ],
        priority: 83,
    })
}
```

#### `verify_device_attestation`

**Replaces:** `VerificationDeviceStates::GetVerifierResponse`, `VerifyResponse`

```rust
fn verify_device_attestation(i: usize) -> Operation {
    op!(verify_device_attestation_{i} {
        provides: [AttestationDeviceVerifierResult(i)],
        guard: and(
            neq(AttestationDeviceMeasurementHash(i), ""),
            eq(AttestationDeviceVerifierResult(i), ""),
        ),
        locks: [AttestationDevice(i), Nras],
        effects: [AttestationDeviceVerifierResult(i) => "passed"],
        steps: [
            action(nras_submit_evidence, device_index = i),
            action(nras_verify_response),
        ],
        priority: 80,
    })
}
```

#### `appraise_device_attestation`

**Replaces:** `EvidenceResultAppraisalPolicyDeviceStates::ApplyAppraisalPolicy`

```rust
fn appraise_device_attestation(i: usize) -> Operation {
    op!(appraise_device_attestation_{i} {
        provides: [
            AttestationDeviceAppraisalResult(i),
            AttestationDeviceStatus(i),
        ],
        guard: and(
            eq(AttestationDeviceVerifierResult(i), "passed"),
            eq(AttestationDeviceAppraisalResult(i), ""),
        ),
        locks: [AttestationDevice(i)],
        effects: [
            AttestationDeviceAppraisalResult(i) => "passed",
            AttestationDeviceStatus(i) => "passed",
        ],
        steps: [action(apply_appraisal_policy, device_index = i)],
        priority: 75,
    })
}
```

### 3.3 Aggregation Operation

#### `complete_attestation`

**Replaces:** Transition to `AttestationState::Completed`

```rust
fn complete_attestation(device_count: usize) -> Operation {
    let status_guards: Vec<_> = (0..device_count)
        .map(|i| eq(AttestationDeviceStatus(i), "passed"))
        .collect();
    op!(complete_attestation {
        provides: [AttestationStatus],
        guard: and(status_guards),
        locks: [Attestation],
        effects: [AttestationStatus => "passed"],
        steps: [
            action(aggregate_device_attestation_results),
            action(set_attestation_status),
        ],
        priority: 70,
    })
}
```

### What Disappears

| Old | Property-oriented view |
|-----|------------------------|
| Machine-level `AttestationState` FSM | Properties converge naturally (per-device granularity) |
| `Completed` | Δ = ∅ |

---

## 4. Profiles

| Profile | Match Rule | Description |
|---------|-----------|-------------|
| `spdm_default` | `true` | Default SPDM attestation profile |

### 4.1 Nested Object Consideration

The SPDM handler's two-level structure (machine + per-device) presents a design consideration. Two approaches:

**Approach A — Dynamic key expansion.** The engine generates per-device state keys (`AttestationDevice*(0)`, `AttestationDevice*(1)`, etc.) dynamically based on discovered targets. Per-device operations are instantiated for each device. This fits the convergence model naturally but requires dynamic operation generation.

**Approach B — Sub-engine.** Each device runs its own mini convergence loop within the machine-level engine tick. The machine-level operation `fetch_data_all_devices` delegates to a sub-engine. This isolates complexity but adds architectural weight.

The recommended approach is **A** — dynamic key expansion — as it preserves the flat state model and allows the scheduler to parallelize per-device operations across different devices.

---

## 5. Example Convergence Trace

**Scenario:** A machine with 2 attestable devices needs full attestation.

**Initial observed state:**
```
AttestationComponentCount          = "0"
AttestationTargetCount             = "0"
AttestationDeviceMetadataHash(0)   = ""
AttestationDeviceCertFingerprint(0) = ""
AttestationDeviceMeasurementHash(0) = ""
AttestationDeviceVerifierResult(0) = ""
AttestationDeviceAppraisalResult(0) = ""
AttestationDeviceStatus(0)         = "not_started"
AttestationDeviceMetadataHash(1)   = ""
AttestationDeviceCertFingerprint(1) = ""
AttestationDeviceMeasurementHash(1) = ""
AttestationDeviceVerifierResult(1) = ""
AttestationDeviceAppraisalResult(1) = ""
AttestationDeviceStatus(1)         = "not_started"
AttestationStatus                  = "not_started"
```

**Desired state:**
```
AttestationStatus = "passed"
AttestationDeviceStatus(0) = "passed"
AttestationDeviceStatus(1) = "passed"
```

**Tick 1:** `check_attestation_support` -> `AttestationComponentCount = "5"`.

**Tick 2:** `discover_attestation_targets` -> `AttestationTargetCount = "2"`.

**Tick 3:** `fetch_device_metadata` for device 0 and device 1 (parallel). `AttestationDeviceMetadataHash(0) = "a1b2c3"`, `AttestationDeviceMetadataHash(1) = "d4e5f6"`.

**Tick 4:** `fetch_device_certificate` for both devices (parallel). Cert fingerprints populated.

**Tick 5:** `collect_device_measurements` for both devices (parallel). Measurement hashes populated.

**Tick 6:** `verify_device_attestation` for both devices (parallel if NRAS supports concurrent requests). `AttestationDeviceVerifierResult(0) = "passed"`, `AttestationDeviceVerifierResult(1) = "passed"`.

**Tick 7:** `appraise_device_attestation` for both devices. `AttestationDeviceStatus(0) = "passed"`, `AttestationDeviceStatus(1) = "passed"`.

**Tick 8:** `complete_attestation` -> `AttestationStatus = "passed"`.

**Result:** CONVERGED in 8 ticks. Per-device operations are parallelized across devices, and each step produces real observable data (hashes, fingerprints, results) rather than boolean flags.
