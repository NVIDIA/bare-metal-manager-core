# DPU device identity: hardware-rooted `machine_id` vs. verified attribute

**Status:** Proposed — open for discussion before the DPU device-identity work
(NVIDIA/infra-controller#2917, PR #3439) merges.

## Context

DPU device-identity attestation fetches a BlueField IRoT device certificate
out-of-band from the DPU BMC (Redfish SPDM `ComponentIntegrity`), verifies it
chains to a seeded NVIDIA device root CA, and produces a verified hardware
fingerprint (`SHA256(leaf DER)`). The design question is **how the rest of the
system consumes that verified fingerprint.** There are two options; the current
branch implements Option A.

Note up front: a `machine_id` is not self-authenticating — it is an opaque,
stable *name* (a hash with type/source tags). Neither option makes the id carry
proof; in both, the trust is established by `verify_device_cert_chain` at
verification time. The options differ only in **what the verified result is
bound to.**

## Option A — identity *is* the hardware (current branch)

Derive the DPU's `machine_id` from the verified cert: add a new
`MachineIdSource::DpuDeviceCert` (`b`) to the shared `carbide_uuid` format and
mint `machine_id = machine_id_from_device_cert(leaf)`. `select_dpu_machine_id`
swaps the id per `[dpu_device_attestation] mode`.

- **Pros**
  - Secure *by construction*: provenance is inseparable from the identity and
    travels everywhere `machine_id` is referenced (network config, instance
    allocation, RBAC, the node-auth JWT subject). No enforcement point can
    accidentally skip the hardware check by omission.
  - Unforgeable namespace: two physically distinct devices can never share an
    id, and a device that cannot present the cert cannot obtain a
    hardware-rooted id at all.
- **Cons**
  - Changes the **shared `machine_id` wire format** (new source char `b`). Any
    component that parses a `machine_id` — notably the DPU agent's
    `carbide_uuid` — must be rebuilt to accept `b` first, or it rejects the id
    and loops at discovery. This couples the rollout to agent versions.
  - Operational churn: newly device-rooted DPUs re-key from their legacy `s` id,
    requiring the delete/re-key flow and careful ordering vs. agent upgrades.

## Option B — hardware is a *verified attribute*

Keep the DPU's `machine_id` as its existing serial-derived (`s`) id and store
the verified fingerprint as a column on the machine (the
`dpu_device_cert_status` binding already holds `device_cert_sha256`,
`device_serial`, `verified_at`). Enforcement points consult that attribute.

- **Pros**
  - **The id hashing scheme is unchanged.** No new `MachineIdSource`, no shared
    format change, so **the agent-version coupling and re-keying disappear
    entirely** — the single largest operational cost of Option A.
  - Purely additive / backward compatible; nothing that references `machine_id`
    changes.
  - Decouples the identity *name* from *verification state*: attest, re-attest,
    or revoke the binding without renaming the machine.
- **Cons**
  - Secure *by policy*, not by construction: every security-sensitive consumer
    of `machine_id` must remember to also check the attribute. A missed check is
    **fail-open** (a verified and an unverified device look identical).
  - Namespace collision under spoofing: a device that asserts an existing DPU's
    serial collides into that DPU's `machine_id`; disambiguation relies on a
    downstream attestation check rather than the names being intrinsically
    distinct.

## What actually changes between A and B (code)

Independent of the choice, these stay:

- `model::dpu_device_attestation::verify_device_cert_chain` — the crypto
  (out-of-band fetch, chain-to-root, `SHA256(leaf)`). Unchanged.
- The `dpu_device_cert_status` record as the durable store of the verified
  fingerprint.
- node-auth `RefreshNodeToken` anti-theft (O4): re-fetch the live IRoT and
  compare. **This works either way** — under A it re-derives the same
  `machine_id`; under B it compares the live hash to the stored
  `device_cert_sha256` column. Equal strength. The auth-layer security therefore
  does **not** require id-as-key.

Only under Option B, these go away:

- `MachineIdSource::DpuDeviceCert` / the `b` id char in `crates/uuid`.
- `machine_id_from_device_cert` *as an id source* (the hash becomes a column
  value, not a primary key).
- `select_dpu_machine_id`'s id-swap → replaced by "verify, then set/validate the
  `device_cert_sha256` attribute; `machine_id` is always the legacy id."

## Recommendation / open question

The deciding trade is **secure-by-construction vs. no-rollout-coupling**:

- Option A cannot be gotten wrong by omission, at the cost of a shared id-format
  change that couples the rollout to agent versions and forces re-keying.
- Option B keeps the entire auth-layer security (O4 compares against the stored
  fingerprint) and drops the format change, re-keying, and agent-version
  coupling — but is only as strong as its least-careful consumer of `machine_id`.

Given the observed operational cost of the id-format change, **Option B with
node-auth issue/refresh and discovery de-dup explicitly consulting
`device_cert_sha256`** is a defensible sweet spot. The team should decide which
property to prioritize before this merges.
