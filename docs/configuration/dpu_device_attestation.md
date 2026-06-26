# DPU Device-Identity Attestation

Operator guide for giving BlueField DPUs a **hardware-rooted `machine_id`** derived from
their factory-provisioned BlueField device-identity certificate (IRoT), verified against
NVIDIA device root CAs.

Without this, a DPU's identity is a hash of self-asserted DMI serials presented over an
unauthenticated discovery call. With it, a DPU's identity is rooted in a certificate that
chains to a trusted NVIDIA device CA and is fetched out-of-band from the DPU BMC.

> **Scope:** DPF environments only — the controller needs Redfish access to the DPU BMC.
> Applies to BlueField-3 DPUs whose BMC exposes the `Bluefield_DPU_IRoT` SPDM target.

---

## How it works

1. A DPU calls `DiscoverMachine` and reports its DMI serial.
2. The API correlates the serial to the DPU's BMC via site-explorer's explored endpoints.
3. The API fetches the `Bluefield_DPU_IRoT` certificate chain from the BMC over Redfish
   (`GET /redfish/v1/Chassis/Bluefield_DPU_IRoT/Certificates/CertChain`).
4. The chain is verified against the configured NVIDIA device root CAs.
5. The DPU's `machine_id` is assigned according to the configured **mode** (below), and the
   verified binding is recorded.

Verification reuses the same SPDM/Redfish machinery as GPU attestation and is performed in
the API, alongside the host TPM EK-certificate path.

---

## Before You Start

You need:

- **DPF provisioning** — the controller must be able to reach each DPU's BMC (Redfish).
- **Site-explorer pre-ingestion** — the DPU's BMC must already be explored so the API can
  map the DPU's serial to its BMC. Ensure `[site_explorer].enabled = true` and that the DPU
  BMC has been ingested **before** the DPU is discovered. If it has not, a new DPU cannot be
  given a device-rooted id (it falls back per mode).
- **Trusted device root CA(s)** loaded into the `dpu_device_ca_certs` table (see
  [Trust anchors](#trust-anchors)). Until this is populated, verification fails closed.

Confirm a target DPU BMC exposes the IRoT target (replace IP / credentials):

```bash
curl -sk -u root:'<bmc-pass>' \
  "https://<dpu-bmc-ip>/redfish/v1/ComponentIntegrity?\$expand=.(\$levels=1)" \
  | jq '.Members[] | {Id, Type:.ComponentIntegrityType, Version:.ComponentIntegrityTypeVersion, Enabled:.ComponentIntegrityEnabled}'
```

Expect a `Bluefield_DPU_IRoT` member with `Type=SPDM`, `Version=1.1.0`, `Enabled=true`, and
`ServiceRoot.Product = "BlueField-3 DPU"`.

---

## Configuration

Add a `[dpu_device_attestation]` section to the site `nico-api` config:

```toml
[dpu_device_attestation]
# Policy for using a DPU's BlueField IRoT device certificate to assign its machine_id.
#   disabled    - never use device attestation; DPUs keep the legacy serial-derived id.
#   best_effort - use the device-rooted id when the cert is available and verifies;
#                 otherwise fall back to the legacy serial-derived id (no failure).
#   required    - a new DPU must present a verifiable device identity; discovery fails
#                 (fail closed) when one is unavailable.
mode = "best_effort"
```

| Field | Type | Default | Meaning |
|---|---|---|---|
| `mode` | `disabled` \| `best_effort` \| `required` | `disabled` | Identity-assignment policy (see above). |

If the section is omitted, the mode is `disabled` (legacy behavior).

### Backward compatibility

A DPU that is **already enrolled keeps its existing `machine_id` in every mode** — enabling
this feature never re-keys the existing fleet. Only a **previously unseen** DPU adopts a
device-rooted id; its id is deterministic in the device certificate, so re-discovery is
stable.

---

## Trust anchors

Device-certificate chains are verified against the NVIDIA BlueField device root CA(s) stored
in the `dpu_device_ca_certs` table — the DPU analog of `tpm_ca_certs`. These are expected to
be seeded at site creation. Until at least one matching root is present, every chain fails
verification (`NoTrustedRoot`), which in `best_effort` mode means DPUs simply keep their
legacy id, and in `required` mode means new-DPU discovery fails.

> Seeding tooling is tracked with the epic; the table mirrors `tpm_ca_certs`
> (`ca_cert_der`, validity, subject).

---

## Recommended rollout

1. **`disabled`** (default) — no change.
2. **`best_effort`** — once the device root CA(s) are seeded and DPU BMCs are being
   pre-ingested. New DPUs that verify get hardware-rooted ids; everything else is unaffected.
3. **`required`** — only after confirming fleet coverage (BMC reachability + pre-ingestion +
   roots), since it fails closed for any new DPU that can't present a verified identity.

---

## Verifying it works

- **Logs (`nico-api`):** a successful path logs
  `DPU <serial>: verified IRoT device identity -> machine_id <id>`. Soft failures log the
  reason (no explored BMC, no IRoT component, Redfish error, verification failure) at
  `warn`/`info`.
- **Machine id:** a device-rooted DPU id renders with the `db` source segment (e.g.
  `fm100db…`) versus the legacy serial source `ds` (`fm100ds…`).
- **Binding record:** the `dpu_device_cert_status` table has one row per machine that was
  assigned a verified device identity (device serial, cert hash, timestamp).

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| DPUs keep legacy ids in `best_effort` | Root CA(s) not seeded; DPU BMC not pre-ingested; or `ServiceRoot.Product` ≠ `"BlueField-3 DPU"`. |
| `required` discovery fails for a DPU | Same as above — no verifiable identity available. Confirm the BMC exposes `Bluefield_DPU_IRoT` and the chain verifies against a seeded root. |
| Verification fails (`NoTrustedRoot`) | The fetched chain doesn't chain to any root in `dpu_device_ca_certs`. |

> Note: the BMC reports the component id as `Bluefield_DPU_IRoT` (lowercase "f"); the API
> matches it case-insensitively, so either casing works.
