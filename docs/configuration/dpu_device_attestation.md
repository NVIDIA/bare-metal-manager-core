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
the API, alongside the host TPM EK-certificate path. The same happens at **exploration
time**: site-explorer resolves a DPU's id before the exploration report is persisted, so a
new DPU receives its hardware-rooted id at machine creation.

The SPDM controller's per-device attestation status for `Bluefield_DPU_IRoT` reflects the
same verification: the fetched chain is checked against the seeded device roots, and the
status is `Passed` only when the chain verifies (`Failed` otherwise). If **no** device
roots are seeded, the SPDM status passes through with a warning instead of failing the
fleet — seeding the roots is what opts a site into enforcement.

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

Identity stability also covers DPUs that already **adopted a device-rooted id**: the
adoption is recorded (with the DPU's legacy serial-derived id) in `dpu_device_cert_status`,
and every later resolution recognizes the DPU from that binding — so a transient BMC/Redfish
failure, or even rolling `mode` back to `disabled`, never flips an adopted DPU back to its
legacy id. `disabled` means "assign no *new* device-rooted ids", not "forget existing
ones".

---

## Trust anchors

Device-certificate chains are verified against the NVIDIA BlueField device root CA(s) stored
in the `dpu_device_ca_certs` table — the DPU analog of `tpm_ca_certs`. Seed them with the
admin CLI as a Day-0 / site-setup step, the same way TPM CA certs are loaded:

```bash
# Add a device root CA (DER/CER/PEM accepted; format chosen by file extension)
nico-admin-cli dpu-device-ca add --filename /path/to/bluefield-device-root.pem
# List configured roots (with id, validity, subject)
nico-admin-cli dpu-device-ca show
# Remove one by id
nico-admin-cli dpu-device-ca delete --ca-id 42
```

`add` is idempotent (re-adding an identical certificate reports it as already trusted) and
strict: it accepts exactly **one certificate per file** and rejects trailing bytes after the
DER data or extra PEM blocks — the stored bytes are compared verbatim at verification time,
so a sloppily exported root could never match.

Until at least one matching root is present, every chain fails verification
(`NoTrustedRoot`) — in `best_effort` mode DPUs keep their legacy id, in `required` mode
new-DPU discovery fails.

## Trust model — read before seeding a non-NVIDIA CA

**Verification trusts exactly the roots you seed, and nothing else.** A chain is accepted if
it is well-formed and chains to *any* root in `dpu_device_ca_certs`. There is **no built-in
NVIDIA-specific pinning** (name constraints / policy OIDs are not enforced today), so the
entire trust decision is *which* CAs you add.

This matters because the BlueField IRoT lets the **DPU owner re-provision the CA** that the
device certificate chains to:

- **Seed only the NVIDIA factory device root (recommended).** Only genuine,
  factory-provisioned device identities verify; a DPU presenting an owner-provisioned
  certificate (chaining to some other CA) is rejected with `NoTrustedRoot`. This is the
  posture that makes the device-rooted id a real hardware root of trust.
- **Seed an owner / site CA only if *you* control that CA key.** Doing so means you trust
  whoever holds the key to assert DPU identities: anyone who can sign with it can mint a
  certificate for an arbitrary serial and thereby obtain an arbitrary `machine_id`. If the DPU
  owner controls the CA and is not trusted by the site operator, seeding it **forfeits** the
  hardware-identity guarantee.

Rule of thumb: in a single-owner site (the operator owns the DPUs) either posture is fine;
where DPU owners are distinct from and untrusted by the operator, seed **only** the NVIDIA
factory root.

> **Operational note:** a DPU's device-rooted `machine_id` is derived from its device
> certificate, so re-provisioning the IRoT certificate changes the id and the DPU is seen as a
> new machine on its next discovery. (DPUs already enrolled under a legacy serial-derived id
> are unaffected — see [Backward compatibility](#backward-compatibility).)

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
