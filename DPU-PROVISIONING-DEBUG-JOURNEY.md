# DPU Provisioning — Debug Journey & Production Lessons Learned

Captures the full chronological debugging story of bringing up a BlueField-3
DPU through NICo, with the specific issues encountered, root causes, fixes,
and the production-ready recommendations that emerged from each.

Companion docs:
- [`DPU-PROVISIONING-NX.md`](DPU-PROVISIONING-NX.md) — Reference provisioning workflow
- [`DEBUG.md`](DEBUG.md) — General-purpose troubleshooting reference
- [`DEPLOYMENT.md`](DEPLOYMENT.md) — Full deployment guide

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture: Two Provisioning Paths](#architecture-two-provisioning-paths)
3. [Stage 1 — Site-Explorer / BMC Discovery Issues](#stage-1--site-explorer--bmc-discovery-issues)
4. [Stage 2 — Network Segment Configuration](#stage-2--network-segment-configuration)
5. [Stage 3 — Credentials, Vault, expected_machines.json](#stage-3--credentials-vault-expected_machinesjson)
6. [Stage 4 — DHCP Boot URL Misconfiguration](#stage-4--dhcp-boot-url-misconfiguration)
7. [Stage 5 — Missing Boot Artifacts in carbide-pxe](#stage-5--missing-boot-artifacts-in-carbide-pxe)
8. [Stage 6 — BFB Build Environment on Air-Gapped Host](#stage-6--bfb-build-environment-on-air-gapped-host)
9. [Stage 7 — Switching to Redfish BFB Install Path](#stage-7--switching-to-redfish-bfb-install-path)
10. [Stage 8 — State Machine Reset (Database Surgery)](#stage-8--state-machine-reset-database-surgery)
11. [Stage 9 — Firmware Version Gate at `WaitingForPlatformConfiguration`](#stage-9--firmware-version-gate-at-waitingforplatformconfiguration)
12. [Production Recommendations](#production-recommendations)
13. [Quick-Reference Runbook](#quick-reference-runbook)

---

## Executive Summary

The journey took the deployment from "no DPU discovered" through to a DPU
that NICo successfully drives via the Redfish BFB install path on a
BlueField-3 with BMC firmware `BF-25.10-15`. Key takeaways:

- **NICo supports two DPU install paths:** classic PXE (UEFI HTTP boot) and
  newer Redfish `SimpleUpdate` BFB push. Selection is automatic but
  configuration-gated.
- **Boot artifacts are NOT baked into the carbide-pxe image** — they must be
  delivered via init containers (`bootArtifactContainers`) or copied in
  manually. This is a deliberate architectural choice.
- **The site-explorer pipeline has many strict pre-conditions** (network
  segment types, credentials, BMC reachability, time sync) — each must be
  satisfied for a machine to advance past `DPUInit/Init`.
- **The state machine is timestamp-driven** — `last_discovery_time`,
  `controller_state_version`, `last_reboot_requested` all interact, and stale
  values produce false `ManualInterventionRequired` errors after 15 retries.
- **`WaitingForPlatformConfiguration` is a hard firmware-version gate** —
  BMC, CEC, NIC versions are compared against compiled-in defaults and any
  mismatch parks the DPU in this state forever (no error, no escalation,
  just an infinite `Wait`). Override via site config or flash the
  firmware. See [Stage 9](#stage-9--firmware-version-gate-at-waitingforplatformconfiguration).

The Redfish path turned out to be far simpler than the full PXE path for
this hardware, requiring only the raw BFB file in carbide-pxe plus one
config flag. **Use Redfish whenever BMC firmware ≥ 24.10.**

---

## Architecture: Two Provisioning Paths

### Path A — UEFI HTTP PXE Boot (legacy)

Used when `dpu_enable_secure_boot = false` (default) OR BMC firmware < 24.10.

**Flow:**

```
DPU power-on
  → DHCP from carbide-dhcp (offers HttpBootUri)
  → UEFI HTTP fetches ipxe.efi from carbide-pxe
  → iPXE chainloads carbide.efi + carbide.root
  → carbide.efi boots, DPU agent runs, phones home to carbide-api
  → state machine advances → final BFB install via rshim/Redfish
```

**Artifacts required in carbide-pxe (`/boot-artifacts/blobs/internal/aarch64/`):**

| File | Source | Size |
|------|--------|------|
| `ipxe.efi` | Cross-compiled iPXE for ARM64 | ~1 MB |
| `carbide.efi` | Extracted from BFB (`dump-image-v0`) | ~30 MB |
| `carbide.root` | Extracted from BFB (`dump-initramfs-v0`) modified with carbide agent | ~200-500 MB |
| `forge.bfb` (= `preingestion.bfb`) | Raw BFB file | ~1.5 GB |
| `scout.efi` | mkosi-built host OS installer (only for host PXE) | ~50 MB |

### Path B — Redfish `SimpleUpdate` (modern)

Used when **both** are true:
- BMC firmware ≥ 24.10 (`BmcInfo::supports_bfb_install()`)
- `dpu_enable_secure_boot = true` in `[dpu_config]`

**Flow:**

```
DPU BMC → Redfish UpdateService/SimpleUpdate
  ImageURI = http://carbide-pxe.forge/.../forge.bfb
  Targets  = DPU_OS firmware inventory
DPU BMC fetches forge.bfb directly via HTTP and installs to DPU eMMC
```

**Artifacts required in carbide-pxe:**

| File | Source | Size |
|------|--------|------|
| `forge.bfb` | Raw BFB file (any compatible name) | ~1.5 GB |

That's it. No iPXE compile, no BFB extraction, no scout build.

Code reference for the decision:

```9140:9144:crates/api/src/state_controller/machine/handler.rs
// Skip for DPUs that get their BFB installed via redfish or DPF, they don't need to HTTP boot.
let redfish_install = machine.bmc_info.supports_bfb_install()
    && services.site_config.dpu_config.dpu_enable_secure_boot;

if !redfish_install && !dpf_used_for_ingestion {
    // boot_once(UefiHttp) ...
}
```

The `supports_bfb_install` check:

```45:50:crates/api-model/src/bmc_info.rs
pub fn supports_bfb_install(&self) -> bool {
    self.firmware_version.as_ref().is_some_and(|v| {
        version_compare::compare_to(v.to_lowercase().replace("bf-", ""), "24.10", Cmp::Ge)
            .is_ok_and(|r| r)
    })
}
```

---

## Stage 1 — Site-Explorer / BMC Discovery Issues

### Symptom 1.1 — `ncli site-explorer get-report endpoint` empty

**Root cause:** site-explorer only scans `NetworkSegmentType::Underlay`
segments. The BMC management network was initially configured with
`type = "admin"`, so site-explorer ignored it.

**Code:**

```rust
let underlay_segments =
    db::network_segment::list_segment_ids(&mut txn, Some(NetworkSegmentType::Underlay))
        .await?;
```

**Fix:** Set the BMC subnet to `type = "underlay"` in `values.base.yaml`:

```toml
[networks.admin]
type = "underlay"
prefix = "172.16.0.0/24"
gateway = "172.16.0.1"
mtu = 1500
reserve_first = 20
```

**Production lesson:** Document the network segment type taxonomy clearly.
`admin` and `underlay` look interchangeable but have very different
semantics — `admin` is for host inband post-provisioning, `underlay` is for
discovery.

### Symptom 1.2 — Stale segment after re-config

After changing the segment type, NICo did not pick up the new config — old
segment row still in DB.

**Fix:** Delete the stale segment + dependents via SQL transaction:

```sql
BEGIN;
DELETE FROM dhcp_entries WHERE network_segment_id = '<old-id>';
DELETE FROM machine_interface_addresses WHERE network_prefix_id IN
    (SELECT id FROM network_prefixes WHERE segment_id = '<old-id>');
DELETE FROM machine_interfaces WHERE network_segment_id = '<old-id>';
DELETE FROM instance_subnets WHERE network_segment_id = '<old-id>';
DELETE FROM network_prefixes WHERE segment_id = '<old-id>';
DELETE FROM tags_networksegment WHERE network_segment_id = '<old-id>';
DELETE FROM network_segments WHERE id = '<old-id>';
COMMIT;
```

**Production lesson:** carbide-api never *updates* a segment's `type` —
you must delete and recreate. Use the admin UI or `ncli` instead of direct
SQL where possible.

### Symptom 1.3 — `Failed to create managed host … WHERE network_segment_type = 'admin'`

`create_host_machine_dpu_interface_proactively` unconditionally calls
`network_segment::admin(txn)`. Without any segment of `type = "admin"`,
managed host creation fails after the BMC discovery succeeds.

**Fix:** Add a separate `[networks.host-inband]` segment with `type = "admin"`
and a **distinct** prefix from the underlay subnet:

```toml
[networks.host-inband]
type = "admin"
prefix = "172.16.10.0/24"
gateway = "172.16.10.1"
mtu = 9000
reserve_first = 20
```

**Production lesson:** Two segments are required — one `underlay`
for BMC discovery, one `admin` for the DPU host inband interface. The prefixes
must NOT overlap.

---

## Stage 2 — Network Segment Configuration

The final working layout in `dev/deployment/devspace/values.base.yaml`:

```toml
# VLAN 101 — BMC OOB management network (10G Switch)
# Used by site-explorer to discover BMCs
[networks.admin]
type = "underlay"
prefix = "172.16.0.0/24"
gateway = "172.16.0.1"
mtu = 1500
reserve_first = 20

# Host inband network — used for DPU host interfaces after provisioning
[networks.host-inband]
type = "admin"
prefix = "172.16.10.0/24"
gateway = "172.16.10.1"
mtu = 9000
reserve_first = 20
```

The "admin" name is historical — the **type** is what matters.

---

## Stage 3 — Credentials, Vault, expected_machines.json

### Symptom 3.1 — `HTTP 400 Bad Request … Password is null`

The DPU BMC at `172.16.0.23` was not in `expected_machines.json`, so carbide
had no credentials to talk to it.

**Fix:** Add an entry to `expected_machines.json`:

```json
{
  "bmc_mac": "84:eb:0c:5b:59:b1",
  "expected_serial_number": "MT2615605K5G",
  "fallback_dpu_serial_numbers": ["..."],
  "credentials": {
    "username": "root",
    "password": "nutanix/4u"
  }
}
```

Linked back to the host via `fallback_dpu_serial_numbers` on the host entry.

### Symptom 3.2 — Vault path confusion

`vault kv get secret/bmc/site-wide-root` returned empty. The actual path
the operator uses is:

```bash
vault kv get secrets/machines/bmc/site/root
```

**Production lesson:** Document the Vault paths in DEPLOYMENT.md /
DPU-PROVISIONING-NX.md prominently. The `secret/` vs `secrets/` and the
`/bmc/site/root` suffix are non-obvious.

### Symptom 3.3 — BMC time synchronization failure

After 5+ minute clock skew between DPU BMC and carbide-api, site-explorer
refused to ingest the BMC.

**Fix (manual):** PATCH the DPU BMC `DateTime` via Redfish:

```bash
curl -sk -u root:'nutanix/4u' -X PATCH \
  https://172.16.0.23/redfish/v1/Managers/Bluefield_BMC \
  -H "Content-Type: application/json" \
  -d "{\"DateTime\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
```

Then reset the stuck preingestion state:

```sql
UPDATE explored_endpoints
SET preingestion_state = '{"state": "initial"}'::jsonb
WHERE bmc_ip = '172.16.0.23';
```

**Production lesson:** Configure NTP on all BMCs at the factory/install
stage. Site-explorer's clock-skew tolerance is strict and a leading cause of
discovery failures.

---

## Stage 4 — DHCP Boot URL Misconfiguration

### Symptom — DPU UEFI HTTP boots from `http://127.0.0.1:8080/...`

The DPU serial console showed:

```
URI: http://127.0.0.1:8080/public/blobs/internal/aarch64/ipxe.efi
Error: Could not retrieve NBP file size from HTTP server.
Failed to boot 'UEFI HTTPv4 (MAC:84EB0C5B59B0)'
```

**Root cause:** `helm/charts/carbide-dhcp/values.yaml` had this default:

```yaml
"carbide-provisioning-server-ipv4": "127.0.0.1"
```

This value is injected into the DHCP offer's `HttpBootUri` option.

**Fix:** Override the full `keaConfigJson` in `values.base.yaml`'s
`carbide-dhcp:` section, replacing `127.0.0.1` with the carbide-pxe MetalLB
VIP `172.16.0.86`:

```yaml
carbide-dhcp:
  enabled: true
  externalService:
    enabled: true
    annotations:
      metallb.universe.tf/loadBalancerIPs: "172.16.0.85"
  config:
    enabled: true
    keaConfigJson: |
      {
        "Dhcp4": {
          ...
          "hooks-libraries": [{
            "library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp.so",
            "parameters": {
              ...
              "carbide-provisioning-server-ipv4": "172.16.0.86"
            }
          }]
          ...
        }
      }
```

**Production lesson:** The Helm chart should expose
`carbide-provisioning-server-ipv4` as a top-level value rather than burying
it inside a giant `keaConfigJson` blob, so operators don't have to copy the
entire JSON to override one field.

---

## Stage 5 — Missing Boot Artifacts in carbide-pxe

### Symptom — `curl http://172.16.0.86:8080/public/blobs/internal/aarch64/ipxe.efi` → 404

`kubectl exec` showed `/boot-artifacts/blobs/internal/aarch64/` did not
exist in the pod.

**Root cause:** The Helm chart serves boot artifacts from `/boot-artifacts`
(`bootArtifacts.servePath`), populated by `bootArtifactContainers` init
containers. The default `bootArtifactContainers: []` means **no init
container runs and the directory is never created**.

Chart definition:

```85:97:helm/charts/carbide-pxe/templates/deployment.yaml
{{- if .Values.bootArtifactContainers }}
- name: boot-artifacts
  mountPath: /boot-artifacts/blobs/internal
  readOnly: true
{{- end }}
...
{{- if .Values.bootArtifactContainers }}
- name: boot-artifacts
  emptyDir: {}
{{- end }}
```

The all-services Docker image (`Dockerfile.all-services`) also does **not**
copy `static/blobs/` into the image — by design.

**Why this is intentional:**

- BFB and EFI artifacts are large (1.5+ GB total) and change on a different
  release cycle from NICo code
- Baking them into the NICo image would bloat it and tie release cycles
  together
- Separation of concerns: NICo image = code, boot-artifacts image = blobs

### Production options for delivering artifacts

| Approach | Pros | Cons | Use when |
|----------|------|------|----------|
| **Boot artifact container image** | Versioned, immutable, scales | Need CI pipeline to build it | Production |
| **Manual `kubectl cp`** | Fast, no build pipeline | Doesn't survive pod restart | Lab / one-off |
| **Bake into NICo image** | One image | Bloated, coupled release cycles | Never recommended |
| **PVC / NFS mount** | Centralized storage | Extra infra dependency | Multi-cluster |

The **boot artifact container image** pattern is what the Helm chart was
built for:

```yaml
carbide-pxe:
  bootArtifactContainers:
    - name: boot-artifacts-aarch64
      image: "your-registry.example.com/boot-artifacts-aarch64:latest"
      command: ["sh", "-c", "cp -r /aarch64 /apt /firmware /boot-artifacts/blobs/internal"]
```

The init container's job is just to `cp -r` the blobs into the shared
`emptyDir` volume.

---

## Stage 6 — BFB Build Environment on Air-Gapped Host

The cargo-make pipeline (`cargo make build-boot-artifacts-bfb`) failed
repeatedly on the air-gapped `nico-cp-1`. Each failure produced a fix.

### 6.1 — `error: no such command: 'make'`

`cargo-make` not installed.

```bash
cargo install cargo-make
```

### 6.2 — Cross-compile of `libudev-sys` / `tss-esapi-sys` fails

Host doesn't have arm64 cross-compile libraries. The Makefile is designed
to run those builds **inside** a Docker container — `build-artifacts-container-cross-aarch64`.

`Dockerfile.build-artifacts-container-cross-aarch64` defines:

```dockerfile
FROM rust:1.90.0-bookworm
RUN dpkg --add-architecture arm64 && apt-get update && apt-get install -y \
    libudev-dev:arm64 libssl-dev:arm64 libtss2-dev:arm64 \
    g++-aarch64-linux-gnu libc6-dev-arm64-cross libclang-dev cmake
```

### 6.3 — Docker build can't reach `deb.debian.org`

nico-cp-1 has no direct internet — only via Squid proxy at `172.16.0.50:3128`.

**Fix applied to `dev/docker/Dockerfile.build-artifacts-container-cross-aarch64`:**

```dockerfile
FROM rust:1.90.0-bookworm

ARG SQUID_PROXY
ENV http_proxy=${SQUID_PROXY} \
    https_proxy=${SQUID_PROXY} \
    HTTP_PROXY=${SQUID_PROXY} \
    HTTPS_PROXY=${SQUID_PROXY}
```

**Fix applied to `Makefile.toml` `build-cross-docker-image` task:**

```bash
docker build ${REPO_ROOT}/dev/docker \
  -f ${REPO_ROOT}/dev/docker/Dockerfile.build-artifacts-container-cross-aarch64 \
  ${SQUID_PROXY:+--build-arg SQUID_PROXY=${SQUID_PROXY}} \
  --network=host \
  -t build-artifacts-container-cross-aarch64
```

Then build with:

```bash
export SQUID_PROXY=http://172.16.0.50:3128
cargo make build-boot-artifacts-bfb
```

### 6.4 — `wget` calls in BFB pipeline time out

`wget -Nnv` always contacts the server to compare timestamps, even when the
file exists locally. With no internet, this hangs.

**Fix applied to `pxe/Makefile.toml`:** Convert each `wget` task to check
file existence first and use proxy env vars:

```toml
[tasks.bfb-download]
script = '''
if [ -f "/tmp/bfb-dump/${BFB_NAME}" ]; then
  echo "BFB already present, skipping download."
else
  wget -nv ${SQUID_PROXY:+-e use_proxy=yes -e https_proxy=${SQUID_PROXY} -e http_proxy=${SQUID_PROXY}} \
    "${BFB_URL}/${BFB_NAME}" -P /tmp/bfb-dump
fi
'''
```

Same pattern applied to `bfbtools-download` and `download-debs-for-bfb`.

### 6.5 — Ubuntu 22.04 vs 24.04 BFB filename mismatch

`BFB_NAME` is hardcoded to `bf-bundle-...ubuntu-22.04_prod.bfb`. Operator
had only the `ubuntu-24.04_64k` variant.

**Workaround:** Hard-link or copy the file under the expected 22.04 name:

```bash
cp /path/to/bf-bundle-...ubuntu-24.04_64k_prod.bfb \
   /tmp/bfb-dump/bf-bundle-3.2.2-125_26.02_ubuntu-22.04_prod.bfb
```

**Long-term fix:** Either download the 22.04 BFB on the jump host (has
internet) and scp it, or parameterise `BFB_NAME` properly.

### 6.6 — `doas: not found`

The `bfb-extract-efi` task uses `doas` (an `sudo` alternative). On a
Debian-based root shell:

```bash
cat > /usr/local/bin/doas << 'EOF'
#!/bin/sh
exec "$@"
EOF
chmod +x /usr/local/bin/doas
```

### 6.7 — Conclusion: BFB build is heavyweight

The full `build-boot-artifacts-bfb` chain pulls in:
- iPXE cross-compile (works)
- BFB download + extraction (works with workarounds)
- forge-dpu .deb build → includes OpenTelemetry collector → downloads Go +
  otelcol-builder from internet

For an air-gapped host this is a **lot** of internet dependencies. The
Redfish path (Stage 7) avoids the entire build.

**Production lesson:** Build boot artifacts on a CI runner with internet
access, package them as a container image, and ship that to the air-gapped
site. Never try to build them on-site.

---

## Stage 7 — Switching to Redfish BFB Install Path

Once we confirmed:

- DPU BMC firmware = `BF-25.10-15` (≥ 24.10 ✓)
- The raw BFB file was already on the host

…the Redfish path became the obvious choice — bypassing the entire BFB
build pipeline.

### Step 1 — Enable in `values.base.yaml`

```toml
carbide-api:
  siteConfig:
    enabled: true
    carbideApiSiteConfig: |
      bypass_rbac = true
      attestation_enabled = false
      ...

      [dpu_config]
      dpu_enable_secure_boot = true
```

### Step 2 — Copy BFB into carbide-pxe pod

```bash
POD=$(kubectl get pod -n forge-system -l app.kubernetes.io/name=carbide-pxe -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n forge-system $POD -- mkdir -p /boot-artifacts/blobs/internal/aarch64
kubectl cp /tmp/bfb-dump/bf-bundle-3.2.2-125_26.02_ubuntu-22.04_prod.bfb \
  forge-system/${POD}:/boot-artifacts/blobs/internal/aarch64/forge.bfb
```

The filename **must be `forge.bfb`** — that's the literal string in:

```2454:2462:crates/api/src/state_controller/machine/handler.rs
let task = dpu_redfish_client
    .update_firmware_simple_update(
        "carbide-pxe.forge//public/blobs/internal/aarch64/forge.bfb",
        vec!["redfish/v1/UpdateService/FirmwareInventory/DPU_OS".to_string()],
        TransferProtocolType::HTTP,
    )
```

### Step 3 — Redeploy

```bash
devspace deploy -n forge-system --force-deploy
```

### Step 4 — Verify

```bash
# Config picked up by carbide-api
kubectl exec -n forge-system deployment/carbide-api -- \
  grep -A2 "dpu_config\|secure_boot" \
  /etc/forge/carbide-api/site/carbide-api-site-config.toml

# BFB reachable from inside cluster
curl -sk -o /dev/null -w "%{http_code}\n" \
  http://172.16.0.86:8080/public/blobs/internal/aarch64/forge.bfb
# expect: 200
```

### Clear stale boot override on DPU

If the DPU was previously trying PXE boot, clear its `BootSourceOverride`:

```bash
curl -sk -u root:'nutanix/4u' \
  -X PATCH https://172.16.0.23/redfish/v1/Systems/Bluefield \
  -H "Content-Type: application/json" \
  -d '{"Boot": {"BootSourceOverrideEnabled": "Disabled"}}'
```

---

## Stage 8 — State Machine Reset (Database Surgery)

After multiple retry cycles, the state machine accumulates stale state and
needs a manual reset. This is **expected lab-only behaviour** — production
should not require this if the prior stages are correct.

### Schema cheat sheet (from this debug session)

| Column | Type | Notes |
|--------|------|-------|
| `controller_state` | jsonb | Snake_case state object: `{"state": "dpuinit", "dpu_states": {...}}` |
| `controller_state_version` | varchar(64) | Format: `V1-T<microseconds-since-epoch>` |
| `last_reboot_requested` | jsonb | Stale value triggers spurious "machine has not responded" timeouts |
| `last_reboot_time` | timestamptz | When DPU last actually rebooted |
| `last_discovery_time` | timestamptz | Set by DPU agent calling `DiscoveryCompleted` RPC. Must be > version timestamp for state to advance past `Init`. |
| `controller_state_outcome` | varchar | Set when a state errors out — clear it to retry |
| `machine_topologies.topology->'bmc_info'` | jsonb | Contains `firmware_version` used by `supports_bfb_install()` |

### Reset script (lab use only)

```bash
DPU_ID=fm100dskaknaj98j3f73vnjkii7m8bskf7kc5lpoqd9n8nagcvcm001keu0
HOST_ID=fm100pskaknaj98j3f73vnjkii7m8bskf7kc5lpoqd9n8nagcvcm001keu0

kubectl exec -n postgres -it postgres-0 -- psql -U carbide carbide -c " \
  BEGIN; \
  UPDATE machines SET \
    controller_state = '{\"state\": \"dpuinit\", \"dpu_states\": {\"states\": {\"${DPU_ID}\": {\"dpustate\": \"init\"}}}}'::jsonb, \
    controller_state_version = 'V1-T' || floor(extract(epoch from now()) * 1000000)::bigint::text, \
    controller_state_outcome = NULL, \
    last_reboot_requested = NULL \
    WHERE id = '${HOST_ID}'; \
  UPDATE machines SET \
    controller_state_version = 'V1-T' || floor(extract(epoch from now()) * 1000000)::bigint::text, \
    controller_state_outcome = NULL, \
    last_reboot_requested = NULL, \
    last_reboot_time = NULL \
    WHERE id = '${DPU_ID}'; \
  COMMIT;"
```

### Why `last_discovery_time` matters

```4455:4460:crates/api/src/state_controller/machine/handler.rs
fn discovered_after_state_transition(
    version: ConfigVersion,
    last_discovery_time: Option<DateTime<Utc>>,
) -> bool {
    last_discovery_time.unwrap_or_default() > version.timestamp()
}
```

The state machine waits in `DpuInit::Init` until
`last_discovery_time > controller_state_version.timestamp()`. With a stale
or null `last_discovery_time`, it loops forever issuing reboots, eventually
hitting `ManualInterventionRequired` after 15 cycles (~91 hours).

If the DPU agent isn't yet installed (which is exactly the state we're
trying to escape from), `last_discovery_time` is never set — chicken-and-egg.

**Workaround (lab):**

```sql
UPDATE machines SET last_discovery_time = now()
WHERE id = '<dpu-id>';
```

**Production fix:** Ensure stage 7 (Redfish path) is properly enabled
**before** the first DPU boot — that way the state machine takes the
correct path from the start and `last_discovery_time` is never needed.

---

## Stage 9 — Firmware Version Gate at `WaitingForPlatformConfiguration`

After all earlier stages were fixed and the DPU advanced past
`DpuInit/Init`, the state machine settled in
`DPUInitializing/WaitingForPlatformConfiguration` and stayed there
indefinitely, with the following WARN repeating each iteration:

```
WARN object_id=fm100pska...
  msg="Bmc FW didn't update succesfully. Expected version: BF-25.10-20, Current version: BF-25.10-15"
  location="crates/api/src/state_controller/machine/handler.rs:3160"
```

### Root cause

`WaitingForPlatformConfiguration` calls `check_fw_component_version` before
it advances. The check iterates **BMC → CEC → NIC**, queries each via
Redfish, and compares the live version to the expected version. On any
mismatch it returns `StateHandlerOutcome::wait(...)` — intentionally **not**
an error, so retry timers do not fire and the state machine does not
escalate to `ManualInterventionRequired`. It just sits.

```3109:3186:crates/api/src/state_controller/machine/handler.rs
for component in [
    FirmwareComponentType::Bmc,
    FirmwareComponentType::Cec,
    FirmwareComponentType::Nic,
] {
    ...
    let expected_version = hardware_models
        .find(bmc_vendor::BMCVendor::Nvidia, &model.to_string())
        .and_then(|fw| fw.components.get(&component).cloned())
        .and_then(|fw_component| {
            fw_component
                .known_firmware
                .iter()
                .filter(|fw_entry| !fw_entry.preingestion_exclusive_config)
                .next_back()  // <-- last non-preingestion entry
                .cloned()
        })
        .map(|f| f.version)
        .unwrap_or("Unknown current configured BMC FW version".to_string());

    if cur_version != expected_version {
        ...
        tracing::warn!(
            machine_id=%dpu_snapshot.id,
            "{:#?} FW didn't update succesfully. Expected version: {}, Current version: {}",
            component, expected_version, cur_version,
        );
        return Ok(Some(StateHandlerOutcome::wait(format!(
            "{:#?} FW didn't update succesfully. ...", ...
        ))));
    }
}
```

The expected versions are hard-coded defaults in
`crates/api/src/cfg/file.rs`:

```58:65:crates/api/src/cfg/file.rs
static BF2_NIC: &str = "24.47.2682";
static BF2_BMC: &str = "BF-25.10-20";
static BF2_CEC: &str = "4-15";
static BF2_UEFI: &str = "4.13.2-12-g943a91640d";
static BF3_NIC: &str = "32.47.2682";
static BF3_BMC: &str = "BF-25.10-20";
static BF3_CEC: &str = "00.02.0195.0000_n02";
static BF3_UEFI: &str = "4.13.2-12-g943a91640d";
```

Important notes about this check:
- **UEFI is not in the loop** — only BMC, CEC, NIC are gated here.
- There is **no automatic BMC self-upgrade** in this state. The check only
  reads versions. The actual BMC FW upgrade happens via the BFB push in a
  later `InstallDpuOs` state, or by an external operator.
- The exception is **CEC < `00.02.0180.0000`** which triggers a host
  power cycle (see lines 3157-3170) — only that specific case auto-acts.

### Reading the DPU's actual firmware inventory

```bash
DPU_BMC=172.16.0.23
curl -sk -u root:'nutanix/4u' \
  https://${DPU_BMC}/redfish/v1/UpdateService/FirmwareInventory \
  | jq -r '.Members[]."@odata.id"' | \
while read inv; do
  curl -sk -u root:'nutanix/4u' "https://${DPU_BMC}${inv}" \
    | jq -r '"\(.Id // (."@odata.id" | split("/")|last))\t\(.Name)\t\(.Version)"'
done
```

Example output from a real BF-3 with `BF-25.10-15`:

| Inventory ID | Name | Version | Used by check? |
|---|---|---|---|
| `BMC_Firmware` | Software Inventory | `BF-25.10-15` | **YES (BMC)** |
| `Bluefield_FW_ERoT` | Software Inventory | `00.02.0195.0000_n02` | **YES (CEC)** |
| `DPU_NIC` | NIC image | `32.47.1088` | **YES (NIC)** |
| `DPU_UEFI` | UEFI image | `4.13.1-14-g8a01157b7f` | no |
| `ATF_Image` / `BSP_Image` / `Board_Image` / `OFED_Image` / etc. | various | various | no |

Cross-reference vs. expected (BF3 defaults):

| Component | Live | Expected | Status |
|---|---|---|---|
| BMC | `BF-25.10-15` | `BF-25.10-20` | **MISMATCH** |
| CEC | `00.02.0195.0000_n02` | `00.02.0195.0000_n02` | ✓ |
| NIC | `32.47.1088` | `32.47.2682` | **MISMATCH** |

So even after fixing BMC, NIC will also block — both need to be addressed.

### Fix options

| Option | Effort | Suitability |
|---|---|---|
| **A. Flash DPU BMC/NIC to expected versions** | Out-of-band: `bfb-install`, `mlxfwmanager`, or BMC web UI | Best long-term — matches what NICo's release was built/tested against. The full BFB push (Stage 7 Redfish path) usually updates BMC + NIC + UEFI all at once. |
| **B. Override expected versions via site config** | Add `[dpu_config.dpu_models.bluefield3.components.*]` blocks to `carbideApiSiteConfig`, redeploy | Clean lab/POC workaround; survives carbide-api rebuilds. **No source edits, no rebuild.** ← documented below |
| **C. Patch `cfg/file.rs` defaults + rebuild** | Edit constants at lines 58-65, run `cargo make build-and-test-release-container-services`, redeploy | Worst — diverges from upstream every rebase |

### Option B — Override via site config (recommended workaround)

The TOML schema mirrors the in-code `DpuConfig::default()` structure.
The `known_firmware` list is taken as-is for that component, replacing the
hard-coded defaults. The `check_fw_component_version` code calls
`.next_back()` on `known_firmware`, meaning **the last entry in the array
is the one used as `expected_version`**.

#### Step 1 — Read the live versions

Run the curl loop above. Note the BMC, CEC, NIC values. Skip CEC if it
already matches.

#### Step 2 — Patch `values.base.yaml`

In `dev/deployment/devspace/values.base.yaml`, extend the existing
`[dpu_config]` section inside `carbide-api.siteConfig.carbideApiSiteConfig`:

```toml
[dpu_config]
dpu_enable_secure_boot = true

# Override the firmware version gate at WaitingForPlatformConfiguration.
# Reference: crates/api/src/cfg/file.rs (defaults), handler.rs:3109+ (gate logic).
# `check_fw_component_version` uses the LAST entry of `known_firmware` as
# `expected_version`, so list your live versions last.

[dpu_config.dpu_models.bluefield3]
vendor = "Nvidia"
model = "Bluefield 3 SmartNIC Main Card"
ordering = ["bmc", "cec"]

[dpu_config.dpu_models.bluefield3.components.bmc]
current_version_reported_as = "BMC_Firmware"
known_firmware = [
  { version = "BF-25.10-15", default = true },
]

[dpu_config.dpu_models.bluefield3.components.cec]
current_version_reported_as = "Bluefield_FW_ERoT"
known_firmware = [
  { version = "00.02.0195.0000_n02", default = true },
]

[dpu_config.dpu_models.bluefield3.components.nic]
current_version_reported_as = "DPU_NIC"
known_firmware = [
  { version = "32.47.1088", default = true },
]

# UEFI is not in the gate iteration, but keep it in sync for other
# code paths that look up the firmware config.
[dpu_config.dpu_models.bluefield3.components.uefi]
current_version_reported_as = "DPU_UEFI"
known_firmware = [
  { version = "4.13.1-14-g8a01157b7f", default = true },
]
```

Important TOML caveats:

- `vendor = "Nvidia"` — capitalised; serde reads the enum variant name (see
  `crates/bmc-vendor/src/lib.rs:35-46`).
- Component keys are lowercase (`bmc`, `cec`, `nic`, `uefi`) — from
  `#[serde(rename_all = "lowercase")]` on `FirmwareComponentType`.
- `model` is matched against `DpuModel::from(...)` of the report. For BF3
  the keying string in the default config is the literal model
  `"Bluefield 3 SmartNIC Main Card"` — keep it identical.
- Overriding `dpu_models.bluefield3` **replaces** the default entry for
  BF3 wholesale (`partial.dpu_models.unwrap_or(default.dpu_models)` in
  `Deserialize for DpuConfig` at `cfg/file.rs:1754`). If you also have
  BF2 in the fleet you must add a `[dpu_config.dpu_models.bluefield2]`
  block too, otherwise BF2 falls back to defaults (which is fine if BF2
  matches them) **but only if you don't supply `dpu_models` at all**. As
  soon as you set any DPU model entry, the entire map is replaced.

#### Step 3 — Redeploy carbide-api

```bash
devspace deploy -n forge-system --force-deploy
```

Or, faster (just restart the deployment to re-read the configmap):

```bash
kubectl -n forge-system rollout restart deployment/carbide-api
kubectl -n forge-system rollout status deployment/carbide-api --timeout=180s
```

#### Step 4 — Verify the override is live

```bash
kubectl exec -n forge-system deployment/carbide-api -- \
  cat /etc/forge/carbide-api/site/carbide-api-site-config.toml | \
  grep -A2 -E 'dpu_models\.bluefield3|known_firmware'
```

#### Step 5 — Watch the state machine advance

```bash
kubectl logs -n forge-system deployment/carbide-api -f --since=1m | \
  grep -E "WaitingForPlatformConfiguration|FW updated succesfully|FW didn't update|InstallDpuOs|InstallingBFB|set_host_rshim"
```

You should see, in order:

1. `BMC FW updated succesfully to BF-25.10-15` (the override matched)
2. `CEC FW updated succesfully to 00.02.0195.0000_n02`
3. `NIC FW updated succesfully to 32.47.1088`
4. State transitions to `InstallDpuOs/InstallingBFB`
5. Redfish `SimpleUpdate` push of `forge.bfb` begins

### What this override actually disables

It tells NICo "the live versions you observe are the expected versions".
Two real consequences:

1. Any code path that uses `hardware_models.find(...)` to decide whether a
   firmware update is needed (host BMC reprovision flow, NIC firmware
   reprovision flow gated by `dpu_nic_firmware_reprovision_update_enabled`)
   will now think the DPU is already up-to-date.
2. The full BFB push (Redfish `SimpleUpdate`) still happens — it's driven
   by `dpu_enable_secure_boot = true` + DPU OS install state, not by this
   version check. After the BFB lands, the DPU's BMC/NIC/UEFI versions
   will change to whatever was in the BFB. **Update the override (or
   remove it) afterwards to match.**

### Production guidance

- This override is appropriate for **lab and POC** clusters where you
  can't (or don't want to) flash to upstream-expected versions yet.
- In **production** prefer Option A: align BMC/NIC firmware with what the
  carbide-api build expects, since these versions are usually pinned for
  qualification reasons (compatibility with DOCA / driver versions / BFB
  contents).
- The override can be made permanent by promoting it from
  `dev/deployment/devspace/values.base.yaml` into the production Helm
  overlay's `carbide-api.siteConfig.carbideApiSiteConfig`.

---

## Production Recommendations

### 1. Pre-build boot artifacts as a container image

Run this on a CI runner with internet access:

```bash
cargo make build-boot-artifacts-bfb
```

Then build a thin container:

```dockerfile
FROM scratch
COPY pxe/static/blobs/internal/aarch64/ /aarch64/
COPY pxe/static/blobs/internal/x86_64/ /x86_64/
COPY pxe/static/blobs/internal/apt/ /apt/
COPY pxe/static/blobs/internal/firmware/ /firmware/
```

Push to your registry, reference in `values.base.yaml`:

```yaml
carbide-pxe:
  bootArtifactContainers:
    - name: boot-artifacts-aarch64
      image: "your-registry/boot-artifacts-aarch64:v3.2.2-125"
      command: ["sh", "-c", "cp -r /aarch64 /apt /firmware /boot-artifacts/blobs/internal/"]
```

### 2. Use the Redfish path on supported hardware

If BMC firmware ≥ 24.10 (all BlueField-3 BMCs in the last ~2 years), set:

```toml
[dpu_config]
dpu_enable_secure_boot = true
```

And ensure `forge.bfb` is in the boot-artifacts image at
`/aarch64/forge.bfb`. You can skip the `ipxe.efi`/`carbide.efi`/
`carbide.root` artifacts entirely if **all** DPUs in your fleet use the
Redfish path.

### 3. Production network segments

Always have **two** segments — never collapse them:

```toml
[networks.bmc-discovery]   # name is cosmetic
type = "underlay"
prefix = "<BMC-OOB-subnet>"
# site-explorer scans here

[networks.dpu-host-inband]
type = "admin"
prefix = "<inband-subnet>"  # MUST NOT overlap with discovery
# create_host_machine_dpu_interface_proactively needs this
```

### 4. Pre-populate `expected_machines.json`

Production deployments should NOT rely on operators manually adding rows
during bring-up. Generate the JSON from your inventory system as part of
factory imaging.

Each entry needs:
- BMC MAC
- Expected serial number(s)
- Credentials (or Vault path reference)
- DPU/host linkage via `fallback_dpu_serial_numbers`

### 5. NTP / time sync on BMCs

Configure NTP on every BMC at factory imaging. The 5-minute clock-skew
tolerance in site-explorer is unforgiving, and DPU BMCs often drift after a
hard power loss.

### 6. Proxy support in build / CI pipelines

If any part of your build runs on an air-gapped host:

- Add `ARG SQUID_PROXY` + `ENV http_proxy=` to every Dockerfile
- Add `${SQUID_PROXY:+--build-arg SQUID_PROXY=${SQUID_PROXY}}` and
  `--network=host` to every `docker build` invocation in `Makefile.toml`
- Guard every `wget` with `if [ -f ... ]; then skip; fi`

The patches already applied to this repo as part of this debug journey:

- `Makefile.toml` `build-cross-docker-image` task
- `dev/docker/Dockerfile.build-artifacts-container-cross-aarch64`
- `pxe/Makefile.toml` `bfb-download`, `bfbtools-download`, `download-debs-for-bfb`
- `dev/deployment/devspace/values.base.yaml` `carbide-dhcp` keaConfigJson and
  `carbide-api.siteConfig` `dpu_enable_secure_boot`

### 7. Carbide-dhcp configuration ergonomics

Submit upstream improvement: expose `carbide-provisioning-server-ipv4` (and
`carbide-nameservers`, `carbide-ntpserver`, `carbide-api-url`) as
top-level Helm values rather than requiring an entire `keaConfigJson`
override. This avoids the trap of operators losing the rest of the Kea
config when they want to change one IP.

### 8. State machine observability

The state machine's stuck states (`DPUInit/Init` with no `last_discovery_time`)
are particularly hard to diagnose from logs alone. Recommendations:

- Wire the admin UI's machine state-history view into operator docs
- Add a `ncli machine describe --verbose` that prints all the relevant
  guard conditions (`last_discovery_time`, `controller_state_version`,
  `bmc_info.firmware_version`, `supports_bfb_install()` result)
- Surface the **reason** for staying in a state in the carbide-api logs at
  INFO, not DEBUG

---

## Quick-Reference Runbook

### "DPU stuck in DPUInit/Init forever"

1. Check carbide-api logs for the actual error:
   ```bash
   kubectl logs -n forge-system deployment/carbide-api --since=5m | \
     grep -E "Failed to explore|ManualIntervention|handle_object_state"
   ```
2. Check host & DPU BMC reachability:
   ```bash
   curl -sk -u root:'nutanix/4u' https://172.16.0.20/redfish/v1/ | jq '.RedfishVersion'
   curl -sk -u root:'nutanix/4u' https://172.16.0.23/redfish/v1/ | jq '.RedfishVersion'
   ```
3. If host BMC returns 500 → cold reset: `ipmitool -I lanplus -H <ip> -U root -P <pw> mc reset cold`
4. If DPU BMC is up, check `bmc_info`:
   ```sql
   SELECT topology->'bmc_info'->>'firmware_version'
   FROM machine_topologies WHERE machine_id = '<dpu-id>';
   ```
5. If firmware version ≥ 24.10 and `dpu_enable_secure_boot = true`, expect
   `InstallDpuOs/InstallingBFB`. Otherwise expect PXE boot path.

### "DPU stuck in `WaitingForPlatformConfiguration`" / WARN `FW didn't update succesfully`

Firmware version gate hit (see [Stage 9](#stage-9--firmware-version-gate-at-waitingforplatformconfiguration)).

1. Read live versions:
   ```bash
   DPU_BMC=172.16.0.23
   curl -sk -u root:'nutanix/4u' \
     https://${DPU_BMC}/redfish/v1/UpdateService/FirmwareInventory | \
     jq -r '.Members[]."@odata.id"' | \
   while read inv; do
     curl -sk -u root:'nutanix/4u' "https://${DPU_BMC}${inv}" | \
       jq -r '"\(."@odata.id" | split("/") | last)\t\(.Version)"'
   done
   ```
2. Compare BMC / CEC / NIC against `crates/api/src/cfg/file.rs:58-65`.
3. Either flash to expected versions, or add a
   `[dpu_config.dpu_models.bluefield3.components.*]` override block to
   `carbide-api.siteConfig.carbideApiSiteConfig` listing your live
   versions as the **last** entry in `known_firmware` (it's the entry
   `.next_back()` returns).
4. Redeploy carbide-api or `kubectl rollout restart deployment/carbide-api`.
5. Watch: `kubectl logs -n forge-system deployment/carbide-api -f | grep -E "FW updated succesfully|InstallDpuOs"`

### "DPU PXE boots from 127.0.0.1"

Override `carbide-provisioning-server-ipv4` in `values.base.yaml`'s
`carbide-dhcp.config.keaConfigJson` to point to the carbide-pxe VIP, then
`devspace deploy --force-deploy` and restart carbide-dhcp.

### "404 on /public/blobs/internal/aarch64/<file>"

The `bootArtifactContainers` init container chain didn't populate the
artifact. Either:
- Use the manual `kubectl cp` shortcut to inject the file
- Add the proper `bootArtifactContainers` to your Helm values
- Verify the boot-artifacts image exists and is pull-able

### "Stale state needs reset" (lab only)

See [Stage 8 reset script](#reset-script-lab-use-only).

### "`forge.bfb` exists but Redfish isn't pushing it"

1. Verify the config is live:
   ```bash
   kubectl exec -n forge-system deployment/carbide-api -- \
     grep -A2 dpu_enable_secure_boot \
     /etc/forge/carbide-api/site/carbide-api-site-config.toml
   ```
2. Verify firmware_version:
   ```bash
   kubectl exec -n postgres postgres-0 -- psql -U carbide carbide -c \
     "SELECT topology->'bmc_info' FROM machine_topologies WHERE machine_id = '<dpu-id>';"
   ```
3. If both are correct, the state machine still needs to advance past
   `DpuInit/Init` → `WaitingForPlatformPowercycle` → `WaitingForPlatformConfiguration`
   → `PollingBiosSetup` → `WaitingForNetworkConfig` → `InstallDpuOs`. This
   takes multiple iteration cycles (each ~30s).

---

## Appendix — Files Modified During This Journey

These changes were applied to the repository as part of debugging:

| File | Change | Reason |
|------|--------|--------|
| `dev/deployment/devspace/values.base.yaml` | Added `[networks.host-inband]` admin segment | Stage 1.3 |
| `dev/deployment/devspace/values.base.yaml` | Added `carbide-dhcp.config.keaConfigJson` with correct `carbide-provisioning-server-ipv4` | Stage 4 |
| `dev/deployment/devspace/values.base.yaml` | Added `[dpu_config] dpu_enable_secure_boot = true` | Stage 7 |
| `dev/docker/Dockerfile.build-artifacts-container-cross-aarch64` | Added `ARG SQUID_PROXY` + proxy ENV | Stage 6.3 |
| `Makefile.toml` `build-cross-docker-image` | Pass `--build-arg SQUID_PROXY` + `--network=host` | Stage 6.3 |
| `pxe/Makefile.toml` `bfb-download` | Skip if file exists; use proxy when not | Stage 6.4 |
| `pxe/Makefile.toml` `bfbtools-download` | Same pattern | Stage 6.4 |
| `pxe/Makefile.toml` `download-debs-for-bfb` | Same pattern | Stage 6.4 |
| `dev/deployment/devspace/values.base.yaml` | Added `[dpu_config.dpu_models.bluefield3.components.*]` overrides to match live BMC/CEC/NIC versions | Stage 9 |

These are local lab patches. Some may be candidates for upstream submission
(particularly the proxy support and the wget existence checks).
