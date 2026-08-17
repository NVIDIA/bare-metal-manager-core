# Upgrading NICo

`setup.sh` is designed to be **idempotent**: running it against an existing NICo installation upgrades each component in place. The same script and values files used for initial installation are the mechanism for upgrades — there is no separate upgrade script.

This page documents how each component behaves when `setup.sh` is re-run against a live cluster, what to prepare before upgrading, and version-specific considerations for the 2.0→2.1 path.

## How setup.sh handles upgrades

Every installation phase is designed to be safe to re-run:

| Phase | Behavior on re-run |
|-------|-------------------|
| **1 — local-path-provisioner** | Manifests are `kubectl apply`'d — idempotent. StorageClasses are upserted. |
| **1b — postgres-operator** | `helmfile sync` issues `helm upgrade --install` — upgrades the release in place. Existing `PostgreSQL` CRs (including `nico-pg-cluster`) are untouched. |
| **1c — MetalLB** | CRDs are applied server-side with `--force-conflicts`. Any helm-owned CRDs from a prior install have their ownership labels stripped before sync, preventing deletion. `helmfile sync` upgrades the release. Existing `IPAddressPool`, `BGPPeer`, and `BGPAdvertisement` instances are preserved and re-applied (idempotent `kubectl apply`). See [MetalLB CRD ownership](#metallb-crd-ownership-2021-upgrade-path). |
| **2 — cert-manager** | `helmfile sync` upgrades the release. Existing `ClusterIssuer`, `Certificate`, and `CertificateRequest` objects are untouched. The Vault TLS bootstrap certs are re-applied server-side; existing certs that are still valid are not reissued. |
| **3 — Vault** | `helmfile sync` upgrades the release. The StatefulSet rolling-update leaves Vault pods running. |
| **4 — Vault unseal** | `unseal_vault.sh` checks whether Vault is already initialized. If it is, it skips `vault operator init` and only unseals any pods that were restarted and became sealed again. The Vault cluster keys (`vault-cluster-keys` Secret) and root token (`vaultroottoken`) are preserved. |
| **4 (SSH host key)** | `bootstrap_ssh_host_key.sh` detects an existing SSH host key Secret and skips re-generation. The cluster's SSH identity is preserved across upgrades. |
| **5 — external-secrets + nico-prereqs** | `helmfile sync` upgrades both releases. Existing `ClusterSecretStore` and `ExternalSecret` objects are reconciled to their new definitions. The ESO controller re-syncs all secrets on the next poll cycle. |
| **5b — DPF** | DPF components are upgraded via their helm charts. The `DPFOperatorConfig`, `DPUCluster`, and `DPUService` objects are preserved. See [DPF upgrade considerations](#dpf-upgrade-considerations). |
| **6 — NICo Core** | `helm upgrade --install nico` rolls out the new Core image tag. The PostgreSQL database schema is migrated by the pre-upgrade Job (uses the `imagepullsecret` Secret, which is upserted). NICo state (host records, machine state, firmware inventory) lives in PostgreSQL and is preserved. |
| **7a–7g — NICo REST** | REST components are upgraded via `helm upgrade --install`. The `nico_rest` PostgreSQL database is migrated in-place by the REST migration Job. Temporal workflow state is preserved. The Keycloak realm and client credentials are preserved. |
| **7h — NICo Flow** | Flow, PSM, and NSM are upgraded in place. |
| **7i — NICo REST site-agent** | The site-agent StatefulSet is upgraded. The site UUID (stored in the `site-registration` Secret) and REST site record are preserved. |

### What is preserved across upgrades

- **Vault cluster**: init state, unseal keys, PKI chain, AppRole credentials, all secrets. Vault is never re-initialized on an upgrade run.
- **PostgreSQL data**: all NICo Core and NICo REST database state, including host records, machine state, site config, Keycloak realm data, and Temporal workflow history.
- **MetalLB site config**: `IPAddressPool`, `BGPPeer`, `BGPAdvertisement`, and `L2Advertisement` instances. These are re-applied on every run so any manual changes outside `setup.sh` are reconciled back to the values in `values/metallb-config.yaml`.
- **SSH host key**: the cluster SSH identity is preserved so BMC consoles do not require known-host updates.
- **Site UUID**: the REST site identity and site-agent registration are preserved.
- **Certificates**: all cert-manager-managed certificates remain valid until their natural expiry; they are not reissued on upgrade.

### What changes during an upgrade

- All helm release images are updated to the new tags set in `NICO_CORE_IMAGE_TAG`, `NICO_REST_IMAGE_TAG`, etc.
- CRD schemas are updated to their new versions via server-side apply.
- ConfigMaps and Secrets produced by helm are updated to reflect new chart values.
- The NICo Core and REST database schemas are migrated forward by their respective pre-upgrade Jobs.
- DPF operator and DPUService images are updated to the new `NICO_DPF_VERSION`.

## Pre-upgrade checklist

Complete every item before running `setup.sh`. Missing any of these can cause the upgrade to fail or leave the cluster in a partially upgraded state.

### 1. Back up Vault unseal keys

Vault unseal keys are stored in the `vault-cluster-keys` Secret in the `vault` namespace. If this Secret is lost and all Vault pods restart simultaneously, the cluster is unrecoverable without a Vault snapshot.

```bash
# Verify the backup Secret exists
kubectl get secret vault-cluster-keys -n vault -o jsonpath='{.metadata.name}'
```

Export and store it offline:

```bash
umask 077   # keep the backup readable only by you
kubectl get secret vault-cluster-keys -n vault -o json > vault-cluster-keys-backup.json
```

<Warning>
This file contains the plaintext Vault unseal keys. Store it in a secure, offline location and delete the local copy after storing.
</Warning>

### 2. Check cluster health before upgrading

Do not upgrade a cluster that already has degraded components. Resolve any existing issues first.

```bash
kubectl get pods -n nico-system
kubectl get pods -n nico-rest
kubectl get pods -n temporal
kubectl get pods -n vault
kubectl get pods -n postgres
kubectl get pods -n metallb-system
kubectl get pods -n dpf-operator-system   # if DPF is enabled — phase 5b upgrades it
```

All pods should be `Running` or `Completed`. Check for pods stuck in `CrashLoopBackOff`, `Pending`, or `Error`.

Verify that Vault is fully unsealed — a sealed Vault blocks the upgrade at phase 4:

```bash
kubectl exec -n vault vault-0 -c vault -- vault status -tls-skip-verify | grep -E "Sealed|Initialized"
```

Both should show `Initialized true` and `Sealed false`.

### 3. Pull the new release

Update your local checkout to the target release branch or tag:

```bash
git fetch upstream
git checkout upstream/release/v2.1   # or the specific release tag
```

Review the release changelog for breaking changes:
- `fern/changelog/` — user-facing changelog entries
- `helm-prereqs/` diff from the prior release — any new required values fields or removed flags

### 4. Review values file changes

Check whether new release added required values fields or changed defaults:

```bash
git diff upstream/release/v2.0..upstream/release/v2.1 -- helm-prereqs/values.yaml \
    helm-prereqs/values/nico-core.yaml \
    helm-prereqs/values/nico-rest.yaml \
    helm-prereqs/values/metallb-config.yaml
```

Update your site values files to include any new required fields before running `setup.sh`.

### 5. Update image tags

Set the new image tags for the target release:

```bash
export NICO_IMAGE_REGISTRY=registry.example.com/nico   # your registry
export NICO_CORE_IMAGE_TAG=v2.1.0                      # new Core tag
export NICO_REST_IMAGE_TAG=v2.1.0                      # new REST tag
```

If you are upgrading DPF as part of this release, the DPF version is read from `NICO_DPF_VERSION` (defaulting to the value baked into `setup.sh`). You do not normally need to set this explicitly unless your site uses a pinned version.

### 6. Run the pre-flight check

```bash
cd helm-prereqs/
source ./preflight.sh
```

Fix all errors before proceeding. Warnings about `NICO_DPF_BMC_ROOT_PASSWORD` being unset are safe to ignore on an upgrade (the credential is already stored in Vault from the initial install).

## Running the upgrade

With the checklist complete, run `setup.sh` exactly as you would for a fresh install:

```bash
cd helm-prereqs/
./setup.sh -y
```

`setup.sh` processes all phases in order. Phases that find their components already at the correct state complete quickly. Phases that detect a version delta or config change apply the update.

### Upgrade-specific flags

| Flag | When to use |
|------|------------|
| `--skip-core` | Upgrade only the prerequisite stack (MetalLB, Vault, etc.) without rolling NICo Core. Useful when the prerequisite stack changed but the Core image did not. |
| `--skip-rest` | Upgrade only NICo Core and prerequisites, skipping the REST stack. |
| `--skip-flow` | Skip the Flow upgrade (Phase 7h). |
| `--skip-dpf` | Skip DPF upgrade. Use only if DPF is not enabled at this site. |
| `--core-values <file>` | Use a per-site NICo Core values file (same as initial install). |
| `--metallb-config <path>` | Use a site-specific MetalLB manifest or kustomize dir (same as initial install). |

### Estimated upgrade time

| Phase | Typical duration |
|-------|-----------------|
| Phases 1–1c (storage, postgres-operator, MetalLB) | 2–5 min |
| Phases 2–4 (cert-manager, Vault, unseal) | 1–3 min (Vault is already initialized; only rolling update time) |
| Phase 5 (ESO + nico-prereqs) | 1–3 min |
| Phase 5b (DPF) | 3–10 min (depends on DPF version delta) |
| Phase 6 (NICo Core) | 3–8 min (includes DB migration Job) |
| Phases 7a–7i (NICo REST + site-agent) | 5–15 min (Temporal and DB migrations are the slowest steps) |

Total: typically **15–45 minutes** for a full upgrade with DPF.

## Post-upgrade verification

Run the same checks as after initial installation:

```bash
kubectl get pods -n nico-system
kubectl get pods -n nico-rest
kubectl get pods -n temporal
kubectl get pods -n vault
kubectl get pods -n postgres
kubectl get pods -n metallb-system
kubectl get pods -n dpf-operator-system   # if DPF enabled
```

Verify the deployed image versions match the target tags:

```bash
kubectl get deployment -n nico-system nico-api \
    -o jsonpath='{.spec.template.spec.containers[0].image}'
```

Verify every LoadBalancer service kept its VIP — an upgrade must not reassign them:

```bash
kubectl get svc -n nico-system -o wide | grep LoadBalancer
```

Every service should show the same external IP it had before the upgrade (the VIPs pinned in `values/nico-core.yaml`). Any `<pending>` entry means MetalLB is not advertising — check the MetalLB CRDs and site config objects (see the 2.0→2.1 note below).

Verify PostgreSQL has an elected leader and the cluster is running:

```bash
kubectl get postgresql -n postgres nico-pg-cluster -o jsonpath='{.status.PostgresClusterStatus}'
kubectl get pods -n postgres -l application=spilo,spilo-role=master
```

The first command should print `Running`; the second should show exactly one master pod in `Running` state.

Verify NICo Core is serving — hit the same HTTP health port the liveness probe uses (1080, exposed via the metrics Service):

```bash
kubectl run -i --rm --restart=Never --image=curlimages/curl upgrade-check \
  -n nico-system --quiet -- \
  -sf http://nico-api-metrics.nico-system.svc.cluster.local:1080/ >/dev/null && echo "nico-api healthy"
```

Then run the included health check, which covers the full stack (Vault, cert-manager, ESO, MetalLB, `.forge` DNS records):

```bash
cd helm-prereqs/
./health-check.sh
```

## Version-specific upgrade notes

### 2.0 → 2.1: MetalLB CRD ownership migration

**Impact:** This upgrade path requires special handling that `setup.sh` performs automatically. If you skip MetalLB's phase in your upgrade (e.g., by removing it from the helmfile run), your site config objects (`IPAddressPool`, `BGPPeer`, `BGPAdvertisement`) will be deleted.

**Root cause:** In NICo 2.0, MetalLB was deployed with `crds.enabled: true` (the helm chart default), which places all seven MetalLB CRDs inside the helm release manifest. In NICo 2.1, `crds.enabled: false` is set explicitly so that the MetalLB cert rotator can take SSA field ownership of the CRD `caBundle` without conflicting with helm on every re-sync. When helm sees `crds.enabled` change from `true` to `false`, it removes the CRDs from its manifest — and Kubernetes garbage-collects every `IPAddressPool`, `BGPPeer`, and `BGPAdvertisement` instance stored as CRD resources, permanently deleting your site config.

**How setup.sh handles this:** Before running `helmfile sync` for MetalLB, `setup.sh` strips the `app.kubernetes.io/managed-by: Helm` label and the `meta.helm.sh/release-name` / `meta.helm.sh/release-namespace` annotations from any existing MetalLB CRDs. With the labels removed, helm does not consider the CRDs part of its managed set and does not delete them during the sync. CRDs are then applied directly (server-side, `--force-conflicts`) before and after the helmfile sync.

**If you are upgrading manually** (not via `setup.sh`), you must strip helm ownership from all MetalLB CRDs before running `helmfile sync` or `helm upgrade`:

```bash
for crd in $(kubectl get crd -o name | grep '\.metallb\.io$'); do
    kubectl annotate "${crd}" meta.helm.sh/release-name- meta.helm.sh/release-namespace- --overwrite
    kubectl label  "${crd}" app.kubernetes.io/managed-by- --overwrite
done
```

Then apply the CRDs directly before sync:

```bash
METALLB_VERSION="0.14.5"   # match the version in helmfile.yaml
helm template metallb metallb/metallb --version "${METALLB_VERSION}" \
    -n metallb-system --include-crds \
    | awk '/^---[[:space:]]*$/ { if (doc ~ /kind: CustomResourceDefinition/) printf "%s---\n", doc; doc = ""; next } { doc = doc $0 "\n" } END { if (doc ~ /kind: CustomResourceDefinition/) printf "%s", doc }' \
    | kubectl apply --server-side --force-conflicts -f -
```

### 2.0 → 2.1: DPF version update

The default `NICO_DPF_VERSION` in `setup.sh` is updated with each NICo minor release to the tested DOCA Platform Framework version. On a 2.0→2.1 upgrade, DPF is upgraded from its 2.0 version to the 2.1 version automatically as part of phase 5b.

DPF manages DPU provisioning state in `DPUCluster`, `DPUService`, and `DPF` CRs, all of which persist across the upgrade. In-flight DPU provisioning workflows may pause while the DPF operator restarts; they resume automatically when the new operator pod comes up.

### 2.0 → 2.1: NICo Core startupProbe

NICo 2.1 requires `startupProbe` to be explicitly configured in the machine-a-tron deployment (issue #4298). The chart now validates this at render time and fails with a clear error if `startupProbe` is absent. The default values provide a suitable probe scaled to ~2,300 hosts; for larger sites, refer to `helm-prereqs/values/machine-a-tron-scale.yaml` for recommended parameters scaled to 13,500 hosts.

## Rollback

`setup.sh` does not have a built-in rollback mechanism. Rollback consists of:

1. Checking out the prior release branch or tag.
2. Re-running `setup.sh` with the prior image tags.

For NICo Core and REST, the Helm release is rolled back in place, and the database migration Jobs for the prior version run on startup. NICo's database migrations are designed to be forward-compatible; rolling back does not guarantee schema compatibility if the new version added non-nullable columns — which is why a pre-upgrade database backup is essential.

The `nico-pg-cluster` hosts several databases: `nico_system_nico` (NICo Core), `nico_rest` (NICo REST), and — when Flow is enabled — `flow`, `psm`, and `nsm`. A rollback backup must cover all of them; use `pg_dumpall`, which also captures roles and grants:

```bash
umask 077
kubectl exec -n postgres \
    "$(kubectl get pods -n postgres -l application=spilo,spilo-role=master -o jsonpath='{.items[0].metadata.name}')" \
    -- su postgres -c "pg_dumpall" > nico_pg_pre_upgrade.sql
```

<Note>
This is a **logical** dump, not a PVC snapshot. Restoring it means recreating the databases from SQL (`psql -f nico_pg_pre_upgrade.sql` against a clean cluster) — expect downtime proportional to database size. It also does not capture Vault storage or Temporal workflow history; in-flight workflows at the time of the dump cannot be replayed from it. If your storage class supports volume snapshots, snapshot the PostgreSQL and Vault PVCs as well for a faster, more complete restore point.
</Note>

Because of these limitations, re-running `setup.sh` with the prior image tags alone is **not** a complete rollback if the new version's migrations already ran — restore the database dump first, then deploy the prior version.

For DPF, rolling back to a prior DPF version is not supported by NVIDIA. If DPF fails to upgrade, reach out to NVIDIA support rather than attempting a downgrade.

## Using setup.sh for individual component upgrades

You can re-run only specific phases without going through the full upgrade sequence. The simplest way is to use the `--skip-*` flags:

```bash
# Upgrade only NICo Core image (skip all prereqs and REST)
./setup.sh -y --skip-rest

# Upgrade only NICo REST (skip Core and prereqs)
# Setup.sh does not have --skip-prereqs; re-running the full script is safe
# because all prereq phases are idempotent and fast when nothing changes.
./setup.sh -y --skip-core
```

For a single-helm-chart upgrade (e.g., rotating the NICo Core image tag without going through the full script):

```bash
helm upgrade nico ../helm \
    -n nico-system \
    -f helm-prereqs/values/nico-core.yaml \
    --set global.image.tag="${NICO_CORE_IMAGE_TAG}" \
    --timeout 300s --wait
```

This skips the MetalLB CRD handling, DPF management, and other prereq phases — only do this when you are certain those components do not need updating.
