# forge-unbound — site-built recursive DNS resolver

This directory builds the **unbound** and **unbound_exporter** container
images that the helm chart at `helm/charts/unbound/` deploys to serve the
`.forge` DNS zone to BMCs/DPUs on the OOB management network.

> The chart expects images that honour the env-var contract
> `LOCAL_CONFIG_DIR`, `BROKEN_DNSSEC`, `UNBOUND_CONTROL_DIR`. These
> Dockerfiles implement that contract from public upstream sources
> (NLnetLabs unbound + letsencrypt/unbound_exporter), replacing the
> NVIDIA-internal `nvcr.io/nvidian/nvforge/unbound{,_exporter}` images
> so the supply chain for this dependency is owned by the deploying site.

## Why this exists

`.forge` zone resolution is **required at runtime** by every BMC and DPU
managed by NICo. Several hostnames are hardcoded in compiled crates
(`carbide-pxe.forge`, `carbide-api.forge`, `carbide-ntp.forge`,
`carbide-static-pxe.forge`) so a working resolver MUST be reachable on
the OOB network during PXE boot, BFB install, DPU cloud-init, and DPU
agent runtime. See `helm/charts/unbound/values.yaml` for the rationale
and `dev/deployment/devspace/values.base.yaml`'s `unbound:` block for
the chart-side wiring.

## Files

| File | Purpose |
|---|---|
| `Dockerfile` | Multi-stage build of unbound from the NLnetLabs source tarball |
| `entrypoint.sh` | Implements `LOCAL_CONFIG_DIR` / `BROKEN_DNSSEC` / `UNBOUND_CONTROL_DIR` |
| `unbound.base.conf` | Base unbound config; includes all `*.conf` from `LOCAL_CONFIG_DIR` |
| `../unbound-exporter/Dockerfile` | Builds `letsencrypt/unbound_exporter` for the sidecar |

## Build (lab, no external registry)

```bash
cargo make build-unbound-images
```

That task pins both upstream versions, builds both images, tags them
with the upstream version + this repo's short git SHA, and writes
`unbound-<ver>.tar.gz` + `unbound-exporter-<ver>.tar.gz` to the
workspace root for `ctr -n k8s.io images import` distribution.

To build a single image directly:

```bash
# unbound daemon
docker build \
  -f dev/docker/unbound/Dockerfile \
  --build-arg UNBOUND_VERSION=1.20.0 \
  ${SQUID_PROXY:+--build-arg SQUID_PROXY=${SQUID_PROXY}} \
  -t forge/unbound:1.20.0-$(git rev-parse --short HEAD) \
  dev/docker/unbound

# exporter sidecar
docker build \
  -f dev/docker/unbound-exporter/Dockerfile \
  --build-arg EXPORTER_REF=v0.4.6 \
  ${SQUID_PROXY:+--build-arg SQUID_PROXY=${SQUID_PROXY}} \
  -t forge/unbound_exporter:0.4.6-$(git rev-parse --short HEAD) \
  dev/docker/unbound-exporter
```

## Import into the kubeadm cluster's containerd

Same pattern every other NICo image uses (see DEPLOYMENT.md §7b). The
`cargo make build-unbound-images` task above already wrote tarballs to
`build-out/unbound/` — distribute and import:

```bash
GIT_SHA=$(git rev-parse --short HEAD)
UB_TAG="1.20.0-${GIT_SHA}"
UE_TAG="0.4.6-${GIT_SHA}"

for NODE in 172.16.0.80 172.16.0.81 172.16.0.82; do
  scp build-out/unbound/forge-unbound-${UB_TAG}.tar.gz \
      build-out/unbound/forge-unbound-exporter-${UE_TAG}.tar.gz \
      root@${NODE}:/tmp/
  ssh root@${NODE} "
    sudo ctr -n k8s.io images import /tmp/forge-unbound-${UB_TAG}.tar.gz
    sudo ctr -n k8s.io images import /tmp/forge-unbound-exporter-${UE_TAG}.tar.gz
    sudo ctr -n k8s.io images ls | grep forge/unbound
  "
done
```

> **Why `-n k8s.io`?** Kubelet only sees images in the `k8s.io`
> containerd namespace. Imports without the flag are invisible to it.

## Pin the chart to the built tag

The helm chart at `helm/charts/unbound/` reads `unbound.image.tag` and
`unbound.exporterImage.tag` from values. Update them in
`dev/deployment/devspace/values.base.yaml`:

```yaml
unbound:
  image:
    repository: "forge/unbound"
    tag: "1.20.0-<gitsha>"      # ← matches the tarball you imported
  exporterImage:
    repository: "forge/unbound_exporter"
    tag: "0.4.6-<gitsha>"
```

Then redeploy:

```bash
devspace deploy -n forge-system
kubectl delete pod -n forge-system -l app.kubernetes.io/name=unbound
kubectl get pod -n forge-system -l app.kubernetes.io/name=unbound -w
```

> **Why not let devspace build unbound?** devspace generates a random
> tag (e.g. `dNNbdQX`) for every image in its `images:` block and
> assumes a registry it can push to. We build deterministic
> `<version>-<sha>` tags and ship them straight to each node's
> containerd, so unbound stays out of devspace's `images:` list.

## Production registry path

For a real deployment, push to your site registry (Harbor / Artifactory /
ghcr.io / ECR …) and update the chart values:

```yaml
# dev/deployment/devspace/values.base.yaml  (or your prod overlay)
unbound:
  image:
    repository: "your-registry.example.com/forge/unbound"
    tag: "1.20.0-<gitsha>"
  exporterImage:
    repository: "your-registry.example.com/forge/unbound_exporter"
    tag: "0.4.6-<gitsha>"
  imagePullSecrets:
    - name: <your-registry-pull-secret>
```

## When to rebuild

| Trigger | Action |
|---|---|
| Upstream unbound release (every ~quarter) | Bump `UNBOUND_VERSION` + `UNBOUND_SHA256` in `Dockerfile`, rebuild |
| Unbound CVE advisory | Bump version OR cherry-pick patch + rebuild + push new tag |
| Upstream `unbound_exporter` release | Bump `EXPORTER_REF` in `unbound-exporter/Dockerfile`, rebuild |
| Base image CVE (`ubuntu:24.04`) | `--no-cache` rebuild to pull the latest patched base |

CI should run this build on a schedule (e.g. weekly) and on changes to
any file in `dev/docker/unbound/` or `dev/docker/unbound-exporter/`.
