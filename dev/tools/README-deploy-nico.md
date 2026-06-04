# `deploy-nico.sh` — end-to-end NICo deployment automation

`dev/tools/deploy-nico.sh` is a single self-contained Bash script that walks a
fresh Linux host (or set of hosts) through every step required to bring up
NICo: OS prereqs, kubeadm cluster, Calico, MetalLB, helm/devspace tooling,
site-specific helm values, a **local Docker registry**, the bootstrap stack
(cert-manager / vault / postgres), the devspace build, and the final helm
deploy. The same script supports interactive lab usage **and** non-interactive
CircleCI execution.

It implements the steps described in `DEPLOYMENT.md`, but parameterises
everything (subnet, IP pools, node count, VIPs, etc.) so it works on any
`/24` (or larger) network, not just the `172.16.0.0/24` lab.

---

## Files

| File | Purpose |
|---|---|
| `dev/tools/deploy-nico.sh` | Main automation script. |
| `dev/tools/deploy-nico.config.example` | Annotated example config — copy & edit, then pass with `--config`. |
| `dev/tools/README-deploy-nico.md` | This document. |

---

## Quick start

### Interactive (first run on a lab host)

```bash
./dev/tools/deploy-nico.sh
```

You are prompted for every required input (subnet, gateway, control-plane IP,
worker IPs, MetalLB range, DHCP pool, loopback pool, registry settings, …),
shown a confirmation summary, then the script runs every phase end-to-end.

### Non-interactive (CircleCI / repeat runs)

```bash
./dev/tools/deploy-nico.sh --config ./my-site.env --yes
```

Or purely via env vars:

```bash
NICO_SUBNET_CIDR=172.16.0.0/24 \
NICO_GATEWAY=172.16.0.1 \
NICO_CP_IP=172.16.0.80 \
NICO_WORKER_IPS=172.16.0.81,172.16.0.82 \
NICO_METALLB_RANGE=172.16.0.85-172.16.0.95 \
NICO_DHCP_POOL=172.16.0.20-172.16.0.76 \
NICO_LOOPBACK_POOL=172.16.0.100-172.16.0.121 \
NICO_REGISTRY_HOST=172.16.0.80 \
./dev/tools/deploy-nico.sh --yes
```

### Run only some phases

```bash
# Regenerate values files only (no cluster changes)
./dev/tools/deploy-nico.sh --phases values --yes

# Stand up the registry and redeploy without touching kubeadm
./dev/tools/deploy-nico.sh --phases registry,values,deploy,verify --yes
```

Phase names: `prereqs`, `cluster`, `tools`, `metallb`, `values`, `registry`,
`bootstrap`, `deploy`, `verify`, `all` (default).

---

## What it does, phase by phase

| Phase | Action |
|---|---|
| `inputs` | Always runs; collects/validates topology. |
| `prereqs` | swap off, sysctl, `br_netfilter`, `containerd.io`, `kubelet/kubeadm/kubectl` (pinned `NICO_KUBE_VERSION`), `/etc/hosts`, UFW off. Runs on CP **and every worker** via SSH. |
| `cluster` | `kubeadm init` on CP, installs Calico (auto-pinned to `NICO_NIC_NAME`), `kubeadm join` every worker. |
| `tools` | helm + helm-diff + devspace + docker on the control-plane host. |
| `metallb` | helm install MetalLB, applies an `IPAddressPool`/`L2Advertisement` for `NICO_METALLB_RANGE` pinned to `NICO_NIC_NAME`. |
| `values` | Renders `dev/deployment/devspace/values.base.yaml` (and `helm-prereqs/values/ncx-core.yaml` if present) entirely from the collected inputs. Existing files are backed up (`*.bak.<unix-ts>`). All NICo service VIPs, the loopback pool, the DHCP pool (`reserve_first` derived automatically), the unbound `.forge` zone, the kea config — every site-specific value is filled in. |
| `registry` | Runs `registry:2` as a Docker container on `NICO_REGISTRY_HOST:NICO_REGISTRY_PORT`, configures **containerd** on every node to trust it as an insecure HTTP registry (`/etc/containerd/certs.d/<host:port>/hosts.toml`), adds it to `/etc/docker/daemon.json` `insecure-registries`, restarts containerd/docker, and smoke-tests `/v2/` from each node. The rendered `values.base.yaml` already points `global.image.repository` and `carbide-bmc-proxy.image.repository` at this registry. |
| `bootstrap` | cert-manager (jetstack chart), local-path storage class, then `dev/deployment/devspace/bootstrap-prereqs.sh` (vault + postgres + cert issuers) with `LOCAL_DEV_INSTALL_CERT_MANAGER=0`. |
| `deploy` | Builds **all** images NICo deploys: `devspace build` (carbide-api/all-services + carbide-bmc-proxy) **plus** `forge/unbound` + `forge/unbound_exporter` (unless `NICO_BUILD_UNBOUND=0`). Then `docker tag`/`docker push` to the local registry → `devspace deploy`. If `NICO_USE_REGISTRY=0` the script falls back to `docker save \| ctr -n k8s.io images import` on every node. |
| `verify` | `kubectl get nodes/pods/svc/ipaddresspool`, prints all service VIPs and the OOB-switch helper-address you need to configure. |

A timestamped log is written to `${NICO_LOG_DIR}/deploy-YYYYMMDD-HHMMSS.log`.

---

## Required inputs

The script only insists on the topology values it cannot guess. Everything
else has a sensible default. Required inputs (must be set in env, in the
config file, or answered at the prompt):

| Variable | Example |
|---|---|
| `NICO_SUBNET_CIDR` | `172.16.0.0/24` |
| `NICO_GATEWAY` | `172.16.0.1` |
| `NICO_CP_IP` | `172.16.0.80` |
| `NICO_METALLB_RANGE` | `172.16.0.85-172.16.0.95` (≥7 IPs) |
| `NICO_DHCP_POOL` | `172.16.0.20-172.16.0.76` |
| `NICO_LOOPBACK_POOL` | `172.16.0.100-172.16.0.121` |

`NICO_WORKER_IPS` is optional — leave empty for single-node clusters.

All other tunables (versions, NIC name, MTU, namespace, registry host/port,
per-service VIP overrides) are documented inline at the top of
`deploy-nico.sh` and in `deploy-nico.config.example`.

---

## CircleCI usage pattern

1. Pre-bake an Ubuntu 22.04 image (or use a sufficient base) for the CI
   executor that already has SSH keys for the worker nodes installed.

2. Store all `NICO_*` values as **project-level environment variables** in
   CircleCI (or use a project context). Sensitive items: `NICO_SSH_KEY` (as a
   user key), `NICO_SQUID_PROXY` if used.

3. Job snippet:

   ```yaml
   jobs:
     deploy-nico:
       machine:
         image: ubuntu-2204:current
       steps:
         - checkout
         - run:
             name: Run NICo deployment
             no_output_timeout: 60m
             command: |
               sudo apt-get update && sudo apt-get install -y openssh-client curl
               # NICO_* env vars are injected by CircleCI project settings.
               ./dev/tools/deploy-nico.sh --yes --phases all
         - store_artifacts:
             path: /tmp/nico-deploy
             destination: nico-deploy-logs
   ```

4. For per-PR or smoke runs, restrict the phases:

   ```yaml
   command: ./dev/tools/deploy-nico.sh --yes --phases values,registry,deploy,verify
   ```

   This skips the destructive `prereqs`/`cluster` phases and only redeploys
   the helm chart on an already-provisioned cluster.

---

## Idempotency notes

* `prereqs` is safe to re-run — APT installs and sysctl writes are
  idempotent; `/etc/hosts` entries are managed inside a `# nico-managed-hosts`
  block so they are not duplicated.
* `cluster` detects an existing cluster via `kubectl cluster-info` and skips
  `kubeadm init` if one is already running. Worker `kubeadm join` is run
  unconditionally — the script logs (but ignores) "already joined" errors.
* `metallb` checks `helm status` before reinstalling.
* `values` always overwrites the target files but **backs them up first**
  with a `.bak.<unix-ts>` suffix.
* `registry` reuses an existing `nico-registry` container if present.
* `deploy` always runs `devspace deploy`, which is itself idempotent.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `required command missing: docker` in `registry` phase | Phase ordering — `tools` not yet run | Use `--phases all` or run `tools` before `registry`. |
| `registry NOT reachable from <ip>` | Worker node cannot reach `NICO_REGISTRY_HOST` (firewall, wrong NIC) | Verify the registry host/port is reachable: `curl http://<host>:<port>/v2/` from each worker. |
| `ImagePullBackOff` with `http: server gave HTTP response to HTTPS client` | containerd registry config did not load | Re-run `--phases registry` (this rewrites `/etc/containerd/certs.d/...` and restarts containerd). |
| `Resource pool missing or full` after redeploy | postgres holds stale pool state | `kubectl delete pod -n postgres --all && kubectl delete pod -n ${NICO_NAMESPACE} --all` |
| Pods stay `Pending` with `0/1 nodes are available` | MetalLB pool exhausted or NIC mismatch | Confirm `NICO_NIC_NAME` matches the actual NIC carrying the subnet on every node. |
| `IP_AUTODETECTION_METHOD` errors from Calico | Default NIC name differs per VM | Pin all VMs to a uniform NIC name (`eth0`) via udev — see `DEPLOYMENT.md` Phase 0d Step 2. |

The full deploy log lives at `${NICO_LOG_DIR}/deploy-*.log` and is also
streamed to the terminal as the script runs.
