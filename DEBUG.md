# NuraMetal Lab — Debugging & Troubleshooting Guide

This document consolidates all debugging, troubleshooting, and known-issue
fixes for the NICo / Carbide lab deployment. For step-by-step deployment
instructions see [`DEPLOYMENT.md`](DEPLOYMENT.md).

> **DPU-specific debug journey:** see
> [`DPU-PROVISIONING-DEBUG-JOURNEY.md`](DPU-PROVISIONING-DEBUG-JOURNEY.md)
> for the end-to-end story of bringing up a BlueField-3 DPU through NICo,
> covering site-explorer, DHCP, PXE artifacts, BFB build, the Redfish
> install path, and state machine recovery.

---

## Quick Reference Table

| Symptom | Likely cause | Fix / Section |
|---------|-------------|---------------|
| Cannot reach VMs | Jump host down or credentials wrong | `ssh root@10.17.48.50` — password `nutanix/4u` |
| MetalLB services `<pending>` | `eth0` not on 10G subnet, or AHV Forged Transmits disabled | [MetalLB VIPs Pending](#metallb-vips-pending) |
| DHCP: only DISCOVER, no OFFER | Switch `ip helper-address` not set, or VIP not reachable | `arping -I eth0 172.16.0.85` from any VM — [DHCP no OFFER](#dhcp-only-discover-no-offer) |
| DHCP relay: `No network segment defined for relay addresses` | `admin` segment has stale prefix from old config | [Stale Network Segment Prefix](#dhcp-relay-fails--no-network-segment-defined-for-relay-address) |
| DHCP relay: `Received a non-relayed packet, dropping it` | `dhcping`/`dhclient` sent directly without relay agent | Must use `dhcrelay` or the Python relay test script — [Relay Testing](#testing-dhcp-relay-from-a-linux-host) |
| PXE 404 | BMC MAC not in `expected_machines.json` | `ncli em list`, re-register |
| PXE connection refused | `carbide-pxe` pod not running or VIP unassigned | `kubectl get pods,svc -n forge-system` |
| Scout can't reach carbide-api | Route from `172.16.0.0/24` to `172.16.0.89` missing | `ip route \| grep 172.16.0` on all VMs |
| carbide-api CrashLoopBackOff | siteConfig TOML parse error | `kubectl logs -n forge-system -l app.kubernetes.io/name=carbide-api --previous` |
| Machine stuck in Discovering | BMC not reachable from bmc-proxy pod | [Machine Stuck in Discovering](#machine-stuck-in-discovering) |
| DPU stuck in `WaitingForPlatformConfiguration` / WARN `Bmc FW didn't update succesfully` | BMC/CEC/NIC firmware version mismatch vs. hard-coded defaults in `crates/api/src/cfg/file.rs` | [`DPU-PROVISIONING-DEBUG-JOURNEY.md § Stage 9`](DPU-PROVISIONING-DEBUG-JOURNEY.md#stage-9--firmware-version-gate-at-waitingforplatformconfiguration) |
| `INVALID FW PACKAGE` on Redfish SimpleUpdate | DOCA BFB version incompatible with BMC firmware generation (BF-25.x vs BF-32.x) | [`DPU-PROVISIONING-NX.md § INVALID FW PACKAGE`](DPU-PROVISIONING-NX.md#invalid-fw-package--bfbmmc-version-mismatch) |
| Redfish task: `TransferFailed` / `Unknown Host` during BFB install | BMC cannot DNS-resolve `carbide-pxe.forge`. `.forge` is hosted by **unbound** (not `carbide-dns`). Enable `unbound` in `values.base.yaml` with `externalService` + `localConfig.local_data.conf` seeded with `.forge` A records, and set `carbide-dhcp` `carbide-nameservers` to the unbound VIP. Note: `host//path` URI is correct per NVIDIA docs — do NOT add `http://` | [`DPU-PROVISIONING-NX.md § TransferFailed`](DPU-PROVISIONING-NX.md#transferfailed--bmc-cannot-download-bfb) |
| `ncli machine show` → `missing field 'state'` | `controller_state` JSON uses wrong discriminant key (`"type"` instead of `"state"`) | [`DPU-PROVISIONING-NX.md § DB surgery`](DPU-PROVISIONING-NX.md#db-surgery--correct-controller_state-json-format) |
| DPU stuck in `DPUINITIALIZING/INIT` — NICo loops issuing reboots | `last_discovery_time` not strictly greater than `controller_state_version` timestamp | [`DPU-PROVISIONING-NX.md § DPU stuck in Init`](DPU-PROVISIONING-NX.md#dpu-stuck-in-dpuinitializinginit) |
| NICo skips BFB install — jumps straight to `WaitingForNetworkConfig` | DB reset set `Init` state then advanced via `last_discovery_time`; must set `installingbfb` directly | [`DPU-PROVISIONING-NX.md § NICo skips BFB install`](DPU-PROVISIONING-NX.md#nico-skips-bfb-install-after-db-reset) |
| `devspace deploy` fails — `no field 'machine_id' on type &mut MachineMetrics` | Branch has stale `handler.rs`; fields refactored into `.health` sub-struct, `machine_id` → `object_id` | [`DPU-PROVISIONING-NX.md § carbide-api build fails`](DPU-PROVISIONING-NX.md#carbide-api-build-fails--machinemetrics-field-not-found) |
| DPU stuck in `WaitingForNetworkConfig` — `forge-dpu-agent` never calls back | DPU booted old eMMC slot (pre-NICo OS) — cloud-init ran in 2025, `oob_net0` down | [`DPU-PROVISIONING-NX.md § WaitingForNetworkConfig`](DPU-PROVISIONING-NX.md#waitingfornetworkconfig--forge-dpu-agent-not-calling-back) |
| kubeadm join fails | Token expired (>24h) | `kubeadm token create --print-join-command` on nico-cp-1 |
| DevSpace build fails (Docker pull timeout) | Docker daemon has no proxy | [Docker Cannot Pull Base Images](#docker-cannot-pull-base-images) |
| DevSpace build fails (apt-get 404) | `SQUID_PROXY` not exported | [apt-get Cannot Find Packages](#apt-get-cannot-find-packages-in-docker-build) |
| `calico-node` 0/1 — BIRD not ready | Two NICs cause ambiguous IP autodetection | [Calico BIRD Not Ready](#calico-bird-not-ready) |
| Felix: `lookup localhost on 8.8.8.8:53: i/o timeout` | NICo VM hostnames missing from `/etc/hosts` | [Calico Felix DNS Timeout](#calico-felix-health-endpoint--dns-timeout) |
| `/sbin/kea-dhcp4: not found` in pod | Stale `carbide-runtime-base` missing kea packages | [kea-dhcp4 Not Found in Pod](#kea-dhcp4-not-found-in-pod) |
| `libdhcp.so: No such file or directory` | `carbide-dhcp` cdylib build failed silently | [libdhcp.so Missing](#libdhcpso-not-found) |
| `file not found for module 'common'/'forge'` | Stale BuildKit cargo cache | [Proto Files Missing](#proto-files-missing--file-not-found-for-module) |
| Cargo `Timeout was reached` | Cargo not using proxy | `export SQUID_PROXY=http://172.16.0.50:3128` |
| `ImagePullBackOff` on any pod | New image tag not imported into containerd | [ImagePullBackOff](#imagepullbackoff) |
| `Resource pool 'vpc-vni' missing or full` | DB exhausted from prior runs | [Resource Pool Full](#resource-pool-missing-or-full) |
| `relation "resource_pool_def" does not exist` | Migration job never ran | [Migration Job Not Created](#migration-job-not-created) |
| `ServiceAccount … must equal "carbide-local"` | Wrong helm release name used | [Wrong Helm Release Name](#wrong-helm-release-name) |
| All services are `ClusterIP`, no MetalLB IPs | `externalService.enabled: false` | Add `externalService.enabled: true` to `values.base.yaml` |
| Need to power on/off/reset a machine | — | Admin UI: `https://172.16.0.89/admin/explored-endpoint/<bmc-ip>` → power buttons — [Admin UI](#carbide-api-admin-ui-https172160089admin) |
| Machine stuck — need state history | — | Admin UI: `https://172.16.0.89/admin/machine/<id>/state-history` — [Admin UI](#carbide-api-admin-ui-https172160089admin) |
| DHCP lease not assigned — check allocation | — | Admin UI: `https://172.16.0.89/admin/ipam/dhcp` — [Admin UI](#carbide-api-admin-ui-https172160089admin) |
| `carbide-admin-cli`: TLS cert name mismatch | Connecting via IP, not DNS name | [CLI TLS Certificate Mismatch](#cli-tls-certificate-mismatch) |
| `carbide-admin-cli`: `UrlParseError("")` | `http_proxy` env vars set in shell | `unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY` |
| `UrlParseError("")` in machine-a-tron pod | `http_proxy` baked into image ENV | [machine-a-tron UrlParseError](#machine-a-tron-urlparseerror) |
| arping no reply on `172.16.0.85` | AHV Forged Transmits disabled | Re-run Phase 0c in DEPLOYMENT.md |
| `ping` returns ICMP Redirect + unreachable | Missing route to `172.16.0.0/24` on source | [ICMP Redirect / Destination Unreachable](#icmp-redirect--destination-host-unreachable) |

---

## Proxy Configuration

### Setting Proxy Environment Variables (bash)

Do **not** use `set VAR=value` (Windows/CMD syntax). In bash use `export`:

```bash
export HTTP_PROXY=http://172.16.0.50:3128
export HTTPS_PROXY=http://172.16.0.50:3128
export http_proxy=http://172.16.0.50:3128
export https_proxy=http://172.16.0.50:3128
```

Verify:
```bash
env | grep -i proxy
```

### apt-get Proxy (host — persistent)

```bash
sudo tee /etc/apt/apt.conf.d/95proxy <<'EOF'
Acquire::http::Proxy "http://172.16.0.50:3128";
Acquire::https::Proxy "http://172.16.0.50:3128";
EOF
```

Or pass inline for a one-off:
```bash
sudo http_proxy=http://172.16.0.50:3128 https_proxy=http://172.16.0.50:3128 apt-get update
# Note: sudo strips env vars — pass inline, or use sudo -E if already exported
```

### Docker Cannot Pull Base Images

**Symptom:**
```
DeadlineExceeded: failed to fetch anonymous token:
Get "https://auth.docker.io/token?...": dial tcp 172.64.144.78:443: i/o timeout
```

**Root cause:** Docker daemon has no proxy configured. `SQUID_PROXY` build args
only affect `RUN` steps — they do not help `FROM` / `docker pull`.

**Fix — configure Docker daemon proxy on `nico-cp-1`:**

```bash
sudo mkdir -p /etc/systemd/system/docker.service.d

sudo tee /etc/systemd/system/docker.service.d/http-proxy.conf <<'EOF'
[Service]
Environment="HTTP_PROXY=http://172.16.0.50:3128"
Environment="HTTPS_PROXY=http://172.16.0.50:3128"
Environment="NO_PROXY=localhost,127.0.0.1,10.0.0.0/8,172.16.0.0/16,192.168.0.0/16,.svc,.cluster.local"
EOF

sudo systemctl daemon-reload
sudo systemctl restart docker
```

Verify:
```bash
sudo systemctl show docker --property=Environment
docker pull debian:bookworm-slim   # should now succeed
```

Then re-run the build:
```bash
export SQUID_PROXY=http://172.16.0.50:3128
devspace build
```

**Why `NO_PROXY` matters:** Without it, Docker routes internal cluster traffic
(`172.16.x`, `.svc.cluster.local`) through the proxy, breaking pod-to-pod
communication.

### apt-get Cannot Find Packages in Docker Build

**Symptom:**
```
E: Unable to locate package iproute2
E: Unable to locate package iputils-ping
```

**Root cause:** `apt-get update` runs without proxy so package lists are empty,
or Docker layer cache is reusing a stale `apt-get update` layer.

**Fix in Dockerfile:** Use `export` to set proxy for the entire shell session
and clear stale lists before updating:

```dockerfile
ARG SQUID_PROXY
RUN export http_proxy=${SQUID_PROXY} https_proxy=${SQUID_PROXY} \
        HTTP_PROXY=${SQUID_PROXY} HTTPS_PROXY=${SQUID_PROXY} && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get update -o Acquire::Check-Valid-Until=false && \
    apt-get install -y --no-install-recommends \
      <packages> \
    && rm -rf /var/lib/apt/lists/*
```

**Fix at build time:** Ensure `SQUID_PROXY` is exported before running devspace:
```bash
export SQUID_PROXY=http://172.16.0.50:3128
devspace build
```

**Why `Hit:` instead of `Get:` in `apt-get update`:** `Hit` means apt considers
its local cache valid. Inside a fresh Docker layer this is caused by BuildKit
reusing a cached layer. The `rm -rf /var/lib/apt/lists/*` before `apt-get update`
forces a real download through the proxy.

---

## Kubernetes / Calico

### Calico BIRD Not Ready

**Symptom:** `calico-node` pods stuck `0/1 Running`:
```
Readiness probe failed: BIRD is not ready: unable to connect to BIRDv4 socket
Liveness probe failed: command "/bin/calico-node -felix-live -bird-live" timed out
```

**Root cause:** VMs have two NICs (`eth0` 172.16.0.x and `eth1` 172.16.10.x).
Calico IP autodetection picks the wrong interface for BGP peering.

**Fix — pin Calico to `eth0`:**

```bash
kubectl set env daemonset/calico-node -n kube-system \
  IP_AUTODETECTION_METHOD=interface=eth0 \
  IP6_AUTODETECTION_METHOD=none

kubectl rollout status daemonset/calico-node -n kube-system

# Verify all pods are 1/1 Running:
kubectl get pods -n kube-system -l k8s-app=calico-node
```

Verify the correct node IP was picked:
```bash
kubectl get node nico-cp-1 -o jsonpath='{.metadata.annotations.projectcalico\.org/IPv4Address}'
# Should print: 172.16.0.80/24  ✅

kubectl logs -n kube-system -l k8s-app=calico-node --tail=30 | grep -i "bird\|felix\|error"
```

**Permanent fix (preferred for re-deploys):** Edit `~/staged/calico.yaml`
before `kubectl apply` to set:
```yaml
- name: IP_AUTODETECTION_METHOD
  value: "interface=eth0"
- name: IP6_AUTODETECTION_METHOD
  value: "none"
```

### Calico Felix Health Endpoint / DNS Timeout

**Symptom:**
```
Health endpoint failed, trying to restart it...
error=listen tcp: lookup localhost on 8.8.8.8:53: i/o timeout
```

**Root cause:** VM hostnames (`nico-cp-1`, `nico-worker-1`, `nico-worker-2`) and
`localhost` missing from `/etc/hosts`. OS falls through to external DNS (8.8.8.8)
which is unreachable in the air-gapped environment.

**Fix — add all required entries on every node:**

```bash
# Run on ALL nodes (nico-cp-1, nico-worker-1, nico-worker-2):

grep -q "^127.0.0.1.*localhost" /etc/hosts || \
  echo "127.0.0.1  localhost" | sudo tee -a /etc/hosts
grep -q "^::1.*localhost" /etc/hosts || \
  echo "::1        localhost ip6-localhost ip6-loopback" | sudo tee -a /etc/hosts

grep -q "nico-cp-1" /etc/hosts || sudo tee -a /etc/hosts <<'EOF'
172.16.0.80  nico-cp-1
172.16.0.81  nico-worker-1
172.16.0.82  nico-worker-2
EOF

# Verify:
getent hosts localhost      # 127.0.0.1  localhost  ✅
getent hosts nico-cp-1     # 172.16.0.80  nico-cp-1  ✅
```

Restart calico after the fix:
```bash
kubectl rollout restart daemonset/calico-node -n kube-system
kubectl rollout status daemonset/calico-node -n kube-system
kubectl get pods -n kube-system -l k8s-app=calico-node
# All 1/1 Running  ✅
```

---

## MetalLB

### MetalLB VIPs Pending

**Symptom:** `kubectl get svc -n forge-system` shows `<pending>` for
`EXTERNAL-IP` on LoadBalancer services.

**Diagnose:**
```bash
kubectl get pods -n metallb-system
kubectl logs -n metallb-system -l component=speaker | grep -i "172.16.0\|error\|warn"
kubectl get ipaddresspool -n metallb-system -o yaml
kubectl get l2advertisement -n metallb-system -o yaml
```

**Common causes:**

1. **AHV Forged Transmits disabled** — MetalLB speaker sends gratuitous ARPs but
   the hypervisor drops them:
   ```bash
   # From nico-cp-1 — if no reply, Forged Transmits is off on the vSwitch:
   arping -I eth0 172.16.0.85
   # Fix: re-run Phase 0c in DEPLOYMENT.md (Prism Element → vSwitch settings)
   ```

2. **`eth0` not on `172.16.0.0/24` subnet** — L2Advertisement must be pinned to
   the correct NIC. Check `helm-prereqs/values/metallb-config.yaml` has the
   correct `nodeSelectors` or interface binding.

3. **IP pool range mismatch** — the VIPs (`.85–.95`) must be inside the
   IPAddressPool range configured in MetalLB.

### ICMP Redirect / Destination Host Unreachable

**Symptom:**
```
From 172.16.0.81 icmp_seq=1 Redirect Host(New nexthop: 172.16.0.86)
From 172.16.0.81 icmp_seq=1 Destination Host Unreachable
```

**Root cause:** The source host has no direct route to `172.16.0.0/24`. Traffic
goes to the default gateway (172.16.0.81), which sends an ICMP Redirect saying
"it's local, go direct" — but the source has no route to do so.

`arping` still works (L2 / MetalLB is fine). This is purely a routing gap.

**Fix — add missing route on the source host:**
```bash
# Find the correct interface
ip addr show | grep 172.16

# Add route (replace ens4 with your interface)
sudo ip route add 172.16.0.0/24 dev ens4

# Make persistent (Ubuntu netplan):
# Add under the interface in /etc/netplan/50-cloud-init.yaml:
#   routes:
#     - to: 172.16.0.0/24
#       via: 0.0.0.0   (on-link)
```

---

## DevSpace / Docker Build

### Proto Files Missing / `file not found for module`

**Symptom:**
```
error[E0583]: file not found for module `common`
file not found for module `forge`
file not found for module `health`
```

**Root cause:** Proto-generated `.rs` files missing due to stale BuildKit
cache from a prior failed build.

**Fix:**
```bash
docker builder prune --filter type=exec.cachemount --force
export SQUID_PROXY=http://172.16.0.50:3128
devspace deploy -n forge-system --force-build
```

### kea-dhcp4 Not Found in Pod

**Symptom:** `/sbin/kea-dhcp4: not found` in `carbide-dhcp` pod logs.

**Root cause:** `carbide-runtime-base` image was built before `kea-dhcp4-server`
was properly installed, or was built without the proxy so `apt-get install` failed
silently.

**Fix — rebuild `carbide-runtime-base` with no-cache:**
```bash
export SQUID_PROXY=http://172.16.0.50:3128
docker build --no-cache \
  --build-arg SQUID_PROXY=${SQUID_PROXY} \
  -t carbide-runtime-base \
  -f dev/deployment/devspace/Dockerfile.runtime-base .

docker builder prune --filter type=exec.cachemount --force
devspace deploy -n forge-system --force-build
```

Verify the rebuilt image has kea:
```bash
docker run --rm carbide-runtime-base \
  ls /sbin/kea-dhcp4 /usr/lib/x86_64-linux-gnu/kea/hooks/

# Also verify the final carbide-api image:
TAG_API=$(docker images --format '{{.Tag}}' carbide-api | head -1)
docker run --rm carbide-api:${TAG_API} ls \
  /opt/carbide/carbide-api \
  /opt/carbide/carbide \
  /opt/carbide/carbide-dns \
  /opt/carbide/forge-dhcp-server \
  /opt/carbide/forge-hw-health \
  /opt/carbide/ssh-console \
  /sbin/kea-dhcp4 \
  /usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp.so
# All paths must print without errors ✅
```

### libdhcp.so Not Found

**Symptom:** `libdhcp.so: No such file or directory` in pod logs.

**Root cause:** The `carbide-dhcp` cdylib failed to build silently. Two causes:

**Cause 1 — Stale `build-container-localdev`** (missing kea-dev headers):
```bash
docker rmi build-container-localdev
export SQUID_PROXY=http://172.16.0.50:3128
devspace deploy -n forge-system --force-build
```

Verify kea dev headers are in the build container:
```bash
docker run --rm build-container-localdev ls /usr/include/kea/
```

**Cause 2 — Stale BuildKit cache:**
```bash
docker builder prune --filter type=exec.cachemount --force
export SQUID_PROXY=http://172.16.0.50:3128
devspace deploy -n forge-system --force-build
```

### Cargo Download Timeout

**Symptom:**
```
Timeout was reached (download of 'axum-template' failed)
```

**Root cause:** Cargo cannot reach `crates.io` — `SQUID_PROXY` not exported.

**Fix:**
```bash
export SQUID_PROXY=http://172.16.0.50:3128

# Verify proxy reachability first:
curl -x http://172.16.0.50:3128 https://crates.io

devspace deploy -n forge-system --force-build
```

### machine-a-tron UrlParseError

**Symptom:** `UrlParseError("")` or `Only SOCKS5 Proxy supported` in
machine-a-tron pod logs.

**Root cause:** `http_proxy` / `https_proxy` baked into the image's `ENV`
layer. `machine-a-tron` only accepts `socks5://` proxies and crashes on
`http://` values or empty strings.

**Fix:** The Dockerfile passes proxy only to `RUN` steps via shell `export`,
never via `ENV`. If you see this after a build, the image was built from
a stale layer before the fix. Force rebuild:
```bash
export SQUID_PROXY=http://172.16.0.50:3128
devspace build --force-build -- machine-a-tron
```

If running the CLI and seeing this error, unset proxy vars in your shell:
```bash
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
```

---

## Helm / Kubernetes Deployment

### Migration Job Not Created

**Symptom:**
```
relation "resource_pool_def" does not exist
```
or `carbide-api-migrate` Job is `NotFound`.

**Root cause:** The migration Job is a Helm `pre-install,pre-upgrade` hook.
If devspace's deploy step is cached (no changes detected), Helm is skipped
and the Job never runs. `carbide-api` crashes because the DB tables don't exist.

**Fix:**
```bash
# Force helm to re-run:
devspace deploy -n forge-system --force-deploy

# Watch migration complete before carbide-api starts:
kubectl get pods -n forge-system -w
# carbide-api-migrate-*   Running → Completed  ✅
# carbide-api-*           Running              ✅
```

If the migration pod itself fails:
```bash
kubectl logs -n forge-system -l app=carbide-api-migrate --tail=50
```

Common migration failures:
- **`ImagePullBackOff`** — `carbide-api` image not imported into containerd on
  that node. Re-import and redeploy.
- **postgres connection refused** — postgres pod just restarted; wait:
  ```bash
  kubectl rollout status statefulset/postgres -n postgres --timeout=120s
  devspace deploy -n forge-system --force-deploy
  ```

### Wrong Helm Release Name

**Symptom:**
```
ServiceAccount "carbide-api" exists and cannot be imported into the current
release: annotation validation error: key "meta.helm.sh/release-name" must
equal "carbide": current value is "carbide-local"
```

**Root cause:** A manual `helm upgrade --install carbide ...` was run instead
of `carbide-local` — devspace installed the release as `carbide-local`.

**Fix — use the correct release name:**
```bash
TAG_API=$(docker images --format '{{.Tag}}' carbide-api       | head -1)
TAG_BMC=$(docker images --format '{{.Tag}}' carbide-bmc-proxy | head -1)

helm upgrade --install carbide-local ./helm \
  --namespace forge-system \
  --values dev/deployment/devspace/values.base.yaml \
  --values dev/deployment/devspace/values.generated.yaml \
  --set global.image.repository=carbide-api \
  --set global.image.tag=${TAG_API} \
  --set global.image.pullPolicy=IfNotPresent \
  --set carbide-bmc-proxy.image.repository=carbide-bmc-proxy \
  --set carbide-bmc-proxy.image.tag=${TAG_BMC} \
  --set carbide-bmc-proxy.image.pullPolicy=IfNotPresent
```

Or simply use devspace (handles release name automatically):
```bash
devspace deploy -n forge-system --force-deploy
```

### ImagePullBackOff

**Symptom:** Pod stuck in `ImagePullBackOff` after a devspace build.

**Root cause:** New image tag built by devspace was not imported into containerd
on the node where the pod is scheduled.

**Fix:**
```bash
TAG_API=$(docker images --format '{{.Tag}}' carbide-api       | head -1)
TAG_BMC=$(docker images --format '{{.Tag}}' carbide-bmc-proxy | head -1)
TAG_MAT=$(docker images --format '{{.Tag}}' machine-a-tron    | head -1)

# Import on nico-cp-1:
docker save carbide-api:${TAG_API}       | sudo ctr -n k8s.io images import -
docker save carbide-bmc-proxy:${TAG_BMC} | sudo ctr -n k8s.io images import -
docker save machine-a-tron:${TAG_MAT}    | sudo ctr -n k8s.io images import -

# Copy and import on workers:
docker save carbide-api:${TAG_API}       -o /tmp/carbide-api.tar
docker save carbide-bmc-proxy:${TAG_BMC} -o /tmp/carbide-bmc-proxy.tar
docker save machine-a-tron:${TAG_MAT}    -o /tmp/machine-a-tron.tar

for NODE in 172.16.0.81 172.16.0.82; do
  scp /tmp/carbide-api.tar /tmp/carbide-bmc-proxy.tar /tmp/machine-a-tron.tar \
      root@${NODE}:/tmp/
  ssh root@${NODE} "
    ctr -n k8s.io images import /tmp/carbide-api.tar
    ctr -n k8s.io images import /tmp/carbide-bmc-proxy.tar
    ctr -n k8s.io images import /tmp/machine-a-tron.tar
  "
done

devspace deploy -n forge-system --force-deploy
```

### Resource Pool Missing or Full

**Symptom:**
```
Resource pool 'vpc-vni' missing or full
Resource pool 'vni' missing or full
```

**Root cause:** DB resource pools exhausted from prior runs.

**Fix — reset postgres and restart all forge-system pods:**
```bash
kubectl delete pod -n postgres --all
sleep 15

kubectl delete job -n forge-system --all
kubectl delete pod -n forge-system --all

kubectl get pods -n forge-system -w
# Expected within ~60s:
#   carbide-api-migrate-*        Completed  ✅
#   carbide-api-*                Running    ✅
#   carbide-dhcp-*               Running    ✅
#   carbide-pxe-*                Running    ✅
```

---

## carbide-admin-cli

### CLI TLS Certificate Mismatch

**Symptom:**
```
invalid peer certificate: certificate not valid for name "172.16.0.89"
```

**Root cause:** The TLS cert is issued for a DNS name, not the IP. SNI check
fails when connecting via IP.

**Fix:**
```bash
echo "172.16.0.89 carbide-api.forge-system.svc.cluster.local" >> /etc/hosts

# Use DNS name in the CLI config:
export CARBIDE_API="https://carbide-api.forge-system.svc.cluster.local:443"
```

### CLI Crashes / UrlParseError from Proxy Vars

**Symptom:** `UrlParseError("")` or `Only SOCKS5 Proxy supported`.

**Root cause:** `http_proxy` / `https_proxy` are set in the shell. The CLI only
accepts `socks5://` proxies.

**Fix:**
```bash
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
./carbide-admin-cli machine show
```

### Certs Lost After Reboot

TLS certs extracted to `/tmp` are lost on reboot. Re-extract:
```bash
kubectl get secret machine-a-tron-certificate -n forge-system \
  -o jsonpath='{.data.ca\.crt}'  | base64 -d > /tmp/forge-ca.crt
kubectl get secret machine-a-tron-certificate -n forge-system \
  -o jsonpath='{.data.tls\.crt}' | base64 -d > /tmp/client.crt
kubectl get secret machine-a-tron-certificate -n forge-system \
  -o jsonpath='{.data.tls\.key}' | base64 -d > /tmp/client.key

# Verify:
head -1 /tmp/forge-ca.crt /tmp/client.crt /tmp/client.key
```

Or store to a persistent path and update `~/.config/carbide_api_cli.json`
to point there instead of `/tmp`.

---

## DHCP / PXE / Networking

### DHCP Only DISCOVER, No OFFER

**Symptom:** `kubectl logs carbide-dhcp` shows DISCOVER but no OFFER.

**Diagnose in order:**

```bash
# 1. Is the VIP reachable at L2?
arping -I eth0 172.16.0.85

# 2. Is MetalLB announcing the VIP?
kubectl get pods -n metallb-system
kubectl logs -n metallb-system -l component=speaker | grep 172.16.0.85

# 3. Is the pod healthy and backed by an endpoint?
kubectl get pods -n forge-system | grep carbide-dhcp
kubectl get endpoints -n forge-system carbide-dhcp

# 4. Is the switch relay configured?
# On the 10G Switch:
#   interface Vlan101
#     ip helper-address 172.16.0.85

# 5. Sniff for DHCP packets:
sudo tcpdump -i eth0 -n port 67 or port 68 -v
```

### DHCP Relay Fails — `No network segment defined for relay address`

**Symptom:** carbide-dhcp logs show the DISCOVER is received and forwarded to carbide-api,
but carbide-api returns:

```
Internal error: No network segment defined for relay addresses: [172.16.0.81]
```

**Root cause — why this happens:**

`carbide-api` runs `create_initial_networks()` **once on first startup** and writes the
`[networks.admin]` prefix (e.g. `172.16.0.0/24`) into the `network_segments` /
`network_prefixes` tables. It then **skips** that function on every subsequent restart.

This means if the site config contained the wrong (or placeholder) subnets at the time
of the very first `devspace deploy` — for example the default `192.168.64.0/18` — those
stale prefixes stay in the database forever. When a real relay packet arrives with
`giaddr = 172.16.0.x`, the SQL query:

```sql
WHERE $1::inet <<= network_prefixes.prefix
-- 172.16.0.81 is NOT contained in 192.168.64.0/18 → returns 0 rows → error
```

**Diagnose:**

```bash
# 1. Check what prefixes are actually in the DB
ncli network-segment show
# Look at the "admin" row — Prefix must be 172.16.0.0/24
# If it shows 192.168.x.x → stale, needs fixing

# 2. Confirm with the exact SQL carbide-api uses
PG_POD=$(kubectl get pods -n postgres \
  -o custom-columns=:metadata.name --no-headers | head -n1)

kubectl exec -n postgres $PG_POD -- \
  psql -U postgres carbide -c "
    SELECT ns.name, np.prefix,
           '172.16.0.81'::inet <<= np.prefix AS relay_matches
    FROM network_segments ns
    INNER JOIN network_prefixes np ON np.segment_id = ns.id
    WHERE ns.deleted IS NULL;
  "
# relay_matches must be 't' for the admin row
```

**Fix — delete stale segments and let carbide-api recreate them:**

> **Warning:** this deletes all machine_interface data associated with the stale
> segments. Only do this when no real machines have been discovered yet, or after
> you have noted down any data you need to preserve.

```bash
# Step 1 — get the stale segment IDs
ncli network-segment show
# Note the IDs of: admin, and any DEV-K3S-* segments with wrong prefixes

# Step 2 — delete child rows first (FK chain: addresses → dhcp_entries → interfaces)
PG_POD=$(kubectl get pods -n postgres \
  -o custom-columns=:metadata.name --no-headers | head -n1)

kubectl exec -n postgres $PG_POD -- \
  psql -U postgres carbide -c "
    BEGIN;

    -- Replace the UUIDs below with your actual stale segment IDs
    DELETE FROM machine_interface_addresses
    WHERE interface_id IN (
      SELECT id FROM machine_interfaces
      WHERE segment_id IN (
        '<admin-segment-id>',
        '<other-stale-segment-id>'
      )
    );

    DELETE FROM dhcp_entries
    WHERE machine_interface_id IN (
      SELECT id FROM machine_interfaces
      WHERE segment_id IN (
        '<admin-segment-id>',
        '<other-stale-segment-id>'
      )
    );

    DELETE FROM machine_interfaces
    WHERE segment_id IN (
      '<admin-segment-id>',
      '<other-stale-segment-id>'
    );

    COMMIT;
  "

# Step 3 — delete the stale network segments and their prefixes
kubectl exec -n postgres $PG_POD -- \
  psql -U postgres carbide -c "
    BEGIN;
    DELETE FROM network_prefixes
    WHERE segment_id IN (
      '<admin-segment-id>',
      '<other-stale-segment-id>'
    );
    DELETE FROM network_segments
    WHERE id IN (
      '<admin-segment-id>',
      '<other-stale-segment-id>'
    );
    COMMIT;
  "

# Step 4 — restart carbide-api; create_initial_networks() will now run
# (only runs when the admin segment is absent AND there is exactly 1 DNS domain)
kubectl rollout restart deployment/carbide-api -n forge-system
kubectl rollout status deployment/carbide-api -n forge-system --timeout=120s

# Watch for recreation
kubectl logs -n forge-system \
  -l app.kubernetes.io/name=carbide-api -f --tail=0 \
  | grep -iE "created network|admin|172\.16"
# Expected: msg="Created network segment admin"

# Step 5 — verify correct prefix is now in DB
ncli network-segment show
# admin row must show: 172.16.0.0/24
```

**Why `create_initial_networks` may still skip even after deletion:**

The function also skips if there is more than one DNS domain in the DB (`domains` table).
Check:

```bash
kubectl exec -n postgres $PG_POD -- \
  psql -U postgres carbide -c "SELECT id, name FROM domains;"
# Must show exactly 1 row
```

If there are 0 domains, `initial_domain_name` is not set correctly in `values.base.yaml`.
If there are 2+, the function skips — delete extras or use the manual SQL insert below.

---

### Testing DHCP Relay from a Linux Host

**Symptom:** `dhcping` or `dhclient` appear to work but carbide-dhcp logs show:

```
Received a non-relayed packet, dropping it
```

**Root cause:** carbide-dhcp's kea hook **requires `giaddr != 0.0.0.0`** — it drops
any packet that was not forwarded by a relay agent. `dhcping` and direct `dhclient`
send packets with `giaddr = 0.0.0.0` (no relay), so they are always dropped regardless
of the MAC address.

**Fix — use the relay test script (stdlib only, no extra dependencies):**

The script lives at [`dev/tools/dhcp_relay_test.py`](dev/tools/dhcp_relay_test.py).
Copy it to the test host — requires only Python 3 stdlib, no pip install needed.

```bash
# No dependencies required
sudo python3 dhcp_relay_test.py \
    --server 172.16.0.85 \
    --giaddr 172.16.0.121 \
    --mac    50:6b:8d:a3:05:39
```

Expected output on success:

```
[TX] DHCP Discover
     client MAC : 50:6b:8d:a3:05:39
     giaddr     : 172.16.0.121  ← relay agent IP, must be in networks.admin subnet
     server     : 172.16.0.85:67
     xid        : 0x2d003e35

Discover sent. Waiting up to 5s for OFFER ...

[OK] Got DHCP Offer from 172.16.0.81
     Offered IP  : 172.16.0.2
     Subnet mask : 255.255.255.0
     Gateway     : 172.16.0.1
     DNS         : 127.0.0.1
     Lease time  : 3600s
     Server ID   : 10.244.252.144

  NOTE: Offered IP is a placeholder — the MAC is not yet registered
  as an expected machine. The relay and network segment are working.
  Add the MAC to expected_machines.json to get a stable 172.16.0.x lease.
```

carbide-admin-cli em show command
+---------------+-------------------+--------------+---------------+--------------------+------+-------------+--------+--------+--------------------+-------------+------------------+
| Serial Number | BMC Mac           | Interface IP | Fallback DPUs | Associated Machine | Name | Description | Labels | SKU ID | Pause On Ingestion | DPF Enabled | Disable Lockdown |
+===============+===================+==============+===============+====================+======+=============+========+========+====================+=============+==================+
| TEST-HOST-001 | 50:6B:8D:E3:19:F2 | 172.16.0.3   |               | Unlinked           |      |             |        |        | false              | false       | false            |
+---------------+-------------------+--------------+---------------+--------------------+------+-------------+--------+--------+--------------------+-------------+------------------+


**Understanding the OFFER reply (RFC 2131 §4.1):**

When `giaddr != 0.0.0.0`, carbide-dhcp sends the OFFER **unicast to `giaddr` on
port 67** (not port 68). The test script binds a UDP socket on port 67, so it
receives the reply normally via the kernel UDP stack. The reply may arrive via the
default gateway (you may see `from 172.16.0.81` rather than `from 172.16.0.85` in
the source address — this is normal routing and does not indicate a problem).

**Interpreting carbide-dhcp logs during the test:**

```
INFO  LOG_CARBIDE_PKT4_RECEIVE: Packet type name: DHCPDISCOVER         ← packet accepted
ERROR LOG_CARBIDE_PKT4_RECEIVE: Missing option [60] in packet          ← benign (testing)
ERROR LOG_CARBIDE_PKT4_RECEIVE: Missing option [93] in packet          ← benign (testing)
INFO  DHCP4_LEASE_ADVERT ... lease 172.16.0.x will be advertised       ← pool allocation OK
INFO  LOG_CARBIDE_PKT4_SEND ... msg_type=DHCPOFFER ... remote=giaddr:67 ← OFFER sent ✓
```

Options [60] (vendor class) and [93] (client arch) are missing from the test script
because real BMC/PXE clients send them. They do **not** block the OFFER.

**What a low offered IP (`172.16.0.2`) means:**

carbide-api allocated from the start of the pool because the test MAC is not in
`expected_machines.json`. The relay is working correctly. A real BMC MAC that is
registered will receive its pre-assigned `172.16.0.x` address.

**If you get `No network segment defined for relay address`:**
→ See [Stale Network Segment Prefix](#dhcp-relay-fails--no-network-segment-defined-for-relay-address) above.

**If `dhcrelay` is available** (alternative to the Python script):

```bash
# Give a spare IP on ens3 to act as giaddr
sudo ip addr add 172.16.0.61/24 dev ens3
sudo ip link set ens3 up

# Run relay: listen on ens3 (client side), forward to VIP
sudo dhcrelay -d -i ens3 172.16.0.85

# In second terminal: trigger broadcast on ens3
sudo dhclient -v -1 ens3
```

> **Note:** `dhcrelay` discards packets if the client and server interfaces are the
> same (`Discarding packet received on eth0`). Always use separate interfaces.

---

### Machine Stuck in Discovering

**Symptom:** Machine never progresses past `Discovering` state.

```bash
# Check if bmc-proxy can reach the BMC:
kubectl exec -n forge-system \
  $(kubectl get pod -n forge-system -l app.kubernetes.io/name=carbide-bmc-proxy -o name | head -1) \
  -- curl -sk https://<bmc-ip>/redfish/v1 | head -20

# Check site-explorer logs:
kubectl logs -n forge-system \
  -l app.kubernetes.io/name=carbide-api -f \
  | grep -i "site.explorer\|explore\|bmc\|error"

# Get the exploration report for the BMC:
ncli site-explorer get-report endpoint <bmc-ip>

# Re-trigger exploration:
ncli site-explorer re-explore --address <bmc-ip>
```

### carbide-api CrashLoopBackOff (TOML Parse Error)

```bash
kubectl logs -n forge-system \
  -l app.kubernetes.io/name=carbide-api --previous | tail -30
```

Common TOML errors:
- Empty `prefix` or `gateway` in `[networks.*]` blocks → fill in real subnet/gateway
- Missing `dhcp_servers` array → add `dhcp_servers = ["172.16.0.85"]`
- Indentation error in the YAML `carbideApiSiteConfig: |` block

---

## carbide-api Admin UI (`https://172.16.0.89/admin`)

The admin web UI is built into `carbide-api` and is the fastest way to inspect machine
state, trigger power actions, browse Redfish, and diagnose DHCP/IPAM issues — without
needing the CLI.

### Accessing the UI

Open in a browser from the jump host or any host with a route to `172.16.0.89`:

```
https://172.16.0.89/admin
```

> The UI uses the same mTLS certificate as the gRPC API. Browsers will show a TLS
> warning because it's a self-signed cert — accept the exception. If you get a
> connection refused, check that `carbide-api-external` LoadBalancer has its VIP
> assigned: `kubectl get svc -n forge-system carbide-api-external`.

---

### Page Reference

| URL | What you can do |
|-----|----------------|
| `/admin` | Dashboard / root |
| `/admin/machine` | List all machines with current state, MAC, IP, DPU info |
| `/admin/machine/<id>` | Machine detail: state history, interfaces, health, attestation |
| `/admin/machine/<id>/state-history` | Full state machine transition log |
| `/admin/host` | List host machines (x86 BM) |
| `/admin/dpu` | List DPU machines with state |
| `/admin/dpu/versions` | DPU agent version inventory |
| `/admin/managed-host` | Managed host detail (DPU + host pairing) |
| `/admin/explored-endpoint` | All BMC endpoints discovered by site-explorer |
| `/admin/explored-endpoint/<bmc-ip>` | BMC detail + **power control + re-explore actions** |
| `/admin/ipam/dhcp` | DHCP lease table — all allocated IPs, MACs, hostnames |
| `/admin/ipam/dns` | DNS records in `local.forge` |
| `/admin/ipam/underlay` | Underlay network segments and prefix utilisation |
| `/admin/network-segment` | Network segment list (prefix, MTU, `reserve_first`, state) |
| `/admin/network-segment/<id>` | Segment detail with all allocated addresses |
| `/admin/expected-machine` | `expected_machines.json` contents |
| `/admin/ipxe-template` | iPXE boot templates per machine/OS |
| `/admin/operating-system` | Registered OS images |
| `/admin/redfish-browser` | Live Redfish query browser — query any BMC endpoint |
| `/admin/redfish-actions` | Pending/approved/applied Redfish firmware actions |
| `/admin/machine-validation` | Machine validation test runs and results |
| `/admin/health-history` | Hardware health event history |
| `/admin/attestation/<id>` | TPM attestation results per machine |
| `/admin/resource-pool` | Resource pool utilisation (VNI, VLAN, lo-IP ranges) |
| `/admin/sku` | SKU definitions |
| `/admin/search` | Global search across machines, MACs, IPs, serials |

---

### Power Control (most useful for debugging)

Navigate to **`/admin/explored-endpoint/<bmc-ip>`** and use the action buttons:

| Action | Effect |
|--------|--------|
| **Power On** | Powers on the host via Redfish (`On`) |
| **Graceful Shutdown** | OS-initiated shutdown via ACPI |
| **Force Off** | Hard power cut — immediate, no OS notification |
| **Graceful Restart** | OS reboot via ACPI |
| **Force Restart** | Hard reset — equivalent to pressing the reset button |
| **AC Powercycle** | Full AC power cycle (PDU-level if supported) |
| **BMC Reset** | Resets the BMC itself (not the host) — use when BMC is unresponsive |
| **Re-explore** | Re-triggers site-explorer Redfish discovery on this endpoint |
| **Clear Error** | Clears a stuck exploration error so re-explore can run |
| **Machine Setup** | Re-runs the initial machine setup (Redfish config) |
| **Disable Secure Boot** | Disables UEFI Secure Boot via Redfish |
| **Set DPU First Boot Order** | Sets DPU as first PXE boot device |
| **Disable/Enable Lockdown** | Controls BMC lockdown mode |

> These actions call `carbide-api` → `AdminPowerControl` gRPC → `carbide-bmc-proxy`
> → Redfish on the BMC. The result (success/error) is shown as a banner on the page.

---

### DHCP / IPAM Diagnosis via UI

**Check if a MAC received an IP:**

1. Go to `/admin/ipam/dhcp`
2. Search by MAC address or hostname
3. The table shows: MAC, allocated IP, lease expiry, network segment

**Check if the `admin` segment has the correct prefix:**

1. Go to `/admin/network-segment`
2. Find the `admin` row — Prefix must be `172.16.0.0/24`
3. If it shows `192.168.64.0/18` or any other subnet → stale segment, follow
   [§ DHCP Relay Fails](#dhcp-relay-fails--no-network-segment-defined-for-relay-address)

**Check DNS records:**

1. Go to `/admin/ipam/dns`
2. Verify A records exist for provisioned machines (e.g. `172-16-0-20.local.forge`)

---

### Redfish Browser (live query)

Navigate to **`/admin/redfish-browser`** to issue ad-hoc Redfish GET requests to any
BMC without SSH. Useful for:

- Checking power state: `GET /redfish/v1/Systems/System.Embedded.1`
- Listing BIOS settings
- Checking firmware versions: `GET /redfish/v1/UpdateService/FirmwareInventory`
- Verifying boot order: `GET /redfish/v1/Systems/System.Embedded.1/Bios`

Enter the BMC IP and path in the form — carbide-api proxies the request through
`carbide-bmc-proxy` with credentials injected automatically.

---

### State History

Navigate to **`/admin/machine/<machine-id>/state-history`** to see the full timeline
of state transitions for a machine. This is the first place to look when a machine is
stuck — the log shows every state entered, timestamps, and any error messages recorded
by the state machine.

Quick CLI equivalent:
```bash
ncli machine list          # get <machine-id>
ncli machine show <id>     # current state + last error
```

---

## General Diagnostics

### Full Cluster Health Snapshot

```bash
kubectl get nodes
kubectl get pods -n forge-system
kubectl get pods -n metallb-system
kubectl get pods -n cert-manager
kubectl get pods -n vault
kubectl get pods -n postgres
kubectl get svc -n forge-system | grep LoadBalancer
```

### Watch All forge-system Pods

```bash
kubectl get pods -n forge-system -w
```

### Collect Logs from All NICo Services

```bash
for SVC in carbide-api carbide-dhcp carbide-pxe carbide-dns carbide-bmc-proxy carbide-hardware-health; do
  echo "=== $SVC ==="
  kubectl logs -n forge-system -l app.kubernetes.io/name=${SVC} --tail=50 2>/dev/null
done
```

### Force Full Rebuild and Redeploy

```bash
export SQUID_PROXY=http://172.16.0.50:3128

# Wipe stale BuildKit cache:
docker builder prune --filter type=exec.cachemount --force

# Rebuild runtime base (if kea issues):
docker build --no-cache \
  --build-arg SQUID_PROXY=${SQUID_PROXY} \
  -t carbide-runtime-base \
  -f dev/deployment/devspace/Dockerfile.runtime-base .

# Build all images:
devspace build --force-build

# Verify carbide-api image:
TAG_API=$(docker images --format '{{.Tag}}' carbide-api | head -1)
docker run --rm carbide-api:${TAG_API} ls \
  /opt/carbide/carbide-api /sbin/kea-dhcp4 \
  /usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp.so

# Import to all nodes (see ImagePullBackOff section above)

# Reset DB and redeploy:
kubectl delete pod -n postgres --all && sleep 15
kubectl delete job,pod -n forge-system --all
devspace deploy -n forge-system --force-deploy
kubectl get pods -n forge-system -w
```
