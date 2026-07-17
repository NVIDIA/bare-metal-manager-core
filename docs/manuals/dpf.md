# DPF Setup for NICo Integration

## Introduction

NICo supports two ways of provisioning DPUs:

1. iPXE based
2. DPF based

This manual covers deployment of **DPF based** provisioning as it is used by NICo.
It assumes that a working Kubernetes cluster is already available, and is intentionally
agnostic to the specific cluster implementation (kubeadm, k3s, RKE2, managed clouds, etc.)—any
conformant cluster that satisfies the DPF prerequisites is acceptable.

This guide is **not a replacement** for the official DPF documentation. The
authoritative source for installing and configuring DPF is the [upstream guide](https://docs.nvidia.com/networking/display/dpf25101).

NICo is designed to follow the Zero-Trust use case detailed in the DPF documentation: [DPF Zero-Trust Mode - HBN Usecase](https://docs.nvidia.com/networking/display/dpf25101/hbn-in-dpf-zero-trust).

You should follow that guide as the base. The instructions below only describe
the **deltas, additions, and tweaks** that need to be applied on top of the
official DPF flow so that NICo can integrate with the resulting DPF
installation. This manual is based on **DPF 26.04**; minor adjustments may be
necessary on other versions and on environments other than a development
setup.

The guide is organized into the following sections:

1. **Prerequisites** — work that must be done before installing DPF.
2. **DPF Installation** — NICo-relevant notes when installing the DPF operator.
3. **Post-Installation Configuration** — the cluster state and NICo configuration that must be in place after DPF is installed and before NICo starts.
4. **Restart carbide-api** — what NICo creates on startup, and why a restart is required to apply DPF config changes.

> **Note**: NICo expects DPF to be installed and configured on the same
> Kubernetes cluster where NICo (the controller) runs.

---

## 1. Prerequisites

The official DPF guide lists a set of [cluster-level prerequisites](https://docs.nvidia.com/networking/display/dpf25101/helm-prerequisites) (Argo CD, cert-manager, Kamaji etc.). Follow that guide for those components.

NICo reuses several of those same components (notably Argo CD and cert-manager). If they are already installed for NICo, **do not reinstall them** — only configure the missing pieces and adapt the existing installations so DPF can use them. The subsections below cover the prerequisite configuration that is specific to a NICo + DPF deployment.

### 1.1. Create the DPF operator namespace

All DPF operator workloads, secrets, ConfigMaps, and CRs live in the
`dpf-operator-system` namespace. Create it idempotently:

```bash
kubectl get namespace dpf-operator-system &>/dev/null \
  || kubectl create namespace dpf-operator-system
```

### 1.2. Image pull and helm repository credentials

Access to the DPF staging Helm chart and related container images requires authentication through NVIDIA NGC. Both the DPF operator and the workloads it deploys will need credentials for pulling Helm charts and container images from private registries. Refer to the [Using Private Registries](https://docs.nvidia.com/networking/display/dpf25101/using-private-registries) section of the DPF documentation for detailed instructions.

#### 1.2.a. `hbn-user-password` Secret

A random local credential pair used by the HBN (Host-Based Networking) DPUService,
which runs FRR on the DPU. The DPF operator picks this Secret up by label.

```bash
kubectl -n dpf-operator-system create secret generic hbn-user-password \
  --from-literal=password=`tr -dc 'a-z0-9' < /dev/urandom | head -c 10` \
  || kubectl get secret hbn-user-password -n dpf-operator-system

kubectl -n dpf-operator-system label secret hbn-user-password \
  dpu.nvidia.com/image-pull-secret=""
```

The `dpu.nvidia.com/image-pull-secret=""` label is a DPF convention that tells
the operator *"propagate this Secret into DPUService image-pull secrets."* The
label is reused even though this is not strictly an image-pull Secret — DPF's
controllers selector-match on this label to mirror Secrets onto the DPU
cluster.

#### 1.2.b. `dpf-pull-secret` docker-registry Secret

Credentials for `nvcr.io`, used by the DPF operator and by the operands it
deploys to pull staging images.

```bash
kubectl -n dpf-operator-system create secret docker-registry dpf-pull-secret \
  --docker-server=nvcr.io \
  --docker-username='$oauthtoken' \
  --docker-password="$NGC_API_KEY" \
  || kubectl get secret dpf-pull-secret -n dpf-operator-system

kubectl -n dpf-operator-system label secret dpf-pull-secret \
  dpu.nvidia.com/image-pull-secret=""
```

#### 1.2.c. Secret to pull NICo docker service images

Credentials for `nvcr.io`, used by the DPF operator to download NICo
service images.

```bash
kubectl -n dpf-operator-system create secret docker-registry nico-pull-secret \
  --docker-server=nvcr.io \
  --docker-username='$oauthtoken' \
  --docker-password="$NGC_API_KEY_WITH_NICO_DOCKER_IMAGE_ACCESS" \
  || kubectl get secret nico-pull-secret -n dpf-operator-system

kubectl -n dpf-operator-system label secret nico-pull-secret \
  dpu.nvidia.com/image-pull-secret=""
```

#### 1.2.d. Argo CD repository Secrets for Helm charts

DPF pulls several Helm charts via Argo CD. Apply the following Secrets so that
Argo CD can authenticate to the NGC Helm repositories:

```yaml
---
apiVersion: v1
kind: Secret
metadata:
  name: ngc-doca-oci-helm
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  name: nvstaging-doca-oci
  url: nvcr.io/nvstaging/doca
  type: helm
  password: $NGC_API_KEY
data:
  # $oauthtoken base64 encoded. This prevents envsubst from substituting the value.
  username: JG9hdXRodG9rZW4=
    ## true
  enableOCI: dHJ1ZQ==
---
apiVersion: v1
kind: Secret
metadata:
  name: ngc-doca-https-helm
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  name: nvstaging-doca-https
  url: https://helm.ngc.nvidia.com/nvstaging/doca
  type: helm
  password: $NGC_API_KEY
data:
  username: JG9hdXRodG9rZW4=
---
apiVersion: v1
kind: Secret
metadata:
  name: ngc-carbide-https-helm
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  name: nvstaging-carbide-https
  url: https://helm.ngc.nvidia.com/0837451325059433/carbide-dev
  type: helm
  password: $NGC_API_KEY
data:
  username: JG9hdXRodG9rZW4=
```

Each Secret is labelled `argocd.argoproj.io/secret-type: repository`, which is
how Argo CD discovers Helm repositories.

Important: the `url` field must not end with a `/`, as any difference in the `url` (including an extra slash) will prevent Argo CD from matching the repository to the correct Secret.

| Secret name | Repo URL | Type | Used by |
| --- | --- | --- | --- |
| `ngc-doca-oci-helm` | `nvcr.io/nvstaging/doca` | OCI helm | DPF operator chart pulls |
| `ngc-doca-https-helm` | `https://helm.ngc.nvidia.com/nvstaging/doca` | HTTPS helm | Some DPUService charts |
| `ngc-carbide-https-helm` | `https://helm.ngc.nvidia.com/0837451325059433/carbide-dev` | HTTPS helm | Carbide-private DPUService charts |

### 1.3. Internet access for DPUs

After a DPU joins the DPU cluster, containerd on the DPU must be able to pull
container images from external registries (e.g. `nvcr.io`). Two approaches exist:

**Option A — ACL softening for DPU egress.** Open the required egress paths in your
network ACLs so DPUs can reach the container registries directly. Consult your
network team for the specific rules required.

**Option B — HTTPS proxy in the host cluster.** Deploy an HTTPS-capable forward
proxy (e.g. a SOCKS5 proxy exposed via a Kubernetes Service) that DPUs can reach and
that can forward requests onward to the internet. NICo can configure containerd on
each DPU to route image-pull traffic through the proxy at provisioning time; see
section 3.5 for the TOML configuration.

### 1.4. Cert-manager policy and RBAC for DPF

DPF relies on cert-manager to mint short-lived certificates. If the cluster
runs `approver-policy` (CRD `policy.cert-manager.io/CertificateRequestPolicy`),
**no CSR will be approved unless a matching policy whitelists it**, and DPF's
CSRs will hang in `Pending` indefinitely.

Two objects must therefore be installed:

1. A `CertificateRequestPolicy` that is permissive for the
   `dpf-operator-system` namespace.
2. A `ClusterRole` + `ClusterRoleBinding` granting cert-manager itself the
   `use` verb on that policy.

> **Note**: The policy and role below use wildcard (`*`) values for
> convenience. In production, the exact set of allowed names, SANs, and usages
> should be tightened with help from the DPF team.

#### `policy.yaml`

```yaml
---
apiVersion: policy.cert-manager.io/v1alpha1
kind: CertificateRequestPolicy
metadata:
  labels:
    argocd.argoproj.io/instance: dpf-pki-policies
  name: dpf-approval-policy
spec:
  selector:
    namespace:
      matchNames: [dpf-operator-system]
    issuerRef:
      name: '*'
      kind: '*'
      group: '*'
  allowed:
    commonName:
      value: '*'
    dnsNames:
      values: ['*']
    ipAddresses:
      values: ['*']
    uris:
      values: ['*']
    emailAddresses:
      values: ['*']
    isCA: true
    usages:
      - server auth
      - client auth
      - digital signature
      - key encipherment
```

This allows any CertificateRequest in the `dpf-operator-system` namespace,
against any issuer, with any SAN (DNS / IP / URI / email), CA or not, with the
listed usages.

#### `rbac-role.yaml`

```yaml
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cert-manager-policy:dpf-approval-policy
rules:
  - apiGroups: [policy.cert-manager.io]
    resources: [certificaterequestpolicies]
    verbs: [use]
    resourceNames: [dpf-approval-policy]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cert-manager-policy:dpf-approval-policy
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-manager-policy:dpf-approval-policy
subjects:
  - kind: ServiceAccount
    name: cert-manager
    namespace: cert-manager
```

Without this binding cert-manager's controller cannot reference the policy and
**all DPF CSRs will hang in pending**.

---

## 2. DPF Installation

Follow the [upstream DPF installation guide](https://docs.nvidia.com/networking/display/dpf25101) for the actual install procedure.

When installing the DPF operator chart, two parameter overrides are required
for a NICo-integrated deployment. The example command below illustrates how to
set them:

```bash
REGISTRY="oci://path/to/doca"
TAG="v26.4.0-rc.3"
helm upgrade --install -n dpf-operator-system \
  --set "enableNodeFeatureRules=false" \
  --set "imagePullSecrets[0].name=dpf-pull-secret" \
  dpf-operator $REGISTRY/dpf-operator --version=$TAG
```

NICo-specific notes on the parameters:

- `enableNodeFeatureRules=false` — the chart's bundled `NodeFeatureRule`
  resources are disabled because nodes are labeled via NFD's own configuration
  (relying on PCI class `0200`).
- `imagePullSecrets[0].name=dpf-pull-secret` — ties the operator's pods to the
  pull Secret created in step 1.2.b so that staging images can be pulled.

Adjust `REGISTRY` and `TAG` to the version of DPF you are deploying.

---

## 3. Post-Installation Configuration (before NICo starts)

Once the DPF operator is running, the following objects must be applied
**before NICo is started**. They configure the DPF operator for NICo's
provisioning model and grant the orchestrator the access it needs.

### 3.1. Cluster-wide RBAC for the NICo orchestrator

The NICo orchestrator (the `carbide-api` ServiceAccount in NICo's default
deployment) needs to read and write across namespaces, including
`dpf-operator-system` and the per-DPU namespaces. Grant it `cluster-admin` via
a `ClusterRoleBinding`:

```yaml
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: nico-api-dpf
  namespace: dpf-operator-system
rules:
  - apiGroups: ["provisioning.dpu.nvidia.com"]
    resources: ["bfbs"]
    verbs: ["get", "list", "create", "patch", "delete"]
  - apiGroups: ["provisioning.dpu.nvidia.com"]
    resources: ["dpus"]
    verbs: ["get", "list", "watch", "patch", "delete"]
  - apiGroups: ["provisioning.dpu.nvidia.com"]
    resources: ["dpudevices"]
    verbs: ["get", "list", "create", "patch", "delete"]
  - apiGroups: ["provisioning.dpu.nvidia.com"]
    resources: ["dpunodes"]
    verbs: ["get", "list", "create", "patch", "delete"]
  - apiGroups: ["provisioning.dpu.nvidia.com"]
    resources: ["dpunodemaintenances"]
    verbs: ["get", "patch"]
  - apiGroups: ["provisioning.dpu.nvidia.com"]
    resources: ["dpuflavors"]
    verbs: ["get", "create"]
  - apiGroups: ["provisioning.dpu.nvidia.com"]
    resources: ["dpusets"]
    verbs: ["get"]
  - apiGroups: ["provisioning.dpu.nvidia.com"]
    resources: ["dpuclusters"]
    verbs: ["get", "list"]
  - apiGroups: ["svc.dpu.nvidia.com"]
    resources: ["dpudeployments"]
    verbs: ["get", "list", "create", "patch", "delete"]
  - apiGroups: ["svc.dpu.nvidia.com"]
    resources: ["dpuservices", "dpuservicechains"]
    verbs: ["get", "list", "create", "patch", "delete"]
  - apiGroups: ["svc.dpu.nvidia.com"]
    resources: ["dpuserviceinterfaces", "dpuservicetemplates", "dpuserviceconfigurations", "dpuservicenads", "bluefieldsoftwares"]
    verbs: ["get", "list", "create", "patch", "delete"]
  - apiGroups: ["operator.dpu.nvidia.com"]
    resources: ["dpfoperatorconfigs"]
    verbs: ["get", "patch"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: nico-api-dpf
  namespace: dpf-operator-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: nico-api-dpf
subjects:
  - kind: ServiceAccount
    name: carbide-api
    namespace: forge-system
```

### 3.2. `DPFOperatorConfig`

This is the operator-level CR that tells DPF how to behave in a NICo environment. For more information about the available fields and their details, refer to the official DPF guide.

```yaml
---
apiVersion: operator.dpu.nvidia.com/v1alpha1
kind: DPFOperatorConfig
metadata:
  name: dpfoperatorconfig
  namespace: dpf-operator-system
spec:
  dpuDetector:
    disable: true
  provisioningController:
    osInstallTimeout: "60m"
    installInterface:
      installViaRedfish:
        skipDPUNodeDiscovery: true
  overrides:
    # Replace with the IP of the KubeAPI server where DPF control plane is running
    kubernetesAPIServerVIP: "REPLACE_ME"
    # Replace with the port of the KubeAPI server where DPF control plane is running
    # don't quote "" as it should be integer
    kubernetesAPIServerPort: REPLACE_ME
    argoCDNamespace: argocd
  kamajiClusterManager:
    disable: false
  networking:
    highSpeedMTU: 9000
  imagePullSecrets:
    - dpf-pull-secret
```

Field-by-field:

| Field | Meaning |
| --- | --- |
| `dpuDetector.disable: true` | DPF normally polls hosts to discover new DPUs. NICo disables auto-discovery because DPUs are fed in via `DPUSet` CRs from the orchestrator. |
| `provisioningController.osInstallTimeout: "60m"` | Total budget for the OS install flow per DPU. |
| `provisioningController.installViaRedfish` | Provision DPUs by talking Redfish to the host BMC (vs. PXE-based). |
| `skipDPUNodeDiscovery: true` | Do not auto-detect DPUs as Kubernetes nodes — DPF is told about them explicitly by NICo. |
| `overrides.kubernetesAPIServerVIP` | Replace `REPLACE_ME` with the host-cluster API-server VIP that DPUs should reach. |
| `overrides.kubernetesAPIServerPort` | Host-cluster API-server port (`6443` by default). |
| `overrides.argoCDNamespace` | Namespace where Argo CD is installed. |
| `kamajiClusterManager.disable: false` | Use Kamaji as the DPU control plane. |
| `networking.highSpeedMTU: 9000` | Jumbo frames on the high-speed fabric. |
| `imagePullSecrets: dpf-pull-secret` | Pull Secret inserted into every DPUService spawned by the operator. |

### 3.3. `DPUCluster`

The `DPUCluster` CR defines the Kubernetes control plane that DPU nodes will join. The `interface` and `vip` fields must be customized for the environment. For more information about the available fields and their details, refer to the official DPF guide.

```yaml
---
apiVersion: provisioning.dpu.nvidia.com/v1alpha1
kind: DPUCluster
metadata:
  name: carbide-dpf-cluster
  namespace: dpf-operator-system
spec:
  type: kamaji
  maxNodes: 1000
  clusterEndpoint:
    keepalived:
      # Controller interface where the Kamaji cluster IP is configured
      interface: "REPLACE_ME"
      # External IP used by the Kamaji cluster that needs to be accessible from the DPUs
      vip: "REPLACE_ME"
      virtualRouterID: 126
      nodeSelector:
        # Confirm this with node. Some env can have this as 'true' also.
        # kubectl get node <node-name> -o jsonpath='{.metadata.labels.node-role\.kubernetes\.io/control-plane}'
        node-role.kubernetes.io/control-plane: ""
```

Field-by-field:

| Field | Meaning |
| --- | --- |
| `type: kamaji` | Use the Kamaji cluster manager; the DPU control plane runs as a Kamaji `TenantControlPlane` in the host cluster. |
| `maxNodes: 1000` | Hard cap on DPU nodes that can join. |
| `clusterEndpoint.keepalived.interface` | Host network interface on which keepalived advertises the VIP. |
| `clusterEndpoint.keepalived.vip` | Floating IP that DPU nodes use to reach their control plane. |
| `clusterEndpoint.keepalived.virtualRouterID: 126` | VRRP ID; **must be unique per host** if multiple keepalived instances run there. |
| `nodeSelector` | Schedule keepalived only on control-plane nodes. |

### 3.4. VIP LoadBalancer Service and Endpoints

This step exposes the Kamaji cluster IP so it is routable from the DPUs. It may not be required in environments where routing to the VIP is already in place; in that case skip it.

The Service uses a fixed `loadBalancerIP` matching the VIP set in the `DPUCluster` above. Replace the `loadBalancerIP` value before applying.

> Note: It only applies for MetalLB-managed deployments.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: dpu-cluster-vip-loadbalancer
  namespace: dpf-operator-system
  annotations:
    metallb.io/address-pool: 'REPLACE_ME'
spec:
  allocateLoadBalancerNodePorts: true
  loadBalancerIP: "External IP used by the Kamaji cluster"
  ports:
  - port: 80
    targetPort: 80
    protocol: TCP
  type: LoadBalancer
---
apiVersion: v1
kind: Endpoints
metadata:
  name: dpu-cluster-vip-loadbalancer
  namespace: dpf-operator-system
subsets:
- addresses:
  - ip: 192.0.2.10     # dummy/test IP (RFC 5737 range)
  ports:
  - port: 80
```

What this does and why it looks unusual:

- The `Service` is type `LoadBalancer` with a fixed `loadBalancerIP` (the same VIP used by the `DPUCluster` keepalived). The `metallb.io/address-pool: REPLACE_ME` annotation should be updated with a correct pool name. It tells MetalLB to pull the IP from the updated pool defined elsewhere.
- A **manually-created `Endpoints`** object with a single dummy RFC 5737 IP (`192.0.2.10`) is created **with the same name** as the Service. This is a Kubernetes idiom: when an `Endpoints` resource has the same name as a Service that has **no selector**, the kubelet uses those Endpoints verbatim.  Putting a dummy IP here means: *"reserve the VIP via MetalLB, but route nothing — keepalived is the actual front-end."*
- Net effect: MetalLB advertises the VIP to the network so external machines (DPUs, BMCs) can reach it, while keepalived handles the actual TCP termination.

If your environment uses a different LoadBalancer mechanism (kube-vip, a cloud-provider LB, etc.), use it to expose the VIP and point the `DPUCluster`'s `keepalived.vip` at the same address.

### 3.5. Enable DPF in the NICo site config

DPF integration is gated on a site-level switch in the carbide-api TOML config
(the file mounted into the `carbide-api` deployment, typically via the
`carbide-api-site-config-files` ConfigMap). Add a `[dpf]` section and set
`enabled = true`:

```toml
[dpf]
enabled = true
docker_image_pull_secret = "nico-pull-secret"
```

`docker_image_pull_secret` is an optional parameter that specifies the name of the Kubernetes Secret used to pull service container images for NICo services. If this field is omitted, NICo defaults to using the `dpf-pull-secret` for image pulls. In this scenario, ensure that the `dpf-pull-secret` is configured with a legacy NGC API key for better compatibility.

`[dpf].services.*` sub-tables can additionally override the Helm chart and
container image of each mandatory DPUService that carbide-api deploys
(`dts`, `doca_hbn`, `dpu_agent`, `dhcp_server`, `fmds`, `otel`). All of these
have built-in defaults; override them only when pinning to a non-default
version or registry. Each entry has the same shape:

```toml
[dpf.services.<service>]
name                    = "<logical service name>"
helm_repo_url           = "<helm repository URL>"
helm_chart              = "<helm chart name>"
helm_version            = "<helm chart version>"   # empty → CI default
docker_repo_url         = "<image registry+repo>"
docker_image_tag        = "<image tag>"            # empty → CI default
docker_image_pull_secret = "dpf-pull-secret"
```

#### Per-deployment configuration (`[dpf.deployments.*]`)

Each DPU generation is provisioned by its own `DPUDeployment`, configured under
`[dpf.deployments.<name>]`. **BF3** is always present with built-in defaults;
**BF4 (generic)** is opt-in and is activated only when a
`[dpf.deployments.bf4_generic]` table is present. Both deployments run
side-by-side, each with its own BFB, `DPUFlavor`, and `DPUDeployment`.

Every active deployment must have a **unique** `deployment_name`, `flavor_name`,
and `node_label_key`; carbide-api validates this at startup and refuses to start
if any deployments collide.

```toml
# BF3 is present by default. Override only if any change is needed.
[dpf.deployments.bf3]
bfb_url         = "https://content.mellanox.com/BlueField/BFBs/Ubuntu24.04/bf-bundle-3.2.2-125_26.02_ubuntu-24.04_64k_prod.bfb"
flavor_name     = "carbide-dpu-flavor"
deployment_name = "nico-deployment-v2"
node_label_key  = "carbide.nvidia.com/controlled.node.v2"

# BF4 generic is opt-in. Add this table to provision BF4 DPUs via a second
# DPUDeployment alongside BF3. All identifiers must differ from BF3's.
[dpf.deployments.bf4_generic]
bfb_url         = "https://content.mellanox.com/BlueField/BFBs/Ubuntu24.04/bf-bundle-<bf4-version>.bfb"
flavor_name     = "carbide-dpu-flavor-bf4"
deployment_name = "nico-deployment-bf4"
node_label_key  = "carbide.nvidia.com/controlled.node.bf4"
```

Per-deployment field reference:

| TOML key | Required | Default (bf3) | Meaning |
| --- | :---: | --- | --- |
| `bfb_url` | no | BF3 bf-bundle URL | BlueField firmware bundle (BFB) used to provision the DPU. |
| `flavor_name` | yes | `carbide-dpu-flavor` | `DPUFlavor` CR name for this deployment. |
| `deployment_name` | yes | `nico-deployment-v2` | `DPUDeployment` CR name. |
| `node_label_key` | yes | `carbide.nvidia.com/controlled.node.v2` | Node-selector label key applied to this deployment's DPUNodes. |
| `services` | no | inherit `[dpf.services]` | Optional per-deployment mandatory-services override (see below). |

**Per-deployment services override.** By default every deployment inherits the
top-level `[dpf.services]` mandatory services. A deployment can pin its own
versions by adding a `[dpf.deployments.<name>.services]` block with the same six
sub-tables as `[dpf.services]` (`dts`, `doca_hbn`, `dpu_agent`, `dhcp_server`,
`fmds`, `otel`). This override **replaces** the inherited set for that
deployment; any service sub-table you omit falls back to its **built-in
default**, *not* to the top-level `[dpf.services]` value, so specify all six
when using it. The top-level `docker_image_pull_secret` still applies on top of
the resolved set (every service except `dts` and `doca_hbn`).

```toml
# Pin a BF4-specific HBN chart/image while keeping the other services on defaults.
[dpf.deployments.bf4_generic.services.doca_hbn]
name                     = "doca-hbn"
helm_repo_url            = "https://helm.ngc.nvidia.com/nvidia/doca"
helm_chart               = "doca-hbn"
helm_version             = "3.4.0"
docker_repo_url          = "nvcr.io/nvidia/doca/doca_hbn"
docker_image_tag         = "3.4.0-doca3.4.0"
# ...plus dts, dpu_agent, dhcp_server, fmds, and otel sub-tables.
```

If your environment routes DPU image pulls through an HTTPS forward proxy (Option B
from section 1.3), add a `[dpf.proxy]` table:

```toml
[dpf.proxy]
https_proxy = "socks5://<proxy-host>:<port>"
no_proxy = ["10.0.0.0/8", "192.168.0.0/16", "localhost", ".cluster.local"]
```

When set, NICo embeds a systemd drop-in
(`/etc/systemd/system/containerd.service.d/socks-proxy.conf`) into the `DPUFlavor`
spec so that containerd on every DPU routes outbound HTTPS traffic through the proxy.
The proxy is part of the flavor spec — changing or adding `[dpf.proxy]` produces a
new flavor name (hash-derived) and triggers a full DPU reprovisioning. Set it before
the first NICo startup with DPF enabled if possible.

Field reference (all under `[dpf]`):

| TOML key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Master switch. Must be `true` to use DPF-based provisioning. |
| `docker_image_pull_secret` | string | `dpf-pull-secret` | Pull Secret applied to every mandatory service except `dts` and `doca_hbn`. |
| `services.<svc>` | table | per-service defaults | Helm/image overrides for each mandatory DPUService. |
| `deployments.bf3` | table | BF3 defaults | BF3 DPUDeployment config; always active. |
| `deployments.bf4_generic` | table | — | BF4 (generic) DPUDeployment config; opt-in, active only when present. |
| `deployments.<name>.services.<svc>` | table | inherit `[dpf.services]` | Optional per-deployment mandatory-service override. |
| `proxy.https_proxy` | string | — | HTTPS proxy URL for DPU image pulls (see section 3.5). |
| `proxy.no_proxy` | list of strings | `[]` | Hosts/CIDRs that must bypass the proxy. |

Notes:

- The DPF operator namespace (`dpf-operator-system`) and the kubeconfig used
  to talk to the host cluster are **not** configured here — carbide-api uses
  its in-cluster ServiceAccount and the fixed `dpf-operator-system` namespace.

### 3.6. Mark hosts as DPF-managed in expected machines

Whether a given host is provisioned via DPF or via iPXE is decided per host,
in the *expected machines* list that NICo loads on startup. The relevant
field is **`is_dpf_enabled`** on each expected-machine entry. A host is
provisioned via DPF only when **both** of the following are true:

1. `[dpf].enabled = true` in the site config (section 3.5), and
2. `is_dpf_enabled = true` on that host's expected-machine entry.

There are several operator paths that can set this field. They are described
below in the order an operator typically uses them.

#### 3.6.a. `nico-admin-cli expected-machine add` — create a new entry

Adds a new expected-machine row. `--dpf-enabled` is optional; **omitting it
stores `false`**.

```bash
nico-admin-cli expected-machine add \
  --bmc-mac-address 1a:1b:1c:1d:1e:1f \
  --bmc-username admin \
  --bmc-password secret \
  --chassis-serial-number CHASSIS-SN-001 \
  --dpf-enabled true
```

#### 3.6.b. `nico-admin-cli expected-machine patch` — partial update via flags

Updates an existing entry in place. The lookup key is `--bmc-mac-address`
(or `--id <UUID>`). Omitting `--dpf-enabled` **preserves** the existing
value.

```bash
nico-admin-cli expected-machine patch \
  --bmc-mac-address 1a:1b:1c:1d:1e:1f \
  --chassis-serial-number CHASSIS-SN-001 \
  --dpf-enabled true
```

#### 3.6.c. `nico-admin-cli expected-machine update --filename` — single-host update from JSON

Updates one entry from a JSON file. The JSON shape uses
`chassis_serial_number` (not `serial_number`) and any field omitted from the
file is **preserved** server-side.

`em.json`:

```json
{
  "bmc_mac_address": "1a:1b:1c:1d:1e:1f",
  "bmc_username": "admin",
  "bmc_password": "secret",
  "chassis_serial_number": "CHASSIS-SN-001",
  "dpf_enabled": true
}
```

```bash
nico-admin-cli expected-machine update --filename em.json
```

This is the most ergonomic path for "toggle DPF on one already-existing
expected machine without touching anything else."

#### 3.6.d. `nico-admin-cli expected-machine replace-all --filename` — destructive full reload

Wipes the entire `expected_machines` table and re-creates it from the file.
The file shape is a wrapper object whose `expected_machines` array uses the
same per-entry shape as `update`:

`em-all.json`:

```json
{
  "expected_machines": [
    {
      "bmc_mac_address": "1a:1b:1c:1d:1e:1f",
      "bmc_username": "admin",
      "bmc_password": "secret",
      "chassis_serial_number": "CHASSIS-SN-001",
      "dpf_enabled": true
    }
  ]
}
```

```bash
nico-admin-cli expected-machine replace-all --filename em-all.json
```

> **Important**: this is **not a merge**. Any expected-machine row that is
> not present in the file is **deleted**. Each entry is then re-created via
> the same path as `add`, so any entry whose `dpf_enabled` is omitted is
> re-inserted with `dpf_enabled = false`.

#### 3.6.e. Quick reference

| Goal | Path |
| --- | --- |
| Add a new host with DPF enabled | `nico-admin-cli expected-machine add … --dpf-enabled true` |
| Flip DPF on an existing entry, preserving everything else | `nico-admin-cli expected-machine update --filename em.json` |
| Flip DPF inline with one or more other fields | `nico-admin-cli expected-machine patch … --dpf-enabled true` |
| Replace the entire inventory | `nico-admin-cli expected-machine replace-all --filename em-all.json` |
| Inspect current value | `nico-admin-cli expected-machine show <bmc-mac>` |

### 3.7 Enabling DPF for Existing (Ingested) Nodes

You can enable the DPF flag on an already discovered host without force-deleting or recreating it by using:

```bash
nico-admin-cli dpf enable <host-id>
```

After changing the DPF status for a host in this way, you should trigger a reprovisioning for all the DPUs under a host (using its host ID). For environments where a host has multiple DPUs, make sure to trigger reprovisioning for all DPUs under the host; otherwise, NICo will not transition the node to DPF-managed status.

**Note:** The `nico-admin-cli dpf enable` command updates the DPF flag only for the currently ingested machine. If you later force-delete the host, this change is lost—on rediscovery, the DPF setting will revert to whatever is present in your `expected_machines` database.

---

## 4. Restart carbide-api to create the DPF initialization objects

Once everything in sections 1–3 is in place, carbide-api must be (re)started.
DPF initialization in carbide-api is **startup-only**: the `[dpf]` config is
read once when the process comes up, and that is the only point at which the
DPF initialization objects are created in the host cluster.

On startup with `[dpf].enabled = true`, carbide-api creates the following
objects in the `dpf-operator-system` namespace. It does this **once for each active
deployment** in `[dpf.deployments.*]` (BF3 always, plus `bf4_generic` when
that table is present), using that deployment's own `bfb_url`, `flavor_name`,
and `deployment_name`:

- A `Secret` (`bmc-shared-password`) holding the shared BMC password (shared
  across deployments)
- A `BFB` CR named `bf-bundle-<sha256(bfb_url)>`, from the deployment's `bfb_url`
- A `DPUFlavor` CR named `<flavor_name>-<spec-hash>`. (The 16-character hex suffix is a SHA-256 digest of the spec. Any change to the flavor, including adding or changing `[dpf.proxy]`, produces a new name and triggers reprovisioning of that deployment's DPUs.)
- A set of `DPUServiceInterface`, `DPUServiceTemplate`,
  `DPUServiceConfiguration`, and `DPUServiceNAD` CRs, one per mandatory
  DPUService (`dts`, `doca-hbn`, `carbide-dpu-agent`, `carbide-dhcp-server`,
  `carbide-fmds`, and `carbide-otelcol`). The set is built from the deployment's
  resolved services -- either its `[dpf.deployments.<name>.services]` override if
  set, otherwise the top-level `[dpf.services]`.
- A `DPUDeployment` CR named after the deployment's `deployment_name`, which
  references the BFB, the DPUFlavor, and the service templates above, and which
  the DPF operator then reconciles into actual `DPUService` and per-DPU
  resources.

Because this path runs only at process start, **any change to `[dpf]`** —
enabling DPF for the first time, changing a deployment's BFB URL, renaming a
`DPUDeployment`/`DPUFlavor`, adding or removing `[dpf.deployments.bf4_generic]`,
pinning a different chart/image version under `[dpf.services.*]` or a
deployment's `[dpf.deployments.<name>.services]`, or adding/changing
`[dpf.proxy]` — **requires a carbide-api restart** for the new configuration to
take effect.

---

## Appendix: `nico-admin-cli dpf` command reference

`nico-admin-cli` ships a top-level `dpf` subcommand group for inspecting and
toggling DPF state on already-ingested hosts and for diffing the running DPF
service stack against the configured one. The full set is listed below.

> **Important**: All `dpf enable` changes are written to the
> machine's metadata only. **They are wiped on force-delete** and on
> rediscovery the host reverts to whatever its expected-machine entry says.
> To persist the per-host DPF setting, update the expected-machines table
> (see section 3.6). This is useful when you want to reprovision a host that
> was not previously managed by DPF, using the DPF framework.

### `dpf enable` — turn DPF on for a host

```bash
nico-admin-cli dpf enable <host-machine-id>
```

| Argument | Required | Notes |
|---|:---:|---|
| `<host-machine-id>` | yes | Must be a **host** machine id; DPU ids are rejected. |

Sets `machines.dpf.enabled = true` on the given host's runtime row by calling
the `ModifyDPFState` RPC.

### `dpf show` — inspect DPF state for one or all hosts

```bash
# One host
nico-admin-cli dpf show <host-machine-id>

# All hosts (paginated by --page-size)
nico-admin-cli dpf show
```

| Argument | Required | Notes |
|---|:---:|---|
| `<host-machine-id>` | no | If omitted, lists DPF state for **every** host. DPU ids are rejected. |

Output for a single host prints `Enabled` and `Used For Ingestion` flags; the
multi-host form prints a table with one row per host. DPUs are excluded
from the all-hosts list.

### `dpf snapshot` — dump DPF CRs for a host

```bash
nico-admin-cli dpf snapshot <host-machine-id>
```

| Argument | Required | Notes |
|---|:---:|---|
| `<host-machine-id>` | yes | Must be a host machine id; DPU ids are rejected. |

Calls the `GetDpfHostSnapshot` RPC and prints the `DPUNode`, `DPUDevice`, and
`DPU` CRs that DPF currently has for the given host. Useful for diagnosing
why a host is stuck during DPF-based provisioning.

### `dpf service-version` (alias: `sv`) — diff configured vs. deployed services

```bash
nico-admin-cli dpf service-version
# or
nico-admin-cli dpf sv
```

No arguments. Prints a table comparing each configured DPF service
(`[dpf.services.*]` from the site config if given or read it from
the compile time version) against what is actually deployed
in the cluster:

| Column | Meaning |
| --- | --- |
| `Service` | Logical service name (`dts`, `doca-hbn`, ...). |
| `Config Helm Version` | Helm chart version used by NICo. |
| `Live Helm Version` | Helm chart version currently deployed; suffixed with `(match)` or `(DIFFERS)`, or `n/a` if not deployed. |
| `Config Docker Tag` | Image tag used by NICo (`-` if unset). |
| `Live Docker Tag` | Image tag currently deployed; suffixed with `(match)` or `(DIFFERS)`, or `n/a` if not deployed. |

A `DIFFERS` row indicates the running stack does not match the carbide-api
config and that a carbide-api restart (section 4) is needed to reconcile the
configured versions onto the cluster.

### Quick reference

| Goal | Command |
| --- | --- |
| Turn DPF on for an already-discovered host (transient) | `nico-admin-cli dpf enable <host-id>` |
| Show DPF state for one host | `nico-admin-cli dpf show <host-id>` |
| List DPF state for all hosts | `nico-admin-cli dpf show` |
| Snapshot DPF CRs for a host | `nico-admin-cli dpf snapshot <host-id>` |
| Diff configured vs. deployed DPF service versions | `nico-admin-cli dpf service-version` |
